// Package server implements `escalint serve`: the embedded UI and one
// analysis, read-only, on the loopback interface (ADR 0017). Controls:
// random port, a one-time random token in the first URL exchanged for a
// separate session value in an HttpOnly SameSite=Strict cookie, a Host
// check against DNS rebinding, GET only, a strict Content-Security-Policy
// and isolation headers.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"
)

// CSP is the Content-Security-Policy of every response (ADR 0017).
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; " +
	"connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// CookieName prefixes the session cookie set by the token exchange. The
// listener port is appended: browsers do not scope cookies by port, so two
// servers on 127.0.0.1 would otherwise overwrite each other's session.
const CookieName = "escalint_session"

// NewToken returns 32 random bytes, base64url-encoded.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Handler serves the UI and the analysis.
type Handler struct {
	assets   fs.FS
	analysis []byte
	token    string
	// session is the cookie value. It differs from the token, which is
	// accepted once: a URL that leaks after use (shell history, a screen
	// share) opens nothing.
	session string
	cookie  string // cookie name, CookieName plus the port
	used    atomic.Bool
	// allowedHosts are the Host header values accepted (host:port).
	allowedHosts map[string]bool
}

// New builds the handler. hosts lists the accepted Host header values.
func New(assets fs.FS, analysis []byte, token string, hosts []string) *Handler {
	// crypto/rand.Text never fails (it crashes the program instead).
	h := &Handler{assets: assets, analysis: analysis, token: token, session: rand.Text(), cookie: CookieName, allowedHosts: map[string]bool{}}
	if len(hosts) > 0 {
		if _, port, err := net.SplitHostPort(hosts[0]); err == nil {
			h.cookie += "_" + port
		}
	}
	for _, host := range hosts {
		h.allowedHosts[strings.ToLower(host)] = true
	}
	return h
}

// Hosts returns the Host values a browser sends for a listener address:
// the address itself and, on loopback, localhost and the other loopback
// spelling. A wildcard address (0.0.0.0, ::) accepts every local interface
// address. names are host names the listener was asked for (--listen
// my-host:8080). Attacker-chosen names are still rejected, which is what
// defeats DNS rebinding.
func Hosts(addr net.Addr, names ...string) []string {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return []string{addr.String()}
	}
	port := fmt.Sprint(tcp.Port)
	out := []string{net.JoinHostPort(tcp.IP.String(), port)}
	if tcp.IP.IsLoopback() || tcp.IP.IsUnspecified() {
		out = append(out, net.JoinHostPort("localhost", port), net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port))
	}
	if tcp.IP.IsUnspecified() {
		addrs, err := net.InterfaceAddrs()
		if err == nil { // without the list only loopback and the names work
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					out = append(out, net.JoinHostPort(ipn.IP.String(), port))
				}
			}
		}
	}
	for _, n := range names {
		if n != "" && net.ParseIP(n) == nil {
			out = append(out, net.JoinHostPort(n, port))
		}
	}
	return out
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", CSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
}

func equal(candidate, secret string) bool {
	return candidate != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(secret)) == 1
}

func (h *Handler) validSession(r *http.Request) bool {
	c, err := r.Cookie(h.cookie)
	return err == nil && equal(c.Value, h.session)
}

// ServeHTTP enforces the controls in order: headers, Host, method, auth.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !h.allowedHosts[strings.ToLower(r.Host)] {
		http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if t := r.URL.Query().Get("token"); t != "" {
		if h.validSession(r) {
			// The printed URL opened again in a browser that already has
			// the session.
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !equal(t, h.token) || !h.used.CompareAndSwap(false, true) {
			http.Error(w, "invalid or already used token: restart escalint serve for a new URL", http.StatusUnauthorized)
			return
		}
		// Exchange the token for a cookie and drop it from the address bar
		// (and from history, referrers and screenshots).
		// #nosec G124 -- plain HTTP on loopback: a Secure cookie would not be
		// sent back by every browser; HttpOnly and SameSite=Strict are set.
		http.SetCookie(w, &http.Cookie{
			Name: h.cookie, Value: h.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
			Expires: time.Now().Add(12 * time.Hour),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !h.validSession(r) {
		http.Error(w, "unauthorized: open the URL printed by escalint serve", http.StatusUnauthorized)
		return
	}
	switch p := path.Clean("/" + r.URL.Path); p {
	case "/analysis.json":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(h.analysis) // the client went away: nothing to do
	case "/":
		h.serveFile(w, "index.html")
	default:
		h.serveFile(w, strings.TrimPrefix(p, "/"))
	}
}

var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
	".woff2": "font/woff2", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
}

func (h *Handler) serveFile(w http.ResponseWriter, name string) {
	data, err := fs.ReadFile(h.assets, name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	ct, ok := contentTypes[path.Ext(name)]
	if !ok {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable") // hashed names
	}
	_, _ = w.Write(data) // #nosec G705 -- embedded build output, served with its content type and nosniff
}

// ErrNotLoopback is returned when --listen names a non-loopback address
// and the caller did not confirm it.
var ErrNotLoopback = errors.New("not a loopback address")

// IsLoopback reports whether a listen address binds only to loopback.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
