// Package server implements `escalint serve`: the embedded UI and one
// analysis, read-only, on the loopback interface (ADR 0017). Controls:
// random port, a random token in the first URL exchanged for an HttpOnly
// SameSite=Strict cookie, a Host check against DNS rebinding, GET only,
// a strict Content-Security-Policy and isolation headers.
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
	"time"
)

// CSP is the Content-Security-Policy of every response (project.md §3.7).
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; " +
	"connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// CookieName holds the session after the token exchange.
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
	// allowedHosts are the Host header values accepted (host:port).
	allowedHosts map[string]bool
}

// New builds the handler. hosts lists the accepted Host header values.
func New(assets fs.FS, analysis []byte, token string, hosts []string) *Handler {
	h := &Handler{assets: assets, analysis: analysis, token: token, allowedHosts: map[string]bool{}}
	for _, host := range hosts {
		h.allowedHosts[strings.ToLower(host)] = true
	}
	return h
}

// Hosts returns the Host values a browser sends for a listener address:
// the address itself and, on loopback, localhost and the other loopback
// spelling.
func Hosts(addr net.Addr) []string {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return []string{addr.String()}
	}
	port := fmt.Sprint(tcp.Port)
	out := []string{net.JoinHostPort(tcp.IP.String(), port)}
	if tcp.IP.IsLoopback() {
		out = append(out, net.JoinHostPort("localhost", port), net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port))
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

func (h *Handler) validToken(candidate string) bool {
	return candidate != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(h.token)) == 1
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
		if !h.validToken(t) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// Exchange the token for a cookie and drop it from the address bar
		// (and from history, referrers and screenshots).
		// #nosec G124 -- plain HTTP on loopback: a Secure cookie would not be
		// sent back by every browser; HttpOnly and SameSite=Strict are set.
		http.SetCookie(w, &http.Cookie{
			Name: CookieName, Value: h.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
			Expires: time.Now().Add(12 * time.Hour),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	c, err := r.Cookie(CookieName)
	if err != nil || !h.validToken(c.Value) {
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
