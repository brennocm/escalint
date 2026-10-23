package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const host = "127.0.0.1:43210"

func handler() *Handler {
	assets := fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<!doctype html><title>escalint</title>")},
		"assets/app-1.js":   &fstest.MapFile{Data: []byte("console.log(1)")},
		"assets/font.woff2": &fstest.MapFile{Data: []byte("x")},
		"assets/blob.bin":   &fstest.MapFile{Data: []byte("x")},
	}
	return New(assets, []byte(`{"schema_version":"1"}`), "secret-token", []string{host, "localhost:43210"})
}

func do(h http.Handler, method, target, hostHeader string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = hostHeader
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var session = &http.Cookie{Name: CookieName, Value: "secret-token"}

func TestAccessControl(t *testing.T) {
	h := handler()
	cases := []struct {
		name   string
		method string
		target string
		host   string
		cookie *http.Cookie
		want   int
	}{
		{"no token", http.MethodGet, "/", host, nil, http.StatusUnauthorized},
		{"wrong token", http.MethodGet, "/?token=guess", host, nil, http.StatusUnauthorized},
		{"wrong cookie", http.MethodGet, "/analysis.json", host, &http.Cookie{Name: CookieName, Value: "guess"}, http.StatusUnauthorized},
		{"rebinding host", http.MethodGet, "/", "evil.example:43210", session, http.StatusMisdirectedRequest},
		{"post", http.MethodPost, "/", host, session, http.StatusMethodNotAllowed},
		{"put", http.MethodPut, "/analysis.json", host, session, http.StatusMethodNotAllowed},
		{"head", http.MethodHead, "/", host, session, http.StatusMethodNotAllowed},
		{"delete", http.MethodDelete, "/", host, session, http.StatusMethodNotAllowed},
		{"options", http.MethodOptions, "/", host, session, http.StatusMethodNotAllowed},
		{"index", http.MethodGet, "/", host, session, http.StatusOK},
		{"localhost", http.MethodGet, "/", "LOCALHOST:43210", session, http.StatusOK},
		{"analysis", http.MethodGet, "/analysis.json", host, session, http.StatusOK},
		{"asset", http.MethodGet, "/assets/app-1.js", host, session, http.StatusOK},
		{"missing", http.MethodGet, "/assets/nope.js", host, session, http.StatusNotFound},
		{"traversal", http.MethodGet, "/../../etc/passwd", host, session, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(h, c.method, c.target, c.host, c.cookie)
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d (%s)", w.Code, c.want, w.Body.String())
			}
			// Security headers are on every response, errors included.
			if got := w.Header().Get("Content-Security-Policy"); got != CSP {
				t.Errorf("CSP = %q", got)
			}
			for k, v := range map[string]string{
				"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
				"Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
			} {
				if got := w.Header().Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			if c.want == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodGet {
				t.Error("Allow header missing")
			}
		})
	}
}

func TestCSPIsExact(t *testing.T) {
	want := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	if CSP != want {
		t.Errorf("CSP changed:\n%s\n%s", CSP, want)
	}
}

func TestTokenExchange(t *testing.T) {
	h := handler()
	w := do(h, http.MethodGet, "/?token=secret-token", host, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("exchange: %d %q", w.Code, w.Header().Get("Location"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %+v", cookies)
	}
	c := cookies[0]
	if c.Name != CookieName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("cookie = %+v", c)
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), "SameSite=Strict") {
		t.Errorf("Set-Cookie = %q", w.Header().Get("Set-Cookie"))
	}
	ok := do(h, http.MethodGet, "/analysis.json", host, c)
	if ok.Code != http.StatusOK || ok.Header().Get("Content-Type") != "application/json" || ok.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("analysis: %d %v", ok.Code, ok.Header())
	}
	asset := do(h, http.MethodGet, "/assets/app-1.js", host, c)
	if !strings.HasPrefix(asset.Header().Get("Content-Type"), "text/javascript") || !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset headers = %v", asset.Header())
	}
	if bin := do(h, http.MethodGet, "/assets/blob.bin", host, c); bin.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("bin content type = %q", bin.Header().Get("Content-Type"))
	}
}

func TestHostsAndLoopback(t *testing.T) {
	hosts := Hosts(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	want := map[string]bool{"127.0.0.1:8080": true, "localhost:8080": true, "[::1]:8080": true}
	for _, h := range hosts {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("hosts = %v", hosts)
	}
	if got := Hosts(&net.TCPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 80}); len(got) != 1 || got[0] != "192.168.1.2:80" {
		t.Errorf("lan hosts = %v", got)
	}
	if got := Hosts(&net.UnixAddr{Name: "/tmp/s", Net: "unix"}); got[0] != "/tmp/s" {
		t.Errorf("unix = %v", got)
	}
	for addr, want := range map[string]bool{"127.0.0.1:0": true, "[::1]:8080": true, "localhost:1": true, "0.0.0.0:80": false, "192.168.1.2:80": false, "bad": false} {
		if IsLoopback(addr) != want {
			t.Errorf("IsLoopback(%q) != %v", addr, want)
		}
	}
	tok, err := NewToken()
	if err != nil || len(tok) != 43 {
		t.Errorf("token = %q %v", tok, err)
	}
}
