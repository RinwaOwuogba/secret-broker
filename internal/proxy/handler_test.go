package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RinwaOwuogba/secret-broker/internal/config"
	"github.com/RinwaOwuogba/secret-broker/internal/route"
)

type mapStore map[string]string

func (m mapStore) Get(n string) (string, error) {
	v, ok := m[n]
	if !ok {
		return "", fmt.Errorf("no secret %q", n)
	}
	return v, nil
}

// fixture builds a handler wired to a fake upstream; upstreamSeen captures what
// the upstream received so tests can assert on injected/forwarded headers.
func fixture(t *testing.T, secrets mapStore) (*Handler, *bytes.Buffer, *http.Request) {
	t.Helper()
	rules, _ := route.NewRule("GET", `^/twitter/.+`)
	up := &config.Upstream{Base: "", Header: "x-api-key", Secret: "twitterapi", Rules: []route.Rule{rules}}
	logBuf := &bytes.Buffer{}
	h := &Handler{
		Upstreams: map[string]*config.Upstream{"tw": up},
		Agents:    map[string]*config.Agent{"scout": {Selectors: []string{"tw"}}},
		Authn:     func(tok string) (string, bool) { return "scout", tok == "good-token" },
		Secrets:   secrets,
		Client:    http.DefaultClient,
		Logger:    slog.New(slog.NewTextHandler(logBuf, nil)),
	}
	return h, logBuf, nil
}

func TestProxyInjectsSecretAndStripsBrokerToken(t *testing.T) {
	var gotKey, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	h, _, _ := fixture(t, mapStore{"twitterapi": "SUPERSECRET"})
	h.Upstreams["tw"].Base = upstream.URL

	req := httptest.NewRequest("GET", "/tw/twitter/user/info?userName=x", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if gotKey != "SUPERSECRET" {
		t.Fatalf("upstream got x-api-key %q, want injected secret", gotKey)
	}
	if gotAuth != "" {
		t.Fatalf("broker token leaked upstream: Authorization=%q", gotAuth)
	}
}

func TestProxyAuthAndRoutingErrors(t *testing.T) {
	h, _, _ := fixture(t, mapStore{"twitterapi": "s"})
	cases := []struct {
		name, method, path, auth string
		want                     int
	}{
		{"missing token", "GET", "/tw/twitter/x", "", 401},
		{"bad token", "GET", "/tw/twitter/x", "Bearer nope", 401},
		{"unknown upstream", "GET", "/zz/twitter/x", "Bearer good-token", 404},
		{"route not allowed", "GET", "/tw/admin/keys", "Bearer good-token", 403},
		{"method not allowed", "POST", "/tw/twitter/x", "Bearer good-token", 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			if c.auth != "" {
				req.Header.Set("Authorization", c.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("status = %d want %d (body %s)", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

func TestProxyForbidsSelectorNotGrantedToAgent(t *testing.T) {
	h, _, _ := fixture(t, mapStore{"twitterapi": "s"})
	h.Agents["scout"] = &config.Agent{Selectors: []string{"other"}} // scout may NOT use "tw"
	req := httptest.NewRequest("GET", "/tw/twitter/x", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("status = %d want 403", rec.Code)
	}
}

// Marquee security test: the raw secret must never surface in the client-facing
// error body or in the audit log, even when the upstream call fails.
func TestSecretNeverLeaksOnError(t *testing.T) {
	const sekret = "DEADBEEF-SECRET"
	// Point the upstream at an unroutable address so the forward fails.
	h, logBuf, _ := fixture(t, mapStore{"twitterapi": sekret})
	h.Upstreams["tw"].Base = "http://127.0.0.1:1" // connection refused

	req := httptest.NewRequest("GET", "/tw/twitter/user/info", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code < 500 {
		t.Fatalf("expected a 5xx on upstream failure, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), sekret) {
		t.Fatalf("secret leaked into error body: %s", rec.Body.String())
	}
	if strings.Contains(logBuf.String(), sekret) {
		t.Fatalf("secret leaked into logs: %s", logBuf.String())
	}
}

func TestSecretMissingFailsClosed(t *testing.T) {
	h, _, _ := fixture(t, mapStore{}) // no secret registered
	req := httptest.NewRequest("GET", "/tw/twitter/x", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code < 500 {
		t.Fatalf("missing secret must fail closed with 5xx, got %d", rec.Code)
	}
}

func TestConstantTimeAuthn(t *testing.T) {
	authn := NewTokenAuthn(map[string]string{"tok-abc": "scout", "tok-xyz": "ego"})
	if a, ok := authn("tok-abc"); !ok || a != "scout" {
		t.Fatalf("got (%q,%v) want (scout,true)", a, ok)
	}
	if _, ok := authn("wrong"); ok {
		t.Fatal("unknown token must not authenticate")
	}
}

var _ = io.Discard
