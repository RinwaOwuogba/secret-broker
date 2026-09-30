// Package proxy is the serve path: authenticate the caller, check the route
// allowlist, inject the real upstream credential, forward, and return the
// response. The raw secret is touched only between Secrets.Get and the outbound
// request — it is never logged, never written to the client, never sent back to
// the agent.
package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/RinwaOwuogba/secret-broker/internal/config"
	"github.com/RinwaOwuogba/secret-broker/internal/route"
)

// Per-request deadlines are applied in the handler (not the shared client) so they
// can depend on the upstream's mode: a JSON API call should finish quickly, but a
// git clone or push of a real repository legitimately runs for minutes.
const (
	apiTimeout = 30 * time.Second
	gitTimeout = 30 * time.Minute
)

// Store is the read-only secret dependency (satisfied by secret.DirStore).
type Store interface {
	Get(name string) (string, error)
}

// Handler is the injecting reverse proxy.
type Handler struct {
	Upstreams map[string]*config.Upstream
	Agents    map[string]*config.Agent
	Authn     Authn
	Secrets   Store
	Client    *http.Client
	Logger    *slog.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sel, upath, ok := splitPath(r.URL.Path)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// 1. Authenticate the caller (bearer token → agent).
	token := bearer(r.Header.Get("Authorization"))
	agentName, ok := "", false
	if token != "" {
		agentName, ok = h.Authn(token)
	}
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Resolve the upstream.
	up, ok := h.Upstreams[sel]
	if !ok {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}

	// 3. Authorize: this agent may use this selector, and the route is allowed.
	agent := h.Agents[agentName]
	if agent == nil || !contains(agent.Selectors, sel) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !route.Match(up.Rules, r.Method, upath) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 4. Resolve the secret. Fail closed — never echo the store error to the client.
	key, err := h.Secrets.Get(up.Secret)
	if err != nil {
		h.log().Error("secret resolution failed", "agent", agentName, "selector", sel, "err", err.Error())
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// 5. Build the outbound request. Critically, do NOT carry the caller's
	// Authorization (the broker token) upstream; inject only the credential.
	timeout := apiTimeout
	if up.Mode == config.ModeGit {
		timeout = gitTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	outURL := up.Base + upath
	if r.URL.RawQuery != "" {
		outURL += "?" + r.URL.RawQuery
	}
	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL, r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if up.Mode == config.ModeGit {
		// git negotiates content type, protocol version, and compression through its
		// own headers, so forward them verbatim (minus hop-by-hop and the broker token)
		// instead of forcing JSON. Content-Length rides on the request field below.
		copyHeaders(outReq.Header, r.Header, skipReqHeaders)
		outReq.ContentLength = r.ContentLength
	} else {
		outReq.Header.Set("Accept", "application/json")
		if ct := r.Header.Get("Content-Type"); ct != "" {
			outReq.Header.Set("Content-Type", ct)
		}
	}
	// Injection always overwrites any client-supplied auth, so the broker token
	// (used in step 1) can never reach the upstream.
	injectCredential(outReq, up, key)

	// 6. Forward.
	resp, err := h.client().Do(outReq)
	if err != nil {
		// err may contain outURL but never the secret (it's only in a header).
		h.log().Error("upstream request failed", "agent", agentName, "selector", sel, "err", err.Error())
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if up.Mode == config.ModeGit {
		copyHeaders(w.Header(), resp.Header, skipRespHeaders)
	} else if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)

	h.log().Info("proxied",
		"agent", agentName, "selector", sel, "method", r.Method,
		"path", upath, "status", resp.StatusCode, "bytes", n)
}

func (h *Handler) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

func (h *Handler) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// injectCredential attaches the real secret to the outbound request. The scheme is
// chosen by the upstream's Inject setting; the secret itself is never logged.
func injectCredential(req *http.Request, up *config.Upstream, key string) {
	switch up.Inject {
	case config.InjectBearer:
		req.Header.Set("Authorization", "Bearer "+key)
	case config.InjectGitHubBasic:
		// GitHub's git-over-HTTPS (and its API) take the token as the HTTP Basic
		// password under username "x-access-token" — the form that works for both a
		// PAT and a GitHub App installation token.
		cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + key))
		req.Header.Set("Authorization", "Basic "+cred)
	default: // verbatim: set the stored value as-is under the configured header
		req.Header.Set(up.Header, key)
	}
}

// Hop-by-hop headers are connection-scoped (RFC 7230 §6.1) and must not cross a
// proxy. The request set additionally drops Authorization — the caller's broker
// token, replaced by the injected credential — and Content-Length, carried on the
// request's ContentLength field instead.
var skipReqHeaders = map[string]bool{
	"Authorization": true, "Content-Length": true,
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

var skipRespHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

// copyHeaders forwards every header in src except the connection-scoped ones in skip.
func copyHeaders(dst, src http.Header, skip map[string]bool) {
	for k, vs := range src {
		if skip[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// splitPath turns "/sel/rest/of/path" into ("sel", "/rest/of/path", true).
func splitPath(p string) (sel, rest string, ok bool) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", "", false
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i:], true
	}
	return p, "/", true
}

func bearer(h string) string {
	const pfx = "Bearer "
	if len(h) > len(pfx) && strings.EqualFold(h[:len(pfx)], pfx) {
		return strings.TrimSpace(h[len(pfx):])
	}
	return ""
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
