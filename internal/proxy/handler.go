// Package proxy is the serve path: authenticate the caller, check the route
// allowlist, inject the real upstream credential, forward, and return the
// response. The raw secret is touched only between Secrets.Get and the outbound
// request — it is never logged, never written to the client, never sent back to
// the agent.
package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	"git.hq.shrd.dev/Shrd/secret-broker/internal/config"
	"git.hq.shrd.dev/Shrd/secret-broker/internal/route"
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
	// Authorization (the broker token) upstream; inject only the credential header.
	outURL := up.Base + upath
	if r.URL.RawQuery != "" {
		outURL += "?" + r.URL.RawQuery
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	outReq.Header.Set("Accept", "application/json")
	if ct := r.Header.Get("Content-Type"); ct != "" {
		outReq.Header.Set("Content-Type", ct)
	}
	outReq.Header.Set(up.Header, key)

	// 6. Forward.
	resp, err := h.client().Do(outReq)
	if err != nil {
		// err may contain outURL but never the secret (it's only in a header).
		h.log().Error("upstream request failed", "agent", agentName, "selector", sel, "err", err.Error())
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
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
