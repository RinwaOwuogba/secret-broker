package config

import (
	"os"
	"path/filepath"
	"testing"
)

const valid = `{
  "listen": "127.0.0.1:8080",
  "secretsDir": "/etc/secret-broker/secrets",
  "upstreams": {
    "tw": {"base":"https://api.twitterapi.io","header":"x-api-key","secret":"twitterapi","allow":[["GET","^/twitter/.+"]]}
  },
  "agents": {
    "scout": {"tokenRef":"token_scout","selectors":["tw"]}
  }
}`

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(write(t, valid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.SecretsDir == "" {
		t.Fatalf("top-level fields not parsed: %+v", cfg)
	}
	up := cfg.Upstreams["tw"]
	if up == nil || up.Secret != "twitterapi" || up.Header != "x-api-key" {
		t.Fatalf("upstream not parsed: %+v", up)
	}
	if len(up.Rules) != 1 {
		t.Fatalf("allow rules not compiled: %+v", up.Rules)
	}
	if a := cfg.Agents["scout"]; a == nil || a.TokenRef != "token_scout" {
		t.Fatalf("agent not parsed: %+v", a)
	}
}

func TestLoadRejectsUnknownSelector(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{},"agents":{"a":{"tokenRef":"t","selectors":["nope"]}}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: agent references unknown selector")
	}
}

func TestLoadRejectsBadRegex(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","header":"h","secret":"s","allow":[["GET","("]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: bad route regex")
	}
}

func TestLoadRejectsMissingFields(t *testing.T) {
	bodies := map[string]string{
		"no header": `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","secret":"s","allow":[["GET","^/.+"]]}},"agents":{}}`,
		"no base":   `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"header":"h","secret":"s","allow":[["GET","^/.+"]]}},"agents":{}}`,
		"no secret": `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","header":"h","allow":[["GET","^/.+"]]}},"agents":{}}`,
		"no listen": `{"secretsDir":"/s","upstreams":{},"agents":{}}`,
	}
	for name, body := range bodies {
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestLoadInjectSchemes(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{
		"gh":{"base":"https://api.github.com","inject":"bearer","secret":"github","allow":[["GET","^/repos/.+"]]},
		"ghgit":{"base":"https://github.com","mode":"git","inject":"github-basic","secret":"github","allow":[["POST","^/[^/]+/[^/]+/git-receive-pack$"]]}
	},"agents":{"a":{"tokenRef":"t","selectors":["gh","ghgit"]}}}`
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Upstreams["gh"].Inject != InjectBearer {
		t.Fatalf("bearer inject not parsed: %+v", cfg.Upstreams["gh"])
	}
	if g := cfg.Upstreams["ghgit"]; g.Mode != ModeGit || g.Inject != InjectGitHubBasic {
		t.Fatalf("git upstream not parsed: %+v", g)
	}
}

func TestLoadInjectSchemeNeedsNoHeader(t *testing.T) {
	// bearer/github-basic derive the Authorization header, so `header` is optional.
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","inject":"bearer","secret":"s","allow":[["GET","^/.+"]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("bearer inject should not require header: %v", err)
	}
}

func TestLoadInjectSchemeStillNeedsSecret(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","inject":"bearer","allow":[["GET","^/.+"]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: inject scheme requires secret")
	}
}

func TestLoadRejectsUnknownInject(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","inject":"whoops","secret":"s","allow":[["GET","^/.+"]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: unknown inject scheme")
	}
}

func TestLoadRejectsUnknownMode(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","header":"h","secret":"s","mode":"weird","allow":[["GET","^/.+"]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: unknown mode")
	}
}

func TestLoadRejectsBadAllowArity(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","header":"h","secret":"s","allow":[["GET"]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: allow entry must be [method, pattern]")
	}
}
