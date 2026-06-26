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

func TestLoadRejectsBadAllowArity(t *testing.T) {
	body := `{"listen":":8080","secretsDir":"/s","upstreams":{"u":{"base":"https://x","header":"h","secret":"s","allow":[["GET"]]}},"agents":{}}`
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("expected error: allow entry must be [method, pattern]")
	}
}
