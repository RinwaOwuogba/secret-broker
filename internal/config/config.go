// Package config loads and validates the broker's non-secret configuration.
// Validation is structural and filesystem-free so it is fully unit-testable;
// resolving token/secret values against the store happens later, at serve time.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"git.hq.shrd.dev/Shrd/secret-broker/internal/route"
)

// Upstream is one proxied API: where to forward, which header carries the
// injected credential, which stored secret supplies it, and the route allowlist.
type Upstream struct {
	Base   string       `json:"base"`
	Header string       `json:"header"`
	Secret string       `json:"secret"`
	Allow  [][]string   `json:"allow"` // raw [method, pattern] pairs
	Rules  []route.Rule `json:"-"`     // compiled from Allow at load time
}

// Agent is a caller identity: a token (held in the store under TokenRef) and the
// set of upstream selectors it may use.
type Agent struct {
	TokenRef  string   `json:"tokenRef"`
	Selectors []string `json:"selectors"`
}

// Config is the whole parsed, validated configuration.
type Config struct {
	Listen     string               `json:"listen"`
	SecretsDir string               `json:"secretsDir"`
	Upstreams  map[string]*Upstream `json:"upstreams"`
	Agents     map[string]*Agent    `json:"agents"`
}

// Load reads, parses, and validates the config at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // typos in config become errors, not silent drops
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: listen is required")
	}
	if c.SecretsDir == "" {
		return fmt.Errorf("config: secretsDir is required")
	}
	for name, up := range c.Upstreams {
		if up.Base == "" || up.Header == "" || up.Secret == "" {
			return fmt.Errorf("config: upstream %q requires base, header, and secret", name)
		}
		for _, a := range up.Allow {
			if len(a) != 2 {
				return fmt.Errorf("config: upstream %q allow entry must be [method, pattern], got %v", name, a)
			}
			r, err := route.NewRule(a[0], a[1])
			if err != nil {
				return fmt.Errorf("config: upstream %q: %w", name, err)
			}
			up.Rules = append(up.Rules, r)
		}
	}
	for name, ag := range c.Agents {
		if ag.TokenRef == "" {
			return fmt.Errorf("config: agent %q requires tokenRef", name)
		}
		if len(ag.Selectors) == 0 {
			return fmt.Errorf("config: agent %q requires at least one selector", name)
		}
		for _, sel := range ag.Selectors {
			if _, ok := c.Upstreams[sel]; !ok {
				return fmt.Errorf("config: agent %q references unknown selector %q", name, sel)
			}
		}
	}
	return nil
}
