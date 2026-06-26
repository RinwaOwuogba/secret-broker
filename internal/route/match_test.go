package route

import "testing"

func mustRules(t *testing.T, specs ...[2]string) []Rule {
	t.Helper()
	var rs []Rule
	for _, s := range specs {
		r, err := NewRule(s[0], s[1])
		if err != nil {
			t.Fatalf("NewRule(%q,%q): %v", s[0], s[1], err)
		}
		rs = append(rs, r)
	}
	return rs
}

func TestNewRuleRejectsBadPattern(t *testing.T) {
	if _, err := NewRule("GET", "("); err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestMatch(t *testing.T) {
	rules := mustRules(t,
		[2]string{"GET", `^/twitter/.+`},
		[2]string{"GET", `^/v2/.+`},
	)
	cases := []struct {
		name, method, path string
		want               bool
	}{
		{"allowed twitter", "GET", "/twitter/user/info", true},
		{"allowed v2", "GET", "/v2/currencies", true},
		{"wrong method", "POST", "/twitter/user/info", false},
		{"path not in allowlist", "GET", "/admin/keys", false},
		{"prefix must match anchor", "GET", "/x/twitter/user", false},
		{"empty subpath fails .+", "GET", "/twitter/", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Match(rules, c.method, c.path); got != c.want {
				t.Fatalf("Match(%q,%q)=%v want %v", c.method, c.path, got, c.want)
			}
		})
	}
}

func TestMatchEmptyRulesDeniesAll(t *testing.T) {
	if Match(nil, "GET", "/anything") {
		t.Fatal("empty ruleset must deny by default")
	}
}
