// Package route implements the allowlist matcher: an upstream permits a request
// only if some (method, path-regex) rule matches. Compiling regexes up front
// turns each request-time check into a cheap loop.
package route

import (
	"fmt"
	"regexp"
)

// Rule is one allowed (method, path) pair. Pattern is anchored with regexp.MatchString
// semantics (callers write their own ^…$ as needed).
type Rule struct {
	Method  string
	pattern *regexp.Regexp
	raw     string
}

// NewRule compiles raw into a Rule, returning an error on a bad pattern so
// misconfiguration fails at load time, not at request time.
func NewRule(method, pattern string) (Rule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("route: bad pattern %q: %w", pattern, err)
	}
	return Rule{Method: method, pattern: re, raw: pattern}, nil
}

// Match reports whether method+path is permitted by any rule in the set.
// An empty set denies everything (deny-by-default).
func Match(rules []Rule, method, path string) bool {
	for _, r := range rules {
		if r.Method == method && r.pattern.MatchString(path) {
			return true
		}
	}
	return false
}
