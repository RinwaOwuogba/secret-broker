package proxy

import "crypto/subtle"

// Authn maps a presented bearer token to an agent name.
type Authn func(token string) (agent string, ok bool)

// NewTokenAuthn builds an Authn from a token→agent map. It compares against every
// known token with a constant-time comparison (no early return), so lookup time
// does not reveal which token, if any, matched.
func NewTokenAuthn(tokens map[string]string) Authn {
	type pair struct{ token, agent string }
	pairs := make([]pair, 0, len(tokens))
	for tok, agent := range tokens {
		pairs = append(pairs, pair{tok, agent})
	}
	return func(presented string) (string, bool) {
		agent, ok := "", false
		pb := []byte(presented)
		for _, p := range pairs {
			if subtle.ConstantTimeCompare([]byte(p.token), pb) == 1 {
				agent, ok = p.agent, true
			}
		}
		return agent, ok
	}
}
