// Package secret holds the credential store. The serve path depends only on the
// read-only Store interface; writes live in register.go and are invoked solely by
// the root CLI, so the daemon binary has no code path that can mutate the store.
package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// nameRe guards against path traversal and keeps secret names to a safe charset.
var nameRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]{0,63}$`)

func validName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("secret: invalid name %q", name)
	}
	return nil
}

// Store reads secrets by name. Implementations must fail closed: on any doubt
// about a secret's integrity or exposure, return an error rather than a value.
type Store interface {
	Get(name string) (string, error)
}

// DirStore reads one-file-per-secret from Dir. If OwnerUID >= 0, Get also
// requires the file to be owned by that uid (production sets 0 = root); -1 skips
// the owner check (used in tests, where files are owned by the test user).
type DirStore struct {
	Dir      string
	OwnerUID int
}

// New constructs a DirStore. ownerUID of -1 disables the owner check.
func New(dir string, ownerUID int) *DirStore {
	return &DirStore{Dir: dir, OwnerUID: ownerUID}
}

// Get returns the secret value, failing closed if the file is a symlink, is
// readable/writable by "other", or (when configured) is not owned by OwnerUID.
func (s *DirStore) Get(name string) (string, error) {
	if err := validName(name); err != nil {
		return "", err
	}
	p := filepath.Join(s.Dir, name)
	info, err := os.Lstat(p) // Lstat, not Stat: never follow a planted symlink.
	if err != nil {
		return "", fmt.Errorf("secret %q: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("secret %q: refusing to read symlink", name)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return "", fmt.Errorf("secret %q: refusing to read, perms %o expose it to other users", name, info.Mode().Perm())
	}
	if s.OwnerUID >= 0 {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return "", fmt.Errorf("secret %q: cannot verify ownership on this platform", name)
		}
		if int(st.Uid) != s.OwnerUID {
			return "", fmt.Errorf("secret %q: owned by uid %d, require %d", name, st.Uid, s.OwnerUID)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("secret %q: %w", name, err)
	}
	return string(b), nil
}
