package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// secretMode is the on-disk permission for a secret file: owner rw, group r,
// other none. Combined with a root:broker setgid directory, group resolves to
// broker (read-only) and the agent user is excluded.
const secretMode = 0o640

// Register writes value to <dir>/<name>. It trims a single layer of trailing
// newlines/spaces (so `echo key | ... add` stores the key, not "key\n"), refuses
// to clobber an existing secret unless force is set, and writes atomically.
func Register(dir, name, value string, force bool) error {
	if err := validName(name); err != nil {
		return err
	}
	p := filepath.Join(dir, name)
	if !force {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("secret %q already exists (use --force to rotate)", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	value = strings.TrimRight(value, "\r\n ")

	// Write to a temp file in the same dir, fix perms, then rename atomically so a
	// reader never sees a half-written or world-readable secret.
	tmp, err := os.CreateTemp(dir, ".tmp-"+name+"-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, secretMode); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// Remove deletes a secret.
func Remove(dir, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, name))
}

// Info describes a stored secret without revealing it.
type Info struct {
	Name        string
	Fingerprint string // first 12 hex chars of sha256(value)
}

// List enumerates secrets with a fingerprint of each value — enough to confirm
// "did I store the right thing" without ever disclosing the value.
func List(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, Info{Name: e.Name(), Fingerprint: hex.EncodeToString(sum[:])[:12]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
