package secret

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRegisterWritesTrimmedValueWith0640(t *testing.T) {
	dir := t.TempDir()
	if err := Register(dir, "twitterapi", "secret-value\n", false); err != nil {
		t.Fatalf("Register: %v", err)
	}
	p := filepath.Join(dir, "twitterapi")
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Fatalf("mode = %o, want 0640", perm)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "secret-value" {
		t.Fatalf("stored %q, want trailing newline trimmed", string(b))
	}
}

func TestRegisterCreateOnlyUnlessForce(t *testing.T) {
	dir := t.TempDir()
	if err := Register(dir, "k", "v1", false); err != nil {
		t.Fatal(err)
	}
	if err := Register(dir, "k", "v2", false); err == nil {
		t.Fatal("expected create-only error on existing secret")
	}
	if err := Register(dir, "k", "v2", true); err != nil {
		t.Fatalf("force overwrite should succeed: %v", err)
	}
	s, _ := New(dir, -1).Get("k")
	if s != "v2" {
		t.Fatalf("after force, got %q want v2", s)
	}
}

func TestRegisterRejectsBadNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape", "a/b", "", "UPPER", "with space", strings.Repeat("x", 65)} {
		if err := Register(dir, name, "v", false); err == nil {
			t.Fatalf("expected rejection for name %q", name)
		}
	}
}

func TestGetReturnsValue(t *testing.T) {
	dir := t.TempDir()
	Register(dir, "k", "hunter2", false)
	got, err := New(dir, -1).Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Fatalf("got %q want hunter2", got)
	}
}

func TestGetFailsClosedOnLoosePerms(t *testing.T) {
	dir := t.TempDir()
	Register(dir, "k", "topsecret", false)
	p := filepath.Join(dir, "k")
	if err := os.Chmod(p, 0o644); err != nil { // world-readable: the mistake we must catch
		t.Fatal(err)
	}
	got, err := New(dir, -1).Get("k")
	if err == nil {
		t.Fatal("Get must fail closed when others can read the file")
	}
	if strings.Contains(got, "topsecret") {
		t.Fatal("Get must not return the value when failing closed")
	}
}

func TestGetRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("v"), 0o640)
	link := filepath.Join(dir, "k")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := New(dir, -1).Get("k"); err == nil {
		t.Fatal("Get must reject symlinked secret files")
	}
}

func TestGetOwnerCheck(t *testing.T) {
	dir := t.TempDir()
	Register(dir, "k", "v", false)
	info, err := os.Lstat(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	uid := int(info.Sys().(*syscall.Stat_t).Uid)
	// Correct owner passes.
	if _, err := New(dir, uid).Get("k"); err != nil {
		t.Fatalf("matching owner should pass: %v", err)
	}
	// Wrong owner fails closed.
	if _, err := New(dir, uid+12345).Get("k"); err == nil {
		t.Fatal("mismatched owner must fail closed")
	}
}

func TestListReturnsFingerprintsNotValues(t *testing.T) {
	dir := t.TempDir()
	Register(dir, "alpha", "VALUE-ALPHA", false)
	Register(dir, "beta", "VALUE-BETA", false)
	infos, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d infos want 2", len(infos))
	}
	for _, in := range infos {
		if strings.Contains(in.Name+in.Fingerprint, "VALUE-") {
			t.Fatalf("List leaked a secret value: %+v", in)
		}
		if in.Fingerprint == "" {
			t.Fatal("expected a fingerprint")
		}
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	Register(dir, "k", "v", false)
	if err := Remove(dir, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "k")); !os.IsNotExist(err) {
		t.Fatal("file should be gone")
	}
	if err := Remove(dir, "../etc"); err == nil {
		t.Fatal("Remove must reject bad names too")
	}
}
