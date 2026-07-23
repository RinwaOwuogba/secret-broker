package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestAddListRemoveRoundTrip(t *testing.T) {
	dir := t.TempDir()

	code, out, errs := runCLI(t, "my-value\n", "add", "-dir", dir, "twitterapi")
	if code != 0 {
		t.Fatalf("add exit %d, stderr=%s", code, errs)
	}
	if !strings.Contains(out, "twitterapi") {
		t.Fatalf("add output missing name: %q", out)
	}
	if strings.Contains(out, "my-value") {
		t.Fatalf("add must not echo the value: %q", out)
	}

	code, out, _ = runCLI(t, "", "list", "-dir", dir)
	if code != 0 || !strings.Contains(out, "twitterapi") {
		t.Fatalf("list exit %d out %q", code, out)
	}
	if strings.Contains(out, "my-value") {
		t.Fatalf("list leaked the value: %q", out)
	}

	if code, _, errs = runCLI(t, "", "rm", "-dir", dir, "twitterapi"); code != 0 {
		t.Fatalf("rm exit %d stderr %s", code, errs)
	}
	code, out, _ = runCLI(t, "", "list", "-dir", dir)
	if code != 0 || strings.Contains(out, "twitterapi") {
		t.Fatalf("secret still listed after rm: %q", out)
	}
}

func TestReadSecretValueNonTTY(t *testing.T) {
	// The interactive TTY (echo-off) path can't be exercised without a pty, but the
	// non-terminal paths must read the stream verbatim and never be mistaken for a TTY.

	// A plain reader (as the CLI tests use) reads everything.
	got, err := readSecretValue(strings.NewReader("ghp_secret\n"), io.Discard, "k")
	if err != nil || string(got) != "ghp_secret\n" {
		t.Fatalf("reader path = %q, %v", got, err)
	}

	// A real *os.File that is a pipe must be detected as NOT a terminal and read fully.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { io.WriteString(w, "piped-secret"); w.Close() }()
	if isTerminal(r) {
		t.Fatal("a pipe must not be detected as a terminal")
	}
	got, err = readSecretValue(r, io.Discard, "k")
	if err != nil || string(got) != "piped-secret" {
		t.Fatalf("os.Pipe path = %q, %v", got, err)
	}
}

func TestAddCreateOnly(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := runCLI(t, "v1", "add", "-dir", dir, "k"); code != 0 {
		t.Fatal("first add should succeed")
	}
	if code, _, _ := runCLI(t, "v2", "add", "-dir", dir, "k"); code == 0 {
		t.Fatal("second add without -force should fail")
	}
	if code, _, _ := runCLI(t, "v2", "add", "-force", "-dir", dir, "k"); code != 0 {
		t.Fatal("add -force should succeed")
	}
}

func TestNoArgsShowsUsage(t *testing.T) {
	if code, _, _ := runCLI(t, ""); code == 0 {
		t.Fatal("no subcommand should be a non-zero exit")
	}
	if code, _, _ := runCLI(t, "", "bogus"); code == 0 {
		t.Fatal("unknown subcommand should be a non-zero exit")
	}
}
