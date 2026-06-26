package main

import (
	"bytes"
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
