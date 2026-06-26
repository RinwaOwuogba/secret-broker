// Command secret-broker is a credential-injecting egress proxy.
//
//	serve   run the proxy daemon (runs as the unprivileged broker user)
//	add     register/rotate a secret from stdin (run as root)
//	list    list secret names + fingerprints (never values)
//	rm      delete a secret (run as root)
//
// Flags precede the positional name, e.g. `secret-broker add -force <name>`.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"git.hq.shrd.dev/Shrd/secret-broker/internal/config"
	"git.hq.shrd.dev/Shrd/secret-broker/internal/proxy"
	"git.hq.shrd.dev/Shrd/secret-broker/internal/secret"
)

const (
	defaultConfig     = "/etc/secret-broker/config.json"
	defaultSecretsDir = "/etc/secret-broker/secrets"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stderr)
	case "add":
		return cmdAdd(args[1:], stdin, stdout, stderr)
	case "list":
		return cmdList(args[1:], stdout, stderr)
	case "rm":
		return cmdRemove(args[1:], stderr)
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: secret-broker <serve|add|list|rm> [flags]")
	fmt.Fprintln(w, "  serve -config <path>")
	fmt.Fprintln(w, "  add   [-force] [-dir <path>] <name>   # value read from stdin")
	fmt.Fprintln(w, "  list  [-dir <path>]")
	fmt.Fprintln(w, "  rm    [-dir <path>] <name>")
}

func cmdServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "path to config.json")
	ownerUID := fs.Int("secret-owner-uid", 0, "required uid of secret files (-1 to skip; default 0=root)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	store := secret.New(cfg.SecretsDir, *ownerUID)

	// Resolve each agent's token from the store and build the authenticator.
	tokenToAgent := make(map[string]string, len(cfg.Agents))
	for name, ag := range cfg.Agents {
		tok, err := store.Get(ag.TokenRef)
		if err != nil {
			fmt.Fprintf(stderr, "agent %q: cannot load token %q: %v\n", name, ag.TokenRef, err)
			return 1
		}
		tokenToAgent[tok] = name
	}

	h := &proxy.Handler{
		Upstreams: cfg.Upstreams,
		Agents:    cfg.Agents,
		Authn:     proxy.NewTokenAuthn(tokenToAgent),
		Secrets:   store,
		Client:    &http.Client{Timeout: 30 * time.Second},
		Logger:    logger,
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	logger.Info("serving", "addr", cfg.Listen, "upstreams", len(cfg.Upstreams), "agents", len(cfg.Agents))
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server stopped", "err", err.Error())
		return 1
	}
	return 0
}

func cmdAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultSecretsDir, "secrets directory")
	force := fs.Bool("force", false, "overwrite an existing secret")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secret-broker add [-force] [-dir <path>] <name>   # value on stdin")
		return 2
	}
	name := fs.Arg(0)
	val, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read stdin:", err)
		return 1
	}
	if err := secret.Register(*dir, name, string(val), *force); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// Confirm with the stored fingerprint (never the value) by reading it back.
	fp := "?"
	if infos, err := secret.List(*dir); err == nil {
		for _, in := range infos {
			if in.Name == name {
				fp = in.Fingerprint
			}
		}
	}
	fmt.Fprintf(stdout, "registered %s (sha256:%s)\n", name, fp)
	return 0
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultSecretsDir, "secrets directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	infos, err := secret.List(*dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	for _, in := range infos {
		fmt.Fprintf(stdout, "%-24s sha256:%s\n", in.Name, in.Fingerprint)
	}
	return 0
}

func cmdRemove(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultSecretsDir, "secrets directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secret-broker rm [-dir <path>] <name>")
		return 2
	}
	if err := secret.Remove(*dir, fs.Arg(0)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
