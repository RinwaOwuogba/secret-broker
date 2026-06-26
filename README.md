# secret-broker

A credential-injecting egress proxy for AI agents (e.g. Claude Code running in a VM).

Agents call the broker with a **low-value bearer token**; the broker injects the
**real upstream API key** and forwards the request. Raw keys live only in the
`broker` trust domain — never in the agent's environment, files, or chat
transcript. A token that leaks into a transcript is useless externally, scoped to
allowlisted routes, and revocable in one place.

```
agent ──Bearer <token>──► secret-broker :8080/<sel>/<path> ──inject x-api-key──► api.twitterapi.io
        (holds only a token)            (holds the real keys, allowlists, logs)
```

## Why the agent can't read the raw secrets

This is enforced by the OS, not by hoping the agent behaves:

- **Separate user.** The broker runs as `broker`; agents run as a different user
  (e.g. `dev`). Secret files are `root:broker 0640` in a `2750` (setgid) dir, so
  `other` has no access and the agent user can't even traverse the directory.
- **Read-only daemon.** The serve path depends only on a read-only `Store`
  interface; the binary has no code path that mutates the store. Only `root`,
  via the `add`/`rm` subcommands, can write secrets.
- **Fail-closed reads.** `Get` refuses to return a value if the file is a
  symlink, is readable by `other`, or (in production) is not owned by root — a
  stray `chmod 644` fails loudly instead of leaking.
- **Token never travels upstream.** The caller's `Authorization` (the broker
  token) is stripped; only the injected credential header is sent on.

## Usage

```sh
# register secrets (root) — value on stdin, never in argv/history
printf %s "$TWITTERAPI_IO_KEY" | sudo secret-broker add twitterapi
sudo secret-broker list            # names + sha256 fingerprints, never values
sudo secret-broker rm  twitterapi

# run the daemon (as the broker user, via systemd)
secret-broker serve -config /etc/secret-broker/config.json
```

Agent side — no real key anywhere:

```sh
curl -H "Authorization: Bearer $BROKER_TOKEN" \
  "http://127.0.0.1:8080/tw/twitter/user/info?userName=winsznx"
```

## Configuration

`/etc/secret-broker/config.json` (root-owned, non-secret). Routing — which
secret is injected into which upstream — is **root-only config**, never writable
through the proxy, so an agent can never bind an existing key to a destination it
controls. See [`deploy/config.example.json`](deploy/config.example.json).

## Build & deploy

```sh
go test ./...                                   # full suite
GOOS=linux GOARCH=amd64 go build -o secret-broker-linux-amd64 ./cmd/secret-broker
scp secret-broker-linux-amd64 vm:
ssh vm 'sudo ./secret-broker-linux-amd64 ... '  # or run deploy/setup.sh from the repo
sudo deploy/setup.sh ./secret-broker-linux-amd64
```

Zero external dependencies (Go stdlib only).

## Roadmap (intentionally out of v1)

- **Egress locking** — per-uid `nftables` so the agent can reach *only* the
  broker; this is what actually contains a *compromised* agent (prevents data
  exfil). The broker prevents key **theft**, not key **misuse** or data exfil.
- **Rate / spend caps** per token (bounds misuse).
- **Encrypted-at-rest** secrets via `systemd-creds` + `LoadCredentialEncrypted`
  (`DirStore` already works against `$CREDENTIALS_DIRECTORY`).
- Backend plugins (Vault, 1Password) behind the `Store` interface.
- Agent-side self-service registration (deliberately deferred — see git history).
