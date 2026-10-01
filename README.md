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

## Deployment topology

Run the broker **outside the agent's machine**. The reference setup:

```
host (bare metal) ── secret-broker, listens on the VM bridge only (e.g. 192.168.122.1:8080)
  └── libvirt VM ── agent (Claude Code); reaches the broker over the bridge, holds only its token
```

The broker binds to the private VM bridge, not to the host's public interface.
The keys never exist inside the VM, so they stay out of reach even if the agent
has root there (an agent with `sudo` is the common case). Running the broker on
the same machine as the agent works too (`listen: 127.0.0.1:8080`), but then the
user separation below is the only barrier, and it holds only while the agent has
no root.

## Why the agent can't read the raw secrets

First, by location: in the topology above the secrets are on another machine.
On the broker host itself, the OS enforces the rest, not the agent's good behavior:

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
# or type it interactively — input is hidden (echo disabled), like a password prompt:
sudo secret-broker add twitterapi
sudo secret-broker list            # names + sha256 fingerprints, never values
sudo secret-broker rm  twitterapi

# run the daemon (as the broker user, via systemd)
secret-broker serve -config /etc/secret-broker/config.json
```

Agent side — no real key anywhere (`$BROKER` is the broker's address, e.g.
`http://192.168.122.1:8080` from a libvirt VM):

```sh
curl -H "Authorization: Bearer $BROKER_TOKEN" \
  "$BROKER/tw/twitter/user/info?userName=winsznx"
```

## Configuration

`/etc/secret-broker/config.json` (root-owned, non-secret). Routing — which
secret is injected into which upstream — is **root-only config**, never writable
through the proxy, so an agent can never bind an existing key to a destination it
controls. See [`deploy/config.example.json`](deploy/config.example.json).

Two optional per-upstream knobs shape how a request is handled:

- **`inject`** — how the stored secret becomes the outbound credential:
  - *(omitted)* — set the raw value under `header` (the `x-api-key` style).
  - `"bearer"` — send `Authorization: Bearer <secret>` (`header` unused).
  - `"github-basic"` — send `Authorization: Basic base64("x-access-token:"+secret)`,
    the form GitHub accepts for both git-over-HTTPS and the API, for a PAT or an App
    installation token.
- **`mode`** — `"git"` switches from JSON-API handling to transparent forwarding
  for git's smart-HTTP protocol: the client's content-type/protocol/compression
  headers pass through untouched and bodies stream without a size or time cap
  (a real clone/push runs for minutes). Default handling forces
  `Accept: application/json` and is right for REST/GraphQL.

## GitHub access

One raw token in the store (`github`) backs both the REST/GraphQL API (`gh`
upstream, `inject: bearer`) and git clone/push (`ghgit` upstream, `mode: git` +
`inject: github-basic`). Store the **raw** PAT — the broker adds the scheme:

```sh
# On the broker host, as root — input is hidden; the value never hits argv/history/disk.
secret-broker add github
secret-broker list                 # confirm by fingerprint, never value
```

Agent side (VM), pointing git at the broker with only its low-value broker token:

```sh
# Route github.com through the broker; the broker injects the real credential.
git config --global url."$BROKER/ghgit/".insteadOf "https://github.com/"
# Authenticate to the broker — scoped to its address so the token goes nowhere else.
git config --global http."$BROKER/".extraHeader "Authorization: Bearer $BROKER_TOKEN"
git clone https://github.com/RinwaOwuogba/kora-copilot.git   # rewritten → broker → github
```

For read-only agents, drop the `git-receive-pack` (push) rule and the write verbs
from the allowlist; to pin to specific repos, replace `[^/]+/[^/]+` with `owner/repo`.
The token's own scope (repos + permissions) is the outer bound — the allowlist
narrows within it and is the only thing the agent can see.

The same pattern works for a self-hosted Gitea: add an upstream cloned from
`ghgit` with `base` set to the Gitea URL and a Gitea access token as its secret
(Gitea accepts the token as the Basic-auth password). Use a dedicated,
*restricted* bot user so the token reaches only the repos it is granted.

## Build & deploy

```sh
go test ./...                                   # full suite
GOOS=linux GOARCH=amd64 go build -o secret-broker-linux-amd64 ./cmd/secret-broker
scp -r secret-broker-linux-amd64 deploy broker-host:   # the host, not the agent's VM
# on broker-host, as root:
deploy/setup.sh ./secret-broker-linux-amd64     # broker user, dirs, systemd unit, config
```

Then set `"listen"` in `/etc/secret-broker/config.json` to the VM bridge address
(e.g. `192.168.122.1:8080`). That address exists only after libvirt brings up
the bridge, so order the unit after it:

```ini
# /etc/systemd/system/secret-broker.service.d/virbr0.conf
[Unit]
After=libvirtd.service
Wants=libvirtd.service
StartLimitIntervalSec=0
```

`systemctl daemon-reload && systemctl enable --now secret-broker`.

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
