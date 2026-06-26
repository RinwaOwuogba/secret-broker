#!/usr/bin/env bash
# Provision secret-broker on a host. Run as root. Idempotent.
#   sudo deploy/setup.sh [path-to-linux-binary]
set -euo pipefail

BIN="${1:-./secret-broker}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

# Dedicated, login-less service identity. The agent runs as a DIFFERENT user.
getent group broker >/dev/null || groupadd --system broker
id broker >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin -g broker broker

# Config dir: broker may read (group), only root may write.
install -d -o root -g broker -m 0750 /etc/secret-broker
# Secrets dir: setgid (2750) so files created by `add` inherit group broker;
# other has no access, so the agent user cannot even traverse it.
install -d -o root -g broker -m 2750 /etc/secret-broker/secrets

# Binary.
install -o root -g root -m 0755 "$BIN" /usr/local/bin/secret-broker

# Config (never clobber an existing one).
if [[ ! -f /etc/secret-broker/config.json ]]; then
  install -o root -g broker -m 0640 "$HERE/config.example.json" /etc/secret-broker/config.json
fi

# systemd unit.
install -o root -g root -m 0644 "$HERE/secret-broker.service" /etc/systemd/system/secret-broker.service
systemctl daemon-reload

cat <<'EOF'
Provisioned.

1. Register secrets (value on stdin; never appears in argv or history if piped):
     printf %s "$TWITTERAPI_IO_KEY" | sudo secret-broker add twitterapi
     printf %s "$CRYPTORANK_API_KEY" | sudo secret-broker add cryptorank
     head -c 32 /dev/urandom | base64 | sudo secret-broker add token_scout
2. Edit /etc/secret-broker/config.json to taste.
3. Start it:
     sudo systemctl enable --now secret-broker
4. Point the agent at it (no real keys in the agent env):
     BROKER_BASE=http://127.0.0.1:8080/tw
     BROKER_TOKEN=<the token_scout value>
EOF
