#!/usr/bin/env bash
# Cawala node installer.
#
#   curl -fsSL https://raw.githubusercontent.com/paulrd/cawala/main/packaging/install.sh | sudo bash
#
# Downloads a statically linked `cawala-node` binary for this machine from a
# GitHub release, verifies its SHA-256, installs it to /usr/local/bin, and (on
# systemd hosts) installs the `cawala-node@.service` template unit. It does not
# create or start any node instance; see the printed next steps.
#
# Flags:
#   --version <tag>    Release tag to install (default: the latest release)
#   --repo <owner/name>Source repository (default: paulrd/cawala; env CAWALA_REPO)
#   --bin-dir <dir>    Binary install directory (default: /usr/local/bin)
#   --no-systemd       Do not install the systemd unit
#   --no-verify        Skip SHA-256 verification (not recommended)
#   -h, --help         Show this help
set -euo pipefail

REPO=${CAWALA_REPO:-paulrd/cawala}
VERSION=""
BIN_DIR=/usr/local/bin
INSTALL_SYSTEMD=1
VERIFY=1
SERVICE_USER=cawala
SERVICE_NAME=cawala-node@.service
SERVICE_PATH=/etc/systemd/system/$SERVICE_NAME

log()  { printf '%s\n' "cawala-install: $*"; }
warn() { printf '%s\n' "cawala-install: WARNING: $*" >&2; }
die()  { printf '%s\n' "cawala-install: ERROR: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Cawala node installer.

Usage: install.sh [options]

  --version <tag>      Release tag to install (default: the latest release)
  --repo <owner/name>  Source repository (default: paulrd/cawala; env CAWALA_REPO)
  --bin-dir <dir>      Binary install directory (default: /usr/local/bin)
  --no-systemd         Do not install the systemd unit
  --no-verify          Skip SHA-256 verification (not recommended)
  -h, --help           Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)   [ -n "${2:-}" ] || die "--version needs a tag"; VERSION=$2; shift 2 ;;
        --repo)      [ -n "${2:-}" ] || die "--repo needs owner/name"; REPO=$2; shift 2 ;;
        --bin-dir)   [ -n "${2:-}" ] || die "--bin-dir needs a path"; BIN_DIR=$2; shift 2 ;;
        --no-systemd) INSTALL_SYSTEMD=0; shift ;;
        --no-verify) VERIFY=0; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown argument: $1 (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: curl ... | sudo bash"
[ "$(uname -s)" = "Linux" ] || die "unsupported OS '$(uname -s)': a Linux host is required"

case "$(uname -m)" in
    x86_64|amd64)  TARGET=x86_64-unknown-linux-musl ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
    *)             die "unsupported architecture '$(uname -m)'" ;;
esac

for tool in curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

if [ -z "$VERSION" ]; then
    log "resolving the latest release of $REPO"
    api="https://api.github.com/repos/$REPO/releases/latest"
    auth=()
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    fi
    VERSION=$(curl -fsSL "${auth[@]}" "$api" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$VERSION" ] || die "no release found; pass --version or set GITHUB_TOKEN"
fi

base="https://github.com/$REPO/releases/download/$VERSION"
asset="cawala-node-$TARGET"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

log "downloading $asset ($VERSION)"
curl -fsSL "$base/$asset" -o "$tmp/$asset" \
    || die "download failed: $base/$asset"

if [ "$VERIFY" -eq 1 ]; then
    curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256" \
        || die "checksum download failed: $base/$asset.sha256"
    expected=$(awk 'NR==1 {print $1}' "$tmp/$asset.sha256")
    actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
    [ -n "$expected" ] || die "empty checksum file for $asset"
    [ "$expected" = "$actual" ] \
        || die "SHA-256 mismatch (expected $expected, got $actual)"
    log "SHA-256 verified"
fi

install -d "$BIN_DIR"
install -m 0755 "$tmp/$asset" "$BIN_DIR/cawala-node"
log "installed $BIN_DIR/cawala-node"

if [ "$INSTALL_SYSTEMD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        nologin=$(command -v nologin || true)
        if [ -n "$nologin" ]; then
            useradd --system --no-create-home --home-dir /var/lib/cawala \
                --shell "$nologin" "$SERVICE_USER"
        else
            useradd --system --no-create-home --home-dir /var/lib/cawala "$SERVICE_USER"
        fi
        log "created system user '$SERVICE_USER'"
    fi

    if curl -fsSL "$base/$SERVICE_NAME" -o "$tmp/$SERVICE_NAME" 2>/dev/null; then
        install -m 0644 "$tmp/$SERVICE_NAME" "$SERVICE_PATH"
        systemctl daemon-reload
        log "installed $SERVICE_PATH"
    else
        warn "could not fetch $SERVICE_NAME from release $VERSION; skipping unit install"
    fi
fi

cat <<EOF

Cawala node installed.

Set up and start a node (replace 'leaf1' with a name of your choice):

  sudo install -d -o $SERVICE_USER -g $SERVICE_USER -m 0700 /var/lib/cawala/leaf1
  sudo -u $SERVICE_USER cawala-node --data-dir /var/lib/cawala/leaf1 init
  sudo -u $SERVICE_USER cawala-node --data-dir /var/lib/cawala/leaf1 topo set-address 0
  sudo systemctl enable --now cawala-node@leaf1
  sudo -u $SERVICE_USER cawala-node --data-dir /var/lib/cawala/leaf1 control invite --label leaf1

Run every CLI command as the '$SERVICE_USER' user (files created as root would
block the service). After an out-of-band 'control approve', restart the unit so
the node re-publishes its pkarr record:

  sudo systemctl restart cawala-node@leaf1

Back up /var/lib/cawala/<name>/secret_key and ledger_key: together they are the
node's identity and books. The node needs outbound UDP + HTTPS/DNS to the N0
relays (dns.iroh.link); no inbound port is required while using relays.
EOF
