#!/usr/bin/env sh
# Hivemind binary installer.
#
#   curl -fsSL https://hivemind.wandb.tools/install | sh
#
# Resolves a release manifest, verifies the binary's sha256 (and
# codesign Team ID on macOS), and installs to ~/.local/bin/hivemind.
# See docs/BREW_AUTO_UPGRADE_DESIGN.md for the cross-channel design.
#
# This file is the source of truth. release.yml syncs it to the top
# level of the public wandb/hivemind repo on every stable release:
# https://github.com/wandb/hivemind/blob/main/install.sh

set -eu

# Match upgrade_watcher.py:DEFAULT_MANIFEST_URL and EXPECTED_TEAM_ID.
STABLE_MANIFEST_URL="https://raw.githubusercontent.com/wandb/homebrew-taps/main/manifests/hivemind-latest.json"
PRERELEASE_MANIFEST_URL="https://raw.githubusercontent.com/wandb/homebrew-taps/main/manifests/hivemind-prerelease.json"
EXPECTED_TEAM_ID="5DTHBP38WM"

INSTALL_PREFIX="${HIVEMIND_INSTALL_PREFIX:-$HOME/.local}"
PIN_VERSION="${HIVEMIND_VERSION:-}"
CHANNEL="${HIVEMIND_CHANNEL:-stable}"
DRY_RUN=0
NO_SERVICE=0
ALLOW_ROOT=0

# Colorize diagnostics when stderr is a terminal and NO_COLOR is unset.
# `curl … | sh` only pipes stdin, so stderr is still the user's terminal
# and stays colored (intended) — output is plain only when stderr itself
# is redirected to a file/pipe, or in CI.
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$(printf '\033[31m'); C_GREEN=$(printf '\033[32m')
  C_YELLOW=$(printf '\033[33m'); C_BOLD=$(printf '\033[1m'); C_RESET=$(printf '\033[0m')
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BOLD=''; C_RESET=''
fi

# Log to stderr so `curl … | sh` doesn't capture progress as data.
log() { printf '%s\n' "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die() { printf '%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: install.sh [--version X.Y.Z] [--channel stable|prerelease] [--prefix DIR]
                  [--no-service] [--dry-run] [--allow-root]

Environment:
  HIVEMIND_VERSION              Pin a specific version (same as --version)
  HIVEMIND_CHANNEL              Channel: stable (default) or prerelease
  HIVEMIND_INSTALL_PREFIX       Alt install prefix (default: \$HOME/.local)
  HIVEMIND_UPGRADE_MANIFEST_URL Override manifest URL (overrides --channel)

Without flags, installs the latest stable signed release of hivemind to
~/.local/bin/hivemind and registers a per-user LaunchAgent (macOS) or
systemd user unit (Linux). Use --channel prerelease to opt into the
unstable channel.
EOF
}

require_value() {
  if [ -z "${2:-}" ]; then
    die "missing value for $1 (try --help)"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) require_value "$1" "${2:-}"; PIN_VERSION="$2"; shift 2 ;;
    --version=*) PIN_VERSION="${1#--version=}"; shift ;;
    --channel) require_value "$1" "${2:-}"; CHANNEL="$2"; shift 2 ;;
    --channel=*) CHANNEL="${1#--channel=}"; shift ;;
    --prefix) require_value "$1" "${2:-}"; INSTALL_PREFIX="$2"; shift 2 ;;
    --prefix=*) INSTALL_PREFIX="${1#--prefix=}"; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --allow-root) ALLOW_ROOT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

if [ "$(id -u)" = "0" ] && [ "$ALLOW_ROOT" -ne 1 ]; then
  die "refusing to install as root. Re-run as your normal user, or pass --allow-root if you know what you're doing."
fi

log "Installer source: https://github.com/wandb/hivemind/blob/main/install.sh"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS-$ARCH" in
  Darwin-arm64)
    PLATFORM=darwin-arm64
    ;;
  Darwin-x86_64)
    die "Intel Macs are not currently supported. The hivemind binary is built for Apple Silicon only. Please install via Homebrew formula instead: brew install wandb/taps/hivemind"
    ;;
  Linux-x86_64)
    PLATFORM=linux-x86_64
    ;;
  Linux-aarch64|Linux-arm64)
    PLATFORM=linux-arm64
    ;;
  *)
    die "unsupported platform: $OS-$ARCH"
    ;;
esac
log "Detected platform: $PLATFORM"

have() { command -v "$1" >/dev/null 2>&1; }

if have curl; then
  DL="curl --fail --silent --show-error --location"
elif have wget; then
  DL="wget --quiet --output-document=-"
else
  die "neither curl nor wget found on PATH"
fi

# macOS ships shasum; Linux usually has sha256sum (Alpine has both).
if have sha256sum; then
  SHA256SUM="sha256sum"
elif have shasum; then
  SHA256SUM="shasum -a 256"
else
  die "neither sha256sum nor shasum found on PATH"
fi

# Manifest URL resolution order: env override > --version pin > --channel.
# CHANNEL is only validated when it actually picks the URL.
CHANNEL_USED=0
if [ -n "${HIVEMIND_UPGRADE_MANIFEST_URL:-}" ]; then
  MANIFEST_URL="$HIVEMIND_UPGRADE_MANIFEST_URL"
elif [ -n "$PIN_VERSION" ]; then
  MANIFEST_URL="https://raw.githubusercontent.com/wandb/homebrew-taps/main/manifests/hivemind-${PIN_VERSION}.json"
else
  case "$CHANNEL" in
    stable) MANIFEST_URL="$STABLE_MANIFEST_URL"; CHANNEL_USED=1 ;;
    prerelease) MANIFEST_URL="$PRERELEASE_MANIFEST_URL"; CHANNEL_USED=1 ;;
    *) die "unknown --channel '$CHANNEL' (expected: stable, prerelease)" ;;
  esac
fi
if [ "$CHANNEL_USED" -eq 1 ]; then
  log "Channel: $CHANNEL"
elif [ -n "$PIN_VERSION" ]; then
  log "Pinned to v$PIN_VERSION (channel ignored)"
fi
log "Fetching manifest: $MANIFEST_URL"

# file:// for local testing — wget --output-document=- doesn't always handle it.
case "$MANIFEST_URL" in
  file://*)
    MANIFEST_BODY=$(cat "${MANIFEST_URL#file://}")
    ;;
  *)
    MANIFEST_BODY=$($DL "$MANIFEST_URL") || die "failed to fetch manifest at $MANIFEST_URL"
    ;;
esac

# Both parsers emit four newline-separated values:
#   <version>\n<binary_url>\n<binary_sha256>\n<team_id_or_empty>
# Python is preferred; awk is a fallback for python-less containers.
# Schema matches ReleaseManifest.parse in upgrade_watcher.py.
parse_manifest_python() {
  python3 -c '
import json, sys
platform = sys.argv[1]
data = json.load(sys.stdin)
version = data.get("version", "")
asset = (data.get("platforms") or {}).get(platform) or {}
url = asset.get("binary_url", "")
sha = asset.get("binary_sha256", "")
team = asset.get("team_id", "") or ""
if not url:
    print(f"no asset for {platform}", file=sys.stderr)
    sys.exit(2)
if not sha:
    print("manifest entry missing binary_sha256", file=sys.stderr)
    sys.exit(2)
print(version)
print(url)
print(sha)
print(team)
' "$1"
}

parse_manifest_awk() {
  awk -v platform="$1" '
    BEGIN { in_target=0; ver=""; url=""; sha=""; team="" }
    # Top-level "version": "..." — captured before we descend into platforms.
    !in_target && match($0, /"version"[ \t]*:[ \t]*"[^"]+"/) {
      s = substr($0, RSTART, RLENGTH)
      sub(/.*"version"[ \t]*:[ \t]*"/, "", s); sub(/".*/, "", s)
      if (ver == "") ver = s
    }
    # Enter the platform sub-object on the line that opens it.
    !in_target && index($0, "\"" platform "\"") && /\{/ {
      in_target = 1; next
    }
    in_target && /^[ \t]*\},?[ \t]*$/ { in_target = 0 }
    in_target && match($0, /"binary_url"[ \t]*:[ \t]*"[^"]+"/) {
      s = substr($0, RSTART, RLENGTH)
      sub(/.*"binary_url"[ \t]*:[ \t]*"/, "", s); sub(/".*/, "", s); url = s
    }
    in_target && match($0, /"binary_sha256"[ \t]*:[ \t]*"[^"]+"/) {
      s = substr($0, RSTART, RLENGTH)
      sub(/.*"binary_sha256"[ \t]*:[ \t]*"/, "", s); sub(/".*/, "", s); sha = s
    }
    in_target && match($0, /"team_id"[ \t]*:[ \t]*"[^"]+"/) {
      s = substr($0, RSTART, RLENGTH)
      sub(/.*"team_id"[ \t]*:[ \t]*"/, "", s); sub(/".*/, "", s); team = s
    }
    END {
      if (url == "") { print "no asset for " platform > "/dev/stderr"; exit 2 }
      if (sha == "") { print "manifest entry missing binary_sha256" > "/dev/stderr"; exit 2 }
      print ver
      print url
      print sha
      print team
    }
  '
}

if have python3; then
  PLATFORM_INFO=$(printf '%s' "$MANIFEST_BODY" | parse_manifest_python "$PLATFORM") \
    || die "manifest parse failed (python3)"
else
  PLATFORM_INFO=$(printf '%s' "$MANIFEST_BODY" | parse_manifest_awk "$PLATFORM") \
    || die "manifest parse failed (awk fallback)"
fi

VERSION=$(printf '%s' "$PLATFORM_INFO" | sed -n '1p')
BINARY_URL=$(printf '%s' "$PLATFORM_INFO" | sed -n '2p')
EXPECTED_SHA=$(printf '%s' "$PLATFORM_INFO" | sed -n '3p')
MANIFEST_TEAM_ID=$(printf '%s' "$PLATFORM_INFO" | sed -n '4p')

[ -n "$VERSION" ] || die "manifest missing version"
[ -n "$BINARY_URL" ] || die "manifest missing binary_url for $PLATFORM"
[ -n "$EXPECTED_SHA" ] || die "manifest missing binary_sha256 for $PLATFORM"

log "Resolved version: $VERSION"
log "Binary URL:       $BINARY_URL"

# ─── Downgrade detection ──────────────────────────────────────────────
# `--version 0.5.0` over a working 0.6.x install is almost always a
# typo. Prompt to confirm interactively; refuse with no TTY.
INSTALL_PATH_PREVIEW="$INSTALL_PREFIX/bin/hivemind"
if [ -x "$INSTALL_PATH_PREVIEW" ] && [ -n "$PIN_VERSION" ]; then
  CURRENT_VERSION=$("$INSTALL_PATH_PREVIEW" --version 2>/dev/null \
    | awk '{for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+\./) {print $i; exit}}' \
    || true)
  if [ -n "$CURRENT_VERSION" ]; then
    if have python3; then
      # Use packaging.version when available so PEP 440 (e.g. 0.7.0rc1)
      # compares correctly; fall back to a tuple-of-ints comparator that
      # ignores non-numeric segments so it can't TypeError.
      IS_DOWNGRADE=$(python3 -c "
import re, sys
cur, new = sys.argv[1], sys.argv[2]
try:
    from packaging.version import Version
    print('1' if Version(cur) > Version(new) else '0')
except Exception:
    def parts(v):
        return tuple(int(p) for p in re.findall(r'\d+', v))
    try:
        print('1' if parts(cur) > parts(new) else '0')
    except Exception:
        print('0')
" "$CURRENT_VERSION" "$VERSION")
    else
      IS_DOWNGRADE=0
    fi
    if [ "$IS_DOWNGRADE" = "1" ]; then
      warn "Installing $VERSION over a newer install ($CURRENT_VERSION) — this is a downgrade."
      if [ -t 0 ]; then
        printf 'Continue? [y/N] ' >&2
        read -r REPLY
        case "$REPLY" in
          y|Y|yes|YES) ;;
          *) die "aborted by user" ;;
        esac
      else
        die "downgrade refused in non-interactive mode (re-run with a TTY, or remove $INSTALL_PATH_PREVIEW first)"
      fi
    fi
  fi
fi

# Manifest team_id pre-check is advisory — the codesign Team ID check
# below is the real security boundary.
if [ "$OS" = "Darwin" ] && [ -n "$MANIFEST_TEAM_ID" ] && [ "$MANIFEST_TEAM_ID" != "$EXPECTED_TEAM_ID" ]; then
  die "manifest team_id ($MANIFEST_TEAM_ID) does not match pinned Team ID ($EXPECTED_TEAM_ID) — refusing install"
fi

# ─── Coexistence detection (informational) ────────────────────────────
EXISTING_INSTALLS=""
note_existing() { EXISTING_INSTALLS="$EXISTING_INSTALLS\n  - $1"; }

if [ "$OS" = "Darwin" ]; then
  # A managed .pkg install owns a symlink high on PATH
  # (/usr/local/hivemind/bin/hivemind) plus a root-owned system
  # LaunchAgent. A script binary in ~/.local/bin would shadow neither
  # reliably and install-service can't claim the label anyway, so refuse
  # rather than leave two installs fighting over PATH and launchd.
  # Detect the actual conflicting artifacts, not the pkgutil receipt: a
  # stale receipt can outlive a partial uninstall and wrongly block us.
  # Mirrors _pkg_managed_installed() in install_channels.py (binary AND
  # system plist must both be present).
  if [ -e /usr/local/hivemind/bin/hivemind ] && [ -e /Library/LaunchAgents/com.wandb.hivemind.plist ]; then
    PKG_CONFLICT_MSG="a managed .pkg install of hivemind is already present (/usr/local/hivemind/bin/hivemind).
  The script installer won't overwrite it — they would conflict over PATH and the
  com.wandb.hivemind LaunchAgent. To switch to a script-managed install, first remove
  the .pkg install:
      sudo /usr/local/hivemind/uninstall.sh
  then re-run this installer."
    if [ "$DRY_RUN" -eq 1 ]; then
      warn "(dry-run) the real install would refuse: $PKG_CONFLICT_MSG"
    else
      die "$PKG_CONFLICT_MSG"
    fi
  fi
  if [ -d /opt/homebrew/Caskroom/hivemind-app ] || [ -d /usr/local/Caskroom/hivemind-app ]; then
    note_existing "Homebrew cask hivemind-app"
  fi
  if [ -d /opt/homebrew/Cellar/hivemind ] || [ -d /usr/local/Cellar/hivemind ]; then
    note_existing "Homebrew formula hivemind"
  fi
fi
if [ -d "$HOME/.local/share/uv/tools/wandb-hivemind" ]; then
  note_existing "uv tool install (wandb-hivemind)"
fi

if [ -n "$EXISTING_INSTALLS" ]; then
  printf 'Detected existing hivemind install(s):' >&2
  # %b interprets the accumulated \n without treating data as a format string.
  printf '%b\n' "$EXISTING_INSTALLS" >&2
  log "The script-installed binary will take over the LaunchAgent label (com.wandb.hivemind) on first run; old installs remain on disk and can be removed with their respective uninstallers."
fi

# ─── Download + verify ────────────────────────────────────────────────
TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t hivemind-install)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

STAGED="$TMPDIR/hivemind"
log "Downloading binary..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "(dry-run) would download $BINARY_URL → $STAGED"
else
  case "$BINARY_URL" in
    file://*) cp "${BINARY_URL#file://}" "$STAGED" ;;
    *) $DL "$BINARY_URL" > "$STAGED" || die "download failed: $BINARY_URL" ;;
  esac
fi

if [ "$DRY_RUN" -ne 1 ]; then
  ACTUAL_SHA=$($SHA256SUM "$STAGED" | cut -d' ' -f1)
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    die "sha256 mismatch (got $ACTUAL_SHA, expected $EXPECTED_SHA) — refusing install"
  fi
  log "sha256 verified."

  chmod +x "$STAGED"

  # macOS: signature + Team ID gate, mirrors verify_codesign_team_id() in upgrade_watcher.py.
  if [ "$OS" = "Darwin" ]; then
    if ! codesign --verify --verbose=2 "$STAGED" 2>/dev/null; then
      die "codesign --verify failed — binary is not signed by a trusted identity"
    fi
    SIG_TEAM=$(codesign -dv --verbose=4 "$STAGED" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1)
    if [ "$SIG_TEAM" != "$EXPECTED_TEAM_ID" ]; then
      die "codesign Team ID '$SIG_TEAM' does not match pinned '$EXPECTED_TEAM_ID' — refusing install"
    fi
    log "codesign Team ID verified: $SIG_TEAM"
    # Drop quarantine so Gatekeeper doesn't block the first exec.
    xattr -d com.apple.quarantine "$STAGED" 2>/dev/null || true
  fi
fi

# ─── Install ──────────────────────────────────────────────────────────
INSTALL_DIR="$INSTALL_PREFIX/bin"
INSTALL_PATH="$INSTALL_DIR/hivemind"

if [ "$DRY_RUN" -eq 1 ]; then
  log "(dry-run) would install $STAGED → $INSTALL_PATH"
else
  mkdir -p "$INSTALL_DIR"
  # Stage a sibling of the install path so the final mv is a same-fs
  # rename (atomic); $TMPDIR may live on a different filesystem.
  FINAL_STAGE="$INSTALL_DIR/.hivemind.install.$$"
  cp "$STAGED" "$FINAL_STAGE"
  chmod +x "$FINAL_STAGE"
  mv "$FINAL_STAGE" "$INSTALL_PATH"
  log "Installed: $INSTALL_PATH"

  # Marker so the daemon's upgrade-watcher and service-manager find
  # non-default --prefix installs. Only record `channel` when it
  # actually selected the manifest URL — otherwise the watcher would
  # stick to a channel the user didn't ask for.
  CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hivemind"
  mkdir -p "$CONFIG_DIR"
  MARKER="$CONFIG_DIR/install-method"
  INSTALL_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  {
    printf '# Written by scripts/install.sh — read by hivemind upgrade_watcher.py.\n'
    printf 'method = "script"\n'
    if [ "$CHANNEL_USED" -eq 1 ]; then
      printf 'channel = "%s"\n' "$CHANNEL"
    fi
    printf 'prefix = "%s"\n' "$INSTALL_PREFIX"
    printf 'binary = "%s"\n' "$INSTALL_PATH"
    printf 'version = "%s"\n' "$VERSION"
    printf 'installed_at = "%s"\n' "$INSTALL_TS"
  } > "$MARKER"
  chmod 644 "$MARKER"
fi

# ─── PATH check ───────────────────────────────────────────────────────
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ON_PATH=1 ;;
  *) ON_PATH=0 ;;
esac

if [ "$ON_PATH" -ne 1 ]; then
  cat <<EOS >&2

$INSTALL_DIR is not on your PATH. Add it by running:

    echo 'export PATH="$INSTALL_DIR:\$PATH"' >> ~/.zshrc   # zsh
    # or
    echo 'export PATH="$INSTALL_DIR:\$PATH"' >> ~/.bashrc  # bash

Then open a new terminal (or run \`source ~/.zshrc\`) and re-run
\`hivemind install-service\` if you want the daemon to start on login.

EOS
fi

# ─── Service registration ─────────────────────────────────────────────
if [ "$NO_SERVICE" -eq 1 ]; then
  log "Skipping service registration (--no-service)."
elif [ "$DRY_RUN" -eq 1 ]; then
  log "(dry-run) would run: $INSTALL_PATH install-service"
else
  log "Registering background service..."
  if ! "$INSTALL_PATH" install-service; then
    warn "install-service failed; the binary is installed but won't start on login. Run \`$INSTALL_PATH install-service\` manually after fixing the issue."
  fi
fi

# ─── Done ─────────────────────────────────────────────────────────────
cat <<EOS >&2

${C_GREEN}✓${C_RESET} ${C_BOLD}hivemind v$VERSION installed at $INSTALL_PATH${C_RESET}

Next steps:
  1. hivemind login          # authenticate
  2. hivemind doctor         # verify health

The daemon keeps itself up to date automatically (auto-apply is the
default for script installs). To disable polling, set
HIVEMIND_UPGRADE_WATCHER_DISABLED=1 in the daemon environment.
EOS
