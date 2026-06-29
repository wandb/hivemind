#!/usr/bin/env sh
# HiveMind installer.
#
#   curl -fsSL https://hivemind.wandb.tools/install | sh
#
# On Apple Silicon Macs with Homebrew it prefers the wandb-hivemind
# cask (clean uninstall via brew). Everywhere else — and with --binary —
# it resolves a release manifest, verifies the binary's sha256 (and
# codesign Team ID on macOS), and installs to ~/.local/bin/hivemind.
# A managed .pkg install (MDM) makes this script a no-op unless --force.
# See docs/BREW_AUTO_UPGRADE_DESIGN.md for the cross-channel design.
#
# Tests: scripts/tests/install_sh/run.sh (plain-sh isolated harness; CI
# runs it under dash, bash, and macOS sh — see install-script.yml).
#
# This file is the source of truth. release.yml syncs it to the top
# level of the public wandb/hivemind repo on every stable release:
# https://github.com/wandb/hivemind/blob/main/install.sh

set -eu

# Match upgrade_watcher.py:DEFAULT_MANIFEST_URL and EXPECTED_TEAM_ID.
# wandb/hivemind is the canonical release repo; wandb/homebrew-taps
# carries a mirror for pre-0.7.5 daemons.
STABLE_MANIFEST_URL="https://raw.githubusercontent.com/wandb/hivemind/main/manifests/hivemind-latest.json"
PRERELEASE_MANIFEST_URL="https://raw.githubusercontent.com/wandb/hivemind/main/manifests/hivemind-prerelease.json"
EXPECTED_TEAM_ID="5DTHBP38WM"

INSTALL_PREFIX="${HIVEMIND_INSTALL_PREFIX:-$HOME/.local}"
PIN_VERSION="${HIVEMIND_VERSION:-}"
CHANNEL="${HIVEMIND_CHANNEL:-stable}"

# Self-hosted server endpoint. The /install endpoint
# (backend/api/.../handlers/install.py) rewrites the default below to the host
# it was served from, so `curl https://my.hivemind.example/install | sh` points
# the daemon at that host. Served from the public SaaS host — or fetched
# straight from GitHub — it stays empty and the daemon keeps its built-in
# default endpoint. Override for manual installs with HIVEMIND_SERVER_ENDPOINT.
SERVER_ENDPOINT="${HIVEMIND_SERVER_ENDPOINT:-}"
DRY_RUN=0
NO_SERVICE=0
ALLOW_ROOT=0
BINARY_ONLY=0
FORCE=0
PREFIX_CUSTOMIZED=0
[ -n "${HIVEMIND_INSTALL_PREFIX:-}" ] && PREFIX_CUSTOMIZED=1

# Test seams — unset in real installs. SYSROOT prefixes the absolute
# system paths probed below (pkg payload, Caskroom, Cellar) so the test
# harness (scripts/tests/install_sh/) can fake installed-state in a
# tmpdir; TTY_DEV redirects the interactive prompt the same way.
SYSROOT="${HIVEMIND_INSTALL_SYSROOT:-}"
TTY_DEV="${HIVEMIND_INSTALL_TTY:-/dev/tty}"

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
                  [--binary] [--force] [--dry-run] [--allow-root]

Options:
  --binary    Skip the Homebrew cask preference and install the raw
              signed binary to PREFIX/bin/hivemind.
  --force     Like --binary, but also proceeds when a managed .pkg
              install is present (normally a no-op).

Environment:
  HIVEMIND_VERSION              Pin a specific version (same as --version)
  HIVEMIND_CHANNEL              Channel: stable (default) or prerelease
  HIVEMIND_INSTALL_PREFIX       Alt install prefix (default: \$HOME/.local)
  HIVEMIND_UPGRADE_MANIFEST_URL Override manifest URL (overrides --channel)

On Apple Silicon Macs with Homebrew, the installer prefers
\`brew install --cask wandb/taps/wandb-hivemind\` (clean uninstall via
brew; the daemon still keeps itself updated). Everywhere else, and
with --binary, it installs the latest signed release to
~/.local/bin/hivemind. Run \`hivemind start\` afterwards to accept the
terms, sign in, and register the background service. Use
--channel prerelease to opt into the unstable channel.
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
    --prefix) require_value "$1" "${2:-}"; INSTALL_PREFIX="$2"; PREFIX_CUSTOMIZED=1; shift 2 ;;
    --prefix=*) INSTALL_PREFIX="${1#--prefix=}"; PREFIX_CUSTOMIZED=1; shift ;;
    --binary) BINARY_ONLY=1; shift ;;
    --force) FORCE=1; BINARY_ONLY=1; shift ;;
    # Deprecated: the installer no longer registers the service at all;
    # `hivemind start` owns that. Accepted so existing automation keeps
    # working.
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
    die "Intel Macs are not currently supported. The hivemind binary is built for Apple Silicon only. Install the cross-platform package with uv instead: uv tool install wandb-hivemind"
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

# Point the daemon at a self-hosted server, when this script was served from a
# custom /install host (see SERVER_ENDPOINT above). Runs on fresh installs and
# re-runs over existing ones — re-curling a custom /install is how a user
# repoints an already-installed daemon, so this is called on the "nothing to
# do" exits too. Best-effort: a failure here never fails the install.
# $1 (optional) is the best-known path to the hivemind binary; falls back to
# whatever is on PATH (brew/pkg installs put hivemind there).
configure_server_endpoint() {
  [ -n "$SERVER_ENDPOINT" ] || return 0
  if [ "$DRY_RUN" -eq 1 ]; then
    log "(dry-run) would run: hivemind config set server.endpoint \"$SERVER_ENDPOINT\""
    return 0
  fi
  hm_bin="${1:-}"
  [ -x "$hm_bin" ] || hm_bin=$(command -v hivemind 2>/dev/null || true)
  if [ -z "$hm_bin" ] || [ ! -x "$hm_bin" ]; then
    warn "couldn't find hivemind to point at $SERVER_ENDPOINT — run: hivemind config set server.endpoint \"$SERVER_ENDPOINT\""
    return 0
  fi
  if "$hm_bin" config set server.endpoint "$SERVER_ENDPOINT" >&2; then
    log "${C_GREEN}✓${C_RESET} Updated hivemind to log to $SERVER_ENDPOINT"
  else
    warn "couldn't set server.endpoint=$SERVER_ENDPOINT — run: hivemind config set server.endpoint \"$SERVER_ENDPOINT\""
  fi
}

# ─── Install-path decision (macOS) ────────────────────────────────────
# Probes mirror install_channels.py: pkg = payload binary AND system
# plist (a stale pkgutil receipt alone must not block); cask/formula =
# their Caskroom/Cellar directories.

cask_dir_exists() {
  [ -d "$SYSROOT/opt/homebrew/Caskroom/$1" ] || [ -d "$SYSROOT/usr/local/Caskroom/$1" ]
}

# `curl … | sh` pipes stdin, so prompts must go through the controlling
# terminal instead. No usable TTY → never prompt (fall back to the
# non-interactive behavior of whichever path we're on).
TTY_OK=0
if [ -r "$TTY_DEV" ] && [ -w "$TTY_DEV" ]; then TTY_OK=1; fi

confirm_tty() {  # confirm_tty "question" — returns 0 only on an explicit yes
  # Every confirm gates something destructive or surprising (uninstall,
  # downgrade, cask switch), so a bare Enter or Ctrl-D means NO — a user
  # bailing out must never fall through to the destructive branch.
  # Append, don't truncate: identical on a real /dev/tty, but it keeps
  # the harness's seeded answer file intact when TTY_DEV is overridden.
  printf '%s [y/N] ' "$1" >> "$TTY_DEV"
  REPLY=""
  read -r REPLY < "$TTY_DEV" || true
  case "$REPLY" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$OS" = "Darwin" ] \
   && [ -e "$SYSROOT/usr/local/hivemind/bin/hivemind" ] \
   && [ -e "$SYSROOT/Library/LaunchAgents/com.wandb.hivemind.plist" ]; then
  if [ "$FORCE" -ne 1 ]; then
    log "hivemind is already installed and managed by your organization's .pkg installer"
    log "($SYSROOT/usr/local/hivemind/bin/hivemind). It keeps itself up to date — nothing to do."
    log ""
    log "To replace it with a self-managed install, first remove it:"
    log "    sudo /usr/local/hivemind/uninstall.sh"
    log "then re-run this installer. (--force installs alongside it; not recommended —"
    log "the two fight over PATH and the com.wandb.hivemind LaunchAgent.)"
    configure_server_endpoint "$SYSROOT/usr/local/hivemind/bin/hivemind"
    exit 0
  fi
  warn "--force: installing the script binary alongside the managed .pkg install. They will conflict over PATH and the com.wandb.hivemind LaunchAgent; remove one of them with its uninstaller."
fi

# On Apple Silicon with Homebrew, prefer the cask: brew gives a clean
# uninstall path (`brew uninstall --cask wandb/taps/wandb-hivemind`),
# which the raw-binary install lacks, and the daemon self-updates either
# way. Skipped for --binary/--force, --version pins (the cask always
# installs the latest), and custom --prefix (explicitly a binary ask).
if [ "$OS" = "Darwin" ] && [ "$ARCH" = "arm64" ] && [ "$BINARY_ONLY" -ne 1 ] \
   && [ -z "$PIN_VERSION" ] && [ "$PREFIX_CUSTOMIZED" -ne 1 ]; then

  case "$CHANNEL" in
    stable) CASK_NAME="wandb-hivemind" ;;
    prerelease) CASK_NAME="wandb-hivemind-prerelease" ;;
    *) die "unknown --channel '$CHANNEL' (expected: stable, prerelease)" ;;
  esac

  INSTALLED_CASK=""
  for cask in wandb-hivemind wandb-hivemind-prerelease hivemind-app hivemind-app-prerelease; do
    if cask_dir_exists "$cask"; then
      INSTALLED_CASK="$cask"
      break
    fi
  done

  if [ "$INSTALLED_CASK" = "$CASK_NAME" ]; then
    log "hivemind is already installed via the Homebrew cask ($CASK_NAME) — nothing to do."
    log "The daemon keeps itself up to date. To force a reinstall through brew:"
    log "    brew upgrade --greedy wandb/taps/$CASK_NAME"
    log "(or pass --binary to switch to a script-managed binary install)"
    configure_server_endpoint
    exit 0
  fi

  if [ -n "$INSTALLED_CASK" ]; then
    # A different cask from the family is installed: a channel switch
    # (stable ↔ prerelease) or a legacy hivemind-app migration. The
    # casks conflict over the binary link, so the old one must go first.
    warn "hivemind is installed via the $INSTALLED_CASK cask, but this install targets $CASK_NAME."
    SWITCH_CMD="brew uninstall --cask wandb/taps/$INSTALLED_CASK && brew install --cask wandb/taps/$CASK_NAME"
    if [ "$DRY_RUN" -eq 1 ]; then
      log "(dry-run) would prompt to switch casks: $SWITCH_CMD"
      configure_server_endpoint
      exit 0
    fi
    if have brew && [ "$TTY_OK" -eq 1 ]; then
      confirm_tty "Replace $INSTALLED_CASK with $CASK_NAME?" \
        || die "keeping $INSTALLED_CASK. To switch manually: $SWITCH_CMD"
      log "Running: brew uninstall --cask wandb/taps/$INSTALLED_CASK"
      brew uninstall --cask "wandb/taps/$INSTALLED_CASK" >&2 \
        || brew uninstall --cask "$INSTALLED_CASK" >&2 \
        || die "brew uninstall failed — switch manually: $SWITCH_CMD"
      # fall through to the cask install below
    else
      die "can't confirm the cask switch non-interactively. Run: $SWITCH_CMD"
    fi
  fi

  if have brew && [ "$TTY_OK" -eq 1 ]; then
    CASK_OK=1

    if [ -d "$SYSROOT/opt/homebrew/Cellar/hivemind" ] || [ -d "$SYSROOT/usr/local/Cellar/hivemind" ]; then
      # Distinguish our formula (a python virtualenv keg with
      # libexec/bin/hivemind) from homebrew-core's unrelated `hivemind`
      # process manager (a bare Go binary) before uninstalling anything.
      BREW_PREFIX=$(brew --prefix 2>/dev/null || echo "$SYSROOT/opt/homebrew")
      if [ -e "$BREW_PREFIX/opt/hivemind/libexec/bin/hivemind" ]; then
        warn "the legacy Homebrew formula (wandb/taps/hivemind) is installed. The wandb-hivemind cask can't install alongside it — both link \$(brew --prefix)/bin/hivemind."
        if [ "$DRY_RUN" -eq 1 ]; then
          log "(dry-run) would prompt to remove it: brew uninstall wandb/taps/hivemind"
        elif confirm_tty "Remove the legacy formula now (brew uninstall wandb/taps/hivemind)?"; then
          log "Running: brew uninstall wandb/taps/hivemind"
          brew uninstall wandb/taps/hivemind >&2 \
            || brew uninstall hivemind >&2 \
            || die "brew uninstall failed — remove the formula manually, then re-run this installer"
        else
          die "keeping the legacy formula. Re-run after \`brew uninstall wandb/taps/hivemind\`, or pass --binary for a script-managed binary install."
        fi
      else
        warn "an unrelated 'hivemind' Homebrew formula is installed; its binary link would conflict with the wandb-hivemind cask. Falling back to the script binary install."
        CASK_OK=0
      fi
    fi

    if [ "$CASK_OK" -eq 1 ]; then
      log "Homebrew detected — installing via the cask (preferred on Apple Silicon:"
      log "clean uninstall through brew; the daemon still keeps itself updated)."
      if [ "$DRY_RUN" -eq 1 ]; then
        log "(dry-run) would run: brew install --cask wandb/taps/$CASK_NAME"
        exit 0
      fi
      log "Running: brew install --cask wandb/taps/$CASK_NAME"
      brew install --cask "wandb/taps/$CASK_NAME" >&2 \
        || die "brew install failed — fix the brew error above and re-run, or pass --binary for a script-managed binary install"
      cat <<EOS >&2

${C_GREEN}✓${C_RESET} ${C_BOLD}hivemind installed via Homebrew cask (wandb/taps/$CASK_NAME)${C_RESET}

Next steps:
  1. hivemind start          # accept the terms, sign in, and start the daemon
  2. hivemind doctor         # verify health

The daemon keeps itself up to date automatically. Manage the install
with brew:
    brew upgrade --greedy wandb/taps/$CASK_NAME    # force-reinstall latest
    brew uninstall --cask wandb/taps/$CASK_NAME    # clean uninstall
EOS
      configure_server_endpoint
      exit 0
    fi
  elif have brew; then
    log "Tip: on Apple Silicon with Homebrew, the preferred install is:"
    log "    brew install wandb/taps/wandb-hivemind"
    log "(clean uninstall through brew). No terminal available to confirm, so"
    log "continuing with the script binary install."
  fi
fi

# Manifest URL resolution order: env override > --version pin > --channel.
# CHANNEL is only validated when it actually picks the URL.
CHANNEL_USED=0
if [ -n "${HIVEMIND_UPGRADE_MANIFEST_URL:-}" ]; then
  MANIFEST_URL="$HIVEMIND_UPGRADE_MANIFEST_URL"
elif [ -n "$PIN_VERSION" ]; then
  MANIFEST_URL="https://raw.githubusercontent.com/wandb/hivemind/main/manifests/hivemind-${PIN_VERSION}.json"
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

# ─── Upgrade vs first-install detection ───────────────────────────────
# Captured BEFORE the new binary lands. "Upgrade" means a binary was
# already at the install path AND the service has been registered
# (mirrors _is_service_installed() in cli.py) — i.e. the user has been
# through `hivemind start` at least once, so a post-install
# `hivemind restart` is what applies the new build. A binary with no
# registered service is still a first install (start owns ToS + login).
INSTALL_PATH_PREVIEW="$INSTALL_PREFIX/bin/hivemind"
SERVICE_REGISTERED=0
if [ "$OS" = "Darwin" ]; then
  [ -e "$HOME/Library/LaunchAgents/com.wandb.hivemind.plist" ] && SERVICE_REGISTERED=1
else
  [ -e "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/hivemind.service" ] && SERVICE_REGISTERED=1
fi
IS_UPGRADE=0
if [ -x "$INSTALL_PATH_PREVIEW" ] && [ "$SERVICE_REGISTERED" -eq 1 ]; then
  IS_UPGRADE=1
fi

# ─── Downgrade detection ──────────────────────────────────────────────
# `--version 0.5.0` over a working 0.6.x install is almost always a
# typo. Prompt to confirm interactively; refuse with no TTY.
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
      # Prompt via the controlling terminal, not stdin: under the
      # documented `curl … | sh` usage stdin is the pipe, so a `-t 0`
      # check would refuse even when the user is sitting at a terminal.
      if [ "$TTY_OK" -eq 1 ]; then
        confirm_tty "Continue?" || die "aborted by user"
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
# The managed-pkg case was handled up front (no-op unless --force); the
# rest is informational — a binary install proceeds, and `hivemind
# start` takes over the shared service label.
EXISTING_INSTALLS=""
note_existing() { EXISTING_INSTALLS="$EXISTING_INSTALLS\n  - $1"; }

if [ "$OS" = "Darwin" ]; then
  for cask in wandb-hivemind wandb-hivemind-prerelease hivemind-app hivemind-app-prerelease; do
    if cask_dir_exists "$cask"; then
      note_existing "Homebrew cask $cask"
    fi
  done
  if [ -d "$SYSROOT/opt/homebrew/Cellar/hivemind" ] || [ -d "$SYSROOT/usr/local/Cellar/hivemind" ]; then
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
  log "Running \`hivemind start\` from the script-installed binary will take over the service registration (com.wandb.hivemind); old installs remain on disk and can be removed with their respective uninstallers."
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

  # Pre-warm: the Nuitka onefile binary extracts ~180 MB to
  # ~/.cache/hivemind-<version>/ on its first execution — several
  # seconds of I/O better paid here than on the user's first command.
  # Best-effort (the binary is already sha256- and codesign-verified).
  if ! "$INSTALL_PATH" --version >/dev/null 2>&1; then
    warn "$INSTALL_PATH --version failed; run \`hivemind doctor\` to investigate"
  fi

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

# Set the self-hosted endpoint before the upgrade-restart below, so a restart
# brings the daemon up already pointed at the right server.
configure_server_endpoint "$INSTALL_PATH"

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

Then open a new terminal (or run \`source ~/.zshrc\`) and run
\`hivemind start\` to get the daemon running and starting on login.

EOS
fi

# The installer intentionally does not register or start the service on
# first install: `hivemind start` walks the user through the terms of
# service and the login flow before registering the LaunchAgent /
# systemd unit.
if [ "$NO_SERVICE" -eq 1 ]; then
  warn "--no-service is deprecated and now a no-op: the installer never registers the service. Run \`hivemind start\` when you want the daemon running."
fi

# ─── Restart on upgrade ───────────────────────────────────────────────
# An upgrade of a registered service can be applied right here instead
# of telling the user to run `hivemind restart` themselves. TTY only:
# restart can prompt (keychain, re-login), and a prompt with no terminal
# would hang automation — non-interactive runs get the hint instead.
# Skipped under --force, where a managed .pkg may own the service label.
RESTARTED=0
if [ "$IS_UPGRADE" -eq 1 ] && [ "$FORCE" -ne 1 ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    log "(dry-run) would restart the daemon (existing service detected)"
  elif [ "$TTY_OK" -eq 1 ]; then
    log "Existing service detected — restarting the daemon onto v$VERSION..."
    if "$INSTALL_PATH" restart >&2 < "$TTY_DEV"; then
      RESTARTED=1
    else
      warn "hivemind restart failed — run it manually to finish the upgrade"
    fi
  fi
fi

# ─── Done ─────────────────────────────────────────────────────────────
if [ "$RESTARTED" -eq 1 ]; then
  cat <<EOS >&2

${C_GREEN}✓${C_RESET} ${C_BOLD}hivemind upgraded to v$VERSION and the daemon restarted${C_RESET}

Run \`hivemind status\` to confirm, or \`hivemind doctor\` if anything
looks off. The daemon keeps itself up to date automatically from here.
EOS
elif [ "$IS_UPGRADE" -eq 1 ]; then
  cat <<EOS >&2

${C_GREEN}✓${C_RESET} ${C_BOLD}hivemind v$VERSION installed at $INSTALL_PATH${C_RESET}

The daemon is still running the previous build. Apply the upgrade with:

    hivemind restart

EOS
else
  cat <<EOS >&2

${C_GREEN}✓${C_RESET} ${C_BOLD}hivemind v$VERSION installed at $INSTALL_PATH${C_RESET}

Next steps:
  1. hivemind start          # accept the terms, sign in, and start the daemon
  2. hivemind doctor         # verify health

Once started, the daemon keeps itself up to date automatically
(auto-apply is the default for script installs). To disable polling,
set HIVEMIND_UPGRADE_WATCHER_DISABLED=1 in the daemon environment.
EOS
fi
