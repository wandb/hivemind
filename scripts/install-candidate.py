#!/usr/bin/env python3
"""Install an isolated CLI for self-host testing (Python 3.9+, no dependencies)."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request


MANIFESTS = "https://raw.githubusercontent.com/wandb/hivemind/main/manifests"


def normalize(version):
    version = version.removeprefix("v").replace("-rc", "rc")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:rc\d+)?", version, flags=re.ASCII):
        raise ValueError(f"Expected X.Y.Z or X.Y.ZrcN, got {version!r}")
    return version


def version_key(version):
    core, _, rc = normalize(version).partition("rc")
    return (*map(int, core.split(".")), not bool(rc), int(rc or 0))


def manifest_version(channel, optional=False):
    url = f"{MANIFESTS}/hivemind-{channel}.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return normalize(json.load(response)["version"])
    except urllib.error.HTTPError as error:
        if optional and error.code == 404:
            return None
        raise


def latest_version():
    stable = manifest_version("latest")
    candidate = manifest_version("prerelease", optional=True)
    # A channel manifest can retain the RC after its stable release ships.
    return max(filter(None, (stable, candidate)), key=version_key)


def install(version):
    root = Path.home() / ".local/share/hivemind-releases"
    prefix = root / version
    config = prefix / "config"
    config.mkdir(parents=True, exist_ok=True, mode=0o700)
    prefix.chmod(0o700)
    config.chmod(0o700)
    installer = Path(__file__).resolve().parents[1] / "install.sh"
    subprocess.run(
        ["sh", str(installer), "--binary", "--version", version, "--prefix", str(prefix)],
        env={**os.environ, "XDG_CONFIG_HOME": str(config)},
        check=True,
    )
    # Switch the selected version only after checksum-verified installation succeeds.
    pending = root / f".current-{os.getpid()}"
    try:
        pending.symlink_to(version, target_is_directory=True)
        pending.replace(root / "current")
    finally:
        pending.unlink(missing_ok=True)
    wrapper = Path.home() / ".local/bin/hivemind-rc"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text('''#!/usr/bin/env bash
set -euo pipefail
prefix="$(readlink -f "$HOME/.local/share/hivemind-releases/current")"
exec env XDG_CONFIG_HOME="$prefix/config" "$prefix/bin/hivemind" "$@"
''')
    wrapper.chmod(0o755)
    print(f"Selected {version}: {wrapper} (CLI and config under {prefix})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="explicit version; default: latest RC or stable")
    parser.add_argument("--resolve-only", action="store_true", help="print version without installing")
    args = parser.parse_args()
    version = normalize(args.version) if args.version else latest_version()
    if args.resolve_only:
        print(version)
    else:
        install(version)


if __name__ == "__main__":
    main()
