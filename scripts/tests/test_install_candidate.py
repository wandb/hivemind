"""Release-channel rollover and isolated installation regression tests."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location(
    "candidate", Path(__file__).resolve().parents[1] / "install-candidate.py"
)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateTests(unittest.TestCase):
    def test_channel_rollover(self):
        for stable, rc, expected in [
            ("1.1.0", "1.1.1rc4", "1.1.1rc4"),
            ("1.1.1", "1.1.1rc4", "1.1.1"),
            ("1.2.0", "1.1.1rc4", "1.2.0"),
            ("1.1.1", None, "1.1.1"),
            ("1.1.1", "1.1.2rc1", "1.1.2rc1"),
            ("1.9.0", "1.10.0rc1", "1.10.0rc1"),
        ]:
            with self.subTest(stable=stable, rc=rc):
                with patch.object(candidate, "manifest_version", side_effect=[stable, rc]):
                    self.assertEqual(candidate.latest_version(), expected)
        self.assertGreater(candidate.version_key("1.1.1rc10"), candidate.version_key("1.1.1rc9"))

    def test_missing_rc_only_falls_back_on_404(self):
        for code in [404, 403, 500]:
            error = urllib.error.HTTPError("https://example.invalid", code, "test", {}, None)
            with patch.object(candidate.urllib.request, "urlopen", side_effect=error):
                if code == 404:
                    self.assertIsNone(candidate.manifest_version("prerelease", optional=True))
                    with self.assertRaises(urllib.error.HTTPError):
                        candidate.manifest_version("latest")
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        candidate.manifest_version("prerelease", optional=True)

    def test_pin_validation(self):
        self.assertEqual(candidate.normalize("v1.1.1-rc4"), "1.1.1rc4")
        for value in ["../current", "1.1", "1.1.1beta1", "1.1.1;id"]:
            with self.assertRaises(ValueError):
                candidate.normalize(value)

    def test_install_and_wrapper_isolation(self):
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {"HOME": home}):
            root = Path(home) / ".local/share/hivemind-releases"

            def fake_installer(command, **kwargs):
                prefix = Path(command[-1])
                self.assertEqual(kwargs["env"]["XDG_CONFIG_HOME"], str(prefix / "config"))
                binary = prefix / "bin/hivemind"
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_text('#!/bin/sh\nprintf "%s\\n" "$XDG_CONFIG_HOME" "$@"\n')
                binary.chmod(0o755)

            with patch.object(candidate.subprocess, "run", side_effect=fake_installer):
                candidate.install("1.1.1rc4")
                candidate.install("1.1.1")
            wrapper = Path(home) / ".local/bin/hivemind-rc"
            result = subprocess.check_output([str(wrapper), "two words"], text=True)
            self.assertEqual(result.splitlines(), [str(root / "1.1.1/config"), "two words"])
            with patch.object(candidate.subprocess, "run", side_effect=RuntimeError("download failed")):
                with self.assertRaises(RuntimeError):
                    candidate.install("1.1.2rc1")
            self.assertEqual((root / "current").resolve().name, "1.1.1")


if __name__ == "__main__":
    unittest.main()
