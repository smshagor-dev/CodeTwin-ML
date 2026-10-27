"""Regression tests for the tracked private-key armor CI guard."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.check_tracked_private_keys import (
    CHUNK_SIZE,
    has_private_key_armor,
    scan_tracked_files,
)


def _private_header(prefix: bytes = b"") -> bytes:
    # No complete private-key header is committed as a literal fixture.
    return b"-----" + b"BEGIN " + prefix + b"PRIVATE KEY-----"


class TrackedPrivateKeyGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        subprocess.run(
            ["git", "init", "-q"], cwd=self.root, check=True, capture_output=True
        )

    def _track(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        subprocess.run(
            ["git", "add", "--", name], cwd=self.root, check=True, capture_output=True
        )
        return path

    def test_detects_private_key_armor_in_tracked_file(self) -> None:
        self._track("secret.pem", _private_header() + b"\nnot a real key\n")
        self.assertEqual(scan_tracked_files(self.root), ["secret.pem"])

    def test_detects_openssh_and_pgp_private_armor(self) -> None:
        self._track("openssh.key", _private_header(b"OPENSSH "))
        self._track("pgp.asc", _private_header(b"PGP ")[:-5] + b" BLOCK-----")
        self.assertEqual(
            sorted(scan_tracked_files(self.root)), ["openssh.key", "pgp.asc"]
        )

    def test_detects_header_across_read_chunk_boundary(self) -> None:
        path = self._track(
            "large.txt", b"x" * (CHUNK_SIZE - 9) + _private_header(b"RSA ")
        )
        self.assertTrue(has_private_key_armor(path))

    def test_public_keys_and_untracked_files_are_not_reported(self) -> None:
        self._track("public.pem", b"-----BEGIN PUBLIC KEY-----\n")
        (self.root / "untracked.pem").write_bytes(_private_header())
        self.assertEqual(scan_tracked_files(self.root), [])

    def test_tracked_symlink_is_not_followed(self) -> None:
        outside = self.root.parent / (self.root.name + "-outside.key")
        outside.write_bytes(_private_header())
        self.addCleanup(outside.unlink)
        link = self.root / "link.key"
        link.symlink_to(outside)
        subprocess.run(
            ["git", "add", "--", "link.key"],
            cwd=self.root, check=True, capture_output=True,
        )
        self.assertEqual(scan_tracked_files(self.root), [])

    def test_missing_tracked_file_fails_closed(self) -> None:
        path = self._track("missing.txt", b"ordinary text")
        path.unlink()
        with self.assertRaisesRegex(ValueError, "unavailable"):
            scan_tracked_files(self.root)

    def test_non_git_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):
                scan_tracked_files(Path(directory))


if __name__ == "__main__":
    unittest.main()
