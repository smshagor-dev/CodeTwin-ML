"""Regression tests for the opt-in POSIX external trust-anchor publisher."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts.publish_signer_trust_anchor import FORMAT, publish


@unittest.skipUnless(os.name == "posix", "Publisher requires POSIX file locking")
class TrustAnchorPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.root.chmod(0o700)
        self.anchor = self.root / "anchor.json"
        self.authority = "a1" * 32
        self.old_pin = "b2" * 32
        self.new_pin = "c3" * 32
        self.original = {
            "format": FORMAT,
            "authority_public_key_hex": self.authority,
            "minimum_revision": 4,
            "signed_policy_sha256_hex": self.old_pin,
        }
        self._write_anchor(self.original)

    def _write_anchor(self, data: object) -> None:
        self.anchor.write_text(json.dumps(data), encoding="utf-8")
        self.anchor.chmod(0o600)

    def _publish(self, **overrides: object) -> dict[str, object]:
        arguments = {
            "expected_revision": 4,
            "expected_sha256": self.old_pin,
            "authority_public_key_hex": self.authority,
            "replacement_revision": 5,
            "replacement_sha256": self.new_pin,
            "approved": True,
        }
        arguments.update(overrides)
        return publish(self.anchor, **arguments)

    def _assert_unchanged(self) -> None:
        self.assertEqual(json.loads(self.anchor.read_text(encoding="utf-8")), self.original)

    def test_publishes_revision_and_digest_as_one_private_record(self) -> None:
        result = self._publish()
        self.assertEqual(result["minimum_revision"], 5)
        self.assertEqual(result["signed_policy_sha256_hex"], self.new_pin)
        self.assertEqual(json.loads(self.anchor.read_text(encoding="utf-8")), result)
        self.assertEqual(stat.S_IMODE(self.anchor.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        self.assertTrue((self.root / "anchor.json.lock").is_file())

    def test_rejects_stale_cas_after_successful_update(self) -> None:
        self._publish()
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._publish()
        self.assertEqual(json.loads(self.anchor.read_text())["minimum_revision"], 5)

    def test_rejects_missing_approval_without_writing(self) -> None:
        with self.assertRaisesRegex(ValueError, "approval"):
            self._publish(approved=False)
        self._assert_unchanged()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_rollback_or_same_revision(self) -> None:
        for revision in (3, 4):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "strictly increase"):
                    self._publish(replacement_revision=revision)
                self._assert_unchanged()

    def test_rejects_wrong_old_pin_authority_and_revision(self) -> None:
        for change in (
            {"expected_sha256": "dd" * 32},
            {"authority_public_key_hex": "ee" * 32},
            {"expected_revision": 3},
        ):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    self._publish(**change)
                self._assert_unchanged()

    def test_rejects_malformed_and_reused_replacement_digest(self) -> None:
        for digest in ("ab", "AB" * 32, self.old_pin):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    self._publish(replacement_sha256=digest)
                self._assert_unchanged()

    def test_rejects_world_readable_anchor(self) -> None:
        self.anchor.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            self._publish()
        self._assert_unchanged()

    def test_rejects_nonprivate_directory(self) -> None:
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self._publish()
        self._assert_unchanged()
        self.root.chmod(0o700)

    def test_rejects_symlink_anchor(self) -> None:
        original = self.root / "original.json"
        self.anchor.rename(original)
        self.anchor.symlink_to(original)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            self._publish()
        self.assertEqual(json.loads(original.read_text()), self.original)

    def test_rejects_symlink_directory_component(self) -> None:
        link = self.root / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            publish(
                link / "anchor.json",
                expected_revision=4,
                expected_sha256=self.old_pin,
                authority_public_key_hex=self.authority,
                replacement_revision=5,
                replacement_sha256=self.new_pin,
                approved=True,
            )
        self._assert_unchanged()

    def test_rejects_anchor_metadata_change_during_read(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor

        original_fstat = os.fstat
        calls = 0

        def touch_after_open(fd: int) -> os.stat_result:
            nonlocal calls
            metadata = original_fstat(fd)
            calls += 1
            if calls == 1:
                # Identical JSON bytes but changed modification metadata.
                os.utime(
                    self.anchor,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                )
            return metadata

        with patch("scripts.publish_signer_trust_anchor.os.fstat", side_effect=touch_after_open):
            with self.assertRaisesRegex(ValueError, "changed during read"):
                _read_anchor(self.anchor)
        self._assert_unchanged()

    def test_rejects_anchor_path_swap_during_read(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor

        original_fstat = os.fstat
        moved = self.root / "moved-anchor.json"
        calls = 0

        def swap_after_open(fd: int) -> os.stat_result:
            nonlocal calls
            metadata = original_fstat(fd)
            calls += 1
            if calls == 2:
                # Swap the path after the descriptor's final metadata snapshot,
                # so this specifically exercises the path recheck.
                self.anchor.rename(moved)
                self.anchor.symlink_to(moved)
            return metadata

        with patch("scripts.publish_signer_trust_anchor.os.fstat", side_effect=swap_after_open):
            with self.assertRaisesRegex(ValueError, "path changed during read"):
                _read_anchor(self.anchor)
        self.assertEqual(json.loads(moved.read_text(encoding="utf-8")), self.original)

    def test_rejects_duplicate_json_fields(self) -> None:
        raw = self.anchor.read_text()
        self.anchor.write_text(raw.replace('"format":', '"format":"spoofed","format":'))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self._publish()

    def test_atomic_replace_uses_one_directory_descriptor(self) -> None:
        original_replace = os.replace
        observed: list[tuple[int, int]] = []

        def inspect_replace(source: str, destination: str, **kwargs: int) -> None:
            self.assertEqual(destination, self.anchor.name)
            self.assertTrue(source.startswith(".trust-anchor-"))
            observed.append((kwargs["src_dir_fd"], kwargs["dst_dir_fd"]))
            original_replace(source, destination, **kwargs)

        with patch("scripts.publish_signer_trust_anchor.os.replace", side_effect=inspect_replace):
            self._publish()
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], observed[0][1])
        self.assertEqual(json.loads(self.anchor.read_text())["minimum_revision"], 5)

    def test_rejects_directory_swap_before_opening_publication_fd(self) -> None:
        moved = self.root.with_name(self.root.name + "-previous")
        original_open = os.open
        swapped = False

        def swap_before_open(path: object, flags: int, mode: int = 0o777, *,
                             dir_fd: int | None = None) -> int:
            nonlocal swapped
            if not swapped and flags & os.O_DIRECTORY and Path(path) == self.root:
                swapped = True
                self.root.rename(moved)
                self.root.mkdir(mode=0o700)
                self._write_anchor(self.original)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        try:
            with patch("scripts.publish_signer_trust_anchor.os.open", side_effect=swap_before_open):
                with self.assertRaisesRegex(ValueError, "directory changed before atomic replacement"):
                    self._publish()
            self._assert_unchanged()
            self.assertEqual(json.loads((moved / "anchor.json").read_text()), self.original)
        finally:
            if moved.exists():
                self.anchor.unlink()
                self.root.rmdir()
                moved.rename(self.root)

    def test_rename_cannot_write_into_swapped_directory(self) -> None:
        moved = self.root.with_name(self.root.name + "-previous")
        original_replace = os.replace

        def swap_during_replace(source: str, destination: str, **kwargs: int) -> None:
            self.root.rename(moved)
            self.root.mkdir(mode=0o700)
            self._write_anchor(self.original)
            original_replace(source, destination, **kwargs)

        try:
            with patch("scripts.publish_signer_trust_anchor.os.replace", side_effect=swap_during_replace):
                with self.assertRaisesRegex(ValueError, "directory changed after publication"):
                    self._publish()
            # The old directory may already have been published; the swapped-in
            # pathname must never receive that update.
            self._assert_unchanged()
            self.assertEqual(json.loads((moved / "anchor.json").read_text())["minimum_revision"], 5)
            self.assertEqual(list(moved.glob(".trust-anchor-*.tmp")), [])
        finally:
            if moved.exists():
                self.anchor.unlink()
                self.root.rmdir()
                moved.rename(self.root)

    def test_failed_atomic_replace_keeps_previous_record(self) -> None:
        with patch("scripts.publish_signer_trust_anchor.os.replace", side_effect=OSError("disk error")):
            with self.assertRaisesRegex(OSError, "disk error"):
                self._publish()
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_directory_permission_change_before_replace(self) -> None:
        def expose_directory() -> None:
            self.root.chmod(0o755)

        try:
            with self.assertRaisesRegex(ValueError, "directory must be owned"):
                self._publish(_verify_before_replace=expose_directory)
        finally:
            self.root.chmod(0o700)
        self._assert_unchanged()

    def test_rejects_directory_inode_swap_before_replace(self) -> None:
        moved = self.root.with_name(self.root.name + "-previous")

        def replace_directory() -> None:
            self.root.rename(moved)
            self.root.mkdir(mode=0o700)
            self._write_anchor(self.original)

        try:
            with self.assertRaisesRegex(ValueError, "directory changed before publication"):
                self._publish(_verify_before_replace=replace_directory)
        finally:
            if moved.exists():
                self.anchor.unlink()
                self.root.rmdir()
                moved.rename(self.root)
        self._assert_unchanged()

    def test_rejects_directory_symlink_swap_while_waiting_for_lock(self) -> None:
        import fcntl

        moved = self.root.with_name(self.root.name + "-previous")
        original_flock = fcntl.flock

        def swap_after_lock(fd: int, operation: int) -> None:
            original_flock(fd, operation)
            if operation == fcntl.LOCK_EX:
                self.root.rename(moved)
                self.root.symlink_to(moved, target_is_directory=True)

        try:
            with patch("fcntl.flock", side_effect=swap_after_lock):
                with self.assertRaisesRegex(ValueError, "Symlink"):
                    self._publish()
        finally:
            if moved.exists():
                self.root.unlink()
                moved.rename(self.root)
        self._assert_unchanged()

    def test_rejects_lock_path_replacement_while_acquiring(self) -> None:
        import fcntl

        lock_path = self.root / "anchor.json.lock"
        moved = self.root / "previous-lock"
        original_flock = fcntl.flock

        def replace_after_lock(fd: int, operation: int) -> None:
            original_flock(fd, operation)
            if operation == fcntl.LOCK_EX:
                lock_path.rename(moved)
                lock_path.write_text("replacement", encoding="utf-8")
                lock_path.chmod(0o600)

        with patch("fcntl.flock", side_effect=replace_after_lock):
            with self.assertRaisesRegex(ValueError, "Anchor lock changed"):
                self._publish()
        self._assert_unchanged()
        self.assertTrue(moved.is_file())

    def test_rejects_lock_metadata_change_while_acquiring(self) -> None:
        import fcntl

        lock_path = self.root / "anchor.json.lock"
        original_flock = fcntl.flock

        def touch_after_lock(fd: int, operation: int) -> None:
            original_flock(fd, operation)
            if operation == fcntl.LOCK_EX:
                metadata = os.fstat(fd)
                os.utime(
                    lock_path,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                )

        with patch("fcntl.flock", side_effect=touch_after_lock):
            with self.assertRaisesRegex(ValueError, "Anchor lock changed"):
                self._publish()
        self._assert_unchanged()

    def test_rejects_symlink_lock_file(self) -> None:
        outside = self.root / "outside"
        outside.write_text("do not change", encoding="utf-8")
        (self.root / "anchor.json.lock").symlink_to(outside)
        with self.assertRaises(OSError):
            self._publish()
        self._assert_unchanged()
        self.assertEqual(outside.read_text(), "do not change")


if __name__ == "__main__":
    unittest.main()
