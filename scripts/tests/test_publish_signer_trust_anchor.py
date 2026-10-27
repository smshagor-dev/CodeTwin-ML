"""Regression tests for the opt-in POSIX external trust-anchor publisher."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts.publish_signer_trust_anchor import FORMAT, _publish_anchor


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
            # These tests exercise the internal filesystem CAS primitive only;
            # authenticated policy verification is covered by the integration tests.
            "_verify_before_replace": lambda: True,
        }
        arguments.update(overrides)
        # Test-only hooks may perform a mutation and return None. Convert
        # those legacy side-effect fixtures to an explicit success signal;
        # production callbacks must themselves return exactly True.
        callback = arguments["_verify_before_replace"]
        if callable(callback):
            def test_verifier() -> object:
                result = callback()
                return True if result is None else result
            arguments["_verify_before_replace"] = test_verifier
        return _publish_anchor(self.anchor, **arguments)

    def _assert_unchanged(self) -> None:
        self.assertEqual(json.loads(self.anchor.read_text(encoding="utf-8")), self.original)

    def test_deeply_nested_anchor_fails_closed_without_publication(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor_with_metadata

        # A 128-level input fits the 4096-byte anchor cap, but the schema
        # never requires such nesting. It must fail on every Python runtime.
        raw = b"[" * 128 + b"0" + b"]" * 128
        self.anchor.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "nesting is too deep"):
            _read_anchor_with_metadata(self.anchor)
        with self.assertRaisesRegex(ValueError, "nesting is too deep"):
            self._publish()
        self.assertEqual(self.anchor.read_bytes(), raw)
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_anchor_depth_guard_ignores_brackets_in_strings(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor_with_metadata

        value = dict(self.original)
        value["format"] = "[" * 100 + '\\"' + "{" * 100
        self._write_anchor(value)
        with self.assertRaisesRegex(ValueError, "Unsupported trust-anchor format"):
            _read_anchor_with_metadata(self.anchor)

    def test_publishes_revision_and_digest_as_one_private_record(self) -> None:
        result = self._publish()
        self.assertEqual(result["minimum_revision"], 5)
        self.assertEqual(result["signed_policy_sha256_hex"], self.new_pin)
        self.assertEqual(json.loads(self.anchor.read_text(encoding="utf-8")), result)
        self.assertEqual(stat.S_IMODE(self.anchor.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        self.assertTrue((self.root / "anchor.json.lock").is_file())

    def test_rejects_staged_hard_link_created_before_metadata_snapshot(self) -> None:
        # Another pathname to the staged inode must not be accepted even
        # when the link already exists at the first metadata observation.
        real_fsync = os.fsync
        linked = self.root / "linked-staged.json"
        created = False

        def link_after_staged_sync(fd: int) -> None:
            nonlocal created
            real_fsync(fd)
            staged = list(self.root.glob(".trust-anchor-*.tmp"))
            if staged and not created:
                os.link(staged[0], linked)
                created = True

        try:
            with patch("scripts.publish_signer_trust_anchor.os.fsync",
                       side_effect=link_after_staged_sync):
                with self.assertRaisesRegex(ValueError, "Staged trust anchor must be a private regular file"):
                    self._publish()
            self.assertTrue(created)
            self._assert_unchanged()
            self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        finally:
            linked.unlink(missing_ok=True)

    def test_rejects_staged_hard_link_added_during_final_verification(self) -> None:
        linked = self.root / "linked-staged.json"
        calls = 0

        def link_on_second_verification() -> bool:
            nonlocal calls
            calls += 1
            if calls == 2:
                staged = list(self.root.glob(".trust-anchor-*.tmp"))
                self.assertEqual(len(staged), 1)
                os.link(staged[0], linked)
            return True

        try:
            with self.assertRaisesRegex(ValueError, "Staged trust anchor must be a private regular file"):
                self._publish(_verify_before_replace=link_on_second_verification)
            self.assertEqual(calls, 2)
            self._assert_unchanged()
            self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        finally:
            linked.unlink(missing_ok=True)

    def test_cleanup_preserves_foreign_file_swapped_into_staging_name(self) -> None:
        detached = self.root / "detached-staged-anchor.bin"
        foreign_payload = b"unrelated file must survive failed publication"
        staged_path: Path | None = None
        calls = 0

        def replace_on_second_verification() -> bool:
            nonlocal calls, staged_path
            calls += 1
            if calls == 2:
                (staged_path,) = list(self.root.glob(".trust-anchor-*.tmp"))
                staged_path.rename(detached)
                staged_path.write_bytes(foreign_payload)
                staged_path.chmod(0o600)
            return True

        try:
            with self.assertRaisesRegex(ValueError, "Staged trust anchor changed"):
                self._publish(_verify_before_replace=replace_on_second_verification)
            self.assertEqual(calls, 2)
            self.assertIsNotNone(staged_path)
            self.assertEqual(staged_path.read_bytes(), foreign_payload)
            self._assert_unchanged()
        finally:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            detached.unlink(missing_ok=True)

    def test_cleanup_preserves_foreign_symlink_swapped_into_staging_name(self) -> None:
        detached = self.root / "detached-staged-anchor.bin"
        sentinel = self.root / "unrelated-sentinel.txt"
        sentinel.write_text("must survive", encoding="utf-8")
        staged_path: Path | None = None
        calls = 0

        def replace_with_symlink_on_second_verification() -> bool:
            nonlocal calls, staged_path
            calls += 1
            if calls == 2:
                (staged_path,) = list(self.root.glob(".trust-anchor-*.tmp"))
                staged_path.rename(detached)
                staged_path.symlink_to(sentinel)
            return True

        try:
            with self.assertRaisesRegex(ValueError, "Staged trust anchor"):
                self._publish(_verify_before_replace=replace_with_symlink_on_second_verification)
            self.assertEqual(calls, 2)
            self.assertIsNotNone(staged_path)
            self.assertTrue(staged_path.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "must survive")
            self._assert_unchanged()
        finally:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            detached.unlink(missing_ok=True)
            sentinel.unlink(missing_ok=True)

    def test_rejects_lock_swap_during_published_anchor_readback(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor_with_metadata

        real_read = _read_anchor_with_metadata
        lock_path = self.root / "anchor.json.lock"
        detached = self.root / "detached-readback.lock"
        changed = False

        def swap_lock_after_readback(path: Path) -> object:
            nonlocal changed
            result = real_read(path)
            if result[0]["minimum_revision"] == 5 and not changed:
                lock_path.rename(detached)
                lock_path.write_bytes(b"")
                lock_path.chmod(0o600)
                changed = True
            return result

        try:
            with patch(
                "scripts.publish_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=swap_lock_after_readback,
            ):
                with self.assertRaisesRegex(ValueError, "Anchor lock changed"):
                    self._publish()
            self.assertTrue(changed)
            # The rename was already durable. A failed readback is NOT a
            # rollback and must be reconciled by the external administrator.
            self.assertEqual(json.loads(self.anchor.read_text())["minimum_revision"], 5)
        finally:
            detached.unlink(missing_ok=True)

    def test_rejects_directory_swap_during_published_anchor_readback(self) -> None:
        import shutil
        from scripts.publish_signer_trust_anchor import _read_anchor_with_metadata

        real_read = _read_anchor_with_metadata
        detached = self.root.with_name(self.root.name + "-readback-detached")
        changed = False

        def swap_directory_after_readback(path: Path) -> object:
            nonlocal changed
            result = real_read(path)
            if result[0]["minimum_revision"] == 5 and not changed:
                self.root.rename(detached)
                self.root.mkdir(mode=0o700)
                self.anchor.write_bytes((detached / "anchor.json").read_bytes())
                self.anchor.chmod(0o600)
                changed = True
            return result

        try:
            with patch(
                "scripts.publish_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=swap_directory_after_readback,
            ):
                with self.assertRaisesRegex(ValueError, "Anchor directory changed during publication readback"):
                    self._publish()
            self.assertTrue(changed)
            self.assertEqual(json.loads((detached / "anchor.json").read_text())["minimum_revision"], 5)
        finally:
            if detached.exists():
                if self.root.exists():
                    shutil.rmtree(self.root)
                detached.rename(self.root)

    def test_rejects_identical_content_inode_swap_after_publication(self) -> None:
        # A noncooperating writer can replace the newly published pathname
        # with byte-identical JSON after rename. A value-only readback would
        # silently accept that different inode as the published record.
        real_replace = os.replace
        detached = self.root / "detached-published-anchor.json"

        def swap_after_publish(src: object, dst: object, **kwargs: object) -> None:
            real_replace(src, dst, **kwargs)
            self.anchor.rename(detached)
            self.anchor.write_bytes(detached.read_bytes())
            self.anchor.chmod(0o600)

        try:
            with patch("scripts.publish_signer_trust_anchor.os.replace",
                       side_effect=swap_after_publish):
                with self.assertRaisesRegex(ValueError, "Published anchor identity changed"):
                    self._publish()
            self.assertEqual(self.anchor.read_bytes(), detached.read_bytes())
            self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        finally:
            detached.unlink(missing_ok=True)

    def test_refuses_anchor_inside_source_checkout_before_lock_creation(self) -> None:
        with patch(
            "scripts.publish_signer_trust_anchor._checkout_root",
            return_value=self.root,
        ):
            with self.assertRaisesRegex(ValueError, "outside the CodeTwin source checkout"):
                self._publish()
        self._assert_unchanged()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_internal_publisher_rejects_missing_verification_hook(self) -> None:
        with self.assertRaisesRegex(ValueError, "verification callback is required"):
            _publish_anchor(
                self.anchor,
                expected_revision=4,
                expected_sha256=self.old_pin,
                authority_public_key_hex=self.authority,
                replacement_revision=5,
                replacement_sha256=self.new_pin,
                approved=True,
            )
        self._assert_unchanged()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_internal_publisher_rejects_noncallable_verification_hook(self) -> None:
        with self.assertRaisesRegex(ValueError, "verification callback is required"):
            self._publish(_verify_before_replace=False)
        self._assert_unchanged()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_internal_publisher_rejects_silent_verification_callback(self) -> None:
        # A no-op callback must not count as authenticated verification.
        with self.assertRaisesRegex(ValueError, "callback rejected publication"):
            _publish_anchor(
                self.anchor,
                expected_revision=4,
                expected_sha256=self.old_pin,
                authority_public_key_hex=self.authority,
                replacement_revision=5,
                replacement_sha256=self.new_pin,
                approved=True,
                _verify_before_replace=lambda: None,
            )
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_internal_publisher_rejects_silent_recheck_after_staging(self) -> None:
        calls = 0

        def verify_once() -> bool | None:
            nonlocal calls
            calls += 1
            return True if calls == 1 else None

        with self.assertRaisesRegex(ValueError, "callback rejected publication"):
            _publish_anchor(
                self.anchor,
                expected_revision=4,
                expected_sha256=self.old_pin,
                authority_public_key_hex=self.authority,
                replacement_revision=5,
                replacement_sha256=self.new_pin,
                approved=True,
                _verify_before_replace=verify_once,
            )
        self.assertEqual(calls, 2)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_internal_publisher_rejects_negative_verification_result(self) -> None:
        for result in (False, 0, "verified"):
            with self.subTest(result=result):
                with self.assertRaisesRegex(ValueError, "callback rejected publication"):
                    self._publish(_verify_before_replace=lambda: result)
                self._assert_unchanged()
                self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_negative_verification_after_staging(self) -> None:
        calls = 0

        def verify_again() -> bool:
            nonlocal calls
            calls += 1
            return calls == 1

        with self.assertRaisesRegex(ValueError, "callback rejected publication"):
            self._publish(_verify_before_replace=verify_again)
        self.assertEqual(calls, 2)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_verification_error_after_staging(self) -> None:
        calls = 0

        def verify_again() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("Late signed-policy change")

        with self.assertRaisesRegex(ValueError, "Late signed-policy change"):
            self._publish(_verify_before_replace=verify_again)
        self.assertEqual(calls, 2)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_staged_path_replacement_after_final_verification(self) -> None:
        calls = 0
        staged_path: Path | None = None
        foreign_payload = b"substituted public anchor"
        detached = self.root / "old-stage"

        def replace_stage() -> None:
            nonlocal calls, staged_path
            calls += 1
            if calls == 2:
                (staged_path,) = list(self.root.glob(".trust-anchor-*.tmp"))
                staged_path.rename(detached)
                staged_path.write_bytes(foreign_payload)
                staged_path.chmod(0o600)

        try:
            with self.assertRaisesRegex(ValueError, "Staged trust anchor changed"):
                self._publish(_verify_before_replace=replace_stage)
            self.assertEqual(calls, 2)
            self._assert_unchanged()
            # Cleanup must preserve an unrelated file swapped into the
            # staging pathname, not unlink it to satisfy a stale assertion.
            self.assertIsNotNone(staged_path)
            self.assertEqual(staged_path.read_bytes(), foreign_payload)
            self.assertTrue(detached.exists())
        finally:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            detached.unlink(missing_ok=True)

    def test_rejects_staged_in_place_mutation_after_final_verification(self) -> None:
        calls = 0

        def mutate_stage() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                staged = next(self.root.glob(".trust-anchor-*.tmp"))
                staged.write_bytes(b"modified public anchor")

        with self.assertRaisesRegex(ValueError, "Staged trust anchor (changed|content changed)"):
            self._publish(_verify_before_replace=mutate_stage)
        self.assertEqual(calls, 2)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_staged_metadata_change_during_final_read(self) -> None:
        real_read = os.read
        calls = 0

        def mutate_after_read(fd: int, count: int) -> bytes:
            nonlocal calls
            data = real_read(fd, count)
            calls += 1
            staged = next(self.root.glob(".trust-anchor-*.tmp"))
            # The payload is still byte-for-byte correct, but its mode changes
            # after the pre-read metadata check.
            staged.chmod(0o400)
            return data

        with patch.object(os, "read", side_effect=mutate_after_read):
            with self.assertRaisesRegex(ValueError, "Staged trust anchor changed during final read"):
                self._publish()
        self.assertEqual(calls, 1)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_staged_path_swap_during_final_read(self) -> None:
        real_read = os.read
        detached = self.root / "detached-stage"
        staged_path: Path | None = None
        calls = 0
        foreign_payload: bytes | None = None

        def swap_after_read(fd: int, count: int) -> bytes:
            nonlocal calls, staged_path, foreign_payload
            data = real_read(fd, count)
            calls += 1
            (staged_path,) = list(self.root.glob(".trust-anchor-*.tmp"))
            staged_path.rename(detached)
            # Even a byte-identical replacement must not be published.
            foreign_payload = data
            staged_path.write_bytes(data)
            staged_path.chmod(0o600)
            return data

        try:
            with patch.object(os, "read", side_effect=swap_after_read):
                with self.assertRaisesRegex(ValueError, "Staged trust anchor changed during final read"):
                    self._publish()
            self.assertEqual(calls, 1)
            self._assert_unchanged()
            # The foreign replacement remains for administrator inspection.
            self.assertIsNotNone(staged_path)
            self.assertIsNotNone(foreign_payload)
            self.assertEqual(staged_path.read_bytes(), foreign_payload)
            self.assertTrue(detached.exists())
        finally:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            detached.unlink(missing_ok=True)

    def test_rejects_lock_change_during_final_staged_read(self) -> None:
        real_read = os.read
        calls = 0

        def mutate_lock_after_read(fd: int, count: int) -> bytes:
            nonlocal calls
            data = real_read(fd, count)
            calls += 1
            (self.root / "anchor.json.lock").chmod(0o400)
            return data

        with patch.object(os, "read", side_effect=mutate_lock_after_read):
            with self.assertRaisesRegex(ValueError, "Anchor lock changed before publication"):
                self._publish()
        self.assertEqual(calls, 1)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_old_anchor_change_during_final_staged_read(self) -> None:
        real_read = os.read
        calls = 0

        def mutate_anchor_after_read(fd: int, count: int) -> bytes:
            nonlocal calls
            data = real_read(fd, count)
            calls += 1
            # The JSON is unchanged, but the existing anchor's mode is not.
            self.anchor.chmod(0o400)
            return data

        with patch.object(os, "read", side_effect=mutate_anchor_after_read):
            with self.assertRaisesRegex(ValueError, "Trust anchor changed during final staged read"):
                self._publish()
        self.assertEqual(calls, 1)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_busy_publisher_lock_fails_closed_without_waiting(self) -> None:
        import fcntl

        lock_path = self.root / "anchor.json.lock"
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "Anchor publisher lock is busy"):
                self._publish()
            self._assert_unchanged()
            self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

        # A legitimate later attempt can proceed after the holder releases it.
        self.assertEqual(self._publish()["minimum_revision"], 5)

    def test_busy_lock_never_calls_publication_callback(self) -> None:
        import fcntl

        lock_path = self.root / "anchor.json.lock"
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch("scripts.publish_signer_trust_anchor._atomic_replace") as replace:
                with self.assertRaisesRegex(ValueError, "Anchor publisher lock is busy"):
                    self._publish()
                replace.assert_not_called()
            self._assert_unchanged()
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def test_rejects_stale_cas_after_successful_update(self) -> None:
        self._publish()
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._publish()
        self.assertEqual(json.loads(self.anchor.read_text())["minimum_revision"], 5)

    def test_rejects_truthy_nonboolean_approval_before_lock_or_verification(self) -> None:
        for invalid_approval in (1, "yes", [True], {"approved": True}):
            with self.subTest(approved=invalid_approval):
                with self.assertRaisesRegex(ValueError, "Explicit external administrator approval"):
                    self._publish(
                        approved=invalid_approval,
                        _verify_before_replace=lambda: self.fail("verification must not run"),
                    )
                self._assert_unchanged()
                self.assertFalse((self.root / "anchor.json.lock").exists())
                self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_public_publisher_rejects_truthy_nonboolean_approval(self) -> None:
        from scripts.publish_signer_trust_anchor import publish_verified

        for invalid_approval in (1, "yes", [True], {"approved": True}):
            with self.subTest(approved=invalid_approval):
                with self.assertRaisesRegex(ValueError, "Explicit external administrator approval"):
                    publish_verified(
                        self.anchor,
                        previous_policy_file=self.root / "previous.json",
                        replacement_policy_file=self.root / "replacement.json",
                        expected_revision=4,
                        expected_sha256=self.old_pin,
                        authority_public_key_hex=self.authority,
                        replacement_revision=5,
                        replacement_sha256=self.new_pin,
                        independent_revision_floor=4,
                        approved=invalid_approval,
                    )
                self._assert_unchanged()
                self.assertFalse((self.root / "anchor.json.lock").exists())

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

    def test_rejects_anchor_ancestor_identity_change_after_staging(self) -> None:
        outer = self.root / "changing-anchor-ancestor"
        inner = outer / "private"
        inner.mkdir(parents=True, mode=0o700)
        original = self.anchor
        moved = inner / original.name
        original.rename(moved)
        self.anchor = moved
        original_lstat = Path.lstat
        changed = False
        calls = 0

        def verify_then_switch() -> None:
            nonlocal changed, calls
            calls += 1
            if calls == 2:
                changed = True

        def substituted_ancestor(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            metadata = original_lstat(path, *args, **kwargs)
            if path == outer and changed:
                fields = list(metadata)
                fields[1] += 1
                return os.stat_result(fields)
            return metadata

        try:
            with patch.object(Path, "lstat", new=substituted_ancestor):
                with self.assertRaisesRegex(ValueError, "Anchor directory changed"):
                    self._publish(_verify_before_replace=verify_then_switch)
            self.assertEqual(calls, 2)
            self._assert_unchanged()
            self.assertEqual(list(inner.glob(".trust-anchor-*.tmp")), [])
        finally:
            (inner / "anchor.json.lock").unlink(missing_ok=True)
            moved.rename(original)
            self.anchor = original
            inner.rmdir()
            outer.rmdir()

    def test_rejects_writable_anchor_ancestor_before_lock(self) -> None:
        outer = self.root / "unsafe-ancestor"
        inner = outer / "private"
        inner.mkdir(parents=True, mode=0o700)
        original = self.anchor
        moved = inner / original.name
        original.rename(moved)
        self.anchor = moved
        outer.chmod(0o777)
        try:
            with self.assertRaisesRegex(ValueError, "Anchor ancestor directory"):
                self._publish()
            self._assert_unchanged()
            self.assertFalse((inner / "anchor.json.lock").exists())
        finally:
            outer.chmod(0o700)
            moved.rename(original)
            self.anchor = original
            inner.rmdir()
            outer.rmdir()

    def test_rejects_foreign_owned_anchor_ancestor_before_lock(self) -> None:
        outer = self.root / "foreign-ancestor"
        inner = outer / "private"
        inner.mkdir(parents=True, mode=0o700)
        original = self.anchor
        moved = inner / original.name
        original.rename(moved)
        self.anchor = moved
        original_lstat = Path.lstat

        def foreign_owner(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            metadata = original_lstat(path, *args, **kwargs)
            if path == outer:
                fields = list(metadata)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return metadata

        try:
            with patch.object(Path, "lstat", new=foreign_owner):
                with self.assertRaisesRegex(ValueError, "Anchor ancestor directory must be owned"):
                    self._publish()
            self._assert_unchanged()
            self.assertFalse((inner / "anchor.json.lock").exists())
        finally:
            moved.rename(original)
            self.anchor = original
            inner.rmdir()
            outer.rmdir()

    def test_rejects_symlink_directory_component(self) -> None:
        link = self.root / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            _publish_anchor(
                link / "anchor.json",
                expected_revision=4,
                expected_sha256=self.old_pin,
                authority_public_key_hex=self.authority,
                replacement_revision=5,
                replacement_sha256=self.new_pin,
                approved=True,
                _verify_before_replace=lambda: None,
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

    def test_rejects_byte_identical_anchor_swap_during_json_decoding(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor

        original_loads = json.loads
        moved = self.root / "anchor-before-decoding.json"
        swapped = False

        def swap_after_decode(*args: object, **kwargs: object) -> object:
            nonlocal swapped
            result = original_loads(*args, **kwargs)
            if not swapped:
                swapped = True
                self.anchor.rename(moved)
                self._write_anchor(self.original)
            return result

        with patch("scripts.publish_signer_trust_anchor.json.loads", side_effect=swap_after_decode):
            with self.assertRaisesRegex(ValueError, "changed during decoding"):
                _read_anchor(self.anchor)
        self.assertTrue(swapped)
        self.assertEqual(original_loads(moved.read_text()), self.original)
        self._assert_unchanged()

    def test_rejects_anchor_metadata_mutation_during_json_decoding(self) -> None:
        from scripts.publish_signer_trust_anchor import _read_anchor

        original_loads = json.loads
        changed = False

        def touch_after_decode(*args: object, **kwargs: object) -> object:
            nonlocal changed
            result = original_loads(*args, **kwargs)
            if not changed:
                changed = True
                metadata = self.anchor.stat()
                os.utime(
                    self.anchor,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                )
            return result

        with patch("scripts.publish_signer_trust_anchor.json.loads", side_effect=touch_after_decode):
            with self.assertRaisesRegex(ValueError, "changed during decoding"):
                _read_anchor(self.anchor)
        self.assertTrue(changed)
        self._assert_unchanged()

    def test_rejects_duplicate_json_fields(self) -> None:
        raw = self.anchor.read_text()
        self.anchor.write_text(raw.replace('"format":', '"format":"spoofed","format":'))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self._publish()

    def test_rejects_identical_anchor_inode_swap_after_policy_check(self) -> None:
        moved = self.root / "old-anchor.json"

        def replace_anchor() -> None:
            self.anchor.rename(moved)
            self._write_anchor(self.original)

        with self.assertRaisesRegex(ValueError, "Trust anchor changed before publication"):
            self._publish(_verify_before_replace=replace_anchor)
        self._assert_unchanged()
        self.assertEqual(json.loads(moved.read_text()), self.original)
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_anchor_metadata_change_during_staging(self) -> None:
        original_fsync = os.fsync
        changed = False

        def touch_during_file_sync(fd: int) -> None:
            nonlocal changed
            original_fsync(fd)
            if not changed:
                changed = True
                metadata = self.anchor.stat()
                os.utime(
                    self.anchor,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                )

        with patch("scripts.publish_signer_trust_anchor.os.fsync", side_effect=touch_during_file_sync):
            with self.assertRaisesRegex(ValueError, "Trust anchor changed before publication"):
                self._publish()
        self.assertTrue(changed)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

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

    def test_rejects_directory_symlink_swap_during_lock_acquisition(self) -> None:
        import fcntl

        moved = self.root.with_name(self.root.name + "-previous")
        original_flock = fcntl.flock

        def swap_after_lock(fd: int, operation: int) -> None:
            original_flock(fd, operation)
            if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB):
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

    def test_rejects_lock_replacement_during_staging_before_rename(self) -> None:
        lock_path = self.root / "anchor.json.lock"
        previous = self.root / "previous-staging-lock"
        original_fsync = os.fsync
        swapped = False

        def swap_after_staging(fd: int) -> None:
            nonlocal swapped
            original_fsync(fd)
            if not swapped:
                swapped = True
                lock_path.rename(previous)
                lock_path.write_text("replacement lock", encoding="utf-8")
                lock_path.chmod(0o600)

        with patch(
            "scripts.publish_signer_trust_anchor.os.fsync",
            side_effect=swap_after_staging,
        ):
            with self.assertRaisesRegex(ValueError, "Anchor lock changed before publication"):
                self._publish()
        self.assertTrue(swapped)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])
        self.assertTrue(previous.is_file())

    def test_rejects_lock_metadata_mutation_during_staging_before_rename(self) -> None:
        lock_path = self.root / "anchor.json.lock"
        original_fsync = os.fsync
        changed = False

        def touch_after_staging(fd: int) -> None:
            nonlocal changed
            original_fsync(fd)
            if not changed:
                changed = True
                metadata = lock_path.stat()
                os.utime(
                    lock_path,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                )

        with patch(
            "scripts.publish_signer_trust_anchor.os.fsync",
            side_effect=touch_after_staging,
        ):
            with self.assertRaisesRegex(ValueError, "Anchor lock changed before publication"):
                self._publish()
        self.assertTrue(changed)
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

    def test_rejects_lock_path_replacement_after_policy_verification(self) -> None:
        lock_path = self.root / "anchor.json.lock"
        previous = self.root / "previous-lock"

        def replace_lock() -> None:
            lock_path.rename(previous)
            lock_path.write_text("new lock inode", encoding="utf-8")
            lock_path.chmod(0o600)

        with self.assertRaisesRegex(ValueError, "Anchor lock changed before publication"):
            self._publish(_verify_before_replace=replace_lock)
        self._assert_unchanged()
        self.assertTrue(previous.is_file())
        self.assertEqual(json.loads(self.anchor.read_text())["minimum_revision"], 4)

    def test_rejects_lock_metadata_change_after_policy_verification(self) -> None:
        lock_path = self.root / "anchor.json.lock"

        def touch_lock() -> None:
            metadata = lock_path.stat()
            os.utime(
                lock_path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
            )

        with self.assertRaisesRegex(ValueError, "Anchor lock changed before publication"):
            self._publish(_verify_before_replace=touch_lock)
        self._assert_unchanged()

    def test_rejects_lock_path_replacement_while_acquiring(self) -> None:
        import fcntl

        lock_path = self.root / "anchor.json.lock"
        moved = self.root / "previous-lock"
        original_flock = fcntl.flock

        def replace_after_lock(fd: int, operation: int) -> None:
            original_flock(fd, operation)
            if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB):
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
            if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB):
                metadata = os.fstat(fd)
                os.utime(
                    lock_path,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                )

        with patch("fcntl.flock", side_effect=touch_after_lock):
            with self.assertRaisesRegex(ValueError, "Anchor lock changed"):
                self._publish()
        self._assert_unchanged()

    def test_rejects_fifo_lock_file_without_blocking(self) -> None:
        lock_path = self.root / "anchor.json.lock"
        os.mkfifo(lock_path, 0o600)
        with self.assertRaisesRegex(ValueError, "Anchor lock must be a private regular file"):
            self._publish()
        self._assert_unchanged()
        self.assertEqual(list(self.root.glob(".trust-anchor-*.tmp")), [])

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
