"""Keeps the audit tests hermetic against the live MySQL instance.

The audit log is append-only by design (`docs/SCOPE.md` D7 -- `seq` is never
reused, reordered or deleted in the *product*), which is exactly why the
*tests* need their own reset: without one, `seq` and the hash chain both
carry state from every previous test run, and assertions like "the corrupted
entry is `first_divergent_seq`" become a coin flip depending on what earlier
runs left behind. Truncating before each test is a test-harness concern, not
a violation of the append-only guarantee the product itself provides.
"""

from __future__ import annotations

import pytest

from app.db import execute, store_health


def _db_available() -> bool:
    try:
        return bool(store_health().get("mysql"))
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture(autouse=True)
def _reset_audit_tables():
    if _db_available():
        for table in ("verification_result", "anchor_receipt", "merkle_checkpoint", "audit_entry"):
            execute(f"DELETE FROM `{table}`")
        execute("ALTER TABLE audit_entry AUTO_INCREMENT = 1")
        execute("ALTER TABLE merkle_checkpoint AUTO_INCREMENT = 1")
        execute("ALTER TABLE anchor_receipt AUTO_INCREMENT = 1")
        execute("ALTER TABLE verification_result AUTO_INCREMENT = 1")
    yield
