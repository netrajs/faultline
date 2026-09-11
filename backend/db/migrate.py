"""Apply SQL migrations in order, exactly once each.

Migrations are plain SQL files named ``NNN_description.sql`` and applied in
lexical order. Each is recorded in ``schema_migration`` with a SHA-256 of its
contents, and a file whose checksum no longer matches what was applied is a hard
error rather than a silent divergence -- the schema is part of the correctness
argument, so drift is not something to discover later.

Plain SQL rather than an ORM migration tool is deliberate. Every table in this
project is meant to be readable by someone auditing how a risk number was
produced, and generated DDL is harder to review than DDL somebody wrote.

Usage::

    python -m db.migrate            apply pending migrations
    python -m db.migrate --status   show what is applied and what is pending
    python -m db.migrate --reset    drop and recreate the database, then apply all
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pymysql

from app.core.settings import load_settings

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
SEED_DIR = Path(__file__).parent / "seed"

_LINE_COMMENT = re.compile(r"^\s*--.*$", re.MULTILINE)


@dataclass(frozen=True)
class Migration:
    version: str
    path: Path
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def discover(directory: Path) -> list[Migration]:
    """Return every ``.sql`` file in *directory*, ordered by filename."""
    found = []
    for path in sorted(directory.glob("*.sql")):
        found.append(
            Migration(
                version=path.stem,
                path=path,
                sql=path.read_text(encoding="utf-8"),
            )
        )
    return found


def split_statements(sql: str) -> list[str]:
    """Split a migration file into individual statements.

    Line comments are stripped first so that a semicolon inside a comment cannot
    split a statement in half. The DDL in this project contains no string
    literals with embedded semicolons, which keeps this honest and simple.
    """
    without_comments = _LINE_COMMENT.sub("", sql)
    return [s.strip() for s in without_comments.split(";") if s.strip()]


def connect(settings, *, with_database: bool = True):
    return pymysql.connect(
        host=settings.mysql_host,
        port=settings.mysql_port,
        user=settings.mysql_user,
        password=settings.mysql_password,
        database=settings.mysql_database if with_database else None,
        charset="utf8mb4",
        autocommit=False,
    )


def ensure_database(settings) -> None:
    conn = connect(settings, with_database=False)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{settings.mysql_database}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
            )
        conn.commit()
    finally:
        conn.close()


def drop_database(settings) -> None:
    conn = connect(settings, with_database=False)
    try:
        with conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS `{settings.mysql_database}`")
        conn.commit()
    finally:
        conn.close()


def applied_migrations(conn) -> dict[str, str]:
    """Map of version -> checksum for migrations already applied."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = 'schema_migration'"
        )
        if cur.fetchone()[0] == 0:
            return {}
        cur.execute("SELECT version, checksum FROM schema_migration")
        return {version: checksum for version, checksum in cur.fetchall()}


def apply(conn, migration: Migration) -> None:
    statements = split_statements(migration.sql)
    with conn.cursor() as cur:
        for statement in statements:
            try:
                cur.execute(statement)
            except Exception as exc:  # noqa: BLE001 - re-raised with context
                head = " ".join(statement.split())[:120]
                raise RuntimeError(
                    f"{migration.version}: statement failed -- {head}\n  {exc}"
                ) from exc
        cur.execute(
            "INSERT INTO schema_migration (version, checksum, applied_at) VALUES (%s, %s, %s)",
            (migration.version, migration.checksum, datetime.now(timezone.utc)),
        )
    conn.commit()


def run(*, reset: bool = False, status_only: bool = False, include_seed: bool = True) -> int:
    settings = load_settings()

    if reset:
        drop_database(settings)
    ensure_database(settings)

    pending_sets = [discover(MIGRATIONS_DIR)]
    if include_seed:
        pending_sets.append(discover(SEED_DIR))

    conn = connect(settings)
    try:
        already = applied_migrations(conn)

        if status_only:
            for group in pending_sets:
                for migration in group:
                    mark = "applied" if migration.version in already else "pending"
                    print(f"  [{mark:>7}] {migration.version}")
            return 0

        applied_count = 0
        for group in pending_sets:
            for migration in group:
                recorded = already.get(migration.version)
                if recorded is not None:
                    if recorded != migration.checksum:
                        print(
                            f"error: {migration.version} was applied with a different "
                            f"checksum.\n  Migrations are immutable once applied -- add a "
                            f"new one instead, or use --reset in development.",
                            file=sys.stderr,
                        )
                        return 1
                    continue
                print(f"  applying {migration.version}")
                apply(conn, migration)
                applied_count += 1

        print(f"done: {applied_count} applied, {len(already)} already present")
        return 0
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply faultline database migrations.")
    parser.add_argument("--reset", action="store_true", help="drop and recreate the database first")
    parser.add_argument("--status", action="store_true", help="list applied and pending migrations")
    parser.add_argument("--no-seed", action="store_true", help="skip the seed data files")
    args = parser.parse_args()
    return run(reset=args.reset, status_only=args.status, include_seed=not args.no_seed)


if __name__ == "__main__":
    raise SystemExit(main())
