# Local setup

Everything runs locally. No Docker required.

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | Verified on 3.14. |
| MySQL 8.0+ | The service must be running. MySQL 5.x will not work — the schema uses `CHECK` constraints, generated columns and `utf8mb4_0900_ai_ci`. |
| Java 17 JRE | Only needed to run Neo4j. A JRE is sufficient; a full JDK is not required. |
| Node 20+ | Frontend only. |

If `mysql --version` reports 5.x, an old client is ahead of the 8.x one on your
`PATH`. That only affects the CLI — the Python driver connects to the server on
port 3306 regardless, so it is safe to ignore.

## 1. Python dependencies

```bash
python -m pip install -r backend/requirements.txt
```

## 2. Configuration

```bash
cp backend/.env.example backend/.env
```

Fill in `MYSQL_PASSWORD` and `NEO4J_PASSWORD`. `.env` is gitignored and must stay
that way — never commit real credentials.

`ANTHROPIC_API_KEY` is optional. Without it, path narration falls back to an
offline template renderer, which is also what the demo uses so it cannot fail on
conference wifi.

## 3. Neo4j

Neo4j is not installed as a Windows service. Download Community 5.26 once,
extract it outside the repository, and run it in console mode.

```bash
mkdir -p ~/.faultline-tools && cd ~/.faultline-tools
curl -sSL -o neo4j.zip https://dist.neo4j.org/neo4j-community-5.26.0-windows.zip
python -c "import zipfile; zipfile.ZipFile('neo4j.zip').extractall('.')"
```

Set the initial password **before first start** — Neo4j ignores the command
afterwards:

```bash
JAVA_HOME="/c/Program Files/OpenLogic/jre-17.0.10.7-hotspot" \
  ~/.faultline-tools/neo4j-community-5.26.0/bin/neo4j-admin.bat dbms set-initial-password faultline-dev
```

Adjust `JAVA_HOME` to your JRE. Then start it (leave this running):

```bash
JAVA_HOME="/c/Program Files/OpenLogic/jre-17.0.10.7-hotspot" \
  ~/.faultline-tools/neo4j-community-5.26.0/bin/neo4j.bat console
```

Browser interface at http://localhost:7474, Bolt on port 7687.

## 4. Create the schema

MySQL — creates the database if absent and applies every migration in order:

```bash
cd backend && python -m db.migrate
```

Neo4j — constraints and indexes, idempotent:

```bash
cd backend && python -m db.neo4j_schema
```

Expected: 62 MySQL tables, 9 Neo4j constraints, 14 Neo4j indexes.

## Migration notes

```bash
python -m db.migrate --status    # what is applied and what is pending
python -m db.migrate --reset     # drop the database and rebuild from scratch
```

Migrations are immutable once applied. Each is recorded with a SHA-256 of its
contents, and editing an applied file is a hard error rather than silent drift.
During development, `--reset` is the intended way to iterate.

MySQL commits implicitly around each DDL statement, so a migration that fails
partway leaves the statements before the failure in place. The runner names the
failing statement and does not record the migration; recover with `--reset`.

## Troubleshooting

**`Access denied for user 'root'@'localhost'`** — the password in `backend/.env`
does not match the server. Nothing else reads it, so a typo here is the usual
cause.

**Neo4j `ServiceUnavailable`** — the console process is not running, or is still
starting. First start takes 20–30 seconds. Check `startup.log` in the Neo4j
directory.

**Neo4j authentication fails with the password you set** — `set-initial-password`
only takes effect before the database has ever started. Stop Neo4j, delete
`data/dbms/auth` in the Neo4j directory, set the password again, and restart.
