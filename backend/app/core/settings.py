"""Runtime configuration, read from the environment.

Nothing here carries a default the application would silently run on. A missing
database setting raises rather than falling back to a guess, because a demo that
quietly connects to the wrong database is worse than one that refuses to start.

The one exception is the anchoring mode, which defaults to ``replay`` -- the mode
that needs no network -- so that a fresh checkout runs offline.

faultline uses two stores, and the split is deliberate:

  Neo4j   the identity/asset graph itself, and the ad-hoc exploration surface.
          Storing a graph as a graph keeps the fact model honest and gives the
          Graph Explorer real Cypher. It does NOT run path discovery -- see
          ``docs/SCOPE.md`` D1 for why no query language can.

  MySQL   rules, scoring configuration, analysis results, remediation state and
          the audit ledger. An append-only ledger wants strict sequencing and
          ACID guarantees, and tabular configuration wants a tabular store.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_ENV_FILE = _BACKEND_ROOT / ".env"


class ConfigError(RuntimeError):
    """Raised when required configuration is absent or malformed."""


def _load_env_file(path: Path) -> None:
    """Populate os.environ from a dotenv file, without overriding real env vars.

    Real environment variables win, so a container or CI run can override the
    developer's local file without editing it.
    """
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _required(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise ConfigError(
            f"{key} is not set. Copy backend/.env.example to backend/.env and fill it in."
        )
    return value


def _optional(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


@dataclass(frozen=True)
class Settings:
    mysql_host: str
    mysql_port: int
    mysql_user: str
    mysql_password: str
    mysql_database: str
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_database: str
    anthropic_api_key: str
    anchor_mode: str
    anchor_rpc_url: str
    anchor_contract_address: str

    @property
    def sqlalchemy_url(self) -> str:
        return (
            f"mysql+pymysql://{quote_plus(self.mysql_user)}:{quote_plus(self.mysql_password)}"
            f"@{self.mysql_host}:{self.mysql_port}/{self.mysql_database}?charset=utf8mb4"
        )

    @property
    def narration_available(self) -> bool:
        """Whether live narration is possible, or the offline renderer is used."""
        return bool(self.anthropic_api_key)


@lru_cache(maxsize=1)
def load_settings() -> Settings:
    _load_env_file(_ENV_FILE)

    port_raw = _optional("MYSQL_PORT", "3306")
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ConfigError(f"MYSQL_PORT must be an integer, got {port_raw!r}") from exc

    anchor_mode = _optional("ANCHOR_MODE", "replay").lower()
    valid_modes = {"anvil", "base-sepolia", "replay"}
    if anchor_mode not in valid_modes:
        raise ConfigError(
            f"ANCHOR_MODE must be one of {sorted(valid_modes)}, got {anchor_mode!r}"
        )

    return Settings(
        mysql_host=_required("MYSQL_HOST"),
        mysql_port=port,
        mysql_user=_required("MYSQL_USER"),
        mysql_password=os.environ.get("MYSQL_PASSWORD", ""),
        mysql_database=_required("MYSQL_DATABASE"),
        neo4j_uri=_required("NEO4J_URI"),
        neo4j_user=_required("NEO4J_USER"),
        neo4j_password=os.environ.get("NEO4J_PASSWORD", ""),
        neo4j_database=_optional("NEO4J_DATABASE", "neo4j"),
        anthropic_api_key=_optional("ANTHROPIC_API_KEY"),
        anchor_mode=anchor_mode,
        anchor_rpc_url=_optional("ANCHOR_RPC_URL"),
        anchor_contract_address=_optional("ANCHOR_CONTRACT_ADDRESS"),
    )
