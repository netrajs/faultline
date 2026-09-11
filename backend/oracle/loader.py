"""Load the attacker model out of the database into ``core.model`` types.

The rules are rows. Not constants in this file, not a dictionary keyed by rule
code, not a chain of ``if rule.code == "credential_dump"``. If the oracle
contained its own copy of what R7 requires, then comparing it against the fast
engine would compare two readings of the specification written by the same
process, and agreement would mean nothing.

Two row sources are provided and they must agree:

``MySQLRowSource``
    The real one. Reads ``capability_atom``, ``technique``, ``rule``,
    ``rule_precondition``, ``rule_effect``, ``threat_model`` and
    ``threat_model_grant`` from a live connection.

``SeedFileRowSource``
    Parses the same ``INSERT`` statements out of the seed files under
    ``backend/db/seed`` — ``rule_seed_files()`` finds the ones carrying model
    rows, and reading them in the order the migration runner applies them
    reproduces the rows it inserted. It exists so the oracle's test suite runs
    on a machine with no MySQL, and so CI can check the two sources produce an
    identical :class:`RuleSet` — which is a real check, because a seed file that
    has drifted from the applied schema is otherwise invisible.

Both feed the same row-to-model conversion below, so there is exactly one place
where a column becomes a meaning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

from core.model import (
    Binding,
    Effect,
    Precondition,
    PreconditionKind,
    Rule,
    Technique,
    ThreatModel,
)
from oracle.preconditions import PreconditionEvaluationError, validate_precondition

__all__ = [
    "CapabilityAtom",
    "MODEL_TABLES",
    "MySQLRowSource",
    "RowSource",
    "RuleDataError",
    "RuleSet",
    "SeedFileRowSource",
    "load_ruleset",
    "rule_seed_files",
    "SEED_DIR",
    "SEED_FILE",
]

SEED_DIR = Path(__file__).resolve().parents[1] / "db" / "seed"
SEED_FILE = SEED_DIR / "020_attacker_model.sql"

#: The tables the attacker model lives in.
#:
#: Longest names first: the pattern below anchors on the opening parenthesis of
#: the column list, so ``technique`` cannot match ``technique_baseline``, but
#: ordering the alternation by length keeps that from depending on it.
MODEL_TABLES: tuple[str, ...] = (
    "threat_model_grant",
    "rule_precondition",
    "capability_atom",
    "rule_effect",
    "threat_model",
    "technique",
    "rule",
)

_MODEL_INSERT = re.compile(
    r"INSERT\s+INTO\s+`?(?:" + "|".join(MODEL_TABLES) + r")`?\s*\(",
    re.IGNORECASE,
)


def rule_seed_files(directory: Path | str = SEED_DIR) -> tuple[Path, ...]:
    """Every seed file carrying attacker-model rows, in the order applied.

    Discovered rather than listed, because a list is a thing that goes stale.
    ``020_attacker_model.sql`` is where the model starts, but a fix to it is a
    new numbered file -- ``db.migrate`` refuses to re-apply a file whose
    checksum changed -- and a seed-file row source that reads only the first of
    them describes a database nobody has. That divergence is invisible: the
    rules still load, they are just the rules from before the fix.

    The migration runner applies the directory in lexical order and each of
    these files only inserts, so reading them in the same order reconstructs the
    same rows, ``AUTO_INCREMENT`` ids included.
    """
    return tuple(
        path
        for path in sorted(Path(directory).glob("*.sql"))
        if _MODEL_INSERT.search(path.read_text(encoding="utf-8"))
    )


class RuleDataError(RuntimeError):
    """The rule tables say something that cannot be interpreted."""


# ── Row sources ──────────────────────────────────────────────────────────────


class RowSource(Protocol):
    def fetch(self, table: str, columns: Sequence[str]) -> list[tuple[Any, ...]]:
        """Every row of *table*, projected onto *columns*, in any order."""


@dataclass(frozen=True)
class MySQLRowSource:
    """Rows straight out of MySQL via a DB-API connection (pymysql)."""

    connection: Any

    def fetch(self, table: str, columns: Sequence[str]) -> list[tuple[Any, ...]]:
        # Table and column names are supplied by this module, never by a caller
        # or by data, so interpolating them is not a parameterisation hole. The
        # identifier quoting is here to survive a column that collides with a
        # reserved word.
        select = ", ".join(f"`{c}`" for c in columns)
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT {select} FROM `{table}`")
            return [tuple(row) for row in cursor.fetchall()]


class SeedFileRowSource:
    """Rows parsed out of one or more seed ``.sql`` files.

    Only ``INSERT INTO <table> (<columns>) VALUES (...), (...)`` is understood,
    which is all the seed files use. ``AUTO_INCREMENT`` ids are reconstructed by
    insertion order, and ``(SELECT id FROM rule WHERE code='...')`` subqueries —
    which is how the seed refers to those ids — are resolved against that.

    Several files read as one source, in the order given, which is how a later
    seed file adding rows to an earlier one's tables is represented: the rows
    accumulate exactly as they do in the database, so the reconstructed ids
    match what ``AUTO_INCREMENT`` assigned there.
    """

    #: Tables whose primary key is a reconstructed AUTO_INCREMENT integer.
    _AUTO_INCREMENT = {"rule": "id"}

    def __init__(self, path: Path | str | Sequence[Path | str] = SEED_FILE) -> None:
        paths = [path] if isinstance(path, (str, Path)) else list(path)
        if not paths:
            raise RuleDataError("a seed row source needs at least one file to read")
        self.paths = tuple(Path(p) for p in paths)
        #: The first file, used to name the source in error messages.
        self.path = self.paths[0]
        self._tables: dict[str, list[dict[str, Any]]] = {}
        for seed in self.paths:
            self._parse_statements(seed.read_text(encoding="utf-8"), seed.name)
        self._resolve_subqueries()

    # -- parsing ------------------------------------------------------------

    _INSERT = re.compile(
        r"\AINSERT\s+INTO\s+`?(?P<table>\w+)`?\s*\((?P<columns>[^)]*)\)\s*VALUES\s*(?P<values>.*)\Z",
        re.IGNORECASE | re.DOTALL,
    )

    def _parse(self, sql: str) -> None:
        """Parse one file's worth of SQL and finish the source.

        Kept for subclasses that read a file the constructor cannot: see
        ``validation.world._SanitisedSeedSource``, which rewrites the text
        before it is parsed.
        """
        self._parse_statements(sql, self.path.name)
        self._resolve_subqueries()

    def _parse_statements(self, sql: str, label: str) -> None:
        for statement in _split_statements(sql):
            match = self._INSERT.match(statement.strip())
            if not match:
                continue
            table = match.group("table")
            columns = [c.strip().strip("`") for c in match.group("columns").split(",")]
            rows = self._tables.setdefault(table, [])
            auto_column = self._AUTO_INCREMENT.get(table)
            for tuple_text in _split_value_tuples(match.group("values")):
                values = [_parse_sql_literal(v) for v in _split_top_level(tuple_text)]
                if len(values) != len(columns):
                    raise RuleDataError(
                        f"{label}: INSERT INTO {table} has {len(columns)} columns "
                        f"but a row with {len(values)} values"
                    )
                row = dict(zip(columns, values, strict=True))
                if auto_column and auto_column not in row:
                    row[auto_column] = len(rows) + 1
                rows.append(row)

    def _resolve_subqueries(self) -> None:
        rule_ids = {row["code"]: row["id"] for row in self._tables.get("rule", [])}
        for rows in self._tables.values():
            for row in rows:
                for key, value in list(row.items()):
                    if isinstance(value, _Subquery):
                        row[key] = value.resolve(rule_ids)

    # -- RowSource ----------------------------------------------------------

    @property
    def label(self) -> str:
        return ", ".join(p.name for p in self.paths)

    def fetch(self, table: str, columns: Sequence[str]) -> list[tuple[Any, ...]]:
        rows = self._tables.get(table)
        if rows is None:
            raise RuleDataError(f"{self.label} contains no INSERT into {table!r}")
        out = []
        for row in rows:
            missing = [c for c in columns if c not in row]
            if missing:
                raise RuleDataError(
                    f"{self.label}: INSERT INTO {table} does not set {missing}"
                )
            out.append(tuple(row[c] for c in columns))
        return out


@dataclass(frozen=True)
class _Subquery:
    text: str

    _CODE = re.compile(r"code\s*=\s*'((?:[^']|'')*)'", re.IGNORECASE)

    def resolve(self, rule_ids: Mapping[str, int]) -> int:
        match = self._CODE.search(self.text)
        if not match:
            raise RuleDataError(f"cannot resolve subquery {self.text!r}")
        code = match.group(1).replace("''", "'")
        try:
            return rule_ids[code]
        except KeyError:
            raise RuleDataError(f"subquery refers to unknown rule code {code!r}") from None


def _split_statements(sql: str) -> list[str]:
    """Split a SQL file on top-level semicolons.

    Reuses the migration runner's splitter so the oracle reads the seed exactly
    as the migration runner does — including its handling of the semicolons that
    appear inside seeded prose.
    """
    from db.migrate import split_statements  # imported here to keep import cost local

    return split_statements(sql)


def _split_value_tuples(text: str) -> list[str]:
    """Yield the inside of each top-level ``( ... )`` group in a VALUES clause."""
    groups: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char in " \t\r\n,":
            i += 1
            continue
        if char != "(":
            raise RuleDataError(f"unexpected {char!r} in VALUES clause at offset {i}")
        depth = 0
        start = i + 1
        quote = False
        while i < length:
            c = text[i]
            if quote:
                if c == "\\":
                    i += 2
                    continue
                if c == "'":
                    if i + 1 < length and text[i + 1] == "'":
                        i += 2
                        continue
                    quote = False
                i += 1
                continue
            if c == "'":
                quote = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    groups.append(text[start:i])
                    i += 1
                    break
            i += 1
        else:
            raise RuleDataError("unterminated ( in VALUES clause")
    return groups


def _split_top_level(text: str) -> list[str]:
    """Split one value tuple on commas that are not inside quotes or parentheses."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote = False
    i = 0
    length = len(text)
    while i < length:
        c = text[i]
        if quote:
            current.append(c)
            if c == "\\":
                if i + 1 < length:
                    current.append(text[i + 1])
                    i += 2
                    continue
            elif c == "'":
                if i + 1 < length and text[i + 1] == "'":
                    current.append("'")
                    i += 2
                    continue
                quote = False
            i += 1
            continue
        if c == "'":
            quote = True
            current.append(c)
        elif c == "(":
            depth += 1
            current.append(c)
        elif c == ")":
            depth -= 1
            current.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(c)
        i += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"'}


def _parse_sql_literal(token: str) -> Any:
    token = token.strip()
    if not token:
        raise RuleDataError("empty value in VALUES clause")
    if token.upper() == "NULL":
        return None
    if token.upper() == "TRUE":
        return 1
    if token.upper() == "FALSE":
        return 0
    if token.startswith("("):
        return _Subquery(token)
    if token.startswith("'"):
        if not token.endswith("'") or len(token) < 2:
            raise RuleDataError(f"malformed string literal {token!r}")
        body = token[1:-1]
        out: list[str] = []
        i = 0
        while i < len(body):
            c = body[i]
            if c == "\\" and i + 1 < len(body):
                out.append(_ESCAPES.get(body[i + 1], body[i + 1]))
                i += 2
                continue
            if c == "'" and i + 1 < len(body) and body[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            out.append(c)
            i += 1
        return "".join(out)
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        raise RuleDataError(f"cannot parse SQL literal {token!r}") from None


# ── The loaded model ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CapabilityAtom:
    code: str
    label: str
    description: str
    binding_kind: str
    """'node' or 'global'."""

    @property
    def is_global(self) -> bool:
        return self.binding_kind == "global"


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Everything the oracle needs to decide what an attacker can do."""

    rules: tuple[Rule, ...]
    atoms: Mapping[str, CapabilityAtom]
    techniques: Mapping[str, Technique]
    threat_models: Mapping[str, ThreatModel]
    default_threat_model_code: str | None = None
    """The code of the row flagged ``is_default``, if exactly one row is."""

    @property
    def global_capability_codes(self) -> frozenset[str]:
        return frozenset(a.code for a in self.atoms.values() if a.is_global)

    def rule(self, code: str) -> Rule:
        for r in self.rules:
            if r.code == code:
                return r
        raise KeyError(code)

    def by_id(self, rule_id: int) -> Rule:
        for r in self.rules:
            if r.rule_id == rule_id:
                return r
        raise KeyError(rule_id)

    def default_threat_model(self) -> ThreatModel:
        """The threat model an analysis uses when the caller names none.

        ``threat_model.is_default`` decides it. Falling back to the first code
        alphabetically would silently analyse ``contractor_device`` wherever a
        caller meant ``external_phish``, and the two do not have the same
        answer.
        """
        if not self.threat_models:
            raise RuleDataError("no threat models loaded")
        if self.default_threat_model_code is not None:
            return self.threat_models[self.default_threat_model_code]
        raise RuleDataError("no threat model is flagged as the default")


def _json_value(raw: Any) -> Any:
    """``value_json`` arrives as a JSON document, or as text holding one."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # A bare word that is not valid JSON is data corruption, not a
            # string the author meant literally: 'admin' would have been seeded
            # as '"admin"'. Fail loudly.
            raise RuleDataError(f"value_json is not valid JSON: {raw!r}") from None
    return raw


def load_ruleset(source: RowSource, *, include_disabled: bool = False) -> RuleSet:
    """Read the attacker model and validate it before anything depends on it."""
    atoms = {
        code: CapabilityAtom(code, label, description, binding_kind)
        for code, label, description, binding_kind in source.fetch(
            "capability_atom", ("code", "label", "description", "binding_kind")
        )
    }
    for atom in atoms.values():
        if atom.binding_kind not in ("node", "global"):
            raise RuleDataError(
                f"capability_atom {atom.code!r} has binding_kind {atom.binding_kind!r}"
            )

    techniques = {
        code: Technique(code, name, description, attack_id, attack_name, attack_url, phase)
        for code, name, description, attack_id, attack_name, attack_url, phase in source.fetch(
            "technique",
            ("code", "name", "description", "attack_id", "attack_name", "attack_url", "phase"),
        )
    }

    preconditions: dict[int, list[Precondition]] = {}
    for (
        rule_id,
        seq,
        kind,
        binding,
        capability_code,
        attr_path,
        operator,
        value_json,
        is_negated,
        failure_reason,
    ) in source.fetch(
        "rule_precondition",
        (
            "rule_id",
            "seq",
            "kind",
            "binding",
            "capability_code",
            "attr_path",
            "operator",
            "value_json",
            "is_negated",
            "failure_reason",
        ),
    ):
        if not str(failure_reason).strip():
            raise RuleDataError(f"rule {rule_id} seq {seq} has an empty failure_reason")
        precondition = Precondition(
            seq=int(seq),
            kind=PreconditionKind(kind),
            binding=Binding(binding),
            capability_code=capability_code,
            attr_path=attr_path,
            operator=operator,
            value=_json_value(value_json),
            is_negated=bool(is_negated),
            failure_reason=str(failure_reason),
        )
        try:
            validate_precondition(precondition)
        except PreconditionEvaluationError as exc:
            raise RuleDataError(f"rule {rule_id}: {exc}") from exc
        if precondition.capability_code and precondition.capability_code not in atoms:
            raise RuleDataError(
                f"rule {rule_id} seq {seq} names unknown capability "
                f"{precondition.capability_code!r}"
            )
        preconditions.setdefault(int(rule_id), []).append(precondition)

    effects: dict[int, list[Effect]] = {}
    for rule_id, seq, capability_code, binding in source.fetch(
        "rule_effect", ("rule_id", "seq", "capability_code", "binding")
    ):
        if capability_code not in atoms:
            raise RuleDataError(
                f"rule {rule_id} effect {seq} names unknown capability {capability_code!r}"
            )
        effects.setdefault(int(rule_id), []).append(
            Effect(seq=int(seq), capability_code=capability_code, binding=Binding(binding))
        )

    rules: list[Rule] = []
    for rule_id, code, technique_code, edge_type_code, description, is_traversal, is_enabled in (
        source.fetch(
            "rule",
            (
                "id",
                "code",
                "technique_code",
                "edge_type_code",
                "description",
                "is_traversal",
                "is_enabled",
            ),
        )
    ):
        if not include_disabled and not bool(is_enabled):
            continue
        rule_id = int(rule_id)
        traversal = bool(is_traversal)
        if traversal and not edge_type_code:
            raise RuleDataError(f"rule {code!r} is a traversal but names no edge type")
        if not traversal and edge_type_code:
            raise RuleDataError(
                f"rule {code!r} is not a traversal but names edge type {edge_type_code!r}"
            )
        if technique_code not in techniques:
            raise RuleDataError(f"rule {code!r} names unknown technique {technique_code!r}")

        rule_preconditions = tuple(sorted(preconditions.get(rule_id, ()), key=lambda p: p.seq))
        rule_effects = tuple(sorted(effects.get(rule_id, ()), key=lambda e: e.seq))
        if not rule_effects:
            raise RuleDataError(f"rule {code!r} has no effects; it could never do anything")

        if not traversal:
            for precondition in rule_preconditions:
                if precondition.kind == PreconditionKind.EDGE_ATTR:
                    raise RuleDataError(
                        f"rule {code!r} consumes no edge but its precondition "
                        f"seq {precondition.seq} reads an edge attribute"
                    )
        for effect in rule_effects:
            if not atoms[effect.capability_code].is_global and effect.binding == Binding.GLOBAL:
                raise RuleDataError(
                    f"rule {code!r} effect {effect.seq} grants node-scoped "
                    f"{effect.capability_code!r} with binding 'global'"
                )

        rules.append(
            Rule(
                rule_id=rule_id,
                code=code,
                technique_code=technique_code,
                edge_type=edge_type_code,
                description=description,
                is_traversal=traversal,
                preconditions=rule_preconditions,
                effects=rule_effects,
            )
        )

    rules.sort(key=lambda r: r.rule_id)

    grants: dict[str, list[tuple[int, str, str | None, str | None]]] = {}
    for model_code, seq, capability_code, applies_to_kind, applies_to_node in source.fetch(
        "threat_model_grant",
        ("threat_model_code", "seq", "capability_code", "applies_to_kind", "applies_to_node"),
    ):
        if capability_code not in atoms:
            raise RuleDataError(
                f"threat model {model_code!r} grants unknown capability {capability_code!r}"
            )
        atom = atoms[capability_code]
        if not atom.is_global and not applies_to_kind and not applies_to_node:
            raise RuleDataError(
                f"threat model {model_code!r} grants node-scoped {capability_code!r} "
                f"without naming a node kind or node"
            )
        grants.setdefault(model_code, []).append(
            (int(seq), capability_code, applies_to_kind, applies_to_node)
        )

    threat_models = {}
    default_codes: list[str] = []
    for code, label, description, is_default in source.fetch(
        "threat_model", ("code", "label", "description", "is_default")
    ):
        ordered = sorted(grants.get(code, ()), key=lambda g: g[0])
        threat_models[code] = ThreatModel(
            code=code,
            label=label,
            description=description,
            grants=tuple((c, k, n) for _, c, k, n in ordered),
        )
        if bool(is_default):
            default_codes.append(code)
    if len(default_codes) > 1:
        raise RuleDataError(
            f"more than one threat model is flagged as the default: {sorted(default_codes)}"
        )

    return RuleSet(
        rules=tuple(rules),
        atoms=atoms,
        techniques=techniques,
        threat_models=threat_models,
        default_threat_model_code=default_codes[0] if default_codes else None,
    )


def load_from_mysql(connection: Any, **kwargs: Any) -> RuleSet:
    return load_ruleset(MySQLRowSource(connection), **kwargs)


def load_from_seed_file(path: Path | str = SEED_FILE, **kwargs: Any) -> RuleSet:
    """The model as one seed file states it. Defaults to the original fifteen rules.

    Deliberately not the whole seed directory: a caller asking about one file is
    asking about one file. :func:`load_from_seed_files` is the one that matches
    a migrated database.
    """
    return load_ruleset(SeedFileRowSource(path), **kwargs)


def load_from_seed_files(
    paths: Sequence[Path | str] | None = None, **kwargs: Any
) -> RuleSet:
    """The model as the whole seed directory states it, which is what MySQL holds."""
    return load_ruleset(
        SeedFileRowSource(paths if paths is not None else rule_seed_files()), **kwargs
    )


def describe(ruleset: RuleSet) -> str:
    """A readable dump of what was loaded. Used by the notes and by test output."""
    lines: list[str] = []
    for rule in ruleset.rules:
        edge = rule.edge_type or "<no edge>"
        lines.append(f"[{rule.rule_id:>2}] {rule.code}  ({edge}, {rule.technique_code})")
        for precondition in rule.preconditions:
            if precondition.kind == PreconditionKind.CAPABILITY:
                body = f"{precondition.binding.value}:{precondition.capability_code}"
            else:
                body = (
                    f"{precondition.binding.value}.{precondition.attr_path} "
                    f"{precondition.operator} {precondition.value!r}"
                )
            negated = " NOT" if precondition.is_negated else ""
            lines.append(f"       pre {precondition.seq}:{negated} {precondition.kind.value} {body}")
        for effect in rule.effects:
            lines.append(
                f"       eff {effect.seq}: {effect.capability_code}({effect.binding.value})"
            )
    return "\n".join(lines)


def _unused(*args: Iterable[Any]) -> None:  # pragma: no cover
    """Placeholder kept out of the public surface."""
