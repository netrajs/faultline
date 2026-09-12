"""The reference oracle.

A deliberately slow, deliberately obvious implementation of the attacker model
in ``docs/RULES.md``. It exists so that the fast engine has something
independent to disagree with: both read the same rule rows from MySQL, neither
reads the other's source, and a divergence on a small graph means one of them
has misread the specification.

Nothing in here is optimised. There is no dominance pruning, no probability
cutoff, no memoisation of visited states across branches, and no deduplication
of results. Those are exactly the places a subtle bug hides, and an oracle that
shares the engine's pruning shares the engine's mistakes.
"""

from oracle.loader import (
    CapabilityAtom,
    MySQLRowSource,
    RuleDataError,
    RuleSet,
    SeedFileRowSource,
    load_from_seed_file,
    load_from_seed_files,
    load_ruleset,
    rule_seed_files,
)
from oracle.preconditions import (
    MISSING,
    PreconditionOutcome,
    describe_capability,
    evaluate_precondition,
    resolve_capability,
)
from oracle.search import (
    DEFAULT_MAX_HOPS,
    OracleBudgetExceeded,
    OracleConfig,
    OracleResult,
    canonical_path_key,
    discover,
    entry_nodes_for,
    materialise_grants,
    verify_path,
)

__all__ = [
    "CapabilityAtom",
    "DEFAULT_MAX_HOPS",
    "MISSING",
    "MySQLRowSource",
    "OracleBudgetExceeded",
    "OracleConfig",
    "OracleResult",
    "PreconditionOutcome",
    "RuleDataError",
    "RuleSet",
    "SeedFileRowSource",
    "canonical_path_key",
    "describe_capability",
    "discover",
    "entry_nodes_for",
    "evaluate_precondition",
    "load_from_seed_file",
    "load_from_seed_files",
    "load_ruleset",
    "materialise_grants",
    "resolve_capability",
    "rule_seed_files",
    "verify_path",
]
