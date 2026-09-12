"""The differential harness, actually run.

``backend/validation/differential.py`` compares the fast engine against the
reference oracle over the hand-built worlds in ``backend/validation/world.py``.
This is its entry point: ``docs/RULES.md`` §7 invariant 8 -- "the engine and the
reference oracle return identical path sets on any graph small enough for the
oracle to finish" -- is the only invariant that cannot be checked by looking at
one implementation, and until something runs the comparison it is a claim rather
than a result.

The two directions are asserted separately because they are different claims.
*Engine ⊆ reference* is soundness: nothing the engine reported was invented, and
it is checked against the oracle's raw output with no filter. *Reference ⊆
engine* is completeness, checked against the subset of reference paths the
engine is expected to report -- the oracle prunes nothing, so it enumerates side
excursions and reachability-only arrivals the engine declines on purpose.

Two failure modes of a harness like this are worth naming, because both would
report success. It can compare nothing, so agreement over an empty set is
asserted against explicitly. And it can be incapable of failing, so a case with
a deliberately crippled engine is run and required to disagree.

Rules come from the seed files rather than MySQL, so this runs with no store up.
A separate case re-runs the comparison against the database when one answers,
which is what catches a seed file that has drifted from the applied rows.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Sequence

import pytest

from core.model import GraphSnapshot
from oracle.loader import MySQLRowSource, RowSource, load_ruleset
from validation.differential import (
    CaseReport,
    DifferentialReport,
    bounded_subgraph,
    comparison_key,
    run_report,
    run_snapshot_case,
)
from validation.world import WORLDS, ModelSource, load_model
from validation.world import _engine_ruleset as engine_ruleset_from_rows
from validation.world import edge, node, snapshot


@pytest.fixture(scope="module")
def model() -> ModelSource:
    """The attacker model from the seed files, so no store has to be running."""
    return load_model(prefer_database=False)


@pytest.fixture(scope="module")
def report(model: ModelSource) -> DifferentialReport:
    return run_report(model=model)


def summarise(report: DifferentialReport) -> str:
    """The whole comparison as a table, for a failure message to carry."""
    lines = [
        f"model from {report.model_origin}: {report.model_detail}",
        f"{report.cases_agreeing}/{len(report.cases)} cases agree, "
        f"{report.agreed_total}/{report.comparable_total} paths, "
        f"{report.disagreement_count} disagreements, {report.duration_ms} ms",
        f"{'case':<20} {'engine':>7} {'ref':>7} {'compar':>7} {'agreed':>7} "
        f"{'eng only':>9} {'ref only':>9}",
    ]
    for case in report.cases:
        lines.append(
            f"{case.code:<20} {case.engine_path_count:>7} {case.reference_path_count:>7} "
            f"{case.reference_comparable_count:>7} {case.agreed_count:>7} "
            f"{len(case.engine_only):>9} {len(case.reference_only):>9}"
            + (f"  ERROR {case.error}" if case.error else "")
        )
    for case in report.cases:
        for disagreement in case.engine_only + case.reference_only:
            lines.append(
                f"  {case.code}: found only by the {disagreement.found_by}, "
                f"reaching {disagreement.target_node_id}"
            )
            lines.extend(f"      {step}" for step in disagreement.steps)
    return "\n".join(lines)


# ── The comparison itself ────────────────────────────────────────────────────


def test_every_world_was_actually_compared(report: DifferentialReport) -> None:
    """No case failed to run, and none of them compared nothing.

    The first thing to rule out. A harness whose cases all errored, or whose
    graphs yielded no paths, reports perfect agreement -- over nothing -- and
    that is the most misleading number this module could produce.
    """
    assert len(report.cases) == len(WORLDS)
    for case in report.cases:
        assert case.error is None, f"{case.code}: {case.error}\n{summarise(report)}"
        assert case.comparable_total > 0, (
            f"{case.code} compared no paths at all, so it demonstrates nothing\n"
            f"{summarise(report)}"
        )
        assert not case.engine_truncated, f"{case.code}: the engine hit its k-best allowance"


def test_the_engine_invents_nothing(report: DifferentialReport) -> None:
    """Soundness: every engine path was found by the unpruned enumeration too.

    The load-bearing direction, and the one checked against the oracle's raw
    output with no filter applied. A path here that the reference never
    enumerated is the engine reporting an attack the rules do not permit.
    """
    invented = {c.code: c.engine_only for c in report.cases if c.engine_only}
    assert not invented, (
        f"the engine reported paths the exhaustive reference did not find:\n"
        f"{summarise(report)}"
    )


def test_the_engine_misses_nothing(report: DifferentialReport) -> None:
    """Completeness: every reference path the engine should report, it reported.

    Checked against the comparable subset, since the oracle enumerates paths the
    engine declines on purpose -- a hop that contributed nothing to the arrival,
    or a last hop that granted only reachability, which R15 is explicit is not
    the same as reaching anything.
    """
    missed = {c.code: c.reference_only for c in report.cases if c.reference_only}
    assert not missed, (
        f"the reference found paths the engine did not report:\n{summarise(report)}"
    )


def test_the_two_implementations_agree_completely(report: DifferentialReport) -> None:
    assert report.agreement_rate == 1.0, summarise(report)
    assert report.cases_agreeing == len(report.cases), summarise(report)


def test_the_reference_enumerated_more_than_it_was_compared_on(
    report: DifferentialReport,
) -> None:
    """The comparison is between two different searches, not one search twice.

    If the oracle's output needed no filtering, that would mean it had pruned
    the way the engine prunes -- and an oracle that shares the engine's pruning
    shares the engine's bugs. At least one world must exercise the filter.
    """
    filtered = [
        c for c in report.cases if c.reference_path_count > c.reference_comparable_count
    ]
    assert filtered, (
        "no world produced a reference path the engine was not expected to report; "
        "the oracle is not enumerating anything the engine prunes\n" + summarise(report)
    )


def _nested_groups_case(model: ModelSource) -> CaseReport:
    world = next(w for w in WORLDS if w.code == "nested_groups")
    return run_snapshot_case(
        code=world.code,
        title=world.title,
        mechanism=world.mechanism,
        snapshot=world.build(),
        threat_model_code=world.threat_model_code,
        max_hops=world.max_hops,
        model=model,
    )


def test_an_engine_reading_a_row_differently_is_caught(model: ModelSource) -> None:
    """The harness is only evidence if it can fail.

    The engine is given one precondition value the reference does not have --
    exactly the shape of the bug this exists to find, two readings of the same
    row that do not agree on what it permits. R2's admin check becomes a check
    for a permission level nothing has, so the engine cannot cross the group's
    permission and the reference still can.
    """
    crippled = dataclasses.replace(
        model,
        engine_ruleset=engine_ruleset_from_rows(
            _WithPreconditionValue(
                _SeedRows(), "group_permission_admin", seq=2, value_json='"not-a-level"'
            )
        ),
    )

    case = _nested_groups_case(crippled)

    assert not case.agrees
    assert case.reference_only, "the reference still reaches the target; the engine cannot"
    assert case.engine_path_count == 0


def test_an_engine_missing_a_rule_outright_is_caught(model: ModelSource) -> None:
    """The other way the two can disagree about the model rather than the search.

    A reference path built from a rule the engine does not have cannot be judged
    by the minimal-proof filter, because that filter looks its hops' rules up in
    the engine's own ruleset. Answering "not minimal" there would file the
    disagreement under a filter about search behaviour and report agreement, so
    such a path is comparable by definition.
    """
    crippled = dataclasses.replace(
        model,
        engine_ruleset=engine_ruleset_from_rows(
            _WithoutRule(_SeedRows(), "group_membership_nested")
        ),
    )

    case = _nested_groups_case(crippled)

    assert not case.agrees
    assert case.reference_only
    assert case.engine_path_count == 0


def test_the_database_rows_say_what_the_seed_files_say(
    report: DifferentialReport,
) -> None:
    """The same comparison against MySQL, when one is up.

    Skipped rather than failed without a database, because the point of the
    seed-file source is that this suite runs without one. When a database *is*
    there, the two must produce the same rules -- a seed file that has drifted
    from the applied rows is otherwise invisible, and every result above would
    be about a model nothing runs against.
    """
    try:
        from app.db import mysql_engine

        raw = mysql_engine().raw_connection()
    except Exception as exc:  # noqa: BLE001 - absence of a database is not a failure
        pytest.skip(f"no MySQL to compare against: {exc}")

    try:
        from_database = load_ruleset(MySQLRowSource(raw))
    finally:
        raw.close()

    from_seed = load_model(prefer_database=False).oracle_ruleset
    assert from_database.rules == from_seed.rules
    assert from_database.atoms == from_seed.atoms
    assert from_database.threat_models == from_seed.threat_models

    live = run_report(model=load_model())
    assert live.model_origin == "database", live.model_detail
    assert live.disagreement_count == 0, summarise(live)
    assert live.agreement_rate == report.agreement_rate


# ── The bound the real-graph case is run under ───────────────────────────────


def _pinwheel(spokes: int) -> GraphSnapshot:
    """A hub, a ring around it, and a tail off each ring node.

    Enough structure that a breadth-first bound has something to cut, and small
    enough to count by hand.
    """
    nodes = [node("hub", "Host", crown_jewel=True, status="active")]
    edges = []
    for i in range(spokes):
        nodes.append(node(f"ring-{i}", "Host", status="active"))
        nodes.append(node(f"tail-{i}", "Credential", is_active=True, storage="config_file"))
        edges.append(edge(f"e-in-{i}", f"ring-{i}", "hub", "TRUSTS", trust_type="rdp"))
        edges.append(
            edge(f"e-out-{i}", f"ring-{i}", f"tail-{i}", "EXPOSES_CREDENTIAL", location="config_file")
        )
    return snapshot(nodes, edges)


def test_the_bound_keeps_the_seeds_and_respects_the_cap() -> None:
    graph = _pinwheel(6)

    bounded = bounded_subgraph(graph, ["hub"], node_cap=5)

    assert len(bounded) == 5
    assert bounded.get_node("hub") is not None


def test_the_bound_grows_in_both_directions() -> None:
    """Backwards for what a target is reachable from, forwards for what hangs off it.

    A neighbourhood grown only towards the goal would drop the credentials and
    vulnerabilities that are half the mechanism, and the bounded case would stop
    being about the same graph.
    """
    bounded = bounded_subgraph(_pinwheel(3), ["hub"], node_cap=99)

    kept = {n.node_id for n in bounded.all_nodes}
    assert {"ring-0", "ring-1", "ring-2"} <= kept, "did not grow backwards to the ring"
    assert {"tail-0", "tail-1", "tail-2"} <= kept, "did not grow forwards to the tails"


def test_the_bound_keeps_only_edges_it_kept_both_ends_of() -> None:
    bounded = bounded_subgraph(_pinwheel(6), ["hub"], node_cap=4)

    kept = {n.node_id for n in bounded.all_nodes}
    for e in bounded.all_edges:
        assert e.src_id in kept and e.dst_id in kept


def test_the_bound_is_deterministic() -> None:
    """Same graph, same cap, same subgraph -- including which nodes were dropped.

    A bound that sampled would make the real-graph case's result depend on the
    order a set iterated in, and a differential result nobody can reproduce is
    not a result.
    """
    graph = _pinwheel(8)

    first = bounded_subgraph(graph, ["hub"], node_cap=9)
    second = bounded_subgraph(graph, ["hub"], node_cap=9)

    assert [n.node_id for n in first.all_nodes] == [n.node_id for n in second.all_nodes]
    assert [e.edge_id for e in first.all_edges] == [e.edge_id for e in second.all_edges]


def test_an_unknown_seed_is_ignored_and_a_cap_below_one_is_refused() -> None:
    graph = _pinwheel(2)

    assert len(bounded_subgraph(graph, ["hub", "not-a-node"], node_cap=99)) == len(graph)
    with pytest.raises(ValueError):
        bounded_subgraph(graph, ["hub"], node_cap=0)


# ── Path identity ────────────────────────────────────────────────────────────


def test_comparison_key_ignores_the_source_of_an_edgeless_hop(
    model: ModelSource,
) -> None:
    """The one normalisation the comparison applies, checked rather than trusted.

    A rule consuming no edge has no source: the oracle records where the
    attacker was standing, the engine records the node the rule acted on, and
    the rule loader refuses to bind such a rule's preconditions to ``src`` at
    all. Comparing that field would report a labelling convention as a
    disagreement.
    """
    kerberoast = next(w for w in WORLDS if w.code == "kerberoast")
    case = run_snapshot_case(
        code=kerberoast.code,
        title=kerberoast.title,
        mechanism=kerberoast.mechanism,
        snapshot=kerberoast.build(),
        threat_model_code=kerberoast.threat_model_code,
        max_hops=kerberoast.max_hops,
        model=model,
    )

    # The world's only route starts with a rule that consumes no edge, and the
    # two implementations label its source differently -- which is precisely
    # the case the normalisation exists for, so it must be counted and not
    # silently absorbed.
    assert case.agrees
    assert case.label_only_count == 1


# ── Row sources used by the negative control ─────────────────────────────────


def _SeedRows() -> RowSource:
    """The model's rows, re-read from the seed files.

    ``ModelSource`` holds assembled rulesets rather than the rows they came
    from, and a negative control has to interfere before the engine assembles
    them.
    """
    from oracle.loader import SeedFileRowSource, rule_seed_files

    return SeedFileRowSource(rule_seed_files())


def _rule_id_of(source: RowSource, rule_code: str) -> int:
    for rule_id, code in source.fetch("rule", ("id", "code")):
        if code == rule_code:
            return int(rule_id)
    raise KeyError(f"no rule {rule_code!r} in these rows")


class _WithoutRule:
    """A row source with every trace of one rule removed."""

    def __init__(self, inner: RowSource, rule_code: str) -> None:
        self._inner = inner
        self._rule_id = _rule_id_of(inner, rule_code)

    def fetch(self, table: str, columns: Sequence[str]) -> list[tuple[Any, ...]]:
        rows = self._inner.fetch(table, columns)
        if table == "rule":
            index = list(columns).index("id")
            return [r for r in rows if int(r[index]) != self._rule_id]
        if table in ("rule_precondition", "rule_effect"):
            index = list(columns).index("rule_id")
            return [r for r in rows if int(r[index]) != self._rule_id]
        return rows


class _WithPreconditionValue:
    """A row source with one precondition's compared value replaced."""

    def __init__(
        self, inner: RowSource, rule_code: str, *, seq: int, value_json: str
    ) -> None:
        self._inner = inner
        self._rule_id = _rule_id_of(inner, rule_code)
        self._seq = seq
        self._value_json = value_json

    def fetch(self, table: str, columns: Sequence[str]) -> list[tuple[Any, ...]]:
        rows = self._inner.fetch(table, columns)
        if table != "rule_precondition" or "value_json" not in columns:
            return rows
        rule_index = list(columns).index("rule_id")
        seq_index = list(columns).index("seq")
        value_index = list(columns).index("value_json")
        out = []
        for row in rows:
            if int(row[rule_index]) == self._rule_id and int(row[seq_index]) == self._seq:
                row = row[:value_index] + (self._value_json,) + row[value_index + 1 :]
            out.append(row)
        return out


def test_the_comparison_key_is_the_one_the_harness_documents() -> None:
    """Guards the shape of the key rather than re-deriving it.

    A change to ``comparison_key`` that dropped a field would make every case
    agree, and the suite above would applaud.
    """
    from core.model import AttackPath, Hop

    hop = Hop(
        hop_no=1,
        src_node_id="a",
        dst_node_id="b",
        edge_id="e1",
        technique_code="t",
        rule_id=1,
        p_succ=1.0,
        detectability=0.0,
        neg_log_contribution=0.0,
        gained=(),
        factors=(),
    )
    edgeless = dataclasses.replace(hop, edge_id=None, src_node_id="somewhere-else")
    path = AttackPath(
        path_id="p",
        source_node_id="a",
        target_node_id="b",
        hops=(hop, edgeless),
        p_success=1.0,
        neg_log_success=0.0,
        p_undetected=1.0,
        bottleneck_p=1.0,
        bottleneck_hop=1,
        impact_score=0.0,
        risk_score=0.0,
        risk_tier_code="",
        target_is_crown_jewel=True,
    )

    assert comparison_key(path) == (("e1", 1, "a", "b"), ("", 1, "", "b"))


def test_case_reports_add_up(report: DifferentialReport) -> None:
    """The counts on a report are consistent with each other."""
    for case in report.cases:
        assert isinstance(case, CaseReport)
        assert case.agreed_count <= case.reference_comparable_count
        assert case.agreed_count <= case.engine_path_count
        assert case.reference_comparable_count <= case.reference_path_count
        assert case.comparable_total == (
            case.agreed_count + len(case.engine_only) + len(case.reference_only)
        )
    assert report.comparable_total == sum(c.comparable_total for c in report.cases)
