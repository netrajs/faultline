"""Discovery entry point.

    python -m engine.discover --threat-model external_phish

Run out of band rather than inside a request. A full run against a
two-thousand-node graph is not something to do under an HTTP timeout, and tying
the most important operation in the product to the most fragile part of it is
how a demo fails at the worst moment. The path endpoints read what this wrote.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone

from engine.persistence import RunMetadata, persist_run
from engine.rules import load_ruleset
from engine.scoring import Scorer, load_scoring_config
from engine.search import Discovery, SearchLimits, verify_path
from engine.snapshot import active_graph_version, load_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m engine.discover",
        description="Discover attack paths over the active graph version.",
    )
    parser.add_argument(
        "--threat-model",
        required=True,
        help="threat_model.code to start the attacker from, e.g. external_phish",
    )
    parser.add_argument("--graph-version", type=int, default=None)
    parser.add_argument("--scoring-version", default=None)
    parser.add_argument("--max-hops", type=int, default=8)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument(
        "--purpose",
        default="baseline",
        choices=("baseline", "simulation", "verification", "evaluation"),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-check every discovered path against the rule rows before writing "
        "(invariant 5, checked independently of the search that produced it)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="discover and report, write nothing",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    graph_version = (
        args.graph_version if args.graph_version is not None else active_graph_version()
    )
    snapshot = load_snapshot(graph_version)
    ruleset = load_ruleset()
    config = load_scoring_config(args.scoring_version)
    limits = SearchLimits(max_hops=args.max_hops, top_k=args.top_k)

    engine = Discovery(snapshot, ruleset, Scorer(config), limits)
    if not snapshot.crown_jewels:
        print(
            f"  graph version {graph_version} labels no crown jewels, so there is "
            "no goal set to search towards",
            file=sys.stderr,
        )
        return 1

    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    result = engine.run(args.threat_model)
    duration_ms = int((time.perf_counter() - started) * 1000)

    if args.verify:
        for path in result.paths:
            problem = verify_path(
                path,
                snapshot=snapshot,
                ruleset=ruleset,
                initial_capabilities=result.initial_capabilities.get(path.path_id, ()),
            )
            if problem:
                print(f"  path {path.path_id[:12]} does not hold: {problem}", file=sys.stderr)
                return 2

    print(f"  graph version {graph_version}, scoring {config.version}, {args.threat_model}")
    print(
        f"  {len(result.entry_nodes)} entry nodes, {len(result.targets)} crown jewels, "
        f"{result.expansions} state expansions"
    )
    print(
        f"  {len(result.paths)} paths, {len(result.rejections)} rejected candidates, "
        f"{duration_ms} ms"
    )
    if result.truncated:
        print("  search hit its expansion budget; results are a lower bound", file=sys.stderr)

    if args.dry_run:
        return 0

    run_id = persist_run(
        RunMetadata(
            graph_version_id=graph_version,
            scoring_version=config.version,
            threat_model_code=args.threat_model,
            purpose=args.purpose,
        ),
        limits,
        result,
        duration_ms=duration_ms,
        started_at=started_at,
    )
    print(f"  analysis run {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
