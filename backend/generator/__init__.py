"""Synthetic graph generation.

The generator emits primitive, collector-shaped facts into Neo4j and records
what it intended into MySQL. It never writes a path, and it never writes an
escalation edge: the whole point of the exercise is that the engine has to
derive those itself, and a generator that recorded routes would turn the
evaluation into a reading comprehension test.

Three separations keep the ground truth honest:

  facts      nodes and edges, indistinguishable from what a collector would
             produce against a real directory.
  manifest   intent, endpoints, the seed, and the per-edge probabilities the
             generator actually used. Never the route between the endpoints.
  controls   fourteen decoy/twin pairs, each differing in exactly one deciding
             value, so an engine cannot pass by refusing everything.

Determinism is a product requirement rather than a testing convenience -- the
demo resets mid-run and deep links have to survive it -- so every draw comes
from a named stream of ``core.ids.SeedBundle`` and nothing here touches the
global random module.
"""

from __future__ import annotations

GENERATOR_VERSION = "1.0.0"

__all__ = ["GENERATOR_VERSION"]
