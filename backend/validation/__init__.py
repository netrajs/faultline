"""Measuring the engine instead of asserting it.

Three things live here, and they answer three different questions.

``differential``
    Does the fast engine agree with the independent reference oracle about what
    the rules mean? Both are written from ``docs/RULES.md`` separately, so their
    agreement is evidence and their disagreement locates a bug in one of them.

``metrics``
    Does the engine recover what the generator planted, and does it refuse what
    the generator planted to be refused? Scored against the ground-truth
    manifest and the decoy/twin registry, with precision, recall, rank
    correlation and a calibration curve.

``invariants``
    Do the ten properties in ``docs/RULES.md`` §7 hold under perturbation?
    Property tests rather than examples: remove an edge, harden an attribute,
    raise a baseline, and assert the direction the answer moves in.

Nothing in here writes to the graph or to the analysis tables. Every number a
caller gets back is computed from a real run against real rows, and when the
data needed for a number is absent the number is absent too -- there is no
default, no placeholder and no fallback value anywhere in this package.
"""
