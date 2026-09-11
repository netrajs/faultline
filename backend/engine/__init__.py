"""The precondition-aware attack-path engine.

Discovery runs here, in process, over an immutable in-memory snapshot — never as
a graph or SQL query. No query language can express a precondition satisfied by a
side excursion, so an engine built on variable-length matching reports graph
reachability and calls it an attack path. See ``docs/SCOPE.md`` D1.

This package is written from ``docs/RULES.md`` alone and shares no code with
``backend/oracle``. That independence is the entire value of the oracle: if the
two implementations disagree on a graph, the disagreement is evidence of a real
bug rather than a shared misreading propagated by shared code.
"""
