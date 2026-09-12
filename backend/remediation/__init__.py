"""Remediation: recommend, simulate, apply, verify.

The whole subsystem exists to answer one question honestly — *if we did this,
what would actually change* — and the shape of the code is dictated by the two
ways that question is usually answered wrongly.

``docs/SCOPE.md`` D6: simulation is by re-derivation. A counterfactual is a
copy-on-write overlay over the immutable snapshot plus a full discovery run from
scratch against it (``overlay``, ``simulate``). Patching the existing path list
would be faster and would diverge from reality silently.

``docs/SCOPE.md`` D5: a chokepoint is a cut, not a centrality. Minimum vertex
cut by node-splitting and Dinic max-flow (``cuts``), and greedy set cover over
path coverage with its (1 - 1/e) bound stated rather than implied
(``chokepoints``).
"""
