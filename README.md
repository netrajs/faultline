# faultline

**Attack path & identity privilege graph analyzer.**

faultline models the identities, credentials, permissions and assets of an enterprise as a
graph, derives the privilege-escalation and lateral-movement paths an attacker could actually
walk, ranks them by a probability you can audit, and simulates the fixes before you apply them.

> Reachability is not exploitability. A path that requires a capability the attacker does not
> hold is not an attack path — it is a false positive. faultline searches over what an attacker
> *holds*, not just what the graph *connects*, and it publishes its accuracy against a known
> ground truth rather than asking you to take its word.

---

## What it does

- **Identity & asset graph** — users, groups, service accounts, hosts, databases, cloud
  resources, applications, credentials and vulnerabilities, with the privilege relationships
  between them.
- **Precondition-aware path discovery** — search over `(node, held-capability-set)` rather than
  plain reachability, so a reported path is one an attacker could actually execute.
- **Calibrated risk scoring** — likelihood as a product of per-hop success probabilities in log
  space, impact as a separate axis, and exact per-factor attribution for every number shown.
- **Blast-radius analysis** — what a single compromise reaches, weighted by how likely each
  reach actually is.
- **Remediation simulation** — counterfactual re-derivation of the whole path set, dependency
  analysis, and chokepoint selection that tells you which single fix kills the most paths.
- **Tamper-evident audit** — an append-only log with salted Merkle leaves, periodically anchored
  on-chain, plus cryptographic approval for high-disruption changes.

## Why not just BloodHound

BloodHound computes reachability over static ACL facts and does it well. faultline adds the four
things it does not do: it models preconditions so it can *refuse* paths that do not work; it
ranks probabilistically instead of by hop count; it simulates remediation instead of only
reporting; and it measures its own precision and recall against a published ground truth.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/SCOPE.md`](docs/SCOPE.md) | What we are building, and the twelve locked architectural decisions with their rationale. **Start here.** |
| [`docs/PROGRESS.md`](docs/PROGRESS.md) | Current state, next actions, open questions, session log. |

## Stack

Python · FastAPI · MySQL 8 · SQLAlchemy · React · TypeScript · Vite · Solidity · Foundry

MySQL is the single source of truth. No value the application displays or computes with is
hardcoded anywhere in the stack.

## Status

Early development. See [`docs/PROGRESS.md`](docs/PROGRESS.md) for what is and is not built yet.
