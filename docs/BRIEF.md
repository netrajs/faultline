# faultline — Project Brief

> A one-read summary of where the build actually stands and what's left. `docs/SCOPE.md` is
> the spec, `docs/TASKS.md` is the itemized checklist, `docs/PROGRESS.md` is the running
> session log — this file is the picture you get by stepping back from all three.

---

## 1. What this is

**faultline** is a graph-based attack-path and identity-privilege analyzer for problem
statement PS17 (cyber + blockchain track). It ingests an identity/asset graph, derives which
privilege-escalation paths an attacker could actually walk — not just which nodes are
graph-reachable — scores and ranks them by a calibrated probability, shows blast radius,
simulates remediations before they're applied, and keeps a tamper-evident, externally-anchored
record of every change.

The one-line differentiator: *BloodHound tells you a path exists; faultline proves the path is
real, ranks it by a probability you can audit, tells you which single fix kills the most paths,
and proves the fix worked — against a ground truth it publishes.* The live demonstration of
that claim already works end to end (see §2.3).

## 2. Current state — built and verified

### 2.1 Data and ground truth

The synthetic generator (`backend/generator/`) emits primitive, collector-shaped facts only —
never a stored escalation edge — and separately records planted-scenario intent and a
decoy/twin registry for evaluation. Seeded live: **graph version 1, 691 nodes, 869 edges, 12
planted scenarios, all 14 decoy/twin pairs from `docs/RULES.md` §5**. Determinism is proven,
not assumed: the same seed reproduces an identical graph hash.

### 2.2 The engine

`backend/engine/` is a complete, independent implementation of the attacker model: its own
rule loader and precondition evaluator (deliberately not sharing code with the reference
oracle — see §3), a log-space scorer with exact per-factor attribution, and a best-first search
over attacker capability state with dominance pruning and K-best enumeration. Two real bugs
were only caught by running discovery against the live graph rather than trusting unit tests
alone — top-k was capped per entry instead of per target across a whole run, and the expansion
budget was a shared first-come pool that let one privileged user's search starve every other
entry. Both are fixed.

Live results: `external_phish` (160 entry nodes) → 11 paths, 1,617 candidates rejected with a
named reason each, run truncated at the expansion cap (a real limit, not a bug, at this graph's
branching factor). `public_only` (101 entries) → 4 paths, 1,066 rejected, finished without
truncation.

### 2.3 The claim, demonstrated live

`/api/graph/contrast` runs the naive graph-reachability query the same way a BloodHound-style
tool would, next to what the engine actually reports, on the same live graph:
**61 naive candidates vs. 4 engine-verified paths — 57 false positives refused**, each with a
named rule and the specific precondition that failed. This is the product's central argument,
already running, already on screen (Graph Explorer's "central claim" panel).

### 2.4 API layer

FastAPI app (`backend/app/`) with config, graph (stats/nodes/node-detail/subgraph/saved-queries/
contrast), and path (list/detail/discover/rejections/chokepoints/risk-summary) endpoints — all
reading real data, no mock fallbacks anywhere.

### 2.5 Frontend

Vite + React + TypeScript, hand-rolled design system (no component library) driven entirely by
runtime tokens — risk-tier and node/edge colors are written onto the document from the config
API, never hardcoded. Three real screens:

- **Dashboard** — spotlight hero for the top risk, five coordinated stat cards, risk-tier
  breakdown, crown-jewel exposure.
- **Attack Paths** — filterable ranked table, and a detail view with the full hop-by-hop
  breakdown and a hand-rolled SVG factor waterfall (baseline + every modifier's contribution).
- **Graph Explorer** — live stats, a searchable/paginated node browser with detail panel, saved
  Cypher queries, and the contrast panel from §2.3.

Plus: a one-time intro (the network-graph video cross-fades into the dashboard 1.5s before its
own natural end, matched scale/easing on both halves so it reads as one camera move, not two
animations); an ambient animated canvas star field behind the whole app; a light, sky-blue,
frosted-glass theme with a real font pairing (Manrope body, Space Grotesk display) self-hosted
so it never silently falls back to a system font; a proper favicon/logo.

### 2.6 Test posture

**146/146 backend tests passing** (oracle loader/preconditions, engine
snapshot/rules/preconditions/scoring/search, generator determinism/decoy fidelity). Frontend
typechecks and builds clean.

## 3. In progress

- **Reference oracle** (`backend/oracle/`) — the rule loader and precondition evaluator are
  done and tested; the exhaustive-DFS search itself (the actual oracle) is not yet written.
  This blocks differential testing (the engine and oracle must independently reach the same
  conclusions, or their agreement means nothing).
- **Solidity contracts** (`contracts/`) — `CheckpointRegistry` and `RemediationApproval` exist
  with Foundry tests; the anchoring service, differential fuzzing against the Python Merkle
  implementation (`backend/audit/merkle.py`, which is itself complete and tested), and EIP-712
  approval verification are not yet wired into the API.

## 4. Not started

Everything else in `docs/TASKS.md` Phases 2–5: the evaluation harness (precision/recall/F1,
Kendall-τ/NDCG, calibration), the Hypothesis property suite for the ten invariants, remediation
simulation (copy-on-write overlay, re-derivation, both-direction delta), chokepoints (Dinic
min-cut + greedy set-cover), blast radius, the audit/anchoring endpoints, and five screens:
Validation, Remediation Center, Blast Radius, Audit Trail, Settings.

## 5. Roadmap

Four milestones, in dependency order (detailed in the task-plan message already shared, mirrored
in `docs/TASKS.md`):

| # | Milestone | Backend | Frontend | Depends on |
|---|---|---|---|---|
| A | **Validation** | Finish oracle DFS → differential harness → eval metrics → Hypothesis suite → validation endpoints | Validation screen | Nothing new — highest-value next step, it's the proof-of-correctness demo |
| B | **Remediation + Blast Radius** | COW overlay → re-derivation simulation → Dinic min-cut → set-cover chokepoints → blast radius → lifecycle → endpoints | Remediation Center, Blast Radius screen | Engine's snapshot/rule model (done) |
| C | **Audit Trail** | Salted log entries → anchoring service (anvil/base-sepolia/replay) → finish Foundry tests → differential fuzz → EIP-712 verification → endpoints | Audit Trail screen | Merkle tree (done); lifecycle from B for what gets logged |
| D | **Settings** | Small config endpoints (scoring weights, threat model, regeneration trigger) | Settings screen | Nothing — can run any time |

## 6. Known risks and open items

- **Oracle independence is not yet checked.** Until the exhaustive DFS exists and disagrees (or
  agrees) with the engine on real cases, "correctness" is currently an assertion, not a measured
  claim — closing this is Milestone A's whole point.
- **Demo data is thin relative to target scale.** 691 nodes is well under the ~2,000-node target
  `docs/SCOPE.md` discusses for graph-viz load testing; fine for now, worth revisiting before a
  live demo if graph-rendering performance becomes part of the pitch.
- **No graph-visualization canvas yet.** Graph Explorer is stats/table/panel-based; an actual
  node-link rendering was explicitly scoped out of that task as a bonus, not a requirement.
- **Intro video asset is unresized** (~5.4 MB) and the logo/favicon uses the full-resolution
  source (~1 MB) — no image-resizing tool was available in this environment to make smaller
  variants. Works correctly, just heavier than ideal.
- **Blockchain anchoring has no live network configured yet** — `replay` mode (recorded
  receipts) is the safe default until `anvil`/`base-sepolia` are wired up in Milestone C.
