# faultline — Scope & Locked Decisions

> **Read this first.** This is the authoritative reference for what we are building and why.
> If you are picking this up in a new session or on a different machine, read this file and
> then `docs/PROGRESS.md`. Everything else is detail.

---

## 1. What we are building

**faultline** is a graph-based attack-path and identity-privilege analyzer. It ingests an
identity/asset graph (users, groups, service accounts, hosts, databases, cloud resources,
applications, credentials, vulnerabilities), derives the privilege-escalation and
lateral-movement paths an attacker could actually walk, scores and ranks them, shows the
blast radius of any compromise, and simulates remediations before they are applied — with a
tamper-evident, externally-anchored record of every change.

Submission target: **PS17 — Attack Path & Identity Privilege Graph Analyzer** (Expert),
cyber + blockchain track.

### The one-sentence differentiator

> BloodHound tells you a path *exists*; faultline proves the path is *real*, ranks it by a
> probability you can audit, tells you which single fix kills the most paths, and proves the
> fix worked — against a ground truth it publishes.

### Why "better than BloodHound" is a defensible claim

BloodHound computes graph reachability over static Active Directory ACL facts. It is excellent
at that and we are not going to beat it at enumeration. We beat it on four things it does not do:

| Gap in BloodHound | What faultline does |
|---|---|
| Reachability ≠ exploitability. A path may require a capability the attacker does not hold. | **Precondition-aware search** over held-capability state. We refuse paths that do not actually work — and we show the refusals. |
| No probabilistic ranking. Everything is a path; "shortest" is the only ordering. | **Calibrated likelihood × impact scoring** with per-factor attribution. |
| No remediation simulation. It tells you what is wrong, not what to do first. | **Counterfactual simulation by re-derivation** + greedy set-cover chokepoint selection with a stated optimality gap. |
| No proof of correctness. You trust the output. | **Ground-truth evaluation harness** publishing precision/recall/NDCG, plus planted negative controls we correctly refuse. |

---

## 2. Evaluation criteria → where we earn each

The rubric is: *path correctness; risk prioritization; explainability; remediation impact.*

| Criterion | What earns it |
|---|---|
| **Path correctness** | Precondition-aware engine + independent brute-force oracle + 14 paired decoys we correctly reject + published precision/recall/F1 against a ground-truth manifest. |
| **Risk prioritization** | Log-space product-of-probability likelihood, separate impact axis, calibration curve, Kendall-τ / NDCG@k against ground-truth severity. |
| **Explainability** | Every score is a typed provenance object, never a bare float. Exact Shapley factor attribution (free, because the score is log-additive). ATT&CK technique cited per hop. LLM narrative generated from the structured path object and hard-gated against hallucination. |
| **Remediation impact** | Simulation by full re-derivation (never bookkeeping), then VERIFIED = re-run on the live graph and assert predicted == actual. **Simulation fidelity** displayed as a live metric. |

---

## 3. Locked architectural decisions

These came out of a research pass that audited the original blueprint. Each one corrects a
defect that would have cost us a judging criterion. **Do not silently revert these.**

### D1 — The path engine lives in the application process, not in the database. `BLOCKER FIX`

Graph query languages **cannot express preconditions.** Cypher predicates (and APOC path
expanders, and GDS pathfinding) evaluate against static node/relationship properties; Cypher's
`allReduce` supports only a monotone *scalar* accumulator, not a set of dynamically acquired
capabilities. And no path language can express an AND-precondition satisfied by a side-excursion,
because that needs a proof DAG with multiple parents, not a linear sequence. Recursive SQL CTEs
have exactly the same limitation.

An engine built on variable-length graph matching reports graph *reachability* and calls it attack
paths. That is precisely the false-positive failure the top judging criterion punishes.

**Therefore:** the datastore is a system of record, a provenance store, and an exploration
surface — but not the engine. Analysis runs against an immutable in-memory CSR snapshot keyed by
graph version, plus a copy-on-write overlay for simulation.

Note precisely what this does and does not say. It says *pathfinding cannot be a database query.*
It says nothing against storing a graph in a graph database — and Neo4j is where the graph
belongs (D12).

**And this limitation is a demo asset, not an embarrassment.** In Graph Explorer we run the naive
BloodHound-style query live:

```cypher
MATCH p = (u:User)-[*1..6]->(c:CrownJewel) RETURN count(p)
```

It returns a large number. faultline's engine returns a much smaller one. The difference is
decoys and precondition failures, and every excluded candidate carries a machine-generated reason
naming the attribute that killed it. That side-by-side *is* the product thesis, executed live,
against the same database — which is exactly the "path correctness" criterion made visible.

### D2 — `CAN_ESCALATE_TO` is deleted from the schema. `BLOCKER FIX`

Escalation is the conclusion the product exists to derive. Storing it as an input fact means the
generator writes the answers and the analyzer reads them back — discovery degenerates into
traversal over precomputed results. It also breaks remediation: removing the group membership
that *causes* an escalation would not remove the materialized edge, so the before/after risk
delta would be computed against a stale graph.

**Ground facts are only observable configuration:** `MEMBER_OF`, `HAS_CREDENTIAL`, `ADMIN_TO`,
`HAS_ACCESS_TO`, `HAS_PERMISSION`, `TRUSTS`, `CONNECTED_TO`, `HAS_VULNERABILITY`,
`EXPOSES_CREDENTIAL`. Escalation lives in a recomputed derived layer tagged with the graph
version and the derivation rule id.

### D3 — Risk is two axes, composed multiplicatively in log space. `BLOCKER FIX`

The original `path_risk = max(edge_risks) × 0.9^(hops−1) × criticality` had three fatal defects:

1. `max()` is not a composition. The partial derivative w.r.t. every non-argmax edge is exactly
   zero, so all but one hop are invisible to the score. A 6-hop chain scores identically to a
   1-hop version of its easiest step.
2. `0.9^(hops−1)` is an arbitrary hop penalty invented to compensate for (1), and it
   double-counts detectability, which is already inside `edge_risk`.
3. The combined objective is **not decomposable over prefixes**, so Bellman's principle of
   optimality fails and *no shortest-path algorithm can optimize it.* The system would rank
   paths by a formula it cannot search by.

Separately: max achievable score under the old formula was **4.0**, but the display tiers put
Critical at 9.0–10.0. No path could ever be rated High or Critical.

**Replacement model:**

```
LIKELIHOOD (search-side, per hop)
  p_succ in (0,1]          probability the technique works given preconditions hold
  modifiers applied in LOGIT space so they can never escape (0,1):
      logit(p') = logit(p_base) + sum(beta_i)
      beta = { +0.4 credential age > 90d,  +0.7 shared credential,
               +1.2 plaintext-exposed,     -(large) phishing-resistant MFA, ... }
      clamp p' to [0.001, 0.995]
  p_undetected = 1 - detectability     tracked as a SEPARATE accumulator (no double-count)

PATH LIKELIHOOD
  P_path = product(p_succ)  computed as exp(-sum(-ln p_succ))     # log space, float64
  search weight w = -ln(p_succ) >= 0  ->  Dijkstra/A* minimizing sum(w) maximizes product(p)
  the 0.9^(h-1) term is DELETED - the product penalizes length automatically, correctly
  bottleneck = min(p_succ) reported as a labelled secondary "weakest link" metric

IMPACT (target-side, never inside the search cost)
  crown-jewel status, criticality, data classification, downstream blast reach

DISPLAY
  risk_10 = 10 * clamp(raw / RAW_MAX, 0, 1)    RAW_MAX is a named constant
  unit test: every tier boundary is attainable by a constructible path
  every response and audit entry stamped with scoring_version
```

Bonus that falls out for free: because the score is log-additive, per-factor attribution is
**exactly Shapley**. The "why this score" panel is mathematically principled, not a bar chart
we invented.

### D4 — Search is over (node, held-capability-set), and monotonicity makes it tractable

An attacker never loses a capability (the monotonicity assumption — the same one that takes
MulVAL from exponential to polynomial). Every useful transition strictly *grows* the
held-capability set, so the state space is a **DAG by construction**. This dissolves the cycle
problem the original blueprint never addressed: node-level cycles (host A trusts B trusts A) only
matter for visualization and centrality, handled by Tarjan SCC condensation over free edges as a
preprocess.

Implementation: least-fixpoint over capability facts (semi-naive, Datalog-style), which also
yields a **proof DAG for free** — that is the explainability substrate. Best-first K-best search
with dominance pruning and a hop cap for enumeration.

**A\* heuristic:** one backward Dijkstra on the relaxed (precondition-free) graph gives `d_t(v)`
for all v. It is admissible because a relaxation never overestimates. The same array also powers
O(1) "best path through edge e" scoring for chokepoints and for incremental invalidation —
one cheap precompute, three features.

Do **not** use Yen's for top-k: at n=2000, m=20000, one k=10 run is ~8×10⁸ ops, and we need it
for ~200 (entry, crown-jewel) pairs. Eppstein's is faster but enumerates *walks*, which is
semantically wrong — a walk that revisits a host is not a distinct attack.

### D5 — Chokepoints are cuts and set-cover, not betweenness centrality

Betweenness answers "what is topologically central", which is not "what should I fix". The
correct primitives:

- **Minimum vertex cut** via node-splitting (`v -> v_in -> v_out`, capacity 1) + max-flow
  min-cut (Dinic, ~80 lines in-process).
- **Greedy set-cover** over path coverage, which has the (1 − 1/e) approximation guarantee
  because path coverage is submodular. **Display the optimality gap** — that is a credibility
  moment, not a weakness.

### D6 — Simulation is always by re-derivation, never by bookkeeping

`simulate(fix)` = deep-copy the graph → apply the mutation → run discovery **from scratch** →
diff canonical path sets. The moment we incrementally patch the existing path list, simulated
and actual diverge and we will not notice until a judge asks.

`VERIFIED` in the lifecycle means: re-run discovery on the live graph after apply, assert
predicted == actual. **Simulation fidelity** (exact-set-match rate + Jaccard of predicted vs
actual removed sets) is a displayed metric.

Also: fixes can *create* new paths (credential rotation redistributing a secret, break-glass
fallback to a static-secret principal, a compensating bastion after segmentation, removal of a
DENY ACE). The simulator must diff in both directions, not just count removals.

### D7 — Blockchain is governance, not just logging

A local SHA-256 hash chain in a database the attacker also controls proves very little: an
attacker with write access recomputes the whole chain. That has to be said honestly and then
fixed.

**Must build:**

1. **RFC 6962-style append-only log** with **salted leaves**:
   `leaf = H(0x00 || salt || canonical(entry))`, 16-byte CSPRNG salt stored with the entry and
   released only with the proof. Without the salt, leaves are low-entropy and guessable
   (`revoke_credential | svc_backup_01 | <timestamp> | admin`), so anyone can confirm an entry by
   recomputation — leaking identity-graph contents through what is supposed to be a
   privacy-preserving commitment.
2. **Periodic Merkle root anchored on-chain**, with inclusion proofs (one entry against a
   published root) and consistency proofs (between successive anchors).
3. **`/api/audit/verify` must be able to render RED.** As originally specified it recomputes the
   chain from the database and returns a boolean — verifying a self-consistent structure against
   itself, which returns green for a fully rewritten log. It must return: local chain status,
   on-chain checkpoint (epoch, root, tree size, tx hash, block number/timestamp), inclusion-proof
   result, consistency-proof result, **current tamper window in seconds**, and the first divergent
   leaf index if any.
4. **EIP-712 typed-data approvals for remediation.** This is the strong story. faultline can
   revoke credentials, remove group memberships and disable accounts — domain-admin-equivalent
   power — and the original blueprint specified *no authorization model at all* for
   `/api/remediation/apply`. The tool that finds privilege escalation is itself an unguarded
   privilege-escalation path; an attacker who compromises its API can weaponise mass account
   disable as enterprise-wide DoS. High-disruption fixes therefore require a signature from a
   human key **the faultline server never holds**, bound to
   `(fixId, targetNodeId, graphStateRoot, simulationHash, disruptionTier, validAfter, validUntil, nonce)`.
   Directly motivated by the Bybit/Safe and Radiant incidents, where signers approved something
   other than what they were shown.

**Chain choice: Base Sepolia.** *Not* Ethereum Sepolia — its estimated end of life is around
30 September 2026, roughly three weeks out; the contract and its explorer links could die between
build and judging. Holesky was already shut down in Sept 2025 and Hoodi is a validator testnet,
not an application testnet. Polygon Amoy is the configured secondary; local Anvil is the
always-available fallback.

**Foundry, not Hardhat.** Hardhat's advantage is a TypeScript-native pipeline, which does not
apply — our backend is Python and consumes the contracts from `web3.py`. Foundry gives
Solidity-native fuzzing, Anvil as the offline fallback node, and one-command verification.
Add a differential fuzz test checking the Solidity RFC 6962 verifier against proof vectors
generated by the Python log implementation.

**Three anchoring modes** selected by env var, so the demo cannot die on conference wifi:
`anvil` (local, deterministic) | `base-sepolia` (real tx hashes) | `replay` (recorded receipts
from a JSON fixture, clearly badged "recorded"). Pre-anchor all demo checkpoints the night
before; the live demo mainly performs read-only `eth_call` verification against historical
anchors. Attempt exactly one live anchor with a 20-second timeout that degrades gracefully.

### D8 — Ground truth is a first-class deliverable

The environment is synthetic, which is a gift: the generator knows the answer. Not measuring
against it is leaving the strongest possible correctness evidence on the table.

**Three-layer separation** (this is what keeps the oracle independent):

- **Facts.** The generator emits only primitive, collector-shaped facts — no `CAN_ESCALATE_TO`,
  no path list.
- **Manifest.** Alongside the graph: the plant log recording *intent* ("created an
  intern-to-DA opportunity via nested groups") — never the path itself; per-hop true success
  probabilities used to synthesise edges (these enable the calibration metric); the decoy/twin
  registry naming the deciding attribute for each pair; the designated entry-node set and goal
  predicates; the seed and generator version.
- **Oracle.** A deliberately dumb, obviously-correct exhaustive DFS with an explicit precondition
  checker, **written from the rules spec before the fast engine exists**, used only as a test
  oracle on small graphs. This is what prevents the generator and analyzer from sharing a bug
  and agreeing with each other.

**Negative controls are mandatory.** 14 paired decoys. Non-negotiable design rule: *every decoy
ships with a twin that IS a valid path and differs in exactly ONE attribute.* Without twins we
are testing a keyword blacklist, and an engine that reports nothing scores perfectly. Example —
D1: `AUTHENTICATES_TO {mfa_required: true, mfa_type: 'fido2'}` is a hard block; its twin has
`mfa_type: 'sms'` and the state holds a `session_theft` capability (AiTM, T1539), so it is valid.
Each rejection emits a machine-generated reason string, which doubles as explainability evidence.

**Metrics.** Canonical path identity at two levels, both reported: L2 edge-sequence (strict,
the headline) keyed on `sha256` of the edge-id sequence — using edge ids, not node ids, because
two distinct credentials between the same user and host are two genuinely different attacks;
L1 node-sequence (forgiving). Precision / recall / F1 at both levels, Kendall-τ and NDCG@k for
ranking, plus a calibration curve against the manifest's true probabilities.

Five planted paths cannot support any of this — a single miss swings recall by 20 points and
Kendall-τ over five items is meaningless. **Generate many scenarios across many seeds.**

### D9 — Ship a Validation screen; cut the Reports screen

Reports (executive / technical / compliance PDF export) is the lowest-value screen against this
rubric and among the most time-expensive to polish. The Validation screen is the demo weapon:
it runs the eval harness live and shows precision/recall/NDCG against ground truth, the property
suite passing, and simulation fidelity.

Every other team will *assert* correctness. Exactly one will *measure* it. BloodHound cannot make
this claim, so this is the concrete content of "better than BloodHound" — not prettier, **provable**.

### D10 — Reproducibility contract

One integer seed → `SeedBundle(python_random, numpy_default_rng, faker, networkx_seed,
uuid_namespace)`, threaded explicitly through every call. Never touch global `random`. Never call
`uuid4()` — use `uuid5(NAMESPACE, f'{kind}:{index}')`, enforced by a lint test that greps for
`uuid4(`. Canonical serialisation: sort nodes by id, sort edges by `(src, type, dst, edge_id)`,
sort attribute keys, format floats as `repr(round(x, 9))`. CI test: generate twice with the same
seed, assert identical Merkle roots.

Path ids must be **content hashes**, not autoincrement — otherwise they change on every
regeneration and after every demo reset, breaking deep links, invalidating the narrative cache,
and forcing a live LLM call at the moment of maximum risk.

A `POST /api/demo/reset` endpoint restores the canonical demo state so a failed run mid-demo is
recoverable.

### D11 — LLM narration is hard-gated against hallucination

The dangerous failure mode is not inventing a fictional host — it is naming a **real** host from
elsewhere in the graph. Narration is generated from the structured path object, then
programmatically validated: every entity named in the narrative must appear in the path object.
Fail the gate → reject and regenerate. Narratives are cached by path content hash. An offline
template renderer is the fallback so the demo never depends on an API key or wifi.

### D12 — Two stores, split by shape. Nothing is hardcoded. `TEAM DIRECTIVE`

**Neo4j 5 Community holds the graph. MySQL 8 holds everything else.**

The split follows the shape of the data rather than a preference for one engine:

| Store | Holds | Why |
|---|---|---|
| **Neo4j** | Nodes, edges, graph versions, crown-jewel labels | A graph belongs in a graph database. It keeps the fact model honest, it is the substrate practitioners already associate with this problem, and it gives Graph Explorer real Cypher — including the live naive-query contrast described in D1. |
| **MySQL** | Rules, techniques, capability atoms, scoring config, threat models, analysis results, path provenance, remediation state, ground-truth manifest, eval metrics, audit ledger, UI config | Tabular configuration wants a tabular store, and the append-only audit ledger specifically wants strict sequencing plus ACID guarantees, which is not Neo4j's strength. |

Neo4j is the store and the exploration surface. It is **not** the engine — D1 is unchanged and
non-negotiable: the moment pathfinding becomes a Cypher query, we are reporting reachability and
calling it attack paths, which forfeits the top judging criterion.

**Cost accepted:** two databases is two things that can fail on demo day. Mitigated by a single
bring-up script, a health endpoint that reports both, and the rule that Neo4j being down degrades
Graph Explorer only — analysis runs from the in-memory snapshot and MySQL, so the core demo
survives.

**Nothing may be hardcoded anywhere in the stack.** Not in Python constants, not in TypeScript
literals, not in seeded JSON fixtures the app reads at runtime, not in component props. If the
application displays it or computes with it, it came from MySQL.

Concretely, all of the following live in tables:

| Category | Must be DB-resident |
|---|---|
| Graph | nodes, node attributes, edges, edge attributes, graph versions |
| Rules | precondition rules, technique definitions, ATT&CK technique mappings, capability atoms |
| Scoring | base probabilities, logit modifier betas, `RAW_MAX`, risk tier thresholds, tier colours, `scoring_version` |
| Remediation | fix-type catalogue, effort/disruption values, playbook definitions, lifecycle states |
| Ground truth | manifest, plant log, decoy/twin registry, entry-node set, goal predicates, seeds |
| Audit | log entries, leaf salts, Merkle nodes, checkpoints, anchor receipts, EIP-712 approvals |
| UI config | node type → colour/shape/size mappings, edge type → style mappings, layout defaults, feature flags, nav structure |
| Results | discovered paths, scores, provenance trees, blast-radius runs, simulation results, eval-harness metrics |

The frontend ships with **no mock data and no fixture fallbacks**. An empty database renders
empty states, never invented numbers. The seed/migration scripts are the only place literal
values appear, and they exist to *populate* the database, not to be read at runtime.

Two consequences worth planning for:

- **Graph load.** The engine pulls nodes and edges from Neo4j in two bulk reads at startup and
  builds the CSR adjacency in memory. We never traverse in Cypher during analysis, so Neo4j is
  never on the hot path — it serves the load, the Graph Explorer, and the naive-query contrast.
- **Snapshot/version discipline.** Every analysis result records the `graph_version` it was
  computed against, so a mutation during remediation cannot silently invalidate a displayed
  number. This is the same guarantee we would have needed anyway.

**Also DB-resident, not hardcoded:** the demo's Cypher queries themselves. Graph Explorer's saved
queries — including the naive-reachability one we deliberately show failing — are rows, so the
demo script is data and can be edited without a rebuild.

---

## 4. Tech stack

| Layer | Choice | Note |
|---|---|---|
| Graph store | **Neo4j 5 Community** | The identity/asset graph and the Graph Explorer surface (D12). Bulk-read into memory at startup; never on the analysis hot path. |
| Relational store | **MySQL 8** | Rules, scoring, results, remediation, ground truth, audit ledger, UI config (D12). |
| DB access | SQLAlchemy 2.x Core + numbered SQL migrations; official `neo4j` Python driver | Plain SQL over generated DDL: the schema is part of the correctness argument and hand-written DDL reviews better. |
| Analysis engine | Python, in-memory CSR snapshot + COW overlay | Where all correctness lives. |
| Graph algorithms | hand-rolled Dijkstra/A*, Dinic; `rustworkx` if profiling demands | `networkx` acceptable at this scale. |
| API | FastAPI + Pydantic v2 | |
| Frontend | React + TypeScript + Vite | No mock data, ever. |
| Graph viz | **TBD — pending verification** | Needs measurement at 2000 nodes; Cytoscape.js vs sigma.js/G6 (WebGL). LOD/clustering needed regardless. |
| Charts | Recharts | |
| Styling | Tailwind + shadcn/ui | Tailwind v3 vs v4 config differs — verify before writing config. |
| Glass theme | **`ios26-glassmorphism-react` UNVERIFIED** | No confirmable npm listing found. Assume we hand-roll `backdrop-filter` glass + framer-motion until proven otherwise. Also: stacked `backdrop-filter` over a graph canvas is a real perf problem. |
| LLM | Claude API, structured-input → gated narration | Offline template fallback required. |
| Contracts | Solidity + **Foundry** | Base Sepolia / Amoy / Anvil / replay. |
| Testing | pytest + **Hypothesis** + Vitest | Property/metamorphic tests are a deliverable, not a nicety. |

### Unverified

The recon pass that would have checked the frontend stack and the competitor landscape was cut
short by a session limit. **Still to verify:** the glass library's existence, graph-viz
performance at scale, Tailwind v3-vs-v4, current `framer-motion` package name, React 19 compat.
Tracked in `docs/PROGRESS.md` under Open Questions.

---

## 5. Explicitly cut

| Cut | Reason |
|---|---|
| Neo4j GDS plugin | D1 means no analysis runs in the DB, so GDS buys nothing; its projections also go stale during remediation mutation, silently corrupting numbers on the demo's critical path. Neo4j itself is kept — see D12. |
| Reports screen (PDF exec/technical/compliance) | Lowest rubric value, highest polish cost. Replaced by the Validation screen. |
| `CAN_ESCALATE_TO` stored edge | Circular — see D2. |
| Yen's / Eppstein for top-k | Too slow / semantically wrong — see D4. |
| Betweenness centrality as the chokepoint metric | Wrong primitive — see D5. |
| `0.9^(hops−1)` decay term | Double-counts detectability; unnecessary once the score is a product — see D3. |
| Ethereum Sepolia | End of life ~30 Sept 2026 — see D7. |
| Hardhat | Foundry fits a Python backend better — see D7. |
| All mock/fixture/hardcoded data | See D12. |

---

## 6. Workstreams

Four subsystems, one owner each. Ownership means "you can answer a judge's questions about it".

| Owner | Workstream | Scope |
|---|---|---|
| **tripathidhruv** | Engine | Fact/rule model, precondition-aware search, scoring, chokepoints, blast radius, incremental invalidation. |
| **swamini1662** | Data & Proof | MySQL schema and migrations, Neo4j constraints and loaders, synthetic generator, ground-truth manifest, decoy/twin registry, brute-force oracle, eval harness, property tests. |
| **sanchitaaX** | Frontend | All screens, graph visualization, provenance/attribution UI, motion system. |
| **netrajs** | Platform | Repo, API layer, audit log + Merkle anchoring, Solidity contracts, LLM narration gate, Docker, demo choreography. |

---

## 7. Build order

The ordering is load-bearing: the scoring aggregator determines whether exact Shapley attribution
is available; the oracle must precede the engine to be independent; path ids must be content
hashes before the narrative cache exists.

**Phase 0 — Foundations that cannot be retrofitted.**
MySQL schema + migrations, Neo4j constraints → `rules` spec (prose first, rows second) → generator emitting
primitive facts into Neo4j, manifest + decoy/twin registry into MySQL → `oracle/reference.py` written
from the spec → seed/canonical serialisation contract → path content hashing.

**Phase 1 — Vertical slice.** Neo4j + MySQL → engine → scoring → one API endpoint → one screen showing a
real ranked path with its provenance. End-to-end, demoable, no placeholders.

**Phase 2 — Correctness.** Eval harness, precision/recall/NDCG, Hypothesis property suite,
oracle differential testing, Validation screen.

**Phase 3 — Remediation.** Simulation by re-derivation, chokepoint set-cover, dependency
analysis, lifecycle, fidelity metric.

**Phase 4 — Proof & governance.** Salted Merkle log, anchoring, inclusion/consistency proofs,
EIP-712 approvals, the verify screen that can render red.

**Phase 5 — Polish.** Motion system, LLM narration, blast-radius visuals, demo rehearsal.

Each phase ends demoable. Phase 1 is never allowed to regress.

---

## 8. Open questions for the team

Tracked live in `docs/PROGRESS.md`. Summary:

1. Graph visualization library — needs a measured decision at 2000 nodes.
2. Glass theme library existence — blocks the frontend styling approach.
3. Scenario/seed count for the eval harness — affects generator design.
4. Whether to extend the same engine over a web3 protocol-governance graph (wallets, multisig
   signers, proxy-admin upgrade rights) as a second domain. Strong differentiator, real scope cost.
