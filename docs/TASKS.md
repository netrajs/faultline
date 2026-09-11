# faultline — Task List

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

Owner column is the workstream owner from `docs/SCOPE.md` §6. Each owner should
commit their own tasks from their own GitHub account — see `docs/PROGRESS.md` §5.

---

## Phase 0 — Foundations

| # | Task | Owner | Status |
|---|---|---|---|
| 0.1 | Repository scaffolding, ignore rules, README | netrajs | `[x]` |
| 0.2 | Scope document and twelve locked decisions | netrajs | `[x]` |
| 0.3 | Progress log for cross-session handoff | netrajs | `[x]` |
| 0.4 | MySQL schema — 8 migrations, 62 tables | swamini1662 | `[x]` |
| 0.5 | Migration runner with checksums and quote-aware splitting | swamini1662 | `[x]` |
| 0.6 | Neo4j constraints and index bootstrap | swamini1662 | `[x]` |
| 0.7 | Setup guide | netrajs | `[x]` |
| 0.8 | Rules specification — 15 rules, 14 decoys | tripathidhruv | `[x]` |
| 0.9 | Seed data — vocabularies, rules, scoring, fixes, ground truth, UI config | swamini1662 | `[x]` |
| 0.10 | Shared domain model and repository interfaces | tripathidhruv | `[x]` |
| 0.11 | Deterministic identifier and canonical serialisation utilities | swamini1662 | `[x]` |

## Phase 1 — Vertical slice

| # | Task | Owner | Status |
|---|---|---|---|
| 1.1 | Synthetic generator — nodes and edges into Neo4j | swamini1662 | `[x]` |
| 1.2 | Generator — planted scenarios, intent-only manifest | swamini1662 | `[x]` |
| 1.3 | Generator — decoy and twin instances | swamini1662 | `[x]` |
| 1.4 | CSR snapshot loader from Neo4j, keyed by graph version | tripathidhruv | `[~]` |
| 1.5 | Capability-state model with dominance pruning | tripathidhruv | `[~]` |
| 1.6 | Precondition evaluator reading rule rows | tripathidhruv | `[~]` |
| 1.7 | Log-space scorer with per-factor attribution | tripathidhruv | `[~]` |
| 1.8 | A* search over capability state, admissible heuristic | tripathidhruv | `[~]` |
| 1.9 | K-best enumeration with hop cap and deduplication | tripathidhruv | `[~]` |
| 1.10 | Result persistence — paths, hops, factors, rejections | tripathidhruv | `[~]` |
| 1.11 | FastAPI application, settings, health endpoint | netrajs | `[x]` |
| 1.12 | Graph endpoints — nodes, edges, search, stats, saved queries | netrajs | `[x]` |
| 1.13 | Path endpoints — list, detail, discover, chokepoints | netrajs | `[x]` |
| 1.14 | Frontend scaffold — Vite, TypeScript, routing, API client | sanchitaaX | `[x]` |
| 1.15 | Design system — tokens from the database, glass surfaces, motion | sanchitaaX | `[x]` |
| 1.16 | Dashboard screen | sanchitaaX | `[x]` |
| 1.17 | Attack Paths screen with hop breakdown and factor panel | sanchitaaX | `[x]` |

## Phase 2 — Correctness

| # | Task | Owner | Status |
|---|---|---|---|
| 2.1 | Reference oracle — exhaustive DFS, written from the spec alone | swamini1662 | `[~]` |
| 2.2 | Differential test harness, engine against oracle | swamini1662 | `[ ]` |
| 2.3 | Evaluation harness — precision, recall, F1 at both match levels | swamini1662 | `[ ]` |
| 2.4 | Ranking metrics — Kendall tau, NDCG@10 | swamini1662 | `[ ]` |
| 2.5 | Calibration — reliability curve, expected calibration error, Brier | swamini1662 | `[ ]` |
| 2.6 | Hypothesis property suite for the ten invariants | swamini1662 | `[ ]` |
| 2.7 | Validation endpoints | netrajs | `[ ]` |
| 2.8 | Validation screen — live harness run, decoy inspector | sanchitaaX | `[ ]` |
| 2.9 | Graph Explorer with the naive-reachability contrast | sanchitaaX | `[ ]` |

## Phase 3 — Remediation

| # | Task | Owner | Status |
|---|---|---|---|
| 3.1 | Copy-on-write mutation overlay | tripathidhruv | `[ ]` |
| 3.2 | Simulation by full re-derivation, both-direction delta | tripathidhruv | `[ ]` |
| 3.3 | Dinic max-flow, node-split minimum vertex cut | tripathidhruv | `[ ]` |
| 3.4 | Greedy set-cover chokepoints with optimality bound | tripathidhruv | `[ ]` |
| 3.5 | Blast radius, probability-weighted by reach | tripathidhruv | `[ ]` |
| 3.6 | Recommendation ranking and dependency analysis | tripathidhruv | `[ ]` |
| 3.7 | Lifecycle service enforcing transitions from the table | netrajs | `[ ]` |
| 3.8 | Remediation and blast-radius endpoints | netrajs | `[ ]` |
| 3.9 | Verification — re-derive after apply, compute fidelity | netrajs | `[ ]` |
| 3.10 | Remediation Center screen with simulation comparison | sanchitaaX | `[ ]` |
| 3.11 | Blast Radius screen | sanchitaaX | `[ ]` |

## Phase 4 — Proof and governance

| # | Task | Owner | Status |
|---|---|---|---|
| 4.1 | Salted append-only log, RFC 6962 leaf and node hashing | netrajs | `[ ]` |
| 4.2 | Merkle tree, inclusion and consistency proofs | netrajs | `[ ]` |
| 4.3 | Anchoring service — anvil, base-sepolia, replay | netrajs | `[ ]` |
| 4.4 | Solidity checkpoint registry and Foundry tests | netrajs | `[~]` |
| 4.5 | Differential fuzz — Solidity verifier against Python proofs | netrajs | `[ ]` |
| 4.6 | EIP-712 approval verification | netrajs | `[~]` |
| 4.7 | Audit endpoints, verification that can report failure | netrajs | `[ ]` |
| 4.8 | Audit Trail screen with chain state and tamper window | sanchitaaX | `[ ]` |

## Phase 5 — Narration and polish

| # | Task | Owner | Status |
|---|---|---|---|
| 5.1 | Structured narration input builder | netrajs | `[ ]` |
| 5.2 | Hallucination gate — reject any entity absent from the path object | netrajs | `[ ]` |
| 5.3 | Offline template renderer fallback | netrajs | `[ ]` |
| 5.4 | Narration cache keyed by path content hash | netrajs | `[ ]` |
| 5.5 | Settings screen — scoring weights, threat model, regeneration | sanchitaaX | `[ ]` |
| 5.6 | Background visuals and motion pass | sanchitaaX | `[ ]` |
| 5.7 | Demo reset endpoint and canonical baseline | netrajs | `[ ]` |
| 5.8 | Guided demo mode driven by the demo_step table | sanchitaaX | `[ ]` |
| 5.9 | Full rehearsal against the twelve-step script | all | `[ ]` |

---

## Open decisions

Tracked in `docs/PROGRESS.md` §3. Blocking one:

- **GitHub account emails** for `tripathidhruv`, `sanchitaaX` and `swamini1662`.
  Commits attribute to a profile by verified email, not display name. Each is at
  github.com/settings/emails, shaped `12345678+username@users.noreply.github.com`.
