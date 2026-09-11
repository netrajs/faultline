# faultline — Progress Log

> **Handoff file.** When a session hits its limit and work resumes on another account or
> machine, read `docs/SCOPE.md` first (what and why), then this file (where we are).
> Append to the session log; do not rewrite history.

**Repository:** https://github.com/netrajs/faultline
**Problem statement:** PS17 — Attack Path & Identity Privilege Graph Analyzer (Expert), cyber + blockchain
**Current phase:** Phase 1 — Vertical slice
**Status:** Foundations complete and pushed. Five subsystems under parallel construction.

---

## 1. Where we are right now

| Area | State |
|---|---|
| Scope & architecture | **Locked.** 12 decisions recorded in `docs/SCOPE.md`. |
| Research | 3 of 6 recon reports complete (algorithms, blockchain, validation). 3 cut short by a session limit. |
| MySQL schema | **Done.** 8 migrations, 62 tables, verified against MySQL 8.0.44. |
| Neo4j schema | **Done.** 9 constraints, 14 indexes, verified against 5.26.0 Community. |
| Rules spec | **Done.** 15 rules, 14 paired decoys, 10 invariants — `docs/RULES.md`. |
| Seed data | **Done.** 6 files: vocabularies, attacker model, scoring, fixes, ground truth, UI config. |
| Core model | **Done.** Shared types and determinism utilities, smoke-tested. |
| API | **Config, graph and path/rejection/chokepoint/risk routes done.** Remediation and audit routes pending. |
| Generator | **Done for Phase 1.** Facts, planted scenarios, and all 14 decoy/twin pairs; seeded live (graph v1, 691 nodes / 869 edges, 12 scenarios, 28 decoy instances). |
| Oracle | In progress. Written from the spec alone, deliberately blind to the engine. |
| Engine | In progress, paused mid-implementation. Every module has a first pass (snapshot/rules/preconditions/scoring/search/persistence/discover); 87/92 unit tests passing, 5 failing in the scoring/rules layer, uncommitted. Resume here next. |
| Frontend | **Done for Phase 1.** App shell, routing, runtime theming from the config API, Dashboard and Attack Paths screens with the hop/factor breakdown, verified against the live backend. |
| Contracts | In progress. Checkpoint registry and EIP-712 approvals. |

---

## 2. Immediate next actions, in order

1. ~~MySQL and Neo4j schema.~~ **Done.**
1. ~~`rules` specification — prose first.~~ **Done** — `docs/RULES.md`.
2. ~~Seed the rule/technique/scoring tables from the spec via migration.~~ **Done.**
3. ~~Generator emitting primitive facts + manifest + decoy/twin registry.~~ **Done**, and seeded
   live — graph v1, 691 nodes / 869 edges, 12 scenarios, 28 decoy instances.
4. **`oracle/reference.py`** — loader and precondition evaluator are done; the exhaustive-DFS
   search itself is still open.
5. **Finish the engine vertical slice.** Every module has a first implementation
   (`backend/engine/{snapshot,rules,preconditions,scoring,search,persistence,discover}.py`) but it
   is uncommitted and 5 of 92 unit tests are still failing in the scoring/rules layer — fix those,
   get `python -m pytest backend/tests/engine -v` fully green, then run
   `python -m engine.discover --threat-model external_phish` against the live graph so the
   Dashboard and Attack Paths screens have a real discovery run to render instead of the
   "no completed discovery run yet" empty state.

---

## 3. Open questions — need a decision

| # | Question | Recommended default | Blocks |
|---|---|---|---|
| Q1 | Graph visualization library at ~2000 nodes / ~20000 edges. | Build a throwaway benchmark page with Cytoscape.js and sigma.js, measure, then decide. Do not decide on reputation. | Frontend graph work |
| Q2 | Does `ios26-glassmorphism-react` actually exist on npm? | Assume **no** and hand-roll `backdrop-filter` glass. Verify before writing any styling config. | Frontend styling |
| Q3 | How many scenarios × seeds for the eval harness? | ~20 scenarios × 10 seeds. Five planted paths cannot support precision/recall or rank correlation. | Generator design |
| Q4 | Extend the same engine over a web3 protocol-governance graph (wallets, multisig signers, proxy-admin upgrade rights, token approvals)? | Defer to Phase 5 as a stretch. Strong differentiator for the blockchain track, but real scope cost, and the enterprise graph must be excellent first. | Phase 5 scope |
| Q5 | Tailwind v3 or v4? | Verify current version; the config format changed and the original blueprint assumes v3. | Frontend setup |

---

## 4. Research artifacts

Three recon reports completed. Their findings are already distilled into `docs/SCOPE.md` —
the raw reports are session-scoped and not committed.

| Report | Status | What it produced |
|---|---|---|
| Path algorithms | Complete | D1, D3, D4, D5. The `-ln(p)` transform, monotonicity/DAG argument, A* admissibility, why Yen's and Eppstein's are wrong here, why query languages cannot express preconditions. |
| Blockchain | Complete | D7. Salted leaves, RFC 6962 log, Base Sepolia (Sepolia EOL ~30 Sep 2026), Foundry over Hardhat, EIP-712 governance, three-mode anchoring. |
| Validation | Complete | D8, D9, D10, D11. Three-layer ground-truth separation, 14 paired decoys, metric definitions, Hypothesis property suite, the Validation screen. |
| Competitor landscape | **Not run** — session limit | BloodHound edge taxonomy, honest gap analysis, commercial/OSS prior art. Re-run when quota allows. |
| Risk math | **Not run** — session limit | Partially covered by the other three (D3 is well-founded). Missing: CVSS v4 / EPSS / KEV / SSVC / FAIR grounding and full ATT&CK edge mapping. |
| Stack feasibility | **Not run** — session limit | Q1, Q2, Q5 above are exactly what it would have answered. |

**Re-run the three missing reports when quota allows** — they map directly onto the open questions.

---

## 5. Commit and contribution plan

Target: **≥10 commits from each of four accounts** — `tripathidhruv`, `sanchitaaX`, `netrajs`,
`swamini1662` — on https://github.com/netrajs/faultline.

The workstream split in `docs/SCOPE.md` §6 is designed so each person's commits form a coherent,
defensible body of work. Judges in an expert bracket do ask "who built this part?", so aligning
commit history with who can actually answer for a subsystem is worth more than an even commit count.

**Important mechanical note:** for a commit to appear on a person's GitHub profile and
contribution graph, its **author email must be an email verified on that GitHub account** —
usually `ID+username@users.noreply.github.com`. A commit authored with just a display name shows
as a plain string with no avatar and no profile link, which does not accomplish the goal.

So each contributor needs to set their own identity locally and push their own work:

```bash
git config user.name  "<their github username>"
git config user.email "<their github noreply email>"
```

Per-workstream commit budget (≥10 each, natural granularity):

| Owner | Workstream | Representative commits |
|---|---|---|
| **swamini1662** | Data & Proof | MySQL schema; migrations; seed data for rules/techniques/scoring; node+edge generator; manifest emitter; decoy/twin registry; reference oracle; eval harness; metric implementations; Hypothesis property suite |
| **tripathidhruv** | Engine | CSR loader; capability-state model; precondition evaluator; A* search; K-best enumeration + dominance pruning; log-space scoring; Shapley attribution; Dinic min-cut; greedy set-cover chokepoints; blast radius; COW simulation overlay |
| **netrajs** | Platform | Repo scaffolding; FastAPI app; graph endpoints; path endpoints; remediation endpoints; salted Merkle log; anchoring service; Solidity contracts + Foundry tests; EIP-712 verification; LLM narration gate; Docker compose |
| **sanchitaaX** | Frontend | Vite/TS setup; design tokens; API client; Dashboard; Graph Explorer; Attack Paths; provenance panel; Blast Radius; Remediation Center; Audit Trail; Validation screen; motion system |

---

## 6. Session log

Append one entry per working session. Keep it short and factual.

### 2026-09-11 — Session 4 (generator, frontend, and a UI pass)

- Committed the prior session's uncommitted work first: the reference oracle's loader and
  precondition evaluator, the RFC 6962 Merkle log, the generator scaffold, a checkpoint-registry
  test ordering fix, and new remediation-approval contract tests.
- Built and committed the synthetic generator: primitive graph facts, planted scenarios with an
  intent-only manifest, and all 14 decoy/twin pairs from `docs/RULES.md` §5, isolated from
  background data so a later generator change can't shift a decoy's deciding attribute. 23/23
  tests passing, deterministic (same seed -> identical graph hash).
- Built and committed the frontend application: app shell with the sidebar/topbar/statusbar
  chrome, routing, a typed API layer, runtime theming sourced from the config API (no hardcoded
  domain colors), and the Dashboard and Attack Paths screens including a per-hop "why this score"
  factor waterfall. Verified in-browser against the live backend, both populated-graph and
  no-discovery-run states.
- Seeded the live databases from the new generator — graph v1, 691 nodes, 869 edges, 12 planted
  scenarios, 28 decoy instances.
- Restyled the glass surfaces toward a lighter, more translucent "liquid glass" look per team
  direction: lighter near-white panel tints at low alpha (letting the backdrop blur carry the
  color instead of a baked-in dark tint), a darker app background, and a stronger blur/saturation
  and specular top-edge highlight.
- Started the engine (CSR loader, independent rule/precondition evaluator, log-space scorer,
  best-first search with dominance pruning, persistence, `engine.discover` CLI) in parallel, then
  paused it mid-implementation to prioritize the UI pass above — 87/92 unit tests passing,
  uncommitted. Picking this back up is the next session's first job (see §2).
- **Team directive reaffirmed:** no AI attribution anywhere in the repository, and no commit
  history fabricated under a teammate's identity for work they did not do — including from a
  contributor's own alternate accounts, since the concern is the fabricated signal itself
  (a contribution graph misrepresenting when and by whom code was actually written), not only who
  reads it.

### 2026-09-11 — Session 3 (parallel build)

- Seeded the attacker model as data: 9 capability atoms, 13 MITRE-mapped
  techniques, 15 rules with 38 preconditions and 21 effects, 4 threat models.
- Seeded the scoring configuration. The display score is a weighted sum of three
  normalised components with weights totalling 1.0, so the full 0–10 range is
  attainable — the design this replaced topped out at 4.0 against tiers starting
  "critical" at 9.0, meaning no path could ever be rated critical.
- Found and fixed a real defect in the migration runner: the statement splitter
  split on every semicolon after stripping comments, which cut an INSERT in half
  when a seeded description contained one in prose. Now a single quote-aware pass.
- Wrote the shared domain model. A capability is a `(code, node)` pair rather
  than a scalar level, because a level invites `>=` comparisons that falsely make
  every high privilege imply every lower one.
- Wrote the API's configuration and graph routes. Nine endpoints verified against
  the live databases.
- Started five parallel workstreams: generator, reference oracle, engine,
  frontend, contracts. The oracle and engine are explicitly forbidden from
  reading each other, since their agreement is only evidence of correctness if
  neither was written from the other.
- **Team directive:** Higgsfield MCP is available for UI background imagery —
  deferred to Phase 5 (task 5.6), after the interface works.
- 13 commits pushed.

### 2026-09-11 — Session 2 (foundations)

- **Team directive:** Neo4j is back in, as the graph store and Graph Explorer
  surface. This does not conflict with D1, which constrains where the *engine*
  runs, not where the graph *lives*. Storage is now split by shape — Neo4j for the
  graph, MySQL for rules, scoring, results, remediation, ground truth and the audit
  ledger. Recorded as D12.
- Found a demo beat worth building around: run the naive reachability query in
  Graph Explorer against the same Neo4j the engine reads, and show the engine
  returning far fewer paths, with every excluded candidate carrying a recorded
  reason. The gap is the product thesis, executed live.
- Wrote 8 MySQL migrations, 62 tables. Verified against MySQL 8.0.44 from clean.
  Two defects found and fixed by actually running them: a nullable column in a
  composite primary key, and a column named with a reserved word.
- Wrote the Neo4j constraint and index bootstrap. Verified against 5.26.0
  Community — 9 constraints, 14 indexes.
- Installed Neo4j 5.26 Community standalone (no Docker, no service install; the
  machine has a Java 17 JRE, which is sufficient).
- Added `docs/SETUP.md` so teammates can reproduce the environment.
- Pushed 9 commits to the repository.

### 2026-09-11 — Session 1 (planning)

- Audited the original PathForge blueprint against three independent research passes.
- Found and fixed 6 blocker-class defects before writing any code:
  - `path_risk = max(edge_risks)` is not a composition and is not searchable (Bellman fails).
  - Score range topped out at 4.0 while display tiers started Critical at 9.0.
  - `CAN_ESCALATE_TO` stored as a fact made discovery circular.
  - Graph query languages cannot express preconditions, so the DB-side path engine was unbuildable.
  - No ground-truth manifest or eval harness for the top judging criterion.
  - No negative controls, so precision was unmeasurable.
- Locked 12 architectural decisions in `docs/SCOPE.md`.
- **Team directive received:** MySQL as the single source of truth, nothing hardcoded anywhere
  (D12). Neo4j dropped — D1 had already moved analysis out of the database, so a graph DB bought
  nothing and cost a JVM plus plugin version-matching risk.
- **Team directive received:** no AI attribution anywhere in the repository.
- Created `docs/SCOPE.md` and `docs/PROGRESS.md`.
- Research quota exhausted mid-run; 3 of 6 recon reports incomplete (see §4).
