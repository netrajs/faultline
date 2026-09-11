# faultline — Progress Log

> **Handoff file.** When a session hits its limit and work resumes on another account or
> machine, read `docs/SCOPE.md` first (what and why), then this file (where we are).
> Append to the session log; do not rewrite history.

**Repository:** https://github.com/netrajs/faultline
**Problem statement:** PS17 — Attack Path & Identity Privilege Graph Analyzer (Expert), cyber + blockchain
**Current phase:** Phase 0 — Foundations
**Status:** Both datastores live and schema'd. Rules spec and generator are next.

---

## 1. Where we are right now

| Area | State |
|---|---|
| Scope & architecture | **Locked.** 12 decisions recorded in `docs/SCOPE.md`. |
| Research | 3 of 6 recon reports complete (algorithms, blockchain, validation). 3 cut short by a session limit. |
| MySQL schema | **Done.** 8 migrations, 62 tables, verified against MySQL 8.0.44. |
| Neo4j schema | **Done.** 9 constraints, 14 indexes, verified against 5.26.0 Community. |
| Rules spec | Not started. **Next up** — blocks generator and oracle. |
| Generator | Not started. |
| Oracle | Not started. Must be written from the rules spec *before* the fast engine. |
| Engine | Not started. |
| API | Not started. |
| Frontend | Not started. Blocked on graph-viz and glass-library verification. |
| Contracts | Not started. |

---

## 2. Immediate next actions, in order

1. ~~MySQL and Neo4j schema.~~ **Done.**
1. **`rules` specification — prose first.** Write the precondition semantics as English in
   `docs/RULES.md` before any code. The oracle and the engine are both written from this document,
   independently. That independence is the whole point.
2. **Seed the rule/technique/scoring tables** from the spec via migration.
3. **Generator** emitting primitive facts + manifest + decoy/twin registry into MySQL.
4. **`oracle/reference.py`** — exhaustive DFS with explicit precondition checks, written from
   `docs/RULES.md` without looking at the generator's internals.
5. **Engine vertical slice** — CSR load, A* over capability state, one scored path end to end.

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
