# faultline — UI Reference for Judge Q&A

> Every tab, every panel, every number on screen: what it is, why it exists, and exactly what
> real data it comes from. Written so you can answer "what does this show and why does it
> matter" for anything a judge points at, without having to guess. Nothing described here is
> mocked or hardcoded — every figure named below is a live read from MySQL/Neo4j or a
> just-computed result, per the project's own non-negotiable rule (`docs/SCOPE.md` D12).

---

## How to use this document

Each tab section below follows the same shape: **what it's for** (one line), **what's on
screen** (element by element), and **why it's there** (which judging criterion — path
correctness, risk prioritization, explainability, remediation impact — or which competitive
claim it backs). If a judge asks "why does this exist" about anything, the answer is in here.

---

## 1. Dashboard (`/`)

**What it's for:** the one-glance summary of the current analysis run — is anything critical
reachable right now, and how bad is the worst of it.

**What's on screen:**
- **Spotlight hero** — the single highest-risk discovered path (source → target, risk score,
  tier badge, hop count, success likelihood), pulled from `discovered_path` ordered by
  `risk_score`. This is deliberately the first thing a viewer sees: the worst finding, not a
  summary statistic.
- **Five stat cards** — total paths discovered, rejected candidates (precondition failures the
  engine refused — this number existing *at all* is the product's core differentiator, see
  §3's Graph Explorer contrast panel), crown jewels reached, max risk score, and discovery time
  (from `analysis_run`).
- **Risk tier breakdown** — a bar per tier (Critical/High/Medium/Low/Info), counts from
  `discovered_path` grouped by `risk_tier_code`. Tier colors are read from the `risk_tier`
  table via the config API at runtime, never hardcoded in the frontend (`docs/SCOPE.md` D12).
- **Crown jewel exposure** — which high-value assets have a path leading to them, and how many.

**Why it's there:** this is the "risk prioritization" criterion made visible in one screen —
an analyst's first question is always "what's the worst thing right now," and this answers it
without a single click.

---

## 2. Attack Paths (`/paths`)

**What it's for:** the full ranked list of everything the engine actually found, and the
complete derivation for any one of them.

**What's on screen (list view):**
- A filterable table (tier, crown-jewel-only, max hops) of every `discovered_path` row, ranked
  by risk score, showing hop count, success probability, weakest link, impact, and tier.

**What's on screen (detail view, `/paths/:pathId`):**
- **The path flow diagram** — the entire attack drawn as one node-and-edge picture (not a stack
  of cards), each node colored by asset kind (same palette as Graph Explorer) and each edge
  colored by that hop's own success probability, using the same risk-tier color bands used
  everywhere else in the product. Clicking an edge selects that hop.
- **The selected hop's detail panel** — the technique used (with its MITRE ATT&CK ID/name),
  the rule that fired, the capabilities gained, and detectability.
- **The factor waterfall** — a hand-rolled SVG breakdown of *exactly* how that hop's probability
  was built: the technique's baseline success chance, then every situational modifier that
  fired (weak MFA, plaintext credential, etc.), each shown as its own bar with its own log-odds
  contribution. This is **exact Shapley attribution, not an approximation** — because the score
  is additive in log-odds space (`docs/SCOPE.md` D3), each factor's bar *is* its exact
  contribution, not an estimate of one.

**Why it's there:** "explainability" as a judging criterion, made concrete — every score on this
screen traces back to a named, inspectable reason, never a bare float.

---

## 3. Graph Explorer (`/graph`)

**What it's for:** exploring the raw identity/asset graph itself, and — the single most
important panel in the whole product — proving the central competitive claim live.

**What's on screen:**
- **Graph stats header** — node/edge counts by kind and type, crown jewel count, active graph
  version (seed, generation timestamp), read from Neo4j via `/api/graph/stats`.
- **"The central claim" contrast panel** — runs the naive reachability query a BloodHound-style
  tool would run (`MATCH p = (u:User)-[*1..6]->(c:CrownJewel) RETURN count(p)`) side by side with
  what the precondition-aware engine actually reports, on the *same live graph*. Currently
  showing **61 naive candidates vs. 4 engine-verified paths** — 57 false positives the naive
  query would have handed an analyst, each one now traceable to a named rejection reason
  (`docs/SCOPE.md` D1). **This is the demo's single most important moment** — see the demo
  script.
- **Node browser** — searchable/filterable/paginated list of every node, with a detail panel
  showing one node's full attributes and incident edges.
- **Saved queries panel** — a small set of pre-approved Cypher queries (including the naive
  reachability query itself, stored as a database row, not hardcoded — `docs/SCOPE.md` D12)
  that can be run and inspected live. Arbitrary Cypher from the client is deliberately not
  accepted — this is a read surface, not a write surface, precisely because the product itself
  deals in privilege escalation and an injectable-Cypher endpoint would be an unusually bad
  thing to ship in that context.

**Why it's there:** "path correctness" made adversarial — instead of asserting the engine is
better than reachability search, this panel *runs both, live, on the same data* and shows the
gap.

---

## 4. Blast Radius (`/blast`)

**What it's for:** "if this one thing were compromised right now, what could an attacker reach
from there, and how easily" — a different question from "how do they get to a specific crown
jewel" (that's Attack Paths).

**What's on screen:**
- **Controls** — search for any node to name as already-compromised, a direction toggle
  (*reaches out to* / *can be reached from* / *both* — the inbound direction runs the same
  search over every edge reversed, answering "what's upstream of this"), and a hop-limit
  selector.
- **Summary figures** — things reached, crown jewels reached, worst outcome (highest severity
  score among everything reached, 0–10 with a tier badge), search duration and states examined.
- **The reached-node tree** — every node the compromise could reach, drawn hanging off the
  origin, one row per hop-depth. A node's fill color is its kind (same palette everywhere else);
  the line into it is colored by the probability of actually getting there (redder = easier for
  the attacker), using the identical risk-tier bands the rest of the product uses. A gold ring
  marks a crown jewel. Rows cap at a fixed number of circles with a "+N more" marker for
  anything beyond that, so a highly-connected origin doesn't render an unreadable wall of nodes
  — the exact count is never lost, just moved into the full list below.
- **Full list with exact numbers** — the same reached set as a plain table, for anyone who wants
  precise percentages or is reading with a screen reader.

**Why it's there:** this is the probability-weighted reachability half of the product — a
plain node/edge reachability count would overstate exposure on a densely connected graph; every
number here already carries the probability of actually getting there, not just whether a path
exists at all.

---

## 5. Remediation (`/remediation`)

**What it's for:** turning "here are the paths" into "here is the one change that fixes the
most of them, what it costs, and proof it actually works" — before anything is touched for
real.

**What's on screen:**
- **Rank fixes** action — an explicit, on-demand pass (never computed silently on read) that
  runs a minimum vertex cut (Dinic max-flow on a node-split graph) to find the exact smallest
  set of nodes that would sever every discovered path, then a greedy set-cover pass over the
  fix catalogue to rank candidate real-world fixes by how many paths each actually eliminates.
  The result states the **exact minimum cut size as a floor** — a concrete, checkable number
  any candidate fix is measured against, not a vague "top fixes" list.
- **Ranked fixes table** — one row per candidate fix, its estimated impact, effort, and
  disruption cost, and its current lifecycle state.
- **The cut these came from** (expandable) — the raw chokepoint ranking underneath the fix
  recommendations, including the **stated optimality gap** for the greedy set-cover selection
  (path coverage is submodular, so greedy carries a mathematically guaranteed (1 − 1/e)
  approximation bound — displayed rather than implied, because a reviewer who knows the
  algorithm will ask).
- **Selected fix detail** — what the fix actually does (the exact mutation: which edge/node,
  what attribute it sets), its rationale, and its lifecycle state, read from the
  `remediation_state`/`remediation_transition` tables rather than a hardcoded state machine —
  which buttons are even enabled comes from what transitions that table actually allows from
  where the fix currently sits.
- **Simulate this fix** — runs the fix's mutation on a copy-on-write overlay of the graph and
  re-derives attack paths **from scratch** against the mutated version (never bookkeeping —
  `docs/SCOPE.md` D6). This is a real second search and takes real time (a couple of minutes at
  this graph's scale), so it runs as a background job the page polls rather than blocking the
  UI; you can navigate away and come back.
- **Before/after diff** — risk before/after, crown jewels before/after, and the actual path
  delta: **removed, added, and rescored counts, always in both directions** — a fix can create
  new paths (a rotated shared credential redistributing itself, a compensating bastion after
  segmentation), and this view is built to show that honestly rather than only counting
  removals.
- **What else this touches** — collateral the fix would cause that's actually derivable from
  the graph (e.g. another principal sharing the same credential being revoked), not invented.
- **Apply this fix** — performs the mutation for real, writing a new graph version to both
  stores plus the exact prior state needed to roll it back, and logging who did it. The new
  version is written **inactive** so nothing else silently retargets at an unreviewed graph.
  Fixes the catalogue marks as high-disruption require a named approver before this unlocks —
  a placeholder for the on-chain EIP-712 signature the real governance layer will eventually
  require (`docs/SCOPE.md` D7).

**Why it's there:** "remediation impact" as a judging criterion, with the two things that make
it a checkable claim rather than an assertion — re-derivation instead of bookkeeping, and a
before/after that can't hide a fix's side effects.

---

## 6. Validation (`/validation`)

**What it's for:** the screen every other team's product cannot show — measured proof that the
engine is actually correct, not just a claim that it is.

**What's on screen:**
- **Differential testing panel** — a second, deliberately dumb, exhaustive-search reference
  oracle is written independently from the same rules document the fast engine reads (never
  sharing code with it, so agreement between them is real evidence rather than two readings of
  the same bug). Run side by side across several small hand-built graphs plus a bounded slice
  of the real seeded graph: shown live at **91.7% agreement**, with every disagreement listed
  in full (never silently reconciled) so a judge can read exactly which path one search found
  that the other didn't and why.
- **Metrics table** — precision and recall at two match levels (exact route — same edges, same
  technique order; and right places — same target, any mechanism), F1, decoy-rejection rate,
  twin-acceptance rate, Kendall-τ and NDCG@10 (ranking quality — does the most dangerous path
  actually sit at the top of the list), expected calibration error and Brier score. Every metric
  states its denominator plainly (e.g. "6 of 6") rather than showing a bare ratio, and a metric
  that genuinely can't be computed yet (nothing to score against) says so instead of showing a
  misleading zero.
- **Calibration chart** — a hand-rolled scatter plotting what the engine predicted against what
  actually happened, per probability band. This is the check that separates "ranks well" from
  "the numbers can be trusted" — a model can order paths perfectly while still being badly
  overconfident about the actual chances, and calibration is the only way to catch that.
- **Ten invariants grid** — properties the engine must satisfy on *every* graph, not just ones
  anyone thought to test (e.g. removing an edge can never increase path count; the engine and
  the oracle must return identical results on any graph small enough for the oracle to finish;
  discovery must be exactly deterministic including tie order). Checked against graphs generated
  on the spot by perturbing a known world, not fixtures written to pass — currently **10 of 10
  held across 161 generated checks**.

**Why it's there:** every other team will *assert* correctness. This is the one screen that
*measures* it, live, against a ground truth the product itself published — which is the whole
argument for why this beats a plain reachability tool (`docs/SCOPE.md` D8/D9).

---

## 7. Audit Trail (`/audit`)

**What it's for:** proving the record of what happened can't have been silently rewritten —
and, just as important, proving the check can actually fail, not just always say yes.

**What's on screen:**
- **Chain status panel** — every recorded action is chained by hash to the one before it. This
  panel deliberately reports two separate things rather than one boolean: whether the local
  chain is internally self-consistent, and — separately — how far that self-check can actually
  be trusted right now, stated as a **tamper window in seconds** ("an attacker with database
  write access could have altered anything committed in the last N seconds without this check
  being able to tell"). A local hash chain that only checks itself against itself proves very
  little on its own (an attacker who can rewrite the database can recompute the whole chain);
  the honest fix is anchoring outside the database periodically, which is what shrinks that
  window.
- **Run verification** — actually re-derives the chain and checks it; a built-in test
  deliberately corrupts a real entry and confirms this panel renders **red** with the exact
  divergent entry number, not just green. A verify endpoint that can only ever say "valid" is
  checking a structure against itself and proves nothing.
- **Checkpoints and anchors** — publishes a Merkle root over the log at a point in time, outside
  the database. Three anchoring modes exist (a local dev chain, a real public testnet, and
  *replay* — serving a previously recorded session, clearly labeled "recorded," never passed off
  as a live transaction) so a demo can never die on bad wifi.
- **Entry log** — the paginated, filterable append-only record itself, with each row's leaf hash
  and per-entry salt visible on expand. The salt is why one entry can be proven without exposing
  the content of any other — audit entries are otherwise low-entropy and guessable, and an
  unsalted commitment would leak graph contents through a structure meant to hide them.

**Why it's there:** "governance," concretely, for a tool with domain-admin-equivalent power —
faultline can revoke credentials and disable accounts, so the tool that finds privilege
escalation cannot itself be an unguarded one (`docs/SCOPE.md` D7).

---

## 8. Settings (`/settings`)

**What it's for:** transparency about what's actually driving every number shown everywhere
else, plus the one control that resets the demo environment.

**What's on screen:**
- **Current state** — the active graph version (node/edge counts, seed, generation time), the
  active scoring configuration, the default threat model, and whether narration is running
  against a live model or the offline template fallback.
- **How paths are scored** — the exact table of per-technique base success chance and base
  detectability, plus the three top-level weights (likelihood / impact / stealth) that combine
  into every 0–10 score shown anywhere in the product. This screen exists specifically so
  "where did this number come from" always has a concrete, inspectable answer — nothing about
  scoring is invented in the interface.
- **Regenerate the demo data** — builds a brand-new synthetic graph at a chosen scale and seed
  and makes it active, with an explicit warning that every existing result stops being
  comparable the moment it finishes (used between demo runs, not mid-walkthrough).

**Why it's there:** the "nothing hardcoded" rule (`docs/SCOPE.md` D12) made checkable — a judge
can look at this screen and confirm that every color, weight, and threshold used elsewhere in
the product really does come from a database row, not a constant buried in the frontend.

---

## The official challenge reference resources — how they were used

The six resources in `Kurukshetra_2026_Problem_17_Participant_Resources.pdf` are logged in full,
with per-resource relevance notes, in `docs/REFERENCES.md`. Summary, in case a judge asks
directly:

- **ADSynth** (synthetic AD graph generator) — comparable in purpose to `backend/generator/`,
  not adopted directly. faultline's generator additionally emits a ground-truth manifest,
  planted decoy/twin pairs, and true per-edge probabilities for calibration — none of which
  ADSynth's scope covers, and all of which the Validation screen above depends on.
- **Neo4j Cybersecurity Graph Example** — a worked reference for modeling this domain in Neo4j,
  consistent with the decision to use Neo4j as the graph store (`docs/SCOPE.md` D12).
- **Plaintext — Path to Domain Admin Lab** — an educational walkthrough of real AD attack
  chains, cross-checked against the fifteen rules in `docs/RULES.md`: the technique set
  (kerberoasting, credential exposure, nested-group escalation, trust abuse) matches the attack
  patterns that lab teaches.
- **ADBloodHound-AI** — an LLM-augmented BloodHound analysis layer, adjacent to faultline's own
  (not-yet-built) narration component but not addressing precondition-aware search or
  ground-truth evaluation, which remain this product's differentiators.
- **BloodHound OpenGraph** and **AD-PathFinder's OpenGraph documentation** — the most relevant
  of the six. OpenGraph is the schema SpecterOps/NetSPI are converging on for attack-path data
  beyond AD-specific BloodHound. faultline's own schema (`node_id`/`kind_code`/`attrs` and
  `edge_id`/`type_code`/`attrs`) is conceptually a near-direct match to OpenGraph's
  `id`/`kinds`/`properties` shape — meaning an export endpoint that serialized faultline's graph
  into OpenGraph's ZIP/JSON format (letting a judge literally import faultline's synthetic graph
  into real BloodHound Community Edition) is a small, well-scoped addition given how close the
  two schemas already are. **Not built** — flagged in `docs/REFERENCES.md` as a candidate
  addition, not started, so say exactly that if asked rather than implying it exists.

If a judge specifically asks "did you use the provided resources or ignore them": the honest
answer is *evaluated all six, adopted none directly as dependencies, and used them as a
cross-check* — the Plaintext lab confirmed the rule set matches real-world attack patterns, and
OpenGraph is the one concrete interoperability opportunity identified but not yet built.
