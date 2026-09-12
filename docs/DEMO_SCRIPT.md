# faultline — Demo Script

A ~8-minute walkthrough, screen by screen, built around one thread: **a single crown jewel,
followed from "here's the risk" through "here's the proof it's real" to "here's the fix,
verified before and after."** Keep the same target asset in view the whole time so the story
reads as one investigation, not eight disconnected screens.

Pair this with [`docs/UI_REFERENCE.md`](UI_REFERENCE.md) beforehand — that document is the
answer key for any question a judge asks about *why* something on screen exists; this script is
only the *order* to show things in.

---

## Before you start

- `/settings` → confirm the active graph version and, if you want a clean run, use **Regenerate
  the demo data** a few minutes ahead of time (never mid-demo — it's a multi-minute operation and
  invalidates every number currently on screen).
- Have `/graph`, `/paths`, `/blast`, `/remediation`, `/validation`, and `/audit` each open in a
  tab ahead of time if your setup allows, so no navigation click is ever a live gamble.
- Know your one target crown jewel and its highest-ranked incoming path before you start —
  pick it from `/paths` sorted by risk score, note the id, and use the *same* one in every
  later screen.

---

## 1. Dashboard — open on the worst finding, not a summary (30s)

Land on `/`. Point at the **Spotlight hero** first, not the stat cards: *"this is not a
dashboard that opens on a summary chart — it opens on the single worst thing happening right
now."* Name the risk tier and the crown jewel it reaches. Then sweep the five stat cards and
the tier breakdown for scale: total paths, rejected candidates, crown jewels reached.

**Say:** "Everything after this is me proving that number is actually trustworthy, not just
computed once and displayed."

---

## 2. Graph Explorer — the central claim, live (90s — the most important 90 seconds)

Go to `/graph`, straight to the **contrast panel**. Run the naive reachability query and the
engine's own verified count side by side, on the same graph, live.

**Say:** "This is the whole pitch in one screen. A BloodHound-style reachability query says 61
ways in. faultline says 4 — because it checks every precondition a real attacker needs, not just
whether an edge exists. Those other 57 are false positives, and each one has a name — the engine
tells you exactly which precondition failed, for every single one, not just 'not reachable.'"

Click into the node browser briefly to show the underlying graph is real and inspectable, not a
canned picture — search for the crown jewel you picked, show its incident edges.

---

## 3. Attack Paths — the derivation, not just the score (90s)

Go to `/paths`, filter or sort to your chosen path, open its detail view.

Walk the **flow diagram** left to right, naming each hop's technique. Click one hop and open
its **factor waterfall**.

**Say:** "This bar chart is not an approximation of why this hop scored what it did — because
the model is additive in log-odds space, this *is* the exact decomposition. Weak MFA contributed
this much, this credential type contributed that much. Nothing here is a black-box score."

---

## 4. Blast Radius — the same asset, the other direction (60s)

Go to `/blast`, search for the same crown jewel (or the entry point you used above — pick
whichever makes the point better: *"what else could this same attacker reach from here"* or
*"what upstream compromise would let someone reach this"*).

**Say:** "Attack Paths asks 'how do they get to this one target.' This asks the opposite
question: 'if this one thing goes first, what's the entire footprint' — and every branch here is
still weighted by how likely that hop actually is, not just whether it's graph-reachable."

Point out the tree depth-by-depth, the crown-jewel gold ring if one other than your target shows
up, and the exact-numbers table underneath as the non-visual source of truth.

---

## 5. Remediation — rank, simulate, prove, apply (2 min — the second-most important stretch)

Go to `/remediation`. Click **Rank fixes** live if time allows (otherwise use a run from just
before the demo).

**Say:** "This isn't a heuristic top-5 list. Underneath it is an exact minimum cut — the
smallest possible number of nodes that would sever every path we found — so every fix below is
measured against a real floor, not a guess."

Open the top-ranked fix. Show its rationale and lifecycle state, then click **Simulate this
fix**.

**Say, while it runs:** "This isn't bookkeeping subtracting the path we just cut — it's a full
re-derivation against the mutated graph from scratch, because a fix can create new problems as
easily as it removes old ones. That's why this takes real time and runs in the background instead
of freezing the page." *(If it finishes in time, show the before/after diff — call out removed
vs. added vs. rescored counts explicitly, especially if anything got added.)* *(If it's still
running, that's fine — narrate what the diff will show and move on; come back to it after step 7
if it's ready.)*

If you have time, click **Apply this fix** and show the `VideoLoadingOverlay` — narrate that a
real graph mutation with rollback state is being written, not a UI-only toggle.

---

## 6. Validation — the proof this all can be trusted (90s)

Go to `/validation`.

**Say:** "Every other team in this room is going to tell you their engine is correct. This
screen is the difference — we measure it."

Point at:
- **Differential panel** — an independently written, deliberately dumb oracle agreeing with the
  fast engine 91.7% of the time, with every disagreement listed rather than hidden.
- **Metrics table** — precision/recall, decoy-rejection, and specifically the **calibration
  error and Brier score** — *"a model can rank things perfectly and still lie about the actual
  odds; this is the check that catches that."*
- **Ten invariants, 161 checks, all held** — *"properties that must hold on any graph, not just
  ones we thought to test — generated fresh, not fixtures written to pass."*

---

## 7. Audit Trail — governance for a tool that can revoke access (60s)

Go to `/audit`.

**Say:** "faultline can apply remediations for real — revoke a credential, disable an account.
A tool with that power over identity needs its own audit trail that can't be quietly edited."

Run **verify** live. Then, if a corrupted-entry fixture or prior corrupted run is available, show
the panel turn **red** with the exact divergent entry — *"it's not just a check that always says
yes — we can prove it actually catches tampering."* Point at the **tamper window** figure and
explain in one sentence why a local hash chain alone isn't enough (anyone with DB write access
could recompute it) and why the checkpoint/anchor step exists.

---

## 8. Close — back to Dashboard (20s)

Return to `/`.

**Say:** "One finding, followed all the way through: discovered, explained down to the factor,
its blast radius mapped, a fix ranked against a real optimal, simulated before being trusted,
applied with rollback state, and every step of that logged somewhere that can prove it wasn't
tampered with. That's the full loop — not eight separate features."

---

## If something breaks live

- **Simulate/verify running long** — narrate what it's doing and move on to the next screen;
  come back to it once it settles rather than standing at a spinner.
- **Anchoring endpoint unreachable** — the audit screen's *replay* mode exists exactly for this;
  say plainly "this is a recorded run, shown because live testnet access isn't guaranteed in this
  room" — never present a replay as live.
- **A judge asks about a metric mid-flow** — it's fine to jump to `/validation` out of order; the
  screens don't depend on being shown in this exact sequence, only the crown-jewel thread across
  Dashboard → Paths → Blast Radius → Remediation benefits from staying in order.
