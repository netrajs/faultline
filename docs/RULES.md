# faultline — Attacker Model and Rule Specification

> **This document is the specification, not documentation of the code.** The fast engine and
> the independent reference oracle are both written *from this file*, separately. That
> independence is what makes their agreement evidence of anything. If the two disagree, this
> document decides which is wrong — and if this document is ambiguous, that is the bug.
>
> Rules live in the `rule`, `rule_precondition` and `rule_effect` tables. This file explains
> what those rows mean and why each one is there.

---

## 1. The model

An attacker occupies a **state**: a set of capabilities they currently hold. A **rule** says
that when certain capabilities are held and certain facts are true of the graph, the attacker
may perform a **technique**, which grants further capabilities.

Discovery is a search over states, not over nodes. This is the single most important sentence
in the specification. A tool that searches over nodes answers "is there a route through the
graph"; searching over states answers "is there a sequence of actions an attacker could
actually perform", and those are different questions with different answers.

### 1.1 Why the distinction matters

Take a host that exposes a service-account credential in a configuration file. Every
reachability tool sees `Host --EXPOSES_CREDENTIAL--> Credential` and traverses it. But reading
a file on a host requires being able to read files on that host. If the attacker has merely
*authenticated* to the host as an unprivileged user, the credential is not available to them;
if they have administrative control, it is.

The edge is identical in both cases. The graph cannot tell you which situation you are in.
Only the attacker's held state can.

### 1.2 Monotonicity

Capabilities are never lost. An attacker who gains administrative control of a host does not
subsequently lose it because they moved elsewhere.

This assumption is doing real work:

- **It makes the search tractable.** Every useful transition strictly grows the capability set,
  so the state space is a directed acyclic graph by construction, even though the underlying
  identity graph is full of cycles. The same assumption is what takes MulVAL-style analysis from
  exponential to polynomial.
- **It dissolves the cycle problem.** Host A trusting host B trusting host A is a cycle in the
  graph. In the state space it is not: the second traversal grants nothing new and is pruned by
  dominance.
- **It is an approximation, and we say so.** Credential rotation and account lockout really do
  revoke capabilities. Modelling that would require non-monotonic reasoning and a far larger
  search space. The honest framing is that faultline computes what an attacker could achieve
  *if uninterrupted*, which is the correct question for prioritising defences.

### 1.3 State dominance

A state `(node, C₁)` dominates `(node, C₂)` when `C₂ ⊆ C₁` and the path reaching `C₁` is at
least as probable. Dominated states are pruned. Without this the search does not terminate in
useful time; with it, the frontier stays small because most transitions are redundant.

---

## 2. Capability atoms

| Code | Scope | Meaning |
|---|---|---|
| `authenticated` | global | Holds some valid identity in the directory. Enough to make authenticated requests. |
| `controls_principal` | node | Can act as this user or service account. |
| `holds_credential` | node | Possesses this credential's material. |
| `member_effective` | node | Is effectively a member of this group, including through nesting. |
| `network_reach` | node | Can reach this asset over the network. |
| `access_to` | node | Authenticated, non-administrative access to this asset. |
| `admin_on` | node | Administrative control of this asset. |
| `code_exec_on` | node | Can execute code on this host. |
| `can_read_secret` | node | Can read secret material stored on this asset. |

Two of these are load-bearing in a way that is easy to miss.

`access_to` and `admin_on` are **not** ordered by a single privilege level — they are separate
capabilities, and rules ask for exactly the one they need. This is deliberate. A model with a
numeric privilege level invites comparisons like `level >= 2`, which quietly makes every
high-privilege capability imply every lower one, and that is false: database administrator does
not imply host administrator.

`can_read_secret` is separate from `admin_on` because the two come apart in both directions.
A vault gives read access to secrets without host administration; full-disk encryption can give
host administration without readable secrets.

---

## 3. Threat models

Where the attacker starts. Held as data so the same graph can be analysed under different
assumptions — and the comparison is itself interesting, because a path that is critical for an
insider may be unreachable for an outsider.

| Code | Starting capabilities |
|---|---|
| `external_phish` | `controls_principal` over one standard non-administrative user, plus `authenticated`. The default. |
| `insider_standard` | `authenticated`, plus `controls_principal` over their own account and `network_reach` to internal assets. |
| `contractor_device` | `controls_principal` over one contractor account, `network_reach` limited to assets reachable from the VPN segment. |
| `public_only` | No identity. Only `network_reach` to public-facing assets. The hardest starting position, and the one that makes an exposed public credential genuinely alarming. |

---

## 4. Rules

Every rule below states its preconditions as a conjunction. Disjunction is expressed by writing
two rules, which keeps the evaluator trivial and — more importantly — keeps every refusal
attributable to exactly one unmet condition.

Notation: `src` and `dst` are the endpoints of the traversed edge. `E.attr` is an edge
attribute, `N.attr` a node attribute.

---

### R1 · `group_membership` — inherit group membership

**Edge:** `MEMBER_OF` (User → Group, or Group → Group)
**Technique:** T1078 Valid Accounts

| | |
|---|---|
| Preconditions | `controls_principal(src)` **or** `member_effective(src)` for a nested group; `src.account_status = 'active'`; `dst.type = 'security'` |
| Effects | `member_effective(dst)` |
| Base probability | 0.99 — this is simply how directory membership works, not an exploit |

**Why `dst.type = 'security'`:** distribution groups convey no authorisation. A tool that
traverses them reports paths through mailing lists. *(Decoy D13.)*

Nesting is handled by the rule applying to itself: `member_effective(GroupA)` plus
`MEMBER_OF(GroupA → GroupB)` yields `member_effective(GroupB)`, to arbitrary depth, with the
fixpoint terminating because membership is finite.

---

### R2 · `group_permission_admin` — administrative rights via a group

**Edge:** `HAS_PERMISSION` (Group → Host | Database | CloudResource | Application)
**Technique:** T1078.002 Valid Accounts: Domain Accounts

| | |
|---|---|
| Preconditions | `member_effective(src)`; `E.permission_level = 'admin'` |
| Effects | `admin_on(dst)`, `access_to(dst)` |
| Base probability | 0.97 |

### R3 · `group_permission_access` — non-administrative access via a group

Identical to R2 but `E.permission_level IN ('read_write', 'read_only', 'execute')`, and the
only effect is `access_to(dst)`.

**Why these are two rules:** a read-only grant must not confer administrative control. Splitting
them makes that structural rather than a conditional somebody can get wrong, and it means a
refusal can point at the permission level as the reason. *(Decoy D3.)*

---

### R4 · `direct_admin` — directly assigned administrative rights

**Edge:** `ADMIN_TO` (User | ServiceAccount → Host | Database | CloudResource)
**Technique:** T1078 Valid Accounts

| | |
|---|---|
| Preconditions | `controls_principal(src)`; `src.account_status = 'active'` |
| Effects | `admin_on(dst)`, `access_to(dst)` |
| Base probability | 0.98 |

**Why `account_status`:** a disabled account's assignments persist in the directory long after
the account stops working. Reporting a path through one is a false positive that wastes an
analyst's afternoon. *(Decoy D4.)*

---

### R5 · `service_account_access` — service account's own grants

**Edge:** `HAS_ACCESS_TO` (ServiceAccount → Database | Application | CloudResource)
**Technique:** T1078.004 Valid Accounts: Cloud Accounts

| | |
|---|---|
| Preconditions | `controls_principal(src)` |
| Effects | `access_to(dst)`; additionally `admin_on(dst)` when `E.permission_level = 'admin'` |
| Base probability | 0.97 |

---

### R6 · `credential_from_principal` — use a principal's own credential

**Edge:** `HAS_CREDENTIAL` (User | ServiceAccount → Credential)
**Technique:** T1078 Valid Accounts

| | |
|---|---|
| Preconditions | `controls_principal(src)` |
| Effects | `holds_credential(dst)` |
| Base probability | 0.99 |

---

### R7 · `credential_dump` — read a credential exposed on a compromised asset

**Edge:** `EXPOSES_CREDENTIAL` (Host | Application → Credential)
**Technique:** T1552.001 Unsecured Credentials: Credentials In Files / T1003 OS Credential Dumping

| | |
|---|---|
| Preconditions | `admin_on(src)` **or** `can_read_secret(src)`; `E.location ≠ 'vault'`; `dst.storage ≠ 'vault'` |
| Effects | `holds_credential(dst)`, `can_read_secret(src)` |
| Base probability | 0.85 |

**This is the rule that separates faultline from a reachability tool.**

The `admin_on(src)` precondition is the whole argument. A reachability tool sees the
`EXPOSES_CREDENTIAL` edge and takes it, because the edge exists. But reading a secret out of a
configuration file, a memory dump, or an environment variable requires privileged access to the
thing holding it. An attacker with unprivileged access to the host cannot do it.

The same graph, the same edge, two different answers depending on state. No query language can
express this, which is why the engine is not a query. *(Decoy D8.)*

**Why the vault exclusion:** a credential referenced from a config but stored in a vault is not
readable by dumping the config; the config contains a pointer, not a secret. *(Decoy D2.)*

---

### R8 · `credential_public_exposure` — credential exposed with no access control

**Edge:** `EXPOSES_CREDENTIAL` where `E.location IN ('public_repo', 'public_bucket', 'paste_site')`
**Technique:** T1552 Unsecured Credentials

| | |
|---|---|
| Preconditions | *none* |
| Effects | `holds_credential(dst)` |
| Base probability | 0.95 |

The counterpart to R7, and the reason R7's precondition is not simply "always require admin".
A secret in a public repository requires nothing at all — which is precisely why it is
catastrophic, and why it must remain reachable from the `public_only` threat model.

---

### R9 · `credential_authenticate` — authenticate with a held credential

**Edge:** `AUTHENTICATES_TO` (Credential → Host | Application | CloudResource | Database)
**Technique:** T1078 Valid Accounts / T1550 Use Alternate Authentication Material

| | |
|---|---|
| Preconditions | `holds_credential(src)`; **not** (`E.mfa_required = true` **and** `E.mfa_type IN ('fido2', 'webauthn', 'piv')`); `dst.status ≠ 'decommissioned'` |
| Effects | `access_to(dst)`; additionally `admin_on(dst)` when `E.scope = 'admin'` |
| Base probability | 0.93 |

**MFA is a hard block, not a penalty — but only phishing-resistant MFA.** This distinction
matters more than it might appear.

Modelling MFA as a smooth multiplier ("halve the probability") is wrong in both directions. It
overstates the risk of FIDO2, which genuinely cannot be defeated by credential replay, and it
*understates* the risk of SMS and push, which are routinely defeated by adversary-in-the-middle
and MFA fatigue. A single multiplier cannot represent both.

So: phishing-resistant factors block the rule outright. Weaker factors apply a probability
penalty via the scoring modifiers, and remain traversable. *(Decoy D1 and its twin turn on
exactly this attribute.)*

---

### R10 · `kerberoast` — request and crack a service ticket

**Edge:** none. This rule fires on state alone (`is_traversal = 0`).
**Technique:** T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting

| | |
|---|---|
| Preconditions | `authenticated`; target is a `ServiceAccount` with `N.has_spn = true`; the account's credential has `strength ≠ 'strong'` |
| Effects | `holds_credential(<the account's credential>)` |
| Base probability | 0.70 |

Any authenticated domain user can request a service ticket for any account with a service
principal name — no special privilege is needed, which is what makes kerberoasting so
persistent. The constraint is offline cracking, so credential strength decides it. A strong
random password on an SPN account is not crackable in practice, and reporting it as an attack
path is a false positive. *(Decoy D6.)*

This is the clearest case for a non-traversal rule: nothing in the graph connects the attacker
to the service account. The capability arrives from a property of the directory itself.

---

### R11 · `host_trust` — move laterally across a trust relationship

**Edge:** `TRUSTS` (Host → Host)
**Technique:** T1021 Remote Services / T1199 Trusted Relationship

| | |
|---|---|
| Preconditions | `admin_on(src)` **or** `code_exec_on(src)`; the edge is traversed in its stored direction unless `E.bidirectional = true` |
| Effects | `code_exec_on(dst)`; additionally `admin_on(dst)` when `E.trust_type IN ('kerberos_delegation', 'ssh_key_trust')` |
| Base probability | 0.80 |

**Direction is not decorative.** A one-way trust traversed backwards is a false positive, and
it is an easy one to produce because undirected thinking about "connected hosts" is the default.
*(Decoy D5.)*

Unconstrained Kerberos delegation confers administrative control; a plain RDP trust confers
code execution and no more. Hence the split effect.

---

### R12 · `remote_exploit` — exploit a remotely reachable vulnerability

**Edge:** `HAS_VULNERABILITY` (Host | Application → Vulnerability)
**Technique:** T1190 Exploit Public-Facing Application / T1210 Exploitation of Remote Services

| | |
|---|---|
| Preconditions | `network_reach(src)`; `dst.impact = 'RCE'`; `dst.attack_vector = 'network'`; `src.patch_level ≠ 'current'` |
| Effects | `code_exec_on(src)`, `access_to(src)` |
| Base probability | derived from the vulnerability's EPSS score, not a constant |

**Why EPSS rather than CVSS for the probability.** CVSS measures severity — how bad it is if
exploited. EPSS estimates the probability of exploitation in the wild. The likelihood axis needs
the second one. Using CVSS as a probability is a category error that inflates the score of
severe-but-unexploited vulnerabilities and buries the mundane ones being actively used.
CVSS still contributes, but to the impact axis where it belongs. *(Decoy D7 turns on patch
level.)*

---

### R13 · `local_privilege_escalation` — escalate on a host already compromised

**Edge:** `HAS_VULNERABILITY`
**Technique:** T1068 Exploitation for Privilege Escalation

| | |
|---|---|
| Preconditions | `code_exec_on(src)`; `dst.impact = 'privilege_escalation'`; `src.patch_level ≠ 'current'` |
| Effects | `admin_on(src)`, `can_read_secret(src)` |
| Base probability | derived from EPSS |

The pairing of R12 and R13 is why `code_exec_on` and `admin_on` are separate capabilities. A
remote exploit typically yields code execution as a service account; administrative control is
a second, separate step. Collapsing them into one "compromised" flag would silently skip a hop
that real attackers have to perform, and would make R7's precondition satisfiable when it should
not be.

---

### R14 · `cloud_role_assumption` — pivot between cloud resources

**Edge:** `CONNECTED_TO` (CloudResource → CloudResource)
**Technique:** T1078.004 Valid Accounts: Cloud Accounts / T1548 Abuse Elevation Control Mechanism

| | |
|---|---|
| Preconditions | `access_to(src)` **or** `admin_on(src)`; `E.connection_type = 'iam_assume_role'` |
| Effects | `access_to(dst)`; additionally `admin_on(dst)` when `E.grants_admin = true` |
| Base probability | 0.90 |

---

### R15 · `network_pivot` — reach a new asset from a compromised one

**Edge:** `CONNECTED_TO` (CloudResource → CloudResource) with `connection_type IN ('vpc_peering', 'security_group', 'service_mesh')`
**Technique:** T1021 Remote Services

| | |
|---|---|
| Preconditions | `code_exec_on(src)` **or** `admin_on(src)` |
| Effects | `network_reach(dst)` |
| Base probability | 0.95 |

Network adjacency grants *reachability*, not access. Conflating the two is how segmentation
gets modelled as though it were authorisation. `network_reach` on its own does nothing until
some other rule consumes it — R12, for instance. *(Decoy D9.)*

---

## 5. Negative controls

Fourteen decoy patterns. Each ships with a **twin** that is a genuine attack path and differs in
**exactly one attribute**.

The twins are not a nicety. Without them, an engine could pass every decoy by refusing anything
that smells suspicious — or by refusing everything, which scores perfectly on precision. With
them, passing requires actually evaluating the deciding attribute, because the decoy and the
twin are otherwise indistinguishable.

| # | Deciding attribute | Decoy (must reject) | Twin (must accept) | Rule |
|---|---|---|---|---|
| D1 | `AUTHENTICATES_TO.mfa_type` | `fido2` — phishing-resistant | `sms` — replayable | R9 |
| D2 | `Credential.storage` | `vault` — config holds a pointer | `config_file` — config holds the secret | R7 |
| D3 | `HAS_PERMISSION.permission_level` | `read_only` | `admin` | R2/R3 |
| D4 | `User.account_status` | `disabled` — stale assignment | `active` | R4 |
| D5 | `TRUSTS.bidirectional` | `false`, traversed backwards | `true` | R11 |
| D6 | `Credential.strength` | `strong` — not crackable offline | `weak` | R10 |
| D7 | `Host.patch_level` | `current` | `behind-2+` | R12 |
| D8 | held capability | only `access_to(host)` | `admin_on(host)` | R7 |
| D9 | `CONNECTED_TO` present | absent — segmented | present | R15 |
| D10 | `Credential.is_active` | `false` — already rotated | `true` | R6/R9 |
| D11 | `ServiceAccount.is_interactive` | `false` — no interactive logon | `true` | R9 |
| D12 | `Database.requires_separate_key` | `true` and key not held | `false` | R5 |
| D13 | `Group.type` | `distribution` | `security` | R1 |
| D14 | `AUTHENTICATES_TO.requires_compliant_device` | `true`, no compliant device held | `false` | R9 |

D8 deserves emphasis: it is the only one where the deciding factor is not a graph attribute at
all, but the attacker's own state. The decoy and the twin can be structurally identical — same
nodes, same edges, same attributes — and differ only in what the attacker managed to acquire
before arriving. No amount of graph inspection distinguishes them. That is the case for
state-space search stated as a test.

### 5.1 Missing-attribute semantics

Every implementation reading `rule_precondition`/`scoring_modifier` rows must agree on what
happens when the attribute a check reads is simply absent from the edge or node — e.g.
`mfa_type not_in [...]` when no `mfa_type` key exists at all. This document did not previously
say, which is a defect: the oracle and the engine are meant to be written from this document
*independently*, and an unstated rule is a rule each side is free to guess differently, silently
turning "the two disagree" into noise instead of evidence.

**The rule:** absence makes `eq`, `in`, `lt`, `lte`, `gt`, `gte` and `exists` evaluate **false**,
and makes `ne`, `not_in` and `absent` evaluate **true** — i.e. absence behaves as if the attribute
held a value that satisfies none of the "does this exist and match" operators and all of the
"does this differ or not-exist" operators. This is not an arbitrary pick: it is the one rule that
keeps every operator pair an exact complement under `is_negated`, so negating a precondition never
needs a second special case for the absent branch.

---

## 6. Probability composition

Per hop, the base probability from `technique_baseline` is adjusted by every applicable
`scoring_modifier`, applied additively in log-odds:

```
logit(p') = logit(p_base) + Σ βᵢ         then clamped to [0.001, 0.995]
```

Log-odds rather than multiplication because a multiplicative penalty can push a probability
above 1, at which point `−ln(p)` goes negative, Dijkstra's correctness guarantee is void, and a
graph that deliberately contains trust cycles acquires negative cycles. Additive log-odds cannot
leave `(0,1)`, and each `βᵢ` is directly reportable as that factor's contribution.

Along a path:

```
P_path = Π p_succ           computed as exp(−Σ −ln p_succ), in float64
```

The attacker must succeed at every hop, so the path probability is the product. Length is
therefore penalised automatically and by the correct amount, which is why there is no hop-count
decay term anywhere in the model.

`p_undetected = Π (1 − detectability)` accumulates separately and is never folded into the
success probability. Keeping them apart is what prevents the double-counting that a combined
edge weight plus a length penalty would produce.

Detection and success are reported as two numbers because they answer different questions:
*will this work* and *will anyone notice*. A path with high success and high detectability is a
different problem from one with moderate success and none.

---

## 7. Invariants

These hold for any graph and any threat model. They are property tests, and a violation is a
bug in the engine, not in the test.

1. Removing an edge never increases the number of discovered paths.
2. Removing an edge never increases any path's probability.
3. Adding a hard-block attribute (phishing-resistant MFA, vault storage) never increases path
   count or probability.
4. Increasing any `base_p_succ` never decreases the probability of a path using that technique.
5. Every discovered path's hops each satisfy their rule's preconditions given the state
   accumulated by the preceding hops — checkable independently of the search that produced it.
6. Every path probability lies in `(0, 1]`; every display score lies in `[0, 10]`.
7. Blast radius after applying a fix is a subset of blast radius before, unless the fix is one
   whose simulation predicted additions.
8. The engine and the reference oracle return identical path sets on any graph small enough for
   the oracle to finish.
9. Every rejected candidate names a precondition that genuinely fails under the state recorded
   with it.
10. Discovery is deterministic: the same graph, threat model and scoring version produce
    identical results, including tie ordering.
