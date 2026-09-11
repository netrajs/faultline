# faultline — Official Challenge Resources & External References

Source: `Kurukshetra_2026_Problem_17_Participant_Resources.pdf`, provided by the challenge
organizers for PS17 (Attack Path & Identity Privilege Graph Analyzer).

## Provided reference resources

| Resource | Link | Relevance to faultline |
|---|---|---|
| ADSynth — Synthetic AD Attack Graph Generator | https://github.com/AUCyberLab/ADSynth | Comparable in purpose to `backend/generator/`. Not adopted — our generator additionally emits a ground-truth manifest, planted decoy/twin pairs, and true per-edge probabilities for calibration, none of which are part of ADSynth's scope. |
| Neo4j Cybersecurity Graph Example | https://github.com/neo4j-graph-examples/cybersecurity | A worked example of modelling this domain in Neo4j; consistent with D12's choice of Neo4j as the graph store. |
| Plaintext — Path to Domain Admin Lab | https://plaintext-security.pages.dev/06-active-directory/modules/08-path-to-da/lab/ | An educational walkthrough of real AD attack chains. Cross-checked against `docs/RULES.md`'s fifteen rules — the technique set (kerberoasting, credential exposure, nested-group escalation, trust abuse) matches the realistic attack patterns this lab teaches. |
| ADBloodHound-AI | https://github.com/ayinedjimi/ADBloodHound-AI | An LLM-augmented BloodHound analysis layer. Adjacent to our narration component (D11) but does not address precondition-aware search or ground-truth evaluation, which remain our differentiators. |
| **BloodHound OpenGraph** | https://specterops.io/opengraph/ | SpecterOps' generalized ingest schema, extending BloodHound beyond Active Directory to arbitrary platforms. See below — the most relevant of the six resources. |
| AD-PathFinder OpenGraph Documentation | https://github.com/NetSPI/AD-PathFinder/blob/main/docs/OPENGRAPH.md | NetSPI's concrete implementation of an OpenGraph exporter. This is where the schema is actually documented (SpecterOps' own page is marketing copy without concrete field definitions) — see below. |

## BloodHound OpenGraph — schema notes and a possible interop opportunity

OpenGraph is the schema SpecterOps and NetSPI are converging on for representing attack-path
data outside the AD-specific BloodHound core, and both are pointed at by name in the official
resource list — worth assuming a judge may know it.

**Concrete schema** (from AD-PathFinder's documentation, since SpecterOps' own page does not
publish field-level details):

- **Node:** `id` (required, becomes the Neo4j `objectid`) · `kinds` (required, an array of Neo4j
  labels — the first non-`Base` kind is the primary merge label) · `properties` (optional flat
  JSON object; values are strings/ints/floats/bools or homogeneous lists of those — no `null`,
  no nested objects, no mixed-type lists). Label names must match `[A-Za-z_][A-Za-z0-9_]*`.
- **Edge:** `kind` (required, the Neo4j relationship type, same identifier rule) · `start` /
  `end` (endpoint objects, matched by `id`, `name`, or a `property_matchers` array) ·
  `properties` (optional, same value rules as node properties).
- **Ingest format:** a ZIP archive of JSON files (root or nested under plugin directories), each
  shaped `{"metadata": {"source_kind": "PluginName"}, "graph": {"nodes": [...], "edges": [...]}}`.

**How this compares to faultline's schema** (`docs/SCOPE.md` D12, `backend/db/migrations/001_core_graph.sql`):
conceptually aligned — our `node_id`/`kind_code`/`attrs` and `edge_id`/`type_code`/`attrs` map
directly onto OpenGraph's `id`/`kinds`/`properties` and `kind`/`start`+`end`/`properties`. The
concrete difference is `kind_code` (a single value) versus `kinds` (an array supporting multiple
labels per node, e.g. `["Base", "User"]`), and we have no ZIP/JSON export format today.

**Not built, and deliberately not assumed to be in scope without asking:** a
`GET /api/graph/export/opengraph` endpoint that serializes the active graph version into this
exact ZIP format would let a judge literally import faultline's synthetic graph into real
BloodHound Community Edition and explore it there. That would be a concrete, verifiable
"interoperates with the real ecosystem" demonstration — a materially different claim from
"we compared ourselves to BloodHound in our own slides." The engineering cost is small (a
serializer over data already fully modelled) precisely because our schema is already this close
to OpenGraph's shape. Flagged as a candidate Phase 5 addition, not started.
