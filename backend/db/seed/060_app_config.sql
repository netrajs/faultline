-- 060_app_config
--
-- Audit vocabulary, navigation, layout presets, saved queries and the demo
-- script.
--
-- The saved queries include one whose purpose is to be wrong. See its comment.

INSERT INTO audit_action (code, label, description, is_mutation, ui_color, sort_order) VALUES
  ('graph_generated',    'Graph generated',     'A synthetic graph was created and written to the stores.',    1, '#38bdf8',  1),
  ('analysis_run',       'Analysis run',        'Path discovery executed against a graph version.',            0, '#64748b',  2),
  ('fix_simulated',      'Fix simulated',       'A counterfactual was re-derived for a proposed fix.',         0, '#38bdf8',  3),
  ('fix_approved',       'Fix approved',        'A signed authorisation was recorded for a fix.',              0, '#8b5cf6',  4),
  ('fix_applied',        'Fix applied',         'A mutation was performed against the live graph.',            1, '#f59e0b',  5),
  ('fix_verified',       'Fix verified',        'The actual effect was compared against the prediction.',      0, '#10b981',  6),
  ('fix_rolled_back',    'Fix rolled back',     'A mutation was reverted to its recorded prior state.',        1, '#ef4444',  7),
  ('scoring_changed',    'Scoring changed',     'The active scoring configuration was altered.',               1, '#f59e0b',  8),
  ('checkpoint_created', 'Checkpoint created',  'A Merkle root was computed over the log.',                    0, '#8b5cf6',  9),
  ('checkpoint_anchored','Checkpoint anchored', 'A Merkle root was published outside this database.',          0, '#10b981', 10),
  ('demo_reset',         'Demo reset',          'State was restored to the canonical demonstration baseline.', 1, '#64748b', 11);


INSERT INTO nav_item (code, label, route, icon, description, is_enabled, sort_order) VALUES
  ('dashboard',   'Dashboard',    '/',            'chart-bar',       'Current risk posture at a glance.',                 1, 1),
  ('graph',       'Graph',        '/graph',       'topology-star-3', 'Explore the identity and asset graph.',             1, 2),
  ('paths',       'Attack paths', '/paths',       'route',           'Discovered paths, ranked, with their derivations.', 1, 3),
  ('blast',       'Blast radius', '/blast',       'circles',         'What a single compromise reaches.',                 1, 4),
  ('remediation', 'Remediation',  '/remediation', 'shield-check',    'Simulate and apply fixes.',                         1, 5),
  ('validation',  'Validation',   '/validation',  'checkup-list',    'Measured accuracy against known ground truth.',     1, 6),
  ('audit',       'Audit trail',  '/audit',       'link',            'Tamper-evident record and its external anchors.',   1, 7),
  ('settings',    'Settings',     '/settings',    'settings',        'Scoring weights, threat model, data generation.',   1, 8);


INSERT INTO layout_preset (code, label, description, engine, params, max_nodes, is_default, sort_order) VALUES
  ('force',        'Force directed', 'Organic clustering. Best for spotting dense neighbourhoods.',   'fcose',      '{"quality":"default","nodeRepulsion":8000,"idealEdgeLength":80,"animate":true}', 1500, 1, 1),
  ('hierarchical', 'Hierarchical',   'Layered by tier. Best for seeing escalation direction.',        'dagre',      '{"rankDir":"LR","nodeSep":40,"rankSep":120}',                                    800, 0, 2),
  ('concentric',   'Concentric',     'Rings by distance from an origin. Used by blast radius.',       'concentric', '{"minNodeSpacing":30,"levelWidth":1}',                                          1200, 0, 3),
  ('grid',         'Grid',           'Deterministic placement. Fastest, and stable between renders.', 'grid',       '{"avoidOverlap":true}',                                                         5000, 0, 4);


-- Saved Cypher for the Graph Explorer.
--
-- naive_reachability is the important one, and it is deliberately wrong.
--
-- It is what a reachability tool computes and calls an attack path list:
-- variable-length matching from any user to any crown jewel, with no notion of
-- what the attacker holds. Run against the same database the engine reads, it
-- returns far more results than the engine reports. The difference is the false
-- positives -- candidates requiring a capability the attacker does not have, or
-- refused by a hard block -- and every one has a recorded reason in
-- rejected_candidate.
--
-- Showing the two side by side is the clearest available demonstration of what
-- precondition-aware search buys, which is why this query is a first-class row
-- rather than something wired into a demo script.
INSERT INTO saved_query (code, label, description, cypher, purpose, parameters, is_enabled, sort_order) VALUES
  ('naive_reachability', 'Naive reachability (for contrast)',
   'Plain variable-length matching from users to crown jewels, ignoring preconditions entirely. Returns every route the graph permits, including those no attacker could walk. Compare its count against the engine.',
   'MATCH p = (u:User {graph_version: $graph_version})-[*1..6]->(c {graph_version: $graph_version, is_crown_jewel: true}) RETURN count(p) AS candidate_count',
   'contrast', '{"graph_version": 1}', 1, 1),

  ('crown_jewels', 'Crown jewels',
   'Every asset designated a high-value target, with its inbound relationship count.',
   'MATCH (n {graph_version: $graph_version, is_crown_jewel: true}) OPTIONAL MATCH (n)<-[r]-() RETURN n.node_id AS id, n.name AS name, labels(n)[0] AS kind, count(r) AS inbound ORDER BY inbound DESC',
   'explore', '{"graph_version": 1}', 1, 2),

  ('exposed_credentials', 'Exposed credentials',
   'Assets leaking authentication material, and where the material sits.',
   'MATCH (a {graph_version: $graph_version})-[e:EXPOSES_CREDENTIAL]->(c:Credential) RETURN a.name AS asset, c.name AS credential, e.location AS location, c.storage AS storage ORDER BY e.discoverable DESC',
   'explore', '{"graph_version": 1}', 1, 3),

  ('nested_groups', 'Nested group chains',
   'Group nesting three or more levels deep, where inherited permission stops being reasonable to trace by hand.',
   'MATCH p = (g1:Group {graph_version: $graph_version})-[:MEMBER_OF*3..]->(g2:Group) RETURN g1.name AS start_group, g2.name AS end_group, length(p) AS depth ORDER BY depth DESC LIMIT 25',
   'explore', '{"graph_version": 1}', 1, 4),

  ('orphaned_nodes', 'Orphaned nodes',
   'Nodes with no relationships at all. Usually a generation defect rather than a finding.',
   'MATCH (n {graph_version: $graph_version}) WHERE NOT (n)--() RETURN labels(n)[0] AS kind, n.node_id AS id, n.name AS name',
   'diagnostic', '{"graph_version": 1}', 1, 5);


INSERT INTO demo_step (step_no, title, route, narration, criterion, expected_duration_seconds) VALUES
  ( 1, 'Risk posture',       '/',
   'Open on the current state: how many paths exist, how many reach crown jewels, and what the overall exposure looks like.',
   'context', 40),
  ( 2, 'The contrast',       '/graph',
   'Run the naive reachability query against the same database. It returns a large number. The engine reports far fewer. The gap is the false positives, and every one has a reason.',
   'path_correctness', 70),
  ( 3, 'Why it was refused', '/validation',
   'Open the refusals. Each names the rule and the precondition that failed. The clearest case is a credential exposure the attacker cannot read because they lack administrative control of the host holding it.',
   'path_correctness', 60),
  ( 4, 'Measured accuracy',  '/validation',
   'Run the evaluation harness live: precision, recall and F1 against ground truth the generator recorded, with decoy rejection and twin acceptance side by side.',
   'path_correctness', 70),
  ( 5, 'The top path',       '/paths',
   'Take the highest-ranked path and walk its hops, each with its technique and its contribution to the score.',
   'risk_prioritization', 60),
  ( 6, 'Why this score',     '/paths',
   'Open the factor breakdown. Every number decomposes into the baseline and the modifiers that moved it, because the score is a sum of log terms.',
   'explainability', 60),
  ( 7, 'Blast radius',       '/blast',
   'Compromise the source of that path and show what it reaches, weighted by how likely each reach actually is.',
   'remediation_impact', 50),
  ( 8, 'Which fix first',    '/remediation',
   'Show the ranked fixes and the chokepoint severing the most paths, with the optimality gap stated rather than implied.',
   'remediation_impact', 60),
  ( 9, 'Simulate',           '/remediation',
   'Simulate the top fix. The counterfactual is a full re-derivation, not bookkeeping, so before and after are two real result sets.',
   'remediation_impact', 60),
  (10, 'Apply and verify',   '/remediation',
   'Apply it, then re-derive against the live graph and compare actual against predicted. The fidelity number is the claim being checked.',
   'remediation_impact', 60),
  (11, 'The record',         '/audit',
   'Show the entry in the append-only log, its inclusion proof against the published root, and the tamper window in seconds.',
   'explainability', 60),
  (12, 'Posture after',      '/',
   'Return to the dashboard and compare against where we started.',
   'context', 30);
