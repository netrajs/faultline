-- 080_rule_disjunctions
--
-- Five rules, closing five gaps the reference oracle found by evaluating the
-- rule rows against docs/RULES.md rather than against the engine.
--
-- Section 4 of that document states five preconditions as a disjunction --
-- "A or B" -- and says in the same breath how a disjunction is written: "two
-- rules, which keeps the evaluator trivial and, more importantly, keeps every
-- refusal attributable to exactly one unmet condition". 020_attacker_model
-- seeded only the first disjunct of each. The evaluator was right; the data
-- was half a rule short in five places.
--
-- What each omission cost:
--
--   R1  group_membership       Nested membership was unreachable. A
--                              Group -> Group MEMBER_OF edge needs
--                              controls_principal over a *group*, and nothing
--                              in the model grants that -- so the nesting
--                              docs/RULES.md R1 explicitly describes ("the rule
--                              applying to itself ... to arbitrary depth") could
--                              never happen, and the planted nested-group
--                              escalation was undiscoverable.
--   R7  credential_dump        can_read_secret was a dead capability: R4, R7
--                              and R13 all grant it and nothing consumed it.
--                              docs/RULES.md section 2 argues at length that it
--                              is separate from admin_on precisely because a
--                              vault gives one without the other; with only the
--                              admin_on disjunct seeded, that argument had no
--                              effect on any search.
--   R11 host_trust             A host where the attacker has code execution but
--                              not administrative control could not be pivoted
--                              from, which is the ordinary post-RCE position
--                              R12 leaves them in.
--   R14 cloud_role_assumption  Low impact in practice, since R2 and R4 grant
--                              access_to and admin_on together -- but a resource
--                              reached by a rule granting only admin_on was
--                              wrongly a dead end.
--   R15 network_pivot          Effectively dead. No seeded rule grants
--                              code_exec_on about a CloudResource, so the sole
--                              seeded conjunct was unsatisfiable and the rule
--                              could never fire on the graphs this model
--                              produces.
--
-- Each new rule keeps its original's technique, edge type, every other
-- precondition and every effect, and differs only in the capability row. That
-- is what makes it the same rule under its alternate precondition rather than a
-- new one: the two rows together are one disjunction, and either firing means
-- the technique in docs/RULES.md was performed.
--
-- The new rules sort after the existing fifteen rather than beside the rules
-- they complete. Renumbering sort_order would rewrite rows another migration
-- has already applied, and ordering is a display and enumeration convention
-- here, not semantics.


-- ── Rules ────────────────────────────────────────────────────────────────────

INSERT INTO rule (code, technique_code, edge_type_code, description, is_traversal, is_enabled, sort_order) VALUES
  ('group_membership_nested',       'group_membership',     'MEMBER_OF',    'Inherit a security group''s membership through a group already effectively held. R1''s second disjunct.',        1, 1, 16),
  ('credential_dump_secret_read',   'credential_in_files',  'EXPOSES_CREDENTIAL', 'Read a credential exposed on an asset whose secrets the attacker can already read. R7''s second disjunct.', 1, 1, 17),
  ('host_trust_code_exec',          'trusted_relationship', 'TRUSTS',       'Move across a host trust from a host where code execution is held. R11''s second disjunct.',                      1, 1, 18),
  ('cloud_role_assumption_admin',   'assume_role',          'CONNECTED_TO', 'Assume a role from a cloud resource the attacker administers. R14''s second disjunct.',                          1, 1, 19),
  ('network_pivot_admin',           'remote_services',      'CONNECTED_TO', 'Reach a connected resource from one the attacker administers. R15''s second disjunct.',                          1, 1, 20);


-- ── Preconditions ────────────────────────────────────────────────────────────
--
-- Every non-capability row is copied verbatim from the rule being completed,
-- including its failure_reason: the same condition failing for the same reason
-- should read identically whichever disjunct was being tried.

INSERT INTO rule_precondition (rule_id, seq, kind, binding, capability_code, attr_path, operator, value_json, is_negated, failure_reason) VALUES
  -- R1, second disjunct. src is a Group here, not a User.
  --
  -- account_status is kept rather than dropped, and the reason is worth stating
  -- because it looks at first like a row that cannot apply. A Group carries no
  -- account_status, and under the missing-attribute rule now written down in
  -- docs/RULES.md section 5.1 an absent attribute makes `ne` evaluate true --
  -- so on a Group -> Group edge the row passes and does not block the nesting
  -- this rule exists to enable. That is the correct answer on the merits: a
  -- group has no notion of being disabled, so "is this principal disabled?"
  -- should not be able to refuse it.
  --
  -- Keeping the row costs nothing and buys the case it was written for. R1's
  -- edge is "User -> Group, or Group -> Group", and member_effective is a
  -- capability a User could hold about themselves only if some future rule
  -- granted it that way; if one ever does, a disabled account must not inherit
  -- through this rule any more than it does through the first disjunct.
  -- Omitting the row would make the two disjuncts disagree about a disabled
  -- principal, which is exactly the silent divergence writing a disjunction as
  -- two rules is supposed to avoid.
  ((SELECT id FROM rule WHERE code='group_membership_nested'), 1, 'capability', 'src', 'member_effective', NULL, NULL, NULL, 0, 'The attacker is not an effective member of this group, so it confers no further membership.'),
  ((SELECT id FROM rule WHERE code='group_membership_nested'), 2, 'node_attr',  'src', NULL, 'account_status', 'ne', '"disabled"', 0, 'The account is disabled, so its group memberships confer nothing.'),
  ((SELECT id FROM rule WHERE code='group_membership_nested'), 3, 'node_attr',  'dst', NULL, 'type', 'eq', '"security"', 0, 'This is a distribution group; distribution groups do not confer authorisation.'),

  -- R7, second disjunct. The vault exclusions still apply: being able to read
  -- secrets on an asset is not being able to read a secret the asset only
  -- points at.
  ((SELECT id FROM rule WHERE code='credential_dump_secret_read'), 1, 'capability', 'src', 'can_read_secret', NULL, NULL, NULL, 0, 'Reading a secret from this asset requires being able to read its secret material, which the attacker cannot.'),
  ((SELECT id FROM rule WHERE code='credential_dump_secret_read'), 2, 'edge_attr',  'src', NULL, 'location', 'not_in', '["vault","hsm"]', 0, 'The asset references the secret but does not hold it; the material lives in a vault.'),
  ((SELECT id FROM rule WHERE code='credential_dump_secret_read'), 3, 'node_attr',  'dst', NULL, 'storage', 'not_in', '["vault","hsm"]', 0, 'The credential is vault-stored and cannot be recovered from this asset.'),
  ((SELECT id FROM rule WHERE code='credential_dump_secret_read'), 4, 'node_attr',  'dst', NULL, 'is_active', 'ne', 'false', 0, 'The credential has been rotated and no longer authenticates.'),

  -- R11, second disjunct. Code execution on the trusting host is enough to
  -- present its identity across the trust; administrative control is not
  -- required, and requiring it stranded every attacker sitting on a post-RCE
  -- foothold.
  ((SELECT id FROM rule WHERE code='host_trust_code_exec'), 1, 'capability', 'src', 'code_exec_on', NULL, NULL, NULL, 0, 'Abusing this trust requires code execution on the trusting host.'),

  -- R14, second disjunct.
  ((SELECT id FROM rule WHERE code='cloud_role_assumption_admin'), 1, 'capability', 'src', 'admin_on', NULL, NULL, NULL, 0, 'The attacker does not administer the source resource.'),
  ((SELECT id FROM rule WHERE code='cloud_role_assumption_admin'), 2, 'edge_attr',  'src', NULL, 'connection_type', 'eq', '"iam_assume_role"', 0, 'This connection carries network traffic only; it confers no identity or entitlement.'),

  -- R15, second disjunct. This is the one that takes the rule from unreachable
  -- to reachable: administrative control of a cloud resource is granted by R2,
  -- R4, R5 and R9, whereas code_exec_on about a CloudResource is granted by
  -- nothing in the seeded model.
  ((SELECT id FROM rule WHERE code='network_pivot_admin'), 1, 'capability', 'src', 'admin_on', NULL, NULL, NULL, 0, 'Pivoting requires administrative control of the source resource.'),
  ((SELECT id FROM rule WHERE code='network_pivot_admin'), 2, 'edge_attr',  'src', NULL, 'connection_type', 'in', '["vpc_peering","security_group","service_mesh"]', 0, 'These resources are not network-adjacent.');


-- ── Effects ──────────────────────────────────────────────────────────────────
--
-- Identical to the rule each one completes. A disjunction is one rule with two
-- ways of satisfying it, so what the attacker gains cannot depend on which way
-- they satisfied it.

INSERT INTO rule_effect (rule_id, seq, capability_code, binding) VALUES
  ((SELECT id FROM rule WHERE code='group_membership_nested'),     1, 'member_effective',  'dst'),

  ((SELECT id FROM rule WHERE code='credential_dump_secret_read'), 1, 'holds_credential',  'dst'),
  ((SELECT id FROM rule WHERE code='credential_dump_secret_read'), 2, 'can_read_secret',   'src'),

  ((SELECT id FROM rule WHERE code='host_trust_code_exec'),        1, 'code_exec_on',      'dst'),

  ((SELECT id FROM rule WHERE code='cloud_role_assumption_admin'), 1, 'access_to',         'dst'),

  ((SELECT id FROM rule WHERE code='network_pivot_admin'),         1, 'network_reach',     'dst');
