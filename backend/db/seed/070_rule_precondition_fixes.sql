-- 070_rule_precondition_fixes
--
-- One row, closing a gap the reference oracle found by actually testing
-- against docs/RULES.md's fourteen decoy patterns: D12 names
-- Database.requires_separate_key as R5's deciding attribute, but R5
-- (service_account_access) had no precondition reading it.
--
-- R5's edge is HAS_ACCESS_TO (ServiceAccount -> Database), so the database is
-- the dst binding. Authenticating to the instance is not the same as reading
-- data encrypted under a key held separately, and without this row the
-- distinction was silently absent from the rule set.

INSERT INTO rule_precondition (rule_id, seq, kind, binding, capability_code, attr_path, operator, value_json, is_negated, failure_reason) VALUES
  ((SELECT id FROM rule WHERE code='service_account_access'), 3, 'node_attr', 'dst', NULL,
   'requires_separate_key', 'ne', 'true', 0,
   'The data is encrypted under a key held separately; authenticating to the instance does not read it.');
