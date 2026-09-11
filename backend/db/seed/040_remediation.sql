-- 040_remediation
--
-- The fix catalogue, the lifecycle, and the pre-built playbooks.
--
-- Effort and disruption are stored rather than computed because they are
-- organisational facts, not technical ones. How expensive a manual change is
-- depends on the team; how disruptive revoking a credential is depends on what
-- relies on it. Both belong in a table the team can retune without a rebuild.

INSERT INTO fix_type
  (code, label, description, mutation_kind, mutation_target_attr, mutation_value,
   effort_value, effort_label, disruption_value, disruption_label, requires_approval, d3fend_id, sort_order)
VALUES
  ('revoke_credential',   'Revoke credential',
   'Invalidate the credential so it no longer authenticates anywhere.',
   'set_node_attr', 'is_active', 'false',
   1.000, 'Automated', 1.000, 'Moderate', 0, 'D3-CR',   1),

  ('rotate_credential',   'Rotate credential',
   'Replace the secret and reset its age. Distributes new material to every legitimate consumer.',
   'set_node_attr', 'age_days', '0',
   2.000, 'Scripted',  0.500, 'Minor',    0, 'D3-CR',   2),

  ('vault_credential',    'Move credential to a vault',
   'Relocate the secret into managed storage so it is no longer readable from the asset holding it.',
   'set_node_attr', 'storage', '"vault"',
   2.000, 'Scripted',  0.500, 'Minor',    0, 'D3-CH',   3),

  ('remove_exposure',     'Remove credential exposure',
   'Delete the secret from the configuration file, environment or repository exposing it.',
   'remove_edge',   NULL, NULL,
   2.000, 'Scripted',  0.500, 'Minor',    0, 'D3-FEMC', 4),

  ('remove_membership',   'Remove group membership',
   'Detach the principal from the group. Revokes every permission inherited through it.',
   'remove_edge',   NULL, NULL,
   5.000, 'Manual',    1.000, 'Moderate', 0, 'D3-UAP',  5),

  ('enforce_mfa',         'Require phishing-resistant MFA',
   'Require a hardware-backed second factor, which credential replay cannot satisfy.',
   'set_edge_attr', 'mfa_type', '"fido2"',
   5.000, 'Manual',    0.500, 'Minor',    0, 'D3-MFA',  6),

  ('least_privilege',     'Reduce to least privilege',
   'Downgrade an administrative grant to the access actually exercised.',
   'set_edge_attr', 'permission_level', '"read_only"',
   5.000, 'Manual',    1.000, 'Moderate', 1, 'D3-UAP',  7),

  ('patch_vulnerability', 'Patch vulnerability',
   'Bring the asset current, removing the weakness.',
   'set_node_attr', 'patch_level', '"current"',
   8.000, 'Requires downtime', 1.000, 'Moderate', 1, 'D3-SU', 8),

  ('segment_network',     'Segment network path',
   'Remove connectivity or trust between two assets.',
   'remove_edge',   NULL, NULL,
   8.000, 'Infrastructure change', 3.000, 'Critical service', 1, 'D3-NI', 9),

  ('disable_account',     'Disable unused account',
   'Disable an identity that is dormant or no longer needed.',
   'set_node_attr', 'account_status', '"disabled"',
   5.000, 'Manual',    1.000, 'Moderate', 1, 'D3-ANCI', 10);


INSERT INTO remediation_state (code, label, description, is_terminal, ui_color, sort_order) VALUES
  ('recommended', 'Recommended', 'Ranked by the engine, not yet examined.',                              0, '#64748b', 1),
  ('simulated',   'Simulated',   'Counterfactually re-derived; the predicted effect is recorded.',       0, '#38bdf8', 2),
  ('approved',    'Approved',    'Cryptographically authorised for application.',                        0, '#8b5cf6', 3),
  ('applied',     'Applied',     'Mutation performed against the live graph; verification pending.',     0, '#f59e0b', 4),
  ('verified',    'Verified',    'Re-derived after application; the actual effect matched prediction.',  1, '#10b981', 5),
  ('rolled_back', 'Rolled back', 'Reverted to the exact prior state recorded before application.',       1, '#ef4444', 6),
  ('dismissed',   'Dismissed',   'Rejected as not worth doing, with a recorded reason.',                 1, '#64748b', 7);


-- Legal transitions. A fix cannot be applied without having been simulated:
-- applying an unsimulated change leaves no prediction to verify against, which
-- removes the one check that would catch a wrong simulation.
INSERT INTO remediation_transition (from_state, to_state, label, needs_approval) VALUES
  ('recommended', 'simulated',   'Simulate',    0),
  ('recommended', 'dismissed',   'Dismiss',     0),
  ('simulated',   'approved',    'Approve',     1),
  ('simulated',   'dismissed',   'Dismiss',     0),
  ('simulated',   'recommended', 'Re-evaluate', 0),
  ('approved',    'applied',     'Apply',       0),
  ('approved',    'dismissed',   'Dismiss',     0),
  ('applied',     'verified',    'Verify',      0),
  ('applied',     'rolled_back', 'Roll back',   0),
  ('verified',    'rolled_back', 'Roll back',   1);


INSERT INTO playbook (code, name, description, trigger_description, sort_order) VALUES
  ('exposed_credential', 'Exposed credential',
   'Response to authentication material readable from a compromised or public location.',
   'An EXPOSES_CREDENTIAL edge appears in a critical or high-risk path.', 1),
  ('overprivileged_sa',  'Overprivileged service account',
   'Response to a non-human identity holding materially more access than it exercises.',
   'A service account holds administrative grants unused in the observation window.', 2),
  ('lateral_trust_chain','Lateral movement via trust chain',
   'Response to host trusts that let a single compromise propagate across tiers.',
   'Two or more consecutive TRUSTS hops appear in a path reaching a crown jewel.', 3);


-- Step order is a safety property, not a preference. The ordering notes are
-- shown in the interface, because a playbook whose reasoning is invisible is
-- a sequence somebody will eventually decide to reorder.
INSERT INTO playbook_step (playbook_code, step_no, fix_type_code, description, ordering_note) VALUES
  ('exposed_credential', 1, 'rotate_credential', 'Issue new material and distribute it to legitimate consumers.',
   'Rotation comes first. Revoking before rotating locks out every service still using the old secret, turning a security fix into an outage.'),
  ('exposed_credential', 2, 'remove_exposure',   'Delete the secret from the location exposing it.',
   'Only meaningful once the replacement exists; otherwise the consumers have nothing to move to.'),
  ('exposed_credential', 3, 'revoke_credential', 'Invalidate the old material.',
   'Last, once nothing depends on it.'),
  ('exposed_credential', 4, 'vault_credential',  'Place the replacement under managed storage.',
   'Prevents recurrence. Without this the same exposure returns at the next deployment.'),

  ('overprivileged_sa',  1, 'least_privilege',   'Downgrade the grant to observed usage.',
   'Before rotation, so the new credential is issued against the reduced scope.'),
  ('overprivileged_sa',  2, 'remove_membership', 'Detach stale group memberships.',
   'After scope reduction, so what remains inherited is visible.'),
  ('overprivileged_sa',  3, 'rotate_credential', 'Rotate against the reduced entitlements.',
   'Last, so the new secret never carries the old privilege.'),

  ('lateral_trust_chain',1, 'enforce_mfa',       'Require a phishing-resistant factor on cross-host authentication.',
   'First because it is reversible and barely disruptive; it buys time for the segmentation work.'),
  ('lateral_trust_chain',2, 'segment_network',   'Remove the trust relationship.',
   'High disruption and hard to reverse. Requires signed approval and a maintenance window.');
