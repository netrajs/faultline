-- 030_scoring
--
-- The active scoring configuration.
--
-- The display score is a weighted sum of three components, each normalised to
-- [0,1], scaled to [0,10]:
--
--     likelihood = 1 - min(neg_log_success / RAW_MAX, 1)
--     impact     = the target's impact weight, already in [0,1]
--     stealth    = 1 - min(neg_log_undetected / RAW_MAX, 1)
--
--     risk_10 = 10 * (w_L*likelihood + w_I*impact + w_S*stealth)
--
-- RAW_MAX is 9.2103404, which is -ln(1e-4): the negative log probability at
-- which a path is treated as negligible. Working on the log scale rather than
-- the raw probability matters, because path probabilities span orders of
-- magnitude and a linear scale would compress every multi-hop path into the
-- bottom tier regardless of how much they differ from each other.
--
-- The sum is additive with weights totalling 1.0, so the score reaches both 0
-- and 10 and every tier between them is attainable. That is not a stylistic
-- point: the design this replaces topped out at 4.0 against tiers that started
-- "critical" at 9.0, so no path could ever be rated critical and nothing in the
-- code said so. A migration test now asserts every tier boundary is reachable by
-- a constructible path.

INSERT INTO scoring_config
  (version, label, description, p_clamp_min, p_clamp_max, raw_max, w_likelihood, w_impact, w_stealth, is_active, created_at)
VALUES
  ('v1', 'Baseline log-odds model',
   'Likelihood as the product of per-hop success probabilities in log space, impact as a separate target-side axis, stealth accumulated independently. Weights sum to 1.0 so the 0-10 scale is fully attainable.',
   0.00100, 0.99500, 9.210340, 0.5500, 0.3500, 0.1000, 1, NOW(6));


-- Per-technique baselines: the probability the technique works once its
-- preconditions are satisfied, and the probability the attempt is noticed.
--
-- Directory operations sit near certainty because they are not exploits -- using
-- a permission you legitimately hold works essentially always, and that is the
-- point: most privilege escalation is configuration, not vulnerability.
INSERT INTO technique_baseline (scoring_version, technique_code, base_p_succ, base_detectability, rationale) VALUES
  ('v1', 'group_membership',      0.99000, 0.02000, 'Membership inheritance is how the directory works. Nothing is exploited, and nothing logs an alert.'),
  ('v1', 'group_permission',      0.97000, 0.05000, 'Using a permission the group legitimately holds. Visible in access logs but indistinguishable from ordinary use.'),
  ('v1', 'direct_assignment',     0.98000, 0.05000, 'Directly assigned rights, used as intended. Detection depends entirely on behavioural baselining.'),
  ('v1', 'cloud_account_use',     0.97000, 0.12000, 'Cloud audit logging is generally better than on-premises, so detection is somewhat higher.'),
  ('v1', 'credential_in_files',   0.85000, 0.25000, 'Reading configuration or dumping process memory. Reliable given administrative access; memory access on a monitored host is a common EDR trigger.'),
  ('v1', 'unsecured_credentials', 0.95000, 0.05000, 'Collecting a secret from a public location. Almost always works, and the collection itself is invisible to the victim.'),
  ('v1', 'credential_replay',     0.93000, 0.15000, 'Presenting valid material to a service that accepts it. Detection depends on impossible-travel and device-posture signals.'),
  ('v1', 'kerberoasting',         0.70000, 0.30000, 'Ticket request always succeeds; the uncertainty is offline cracking. Bulk SPN enumeration is a well-known detection signature.'),
  ('v1', 'trusted_relationship',  0.80000, 0.20000, 'Trust abuse depends on delegation configuration that is frequently subtly wrong in the attacker''s favour.'),
  ('v1', 'remote_services',       0.95000, 0.10000, 'Network adjacency either exists or does not; little can go wrong once it does.'),
  ('v1', 'exploit_remote',        0.50000, 0.45000, 'Placeholder baseline. Overridden per-vulnerability by EPSS -- see the note below.'),
  ('v1', 'exploit_privesc',       0.55000, 0.40000, 'Placeholder baseline. Overridden per-vulnerability by EPSS.'),
  ('v1', 'assume_role',           0.90000, 0.15000, 'Role assumption is an ordinary API call, logged but rarely alerted on.');


-- Modifiers, applied additively in log-odds.
--
-- Positive beta makes a step more likely to succeed. The values are calibrated
-- so that a single strong factor shifts the probability meaningfully without
-- saturating it: at a baseline of 0.85, a beta of +1.2 moves the probability to
-- roughly 0.95, and a beta of -1.5 moves it to roughly 0.56.
INSERT INTO scoring_modifier
  (scoring_version, code, label, description, applies_to, attr_path, operator, value_json, target, beta, is_hard_block, sort_order)
VALUES
  -- Credential hygiene
  ('v1', 'cred_age_stale',      'Credential over 90 days old',   'Long-lived credentials are more likely to have leaked into a backup, a ticket, or a former employee''s notes.', 'dst_node', 'age_days',   'gt', '90',                            'p_succ',        0.4000, 0, 1),
  ('v1', 'cred_age_ancient',    'Credential over 365 days old',  'A credential unrotated for a year has had a year of opportunity to escape.',                                  'dst_node', 'age_days',   'gt', '365',                           'p_succ',        0.5000, 0, 2),
  ('v1', 'cred_shared',         'Credential shared',             'Shared credentials multiply the number of places the secret can be recovered from.',                          'dst_node', 'is_shared',  'eq', 'true',                          'p_succ',        0.7000, 0, 3),
  ('v1', 'cred_plaintext',      'Credential stored in plaintext','A secret in a config file or environment variable is readable by anything that can read the filesystem.',      'dst_node', 'storage',    'in', '["plaintext","config_file","env_var"]', 'p_succ', 1.2000, 0, 4),
  ('v1', 'cred_weak',           'Weak credential',               'Weak material is susceptible to guessing and offline cracking.',                                              'dst_node', 'strength',   'eq', '"weak"',                        'p_succ',        0.9000, 0, 5),
  ('v1', 'cred_vaulted',        'Credential vault-managed',      'Vault-managed secrets are short-lived and access-logged.',                                                    'dst_node', 'storage',    'eq', '"vault"',                       'p_succ',       -1.5000, 0, 6),

  -- Authentication strength. Phishing-resistant factors are handled as a hard
  -- block in rule R9, not here, because they defeat replay outright. What
  -- remains are the weaker factors, which add friction without preventing the
  -- attack -- adversary-in-the-middle and push fatigue defeat both routinely.
  ('v1', 'mfa_weak_factor',     'Weak second factor required',   'SMS and push add friction but fall to relay and fatigue attacks.',                                            'edge',     'mfa_type',   'in', '["sms","push","totp"]',         'p_succ',       -0.8000, 0, 7),
  ('v1', 'mfa_weak_detect',     'Weak second factor is noisy',   'A failed or repeated second-factor prompt is a signal the victim may notice and report.',                     'edge',     'mfa_type',   'in', '["sms","push"]',                'detectability', 0.6000, 0, 8),

  -- Asset posture
  ('v1', 'host_public_facing',  'Asset is internet-facing',      'Internet exposure means the attacker needs no prior foothold to reach it.',                                   'dst_node', 'public_facing', 'eq', 'true',                       'p_succ',        0.5000, 0, 9),
  ('v1', 'host_unpatched',      'Asset badly out of date',       'An asset two or more cycles behind is likely vulnerable to more than the one weakness we know about.',         'src_node', 'patch_level','eq', '"behind-2+"',                   'p_succ',        0.6000, 0, 10),
  ('v1', 'host_monitored',      'Asset has endpoint monitoring', 'Endpoint detection substantially raises the chance an action is noticed.',                                     'src_node', 'has_edr',    'eq', 'true',                          'detectability', 1.0000, 0, 11),
  ('v1', 'exposure_discoverable','Exposure easy to find',        'A secret in a well-known location is found by routine enumeration rather than targeted search.',               'edge',     'discoverable','gte','0.7',                           'p_succ',        0.5000, 0, 12),

  -- Identity posture
  ('v1', 'account_dormant',     'Account dormant',               'Nobody notices anomalous use of an account nobody uses.',                                                     'src_node', 'account_status','eq','"dormant"',                    'detectability',-0.8000, 0, 13),
  ('v1', 'account_vendor',      'Third-party account',           'Vendor and contractor accounts are less consistently governed and less consistently reviewed.',               'src_node', 'account_type','in', '["vendor","contractor"]',       'p_succ',        0.3000, 0, 14),
  ('v1', 'sa_non_interactive',  'Service account, non-interactive','A service account logging in interactively is anomalous and comparatively easy to alert on.',               'src_node', 'is_interactive','eq','false',                       'detectability', 0.9000, 0, 15);


-- Restrict modifiers whose meaning is technique-specific. An empty scope means
-- the modifier applies everywhere; these have a scope because credential age is
-- meaningless to a network pivot and patch level is meaningless to a group
-- membership.
INSERT INTO scoring_modifier_scope (scoring_version, modifier_code, technique_code) VALUES
  ('v1', 'cred_age_stale',   'credential_replay'),
  ('v1', 'cred_age_stale',   'credential_in_files'),
  ('v1', 'cred_age_ancient', 'credential_replay'),
  ('v1', 'cred_age_ancient', 'credential_in_files'),
  ('v1', 'cred_shared',      'credential_replay'),
  ('v1', 'cred_shared',      'credential_in_files'),
  ('v1', 'cred_plaintext',   'credential_in_files'),
  ('v1', 'cred_plaintext',   'unsecured_credentials'),
  ('v1', 'cred_weak',        'kerberoasting'),
  ('v1', 'cred_weak',        'credential_replay'),
  ('v1', 'cred_vaulted',     'credential_in_files'),
  ('v1', 'mfa_weak_factor',  'credential_replay'),
  ('v1', 'mfa_weak_detect',  'credential_replay'),
  ('v1', 'host_unpatched',   'exploit_remote'),
  ('v1', 'host_unpatched',   'exploit_privesc'),
  ('v1', 'exposure_discoverable', 'credential_in_files'),
  ('v1', 'exposure_discoverable', 'unsecured_credentials'),
  ('v1', 'sa_non_interactive',    'credential_replay');


-- Impact weights, already normalised to [0,1] so the display sum stays bounded.
INSERT INTO impact_weight (scoring_version, dimension, code, weight) VALUES
  ('v1', 'crown_jewel',    'true',         1.0000),
  ('v1', 'crown_jewel',    'false',        0.0000),
  ('v1', 'criticality',    'critical',     0.8500),
  ('v1', 'criticality',    'high',         0.6500),
  ('v1', 'criticality',    'medium',       0.4000),
  ('v1', 'criticality',    'low',          0.2000),
  ('v1', 'classification', 'restricted',   0.9000),
  ('v1', 'classification', 'confidential', 0.7000),
  ('v1', 'classification', 'internal',     0.4000),
  ('v1', 'classification', 'public',       0.1000);


INSERT INTO risk_tier (scoring_version, code, label, min_score, max_score, ui_color, ui_bg_color, action_text, sort_order) VALUES
  ('v1', 'critical', 'Critical', 9.00, 10.00, '#ef4444', 'rgba(239, 68, 68, 0.15)',   'Immediate action required',  1),
  ('v1', 'high',     'High',     7.00,  8.99, '#f59e0b', 'rgba(245, 158, 11, 0.15)',  'Action within 24 hours',     2),
  ('v1', 'medium',   'Medium',   4.00,  6.99, '#eab308', 'rgba(234, 179, 8, 0.12)',   'Scheduled remediation',      3),
  ('v1', 'low',      'Low',      1.00,  3.99, '#3b82f6', 'rgba(59, 130, 246, 0.15)',  'Monitor',                    4),
  ('v1', 'info',     'Info',     0.00,  0.99, '#64748b', 'rgba(100, 116, 139, 0.12)', 'Accepted risk',              5);
