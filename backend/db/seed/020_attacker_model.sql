-- 020_attacker_model
--
-- Capability atoms, MITRE-mapped techniques, and the fifteen derivation rules
-- specified in docs/RULES.md.
--
-- These rows are the engine's semantics. The reference oracle reads the same
-- rows, which is what makes a disagreement between the two a real finding rather
-- than a difference of interpretation.

INSERT INTO capability_atom (code, label, description, binding_kind, sort_order) VALUES
  ('authenticated',       'Authenticated',        'Holds some valid directory identity; can make authenticated requests.', 'global', 1),
  ('controls_principal',  'Controls principal',   'Can act as this user or service account.',                              'node',   2),
  ('holds_credential',    'Holds credential',     'Possesses this credential''s material.',                                'node',   3),
  ('member_effective',    'Effective member',     'Is a member of this group, including through nesting.',                 'node',   4),
  ('network_reach',       'Network reach',        'Can reach this asset over the network. Reachability, not access.',      'node',   5),
  ('access_to',           'Access',               'Authenticated, non-administrative access to this asset.',               'node',   6),
  ('admin_on',            'Administrative',       'Administrative control of this asset.',                                 'node',   7),
  ('code_exec_on',        'Code execution',       'Can execute code on this host.',                                        'node',   8),
  ('can_read_secret',     'Can read secrets',     'Can read secret material stored on this asset.',                        'node',   9);


INSERT INTO technique (code, name, description, attack_id, attack_name, attack_url, phase, sort_order) VALUES
  ('group_membership',      'Group membership inheritance', 'Authorisation inherited through directory group membership, including nested groups.',                          'T1078',     'Valid Accounts',                                        'https://attack.mitre.org/techniques/T1078/',     'privilege_escalation', 1),
  ('group_permission',      'Group-conferred permission',   'Rights granted to an asset by virtue of group membership.',                                                     'T1078.002', 'Valid Accounts: Domain Accounts',                       'https://attack.mitre.org/techniques/T1078/002/', 'privilege_escalation', 2),
  ('direct_assignment',     'Direct rights assignment',     'Rights assigned directly to a principal rather than through a group.',                                          'T1078',     'Valid Accounts',                                        'https://attack.mitre.org/techniques/T1078/',     'privilege_escalation', 3),
  ('cloud_account_use',     'Cloud account use',            'Use of a cloud identity''s existing entitlements.',                                                             'T1078.004', 'Valid Accounts: Cloud Accounts',                        'https://attack.mitre.org/techniques/T1078/004/', 'lateral_movement',     4),
  ('credential_in_files',   'Credentials in files',         'Reading authentication material from configuration, environment or logs on a compromised asset.',               'T1552.001', 'Unsecured Credentials: Credentials In Files',           'https://attack.mitre.org/techniques/T1552/001/', 'credential_access',    5),
  ('unsecured_credentials', 'Unsecured credentials',        'Authentication material exposed with no access control at all.',                                                'T1552',     'Unsecured Credentials',                                 'https://attack.mitre.org/techniques/T1552/',     'credential_access',    6),
  ('credential_replay',     'Credential replay',            'Presenting captured authentication material to a service.',                                                     'T1550',     'Use Alternate Authentication Material',                 'https://attack.mitre.org/techniques/T1550/',     'lateral_movement',     7),
  ('kerberoasting',         'Kerberoasting',                'Requesting a service ticket for an SPN-bearing account and cracking it offline.',                               'T1558.003', 'Steal or Forge Kerberos Tickets: Kerberoasting',        'https://attack.mitre.org/techniques/T1558/003/', 'credential_access',    8),
  ('trusted_relationship',  'Trusted relationship',         'Moving across a configured trust between hosts.',                                                               'T1199',     'Trusted Relationship',                                  'https://attack.mitre.org/techniques/T1199/',     'lateral_movement',     9),
  ('remote_services',       'Remote services',              'Using legitimate remote access services to move between systems.',                                              'T1021',     'Remote Services',                                       'https://attack.mitre.org/techniques/T1021/',     'lateral_movement',    10),
  ('exploit_remote',        'Exploit remote service',       'Exploiting a network-reachable vulnerability to gain code execution.',                                          'T1210',     'Exploitation of Remote Services',                       'https://attack.mitre.org/techniques/T1210/',     'initial_access',      11),
  ('exploit_privesc',       'Exploit for privilege escalation', 'Exploiting a local vulnerability to raise privilege on an already-compromised host.',                       'T1068',     'Exploitation for Privilege Escalation',                 'https://attack.mitre.org/techniques/T1068/',     'privilege_escalation', 12),
  ('assume_role',           'Assume cloud role',            'Assuming a role that grants entitlements on another cloud resource.',                                           'T1548',     'Abuse Elevation Control Mechanism',                     'https://attack.mitre.org/techniques/T1548/',     'privilege_escalation', 13);


INSERT INTO threat_model (code, label, description, is_default, sort_order) VALUES
  ('external_phish',    'External attacker (phished user)', 'Has compromised one standard non-administrative user account. The default assumption.',                1, 1),
  ('insider_standard',  'Insider (standard employee)',      'A legitimate employee acting maliciously, with their own account and internal network access.',        0, 2),
  ('contractor_device', 'Compromised contractor device',    'A contractor account reachable over the VPN, with network access limited to the VPN segment.',         0, 3),
  ('public_only',       'Unauthenticated internet',         'No identity at all. Only public-facing assets are reachable. The hardest starting position.',          0, 4);

INSERT INTO threat_model_grant (threat_model_code, seq, capability_code, applies_to_kind, applies_to_node) VALUES
  ('external_phish',    1, 'authenticated',     NULL,   NULL),
  ('external_phish',    2, 'controls_principal','User', NULL),
  ('insider_standard',  1, 'authenticated',     NULL,   NULL),
  ('insider_standard',  2, 'controls_principal','User', NULL),
  ('insider_standard',  3, 'network_reach',     'Host', NULL),
  ('contractor_device', 1, 'authenticated',     NULL,   NULL),
  ('contractor_device', 2, 'controls_principal','User', NULL),
  ('public_only',       1, 'network_reach',     'Host', NULL);


-- ── Rules ────────────────────────────────────────────────────────────────────

INSERT INTO rule (code, technique_code, edge_type_code, description, is_traversal, is_enabled, sort_order) VALUES
  ('group_membership',        'group_membership',      'MEMBER_OF',          'Inherit membership of a security group, including through nesting.',                      1, 1,  1),
  ('group_permission_admin',  'group_permission',      'HAS_PERMISSION',     'Gain administrative control of an asset through a group''s admin permission.',            1, 1,  2),
  ('group_permission_access', 'group_permission',      'HAS_PERMISSION',     'Gain non-administrative access through a group''s lesser permission.',                    1, 1,  3),
  ('direct_admin',            'direct_assignment',     'ADMIN_TO',           'Use administrative rights assigned directly to a controlled principal.',                  1, 1,  4),
  ('service_account_access',  'cloud_account_use',     'HAS_ACCESS_TO',      'Use a controlled service account''s own grant on an asset.',                              1, 1,  5),
  ('credential_from_principal','group_membership',     'HAS_CREDENTIAL',     'Take possession of a controlled principal''s own credential.',                            1, 1,  6),
  ('credential_dump',         'credential_in_files',   'EXPOSES_CREDENTIAL', 'Read a credential exposed on an asset the attacker administers.',                         1, 1,  7),
  ('credential_public',       'unsecured_credentials', 'EXPOSES_CREDENTIAL', 'Collect a credential exposed with no access control whatsoever.',                         1, 1,  8),
  ('credential_authenticate', 'credential_replay',     'AUTHENTICATES_TO',   'Authenticate to an asset using held credential material.',                                1, 1,  9),
  ('kerberoast',              'kerberoasting',         NULL,                 'Request and crack a service ticket for an SPN-bearing account. Consumes no edge.',        0, 1, 10),
  ('host_trust',              'trusted_relationship',  'TRUSTS',             'Move laterally across a configured host trust.',                                          1, 1, 11),
  ('remote_exploit',          'exploit_remote',        'HAS_VULNERABILITY',  'Exploit a network-reachable vulnerability for code execution.',                           1, 1, 12),
  ('local_privesc',           'exploit_privesc',       'HAS_VULNERABILITY',  'Escalate privilege on a host where code execution is already held.',                      1, 1, 13),
  ('cloud_role_assumption',   'assume_role',           'CONNECTED_TO',       'Assume a role granting entitlements on a connected cloud resource.',                      1, 1, 14),
  ('network_pivot',           'remote_services',       'CONNECTED_TO',       'Gain network reachability to a connected resource. Reachability only, not access.',       1, 1, 15);


-- ── Preconditions ────────────────────────────────────────────────────────────
--
-- Conjunctive: every row must hold. Each carries the sentence shown when it is
-- the reason a candidate was refused, so a rejection explains itself.

INSERT INTO rule_precondition (rule_id, seq, kind, binding, capability_code, attr_path, operator, value_json, is_negated, failure_reason) VALUES
  -- R1 group_membership
  ((SELECT id FROM rule WHERE code='group_membership'), 1, 'capability', 'src', 'controls_principal', NULL, NULL, NULL, 0, 'The attacker does not control this principal.'),
  ((SELECT id FROM rule WHERE code='group_membership'), 2, 'node_attr',  'src', NULL, 'account_status', 'ne', '"disabled"', 0, 'The account is disabled, so its group memberships confer nothing.'),
  ((SELECT id FROM rule WHERE code='group_membership'), 3, 'node_attr',  'dst', NULL, 'type', 'eq', '"security"', 0, 'This is a distribution group; distribution groups do not confer authorisation.'),

  -- R2 group_permission_admin
  ((SELECT id FROM rule WHERE code='group_permission_admin'), 1, 'capability', 'src', 'member_effective', NULL, NULL, NULL, 0, 'The attacker is not an effective member of this group.'),
  ((SELECT id FROM rule WHERE code='group_permission_admin'), 2, 'edge_attr',  'src', NULL, 'permission_level', 'eq', '"admin"', 0, 'The group''s permission on this asset is not administrative.'),

  -- R3 group_permission_access
  ((SELECT id FROM rule WHERE code='group_permission_access'), 1, 'capability', 'src', 'member_effective', NULL, NULL, NULL, 0, 'The attacker is not an effective member of this group.'),
  ((SELECT id FROM rule WHERE code='group_permission_access'), 2, 'edge_attr',  'src', NULL, 'permission_level', 'in', '["read_write","read_only","execute"]', 0, 'The group holds no usable permission on this asset.'),

  -- R4 direct_admin
  ((SELECT id FROM rule WHERE code='direct_admin'), 1, 'capability', 'src', 'controls_principal', NULL, NULL, NULL, 0, 'The attacker does not control this principal.'),
  ((SELECT id FROM rule WHERE code='direct_admin'), 2, 'node_attr',  'src', NULL, 'account_status', 'eq', '"active"', 0, 'The account is not active; its rights assignments are stale and will not authenticate.'),

  -- R5 service_account_access
  ((SELECT id FROM rule WHERE code='service_account_access'), 1, 'capability', 'src', 'controls_principal', NULL, NULL, NULL, 0, 'The attacker does not control this service account.'),
  ((SELECT id FROM rule WHERE code='service_account_access'), 2, 'node_attr',  'src', NULL, 'account_status', 'eq', '"active"', 0, 'The service account is not active.'),

  -- R6 credential_from_principal
  ((SELECT id FROM rule WHERE code='credential_from_principal'), 1, 'capability', 'src', 'controls_principal', NULL, NULL, NULL, 0, 'The attacker does not control the principal owning this credential.'),
  ((SELECT id FROM rule WHERE code='credential_from_principal'), 2, 'node_attr',  'dst', NULL, 'is_active', 'ne', 'false', 0, 'The credential has been rotated or revoked and no longer authenticates.'),

  -- R7 credential_dump -- the precondition that distinguishes this from a reachability tool
  ((SELECT id FROM rule WHERE code='credential_dump'), 1, 'capability', 'src', 'admin_on', NULL, NULL, NULL, 0, 'Reading a secret from this asset requires administrative control of it, which the attacker does not hold.'),
  ((SELECT id FROM rule WHERE code='credential_dump'), 2, 'edge_attr',  'src', NULL, 'location', 'not_in', '["vault","hsm"]', 0, 'The asset references the secret but does not hold it; the material lives in a vault.'),
  ((SELECT id FROM rule WHERE code='credential_dump'), 3, 'node_attr',  'dst', NULL, 'storage', 'not_in', '["vault","hsm"]', 0, 'The credential is vault-stored and cannot be recovered from this asset.'),
  ((SELECT id FROM rule WHERE code='credential_dump'), 4, 'node_attr',  'dst', NULL, 'is_active', 'ne', 'false', 0, 'The credential has been rotated and no longer authenticates.'),

  -- R8 credential_public -- deliberately has no capability precondition
  ((SELECT id FROM rule WHERE code='credential_public'), 1, 'edge_attr', 'src', NULL, 'location', 'in', '["public_repo","public_bucket","paste_site"]', 0, 'The exposure is not publicly accessible; reading it requires access to the asset.'),
  ((SELECT id FROM rule WHERE code='credential_public'), 2, 'node_attr', 'dst', NULL, 'is_active', 'ne', 'false', 0, 'The credential has been rotated and no longer authenticates.'),

  -- R9 credential_authenticate
  ((SELECT id FROM rule WHERE code='credential_authenticate'), 1, 'capability', 'src', 'holds_credential', NULL, NULL, NULL, 0, 'The attacker does not hold this credential.'),
  ((SELECT id FROM rule WHERE code='credential_authenticate'), 2, 'edge_attr',  'src', NULL, 'mfa_type', 'not_in', '["fido2","webauthn","piv"]', 0, 'Authentication requires a phishing-resistant second factor, which credential replay cannot satisfy.'),
  ((SELECT id FROM rule WHERE code='credential_authenticate'), 3, 'edge_attr',  'src', NULL, 'requires_compliant_device', 'ne', 'true', 0, 'Conditional access requires a compliant enrolled device, which the attacker does not have.'),
  ((SELECT id FROM rule WHERE code='credential_authenticate'), 4, 'node_attr',  'dst', NULL, 'status', 'ne', '"decommissioned"', 0, 'The target asset is decommissioned.'),

  -- R10 kerberoast -- fires on state alone
  ((SELECT id FROM rule WHERE code='kerberoast'), 1, 'capability', 'global', 'authenticated', NULL, NULL, NULL, 0, 'Requesting a service ticket requires an authenticated directory identity.'),
  ((SELECT id FROM rule WHERE code='kerberoast'), 2, 'node_attr',  'dst', NULL, 'has_spn', 'eq', 'true', 0, 'The account has no service principal name, so no service ticket can be requested for it.'),
  ((SELECT id FROM rule WHERE code='kerberoast'), 3, 'node_attr',  'dst', NULL, 'credential_strength', 'ne', '"strong"', 0, 'The account''s password is strong; the recovered ticket is not crackable in practical time.'),

  -- R11 host_trust
  ((SELECT id FROM rule WHERE code='host_trust'), 1, 'capability', 'src', 'admin_on', NULL, NULL, NULL, 0, 'Abusing this trust requires administrative control of the trusting host.'),

  -- R12 remote_exploit
  ((SELECT id FROM rule WHERE code='remote_exploit'), 1, 'capability', 'src', 'network_reach', NULL, NULL, NULL, 0, 'The attacker cannot reach this asset over the network.'),
  ((SELECT id FROM rule WHERE code='remote_exploit'), 2, 'node_attr',  'dst', NULL, 'impact', 'eq', '"RCE"', 0, 'This vulnerability does not yield code execution.'),
  ((SELECT id FROM rule WHERE code='remote_exploit'), 3, 'node_attr',  'dst', NULL, 'attack_vector', 'eq', '"network"', 0, 'This vulnerability is not remotely exploitable.'),
  ((SELECT id FROM rule WHERE code='remote_exploit'), 4, 'node_attr',  'src', NULL, 'patch_level', 'ne', '"current"', 0, 'The asset is fully patched against this vulnerability.'),

  -- R13 local_privesc
  ((SELECT id FROM rule WHERE code='local_privesc'), 1, 'capability', 'src', 'code_exec_on', NULL, NULL, NULL, 0, 'Local escalation requires existing code execution on the host.'),
  ((SELECT id FROM rule WHERE code='local_privesc'), 2, 'node_attr',  'dst', NULL, 'impact', 'eq', '"privilege_escalation"', 0, 'This vulnerability does not yield privilege escalation.'),
  ((SELECT id FROM rule WHERE code='local_privesc'), 3, 'node_attr',  'src', NULL, 'patch_level', 'ne', '"current"', 0, 'The asset is fully patched against this vulnerability.'),

  -- R14 cloud_role_assumption
  ((SELECT id FROM rule WHERE code='cloud_role_assumption'), 1, 'capability', 'src', 'access_to', NULL, NULL, NULL, 0, 'The attacker has no access to the source resource.'),
  ((SELECT id FROM rule WHERE code='cloud_role_assumption'), 2, 'edge_attr',  'src', NULL, 'connection_type', 'eq', '"iam_assume_role"', 0, 'This connection carries network traffic only; it confers no identity or entitlement.'),

  -- R15 network_pivot
  ((SELECT id FROM rule WHERE code='network_pivot'), 1, 'capability', 'src', 'code_exec_on', NULL, NULL, NULL, 0, 'Pivoting requires code execution on the source resource.'),
  ((SELECT id FROM rule WHERE code='network_pivot'), 2, 'edge_attr',  'src', NULL, 'connection_type', 'in', '["vpc_peering","security_group","service_mesh"]', 0, 'These resources are not network-adjacent.');


-- ── Effects ──────────────────────────────────────────────────────────────────

INSERT INTO rule_effect (rule_id, seq, capability_code, binding) VALUES
  ((SELECT id FROM rule WHERE code='group_membership'),         1, 'member_effective',   'dst'),

  ((SELECT id FROM rule WHERE code='group_permission_admin'),   1, 'admin_on',           'dst'),
  ((SELECT id FROM rule WHERE code='group_permission_admin'),   2, 'access_to',          'dst'),

  ((SELECT id FROM rule WHERE code='group_permission_access'),  1, 'access_to',          'dst'),

  ((SELECT id FROM rule WHERE code='direct_admin'),             1, 'admin_on',           'dst'),
  ((SELECT id FROM rule WHERE code='direct_admin'),             2, 'access_to',          'dst'),
  ((SELECT id FROM rule WHERE code='direct_admin'),             3, 'can_read_secret',    'dst'),

  ((SELECT id FROM rule WHERE code='service_account_access'),   1, 'access_to',          'dst'),

  ((SELECT id FROM rule WHERE code='credential_from_principal'),1, 'holds_credential',   'dst'),

  ((SELECT id FROM rule WHERE code='credential_dump'),          1, 'holds_credential',   'dst'),
  ((SELECT id FROM rule WHERE code='credential_dump'),          2, 'can_read_secret',    'src'),

  ((SELECT id FROM rule WHERE code='credential_public'),        1, 'holds_credential',   'dst'),

  ((SELECT id FROM rule WHERE code='credential_authenticate'),  1, 'access_to',          'dst'),

  ((SELECT id FROM rule WHERE code='kerberoast'),               1, 'controls_principal', 'dst'),

  ((SELECT id FROM rule WHERE code='host_trust'),               1, 'code_exec_on',       'dst'),

  ((SELECT id FROM rule WHERE code='remote_exploit'),           1, 'code_exec_on',       'src'),
  ((SELECT id FROM rule WHERE code='remote_exploit'),           2, 'access_to',          'src'),

  ((SELECT id FROM rule WHERE code='local_privesc'),            1, 'admin_on',           'src'),
  ((SELECT id FROM rule WHERE code='local_privesc'),            2, 'can_read_secret',    'src'),

  ((SELECT id FROM rule WHERE code='cloud_role_assumption'),    1, 'access_to',          'dst'),

  ((SELECT id FROM rule WHERE code='network_pivot'),            1, 'network_reach',      'dst');
