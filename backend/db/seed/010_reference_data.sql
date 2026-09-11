-- 010_reference_data
--
-- Vocabularies: what kinds of thing exist in the graph, what kinds of
-- relationship connect them, and how each is drawn.
--
-- Rendering attributes live here rather than in frontend constants because the
-- legend, the node styling and the edge styling must agree, and three copies of
-- a colour map in three components is three chances to disagree. The frontend
-- reads these rows.

INSERT INTO criticality (code, label, description, sort_order) VALUES
  ('critical', 'Critical', 'Loss or compromise halts the business or exposes regulated data.', 1),
  ('high',     'High',     'Significant operational or financial impact.',                      2),
  ('medium',   'Medium',   'Contained impact, recoverable within normal operations.',           3),
  ('low',      'Low',      'Minimal impact if compromised.',                                    4);

INSERT INTO data_classification (code, label, description, sort_order) VALUES
  ('restricted',   'Restricted',   'Regulated data: payment, health, or personally identifying.', 1),
  ('confidential', 'Confidential', 'Commercially sensitive, internal distribution only.',         2),
  ('internal',     'Internal',     'Ordinary internal data, not for publication.',                3),
  ('public',       'Public',       'Already public or intended for publication.',                 4);


INSERT INTO node_kind (code, label, description, category, ui_color, ui_shape, ui_size_min, ui_size_max, ui_size_by, ui_icon, sort_order) VALUES
  ('User',           'User',            'A human identity in the directory.',                                  'identity', '#378ADD', 'ellipse',           20, 40, 'risk',        'user',        1),
  ('Group',          'Group',           'A security or distribution group. Only security groups authorise.',   'identity', '#7F77DD', 'round-rectangle',   30, 50, 'member_count','users',       2),
  ('ServiceAccount', 'Service account', 'A non-human identity used by automation.',                            'identity', '#D85A30', 'diamond',           20, 40, 'risk',        'robot',       3),
  ('Host',           'Host',            'A server or workstation.',                                            'asset',    '#1D9E75', 'rectangle',         20, 40, 'criticality', 'server',      4),
  ('Database',       'Database',        'A database instance.',                                                'asset',    '#EF9F27', 'barrel',            30, 45, 'criticality', 'database',    5),
  ('CloudResource',  'Cloud resource',  'A cloud-managed resource such as a bucket, function or workload.',    'asset',    '#D4537E', 'ellipse',           20, 40, 'criticality', 'cloud',       6),
  ('Application',    'Application',     'An internal or external application.',                                'asset',    '#639922', 'hexagon',           20, 35, 'criticality', 'app-window',  7),
  ('Credential',     'Credential',      'Authentication material: a password, key, token or certificate.',     'secret',   '#888780', 'vee',               15, 25, 'risk',        'key',         8),
  ('Vulnerability',  'Vulnerability',   'A known weakness in an asset, identified by CVE.',                    'weakness', '#E24B4A', 'triangle',          20, 30, 'cvss',        'alert-triangle', 9);


-- Relationship vocabulary.
--
-- Every type here is something a collector could observe in a real environment.
-- There is deliberately no CAN_ESCALATE_TO: escalation is the conclusion the
-- engine derives, and recording it as an input fact would mean the generator
-- writes the answers and the analyser reads them back.
INSERT INTO edge_type (code, label, description, is_directed, ui_color, ui_line_style, ui_width, ui_animated, sort_order) VALUES
  ('MEMBER_OF',          'Member of',           'Principal or group belongs to a group. Nests to arbitrary depth.',        1, '#888780', 'solid',  2, 0, 1),
  ('HAS_CREDENTIAL',     'Has credential',      'Principal owns this authentication material.',                            1, '#888780', 'dashed', 2, 0, 2),
  ('AUTHENTICATES_TO',   'Authenticates to',    'Credential can be presented to this asset.',                              1, '#378ADD', 'solid',  2, 0, 3),
  ('ADMIN_TO',           'Admin to',            'Principal holds administrative rights over this asset.',                  1, '#E24B4A', 'solid',  4, 0, 4),
  ('HAS_ACCESS_TO',      'Has access to',       'Service account holds a specific grant on this asset.',                   1, '#EF9F27', 'solid',  2, 0, 5),
  ('HAS_PERMISSION',     'Has permission',      'Group confers this permission on the asset.',                             1, '#7F77DD', 'solid',  2, 0, 6),
  ('TRUSTS',             'Trusts',              'Host accepts authentication or delegation from another host.',            1, '#7F77DD', 'dashed', 3, 0, 7),
  ('CONNECTED_TO',       'Connected to',        'Network or IAM connectivity between cloud resources.',                    1, '#1D9E75', 'solid',  2, 0, 8),
  ('HAS_VULNERABILITY',  'Has vulnerability',   'Asset is affected by a known weakness.',                                  1, '#E24B4A', 'dotted', 2, 0, 9),
  ('EXPOSES_CREDENTIAL', 'Exposes credential',  'Asset leaks authentication material readable by whoever can access it.',  1, '#E24B4A', 'dashed', 3, 1, 10);


-- Which node kinds each relationship may connect. The generator validates
-- against this, and the oracle uses it to reject structurally impossible
-- candidates before evaluating preconditions.
INSERT INTO edge_type_endpoint (edge_type_code, src_kind_code, dst_kind_code) VALUES
  ('MEMBER_OF',          'User',           'Group'),
  ('MEMBER_OF',          'ServiceAccount', 'Group'),
  ('MEMBER_OF',          'Group',          'Group'),

  ('HAS_CREDENTIAL',     'User',           'Credential'),
  ('HAS_CREDENTIAL',     'ServiceAccount', 'Credential'),

  ('AUTHENTICATES_TO',   'Credential',     'Host'),
  ('AUTHENTICATES_TO',   'Credential',     'Application'),
  ('AUTHENTICATES_TO',   'Credential',     'CloudResource'),
  ('AUTHENTICATES_TO',   'Credential',     'Database'),

  ('ADMIN_TO',           'User',           'Host'),
  ('ADMIN_TO',           'User',           'Database'),
  ('ADMIN_TO',           'User',           'CloudResource'),
  ('ADMIN_TO',           'ServiceAccount', 'Host'),
  ('ADMIN_TO',           'ServiceAccount', 'Database'),
  ('ADMIN_TO',           'ServiceAccount', 'CloudResource'),

  ('HAS_ACCESS_TO',      'ServiceAccount', 'Database'),
  ('HAS_ACCESS_TO',      'ServiceAccount', 'Application'),
  ('HAS_ACCESS_TO',      'ServiceAccount', 'CloudResource'),

  ('HAS_PERMISSION',     'Group',          'Host'),
  ('HAS_PERMISSION',     'Group',          'Database'),
  ('HAS_PERMISSION',     'Group',          'CloudResource'),
  ('HAS_PERMISSION',     'Group',          'Application'),

  ('TRUSTS',             'Host',           'Host'),

  ('CONNECTED_TO',       'CloudResource',  'CloudResource'),

  ('HAS_VULNERABILITY',  'Host',           'Vulnerability'),
  ('HAS_VULNERABILITY',  'Application',    'Vulnerability'),

  ('EXPOSES_CREDENTIAL', 'Host',           'Credential'),
  ('EXPOSES_CREDENTIAL', 'Application',    'Credential');
