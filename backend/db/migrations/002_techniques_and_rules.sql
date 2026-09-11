-- 002_techniques_and_rules
--
-- The attacker model: what capabilities exist, what techniques an attacker can
-- attempt, and the preconditions each technique requires.
--
-- This is the table set that separates faultline from a reachability tool. A
-- graph edge says two things are connected. A rule says under exactly what
-- circumstances an attacker standing at one end can reach the other, and what
-- they gain by doing so. Search runs over (node, held-capability-set), not over
-- nodes alone, which is why a path we report is one an attacker could execute
-- rather than merely a route the graph permits.
--
-- Because every useful transition strictly grows the held-capability set, the
-- state space is acyclic by construction. That is the monotonicity assumption,
-- and it is what keeps the search tractable despite the state augmentation. It
-- also dissolves the cycle problem: host A trusting host B trusting host A is a
-- cycle in the graph but not in the state space, since the second traversal
-- grants nothing new and is pruned by dominance.
--
-- Rules are data, not code. Adding a technique is an INSERT, and the reference
-- oracle and the fast engine both read the same rows -- which is what lets them
-- disagree loudly in tests when one of them is wrong.

-- A capability is something an attacker holds. Node-scoped capabilities are held
-- about a particular node ("admin on host-014"); global ones are held outright
-- ("is an authenticated domain user").
CREATE TABLE capability_atom (
    code         VARCHAR(48)  NOT NULL,
    label        VARCHAR(96)  NOT NULL,
    description  VARCHAR(512) NOT NULL,
    binding_kind ENUM('node', 'global') NOT NULL,
    -- Ordering for the capability-set display in the path detail panel.
    sort_order   SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- An attacker technique, mapped to MITRE ATT&CK. The mapping is not decoration:
-- every hop in a reported path cites the technique it used, which is a large part
-- of how the output stays explainable to a practitioner.
CREATE TABLE technique (
    code         VARCHAR(48)  NOT NULL,
    name         VARCHAR(128) NOT NULL,
    description  TEXT         NOT NULL,
    attack_id    VARCHAR(24)      NULL,
    attack_name  VARCHAR(128)     NULL,
    attack_url   VARCHAR(255)     NULL,
    -- Coarse phase, used to group the hop breakdown and to colour the path flow.
    phase        ENUM('initial_access', 'credential_access', 'privilege_escalation',
                      'lateral_movement', 'persistence', 'collection', 'impact') NOT NULL,
    sort_order   SMALLINT     NOT NULL,
    PRIMARY KEY (code),
    KEY ix_technique_attack (attack_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- One derivation rule: traversing an edge of a given type, using a given
-- technique, provided every precondition holds.
CREATE TABLE rule (
    id             SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code           VARCHAR(64)  NOT NULL,
    technique_code VARCHAR(48)  NOT NULL,
    -- The edge the rule traverses. NULL means the rule fires on state alone and
    -- does not consume an edge -- used for techniques like kerberoasting, where
    -- holding a domain account is itself sufficient to request a ticket.
    edge_type_code VARCHAR(32)      NULL,
    description    TEXT         NOT NULL,
    -- A rule that fires without consuming an edge cannot move the attacker, only
    -- grant capabilities. Recorded explicitly so the search can treat it as a
    -- zero-length transition.
    is_traversal   TINYINT(1)   NOT NULL DEFAULT 1,
    is_enabled     TINYINT(1)   NOT NULL DEFAULT 1,
    sort_order     SMALLINT     NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rule_code (code),
    KEY ix_rule_edge_type (edge_type_code),
    CONSTRAINT fk_rule_technique FOREIGN KEY (technique_code) REFERENCES technique (code),
    CONSTRAINT fk_rule_edge_type FOREIGN KEY (edge_type_code) REFERENCES edge_type (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Preconditions are conjunctive: every enabled row for a rule must hold.
-- Disjunction is expressed by writing two rules with the same technique, which
-- keeps the evaluator trivial and keeps every rejection attributable to one
-- specific unmet condition.
--
-- Three kinds:
--   capability  the attacker must already hold capability C about the bound node
--   edge_attr   an attribute of the traversed edge must satisfy the comparison
--   node_attr   an attribute of the bound node must satisfy the comparison
--
-- The edge_attr kind is what encodes the negative controls. A rule that requires
-- mfa_required = false will refuse the phishing-resistant twin of a decoy pair,
-- and the refusal is reported with the attribute that caused it.
CREATE TABLE rule_precondition (
    rule_id         SMALLINT UNSIGNED NOT NULL,
    seq             SMALLINT     NOT NULL,
    kind            ENUM('capability', 'edge_attr', 'node_attr') NOT NULL,
    -- Which node the condition is about. Ignored for edge_attr.
    binding         ENUM('src', 'dst', 'global') NOT NULL DEFAULT 'src',
    capability_code VARCHAR(48)      NULL,
    -- Dotted path into the attrs JSON document, e.g. 'mfa_type' or 'storage'.
    attr_path       VARCHAR(128)     NULL,
    operator        ENUM('eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'in', 'not_in', 'exists', 'absent') NULL,
    value_json      JSON             NULL,
    is_negated      TINYINT(1)   NOT NULL DEFAULT 0,
    -- Shown verbatim when this condition is the reason a candidate was rejected.
    failure_reason  VARCHAR(255) NOT NULL,
    PRIMARY KEY (rule_id, seq),
    KEY ix_precond_capability (capability_code),
    CONSTRAINT fk_precond_rule FOREIGN KEY (rule_id) REFERENCES rule (id) ON DELETE CASCADE,
    CONSTRAINT fk_precond_cap  FOREIGN KEY (capability_code) REFERENCES capability_atom (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- What the attacker gains when the rule fires.
CREATE TABLE rule_effect (
    rule_id         SMALLINT UNSIGNED NOT NULL,
    seq             SMALLINT     NOT NULL,
    capability_code VARCHAR(48)  NOT NULL,
    binding         ENUM('src', 'dst', 'global') NOT NULL DEFAULT 'dst',
    PRIMARY KEY (rule_id, seq),
    CONSTRAINT fk_effect_rule FOREIGN KEY (rule_id) REFERENCES rule (id) ON DELETE CASCADE,
    CONSTRAINT fk_effect_cap  FOREIGN KEY (capability_code) REFERENCES capability_atom (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Where an attacker is assumed to start. Discovery runs from this set to the
-- crown-jewel set. Held as data because the interesting comparison is between
-- threat models: an external attacker with a phished standard user, an insider
-- who already holds a domain account, a compromised contractor laptop.
CREATE TABLE threat_model (
    code        VARCHAR(48)  NOT NULL,
    label       VARCHAR(96)  NOT NULL,
    description VARCHAR(512) NOT NULL,
    is_default  TINYINT(1)   NOT NULL DEFAULT 0,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Capabilities the attacker is granted for free under a given threat model.
CREATE TABLE threat_model_grant (
    threat_model_code VARCHAR(48) NOT NULL,
    seq               SMALLINT    NOT NULL,
    capability_code   VARCHAR(48) NOT NULL,
    -- Which nodes the grant applies to: a node kind, or a specific node id.
    -- NULL kind with NULL node means the capability is granted globally.
    applies_to_kind   VARCHAR(32)     NULL,
    applies_to_node   VARCHAR(64)     NULL,
    PRIMARY KEY (threat_model_code, seq),
    CONSTRAINT fk_tmg_model FOREIGN KEY (threat_model_code) REFERENCES threat_model (code) ON DELETE CASCADE,
    CONSTRAINT fk_tmg_cap   FOREIGN KEY (capability_code)   REFERENCES capability_atom (code),
    CONSTRAINT fk_tmg_kind  FOREIGN KEY (applies_to_kind)   REFERENCES node_kind (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
