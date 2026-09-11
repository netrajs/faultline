-- 001_core_graph
--
-- The identity/asset graph itself, plus the reference tables that describe what
-- kinds of nodes and edges exist.
--
-- Design notes
--
--   Graph data is versioned. Every analysis result records the graph_version_id it
--   was computed against, so a mutation applied during remediation cannot silently
--   invalidate a number already on screen. Versions form a lineage via parent_id:
--   a simulated fix produces a child version, which is discarded or promoted.
--
--   Node and edge identifiers are deterministic strings derived from the generator
--   seed, not autoincrement integers. Regenerating from the same seed reproduces
--   the same ids, which is what makes deep links, cached narratives and the
--   canonical graph hash stable across a demo reset.
--
--   Adjacency is stored relationally and never traversed in SQL. The engine issues
--   two bulk SELECTs at startup and builds a compressed-sparse-row adjacency in
--   memory. The indexes below exist to make that load fast and to support the
--   Graph Explorer's neighbourhood queries, not to support pathfinding.
--
--   Rendering attributes (colour, shape, size, line style) live on the reference
--   tables rather than in frontend constants. The legend, the node styling and the
--   edge styling are all read from here.

CREATE TABLE schema_migration (
    version     VARCHAR(64)  NOT NULL,
    checksum    CHAR(64)     NOT NULL,
    applied_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (version)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Criticality and data-classification vocabularies. Referenced by nodes and, via
-- the scoring tables, by the impact axis of the risk model.
CREATE TABLE criticality (
    code        VARCHAR(24)  NOT NULL,
    label       VARCHAR(64)  NOT NULL,
    description VARCHAR(512) NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE data_classification (
    code        VARCHAR(24)  NOT NULL,
    label       VARCHAR(64)  NOT NULL,
    description VARCHAR(512) NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- What kinds of thing can appear in the graph, and how each is drawn.
CREATE TABLE node_kind (
    code         VARCHAR(32)  NOT NULL,
    label        VARCHAR(64)  NOT NULL,
    description  VARCHAR(512) NOT NULL,
    category     ENUM('identity', 'asset', 'secret', 'weakness') NOT NULL,
    ui_color     CHAR(7)      NOT NULL,
    ui_shape     VARCHAR(24)  NOT NULL,
    ui_size_min  SMALLINT     NOT NULL,
    ui_size_max  SMALLINT     NOT NULL,
    -- Which node attribute drives rendered size: risk, criticality, member_count, cvss.
    ui_size_by   VARCHAR(32)  NOT NULL,
    ui_icon      VARCHAR(48)      NULL,
    sort_order   SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- What kinds of relationship can appear, and how each is drawn.
--
-- Note the absence of anything resembling CAN_ESCALATE_TO. Every type here is a
-- fact a collector could observe in a real environment. Escalation is a conclusion
-- the engine derives; storing it as an input would make discovery circular and
-- would leave remediation computing deltas against a stale graph.
CREATE TABLE edge_type (
    code          VARCHAR(32)  NOT NULL,
    label         VARCHAR(64)  NOT NULL,
    description   VARCHAR(512) NOT NULL,
    is_directed   TINYINT(1)   NOT NULL DEFAULT 1,
    ui_color      CHAR(7)      NOT NULL,
    ui_line_style ENUM('solid', 'dashed', 'dotted') NOT NULL,
    ui_width      TINYINT      NOT NULL,
    ui_animated   TINYINT(1)   NOT NULL DEFAULT 0,
    sort_order    SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Which node kinds an edge type is allowed to connect. The generator validates
-- against this, and the oracle uses it as a sanity check on candidate transitions.
CREATE TABLE edge_type_endpoint (
    edge_type_code VARCHAR(32) NOT NULL,
    src_kind_code  VARCHAR(32) NOT NULL,
    dst_kind_code  VARCHAR(32) NOT NULL,
    PRIMARY KEY (edge_type_code, src_kind_code, dst_kind_code),
    CONSTRAINT fk_ete_type FOREIGN KEY (edge_type_code) REFERENCES edge_type (code) ON DELETE CASCADE,
    CONSTRAINT fk_ete_src  FOREIGN KEY (src_kind_code)  REFERENCES node_kind (code),
    CONSTRAINT fk_ete_dst  FOREIGN KEY (dst_kind_code)  REFERENCES node_kind (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- One row per immutable snapshot of the graph.
CREATE TABLE graph_version (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    label             VARCHAR(128) NOT NULL,
    origin            ENUM('generated', 'imported', 'mutation') NOT NULL,
    -- Seed and generator version together reproduce a 'generated' graph exactly.
    seed              BIGINT           NULL,
    generator_version VARCHAR(32)      NULL,
    -- Lineage: a simulated or applied fix produces a child of the version it mutated.
    parent_id         INT UNSIGNED     NULL,
    -- sha256 over the canonical serialisation. Two runs of the same seed must match.
    canonical_hash    CHAR(64)         NULL,
    node_count        INT UNSIGNED NOT NULL DEFAULT 0,
    edge_count        INT UNSIGNED NOT NULL DEFAULT 0,
    -- Exactly one version is active at a time; enforced by a partial-unique trick
    -- below since MySQL has no filtered indexes.
    is_active         TINYINT(1)   NOT NULL DEFAULT 0,
    active_flag       TINYINT(1)   GENERATED ALWAYS AS (IF(is_active = 1, 1, NULL)) STORED,
    notes             VARCHAR(1024)    NULL,
    created_at        DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_graph_version_active (active_flag),
    KEY ix_graph_version_parent (parent_id),
    CONSTRAINT fk_gv_parent FOREIGN KEY (parent_id) REFERENCES graph_version (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE node (
    graph_version_id  INT UNSIGNED NOT NULL,
    node_id           VARCHAR(64)  NOT NULL,
    kind_code         VARCHAR(32)  NOT NULL,
    name              VARCHAR(191) NOT NULL,
    display_name      VARCHAR(191)     NULL,
    -- Crown jewels are the goal set for path discovery. Kept as a column rather
    -- than a separate label table because every query filters on it.
    is_crown_jewel    TINYINT(1)   NOT NULL DEFAULT 0,
    criticality_code  VARCHAR(24)      NULL,
    classification_code VARCHAR(24)    NULL,
    -- Kind-specific properties: department and mfa_enabled for a user, os and
    -- patch_level for a host, cvss and epss for a vulnerability. Typed columns
    -- cover what every kind shares; this covers the long tail.
    attrs             JSON         NOT NULL,
    PRIMARY KEY (graph_version_id, node_id),
    KEY ix_node_kind  (graph_version_id, kind_code),
    KEY ix_node_crown (graph_version_id, is_crown_jewel),
    KEY ix_node_name  (graph_version_id, name),
    CONSTRAINT fk_node_gv    FOREIGN KEY (graph_version_id)   REFERENCES graph_version (id) ON DELETE CASCADE,
    CONSTRAINT fk_node_kind  FOREIGN KEY (kind_code)          REFERENCES node_kind (code),
    CONSTRAINT fk_node_crit  FOREIGN KEY (criticality_code)   REFERENCES criticality (code),
    CONSTRAINT fk_node_class FOREIGN KEY (classification_code) REFERENCES data_classification (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE edge (
    graph_version_id INT UNSIGNED NOT NULL,
    edge_id          VARCHAR(64)  NOT NULL,
    src_id           VARCHAR(64)  NOT NULL,
    dst_id           VARCHAR(64)  NOT NULL,
    type_code        VARCHAR(32)  NOT NULL,
    -- Observed configuration only: mfa_required and mfa_type on an authentication
    -- edge, permission_level on an access edge, location and discoverability on a
    -- credential-exposure edge. Success probability is NOT stored here: it is
    -- derived from these observable attributes by the scoring rules, so that
    -- changing a scoring weight re-scores the graph without regenerating it.
    attrs            JSON         NOT NULL,
    PRIMARY KEY (graph_version_id, edge_id),
    KEY ix_edge_out (graph_version_id, src_id, type_code),
    KEY ix_edge_in  (graph_version_id, dst_id, type_code),
    KEY ix_edge_type (graph_version_id, type_code),
    CONSTRAINT fk_edge_gv   FOREIGN KEY (graph_version_id) REFERENCES graph_version (id) ON DELETE CASCADE,
    CONSTRAINT fk_edge_src  FOREIGN KEY (graph_version_id, src_id) REFERENCES node (graph_version_id, node_id) ON DELETE CASCADE,
    CONSTRAINT fk_edge_dst  FOREIGN KEY (graph_version_id, dst_id) REFERENCES node (graph_version_id, node_id) ON DELETE CASCADE,
    CONSTRAINT fk_edge_type FOREIGN KEY (type_code) REFERENCES edge_type (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
