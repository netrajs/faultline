-- 007_ground_truth
--
-- What the generator knows, and how the engine is scored against it.
--
-- The environment is synthetic, which is usually treated as a weakness. It is
-- the opposite: the generator knows the correct answer, so accuracy is
-- measurable rather than asserted. Almost every tool in this space claims to
-- find real attack paths; nearly none publishes a precision figure, because on
-- real infrastructure nobody knows the denominator. Here we do.
--
-- Keeping the oracle honest
--
--   The obvious trap is that the generator and the analyzer end up sharing an
--   assumption, agree with each other, and report a perfect score that means
--   nothing. Three separations prevent it.
--
--   First, the generator emits only primitive facts. It never writes a path.
--   Second, the manifest records INTENT ("an opportunity for an intern to reach
--   domain admin via nested groups") rather than the path itself, so recovering
--   the answer requires actually doing the work. Third, the reference oracle is
--   an exhaustive depth-first search with explicit precondition checks, written
--   from the rules specification before the fast engine exists and never
--   optimized. When the two disagree on a small graph, one of them is wrong and
--   the test says so.
--
-- Negative controls
--
--   Recall alone is easy to game: report everything and score perfectly. What
--   makes precision meaningful is planted decoys -- candidates that look
--   traversable but are not. And what makes decoys meaningful is that each ships
--   with a TWIN that IS valid and differs in exactly one attribute. Without
--   twins the engine could pass by pattern-matching on a keyword; with them, it
--   has to actually evaluate the deciding attribute.

CREATE TABLE generation_manifest (
    graph_version_id  INT UNSIGNED NOT NULL,
    seed              BIGINT       NOT NULL,
    generator_version VARCHAR(32)  NOT NULL,
    scenario_count    SMALLINT     NOT NULL,
    -- Canonical hash of the emitted facts. Generating twice from one seed must
    -- produce the same value; a CI test asserts it.
    facts_hash        CHAR(64)     NOT NULL,
    parameters        JSON         NOT NULL,
    created_at        DATETIME(6)  NOT NULL,
    PRIMARY KEY (graph_version_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- A named attack scenario the generator can plant.
CREATE TABLE scenario (
    code        VARCHAR(48)  NOT NULL,
    name        VARCHAR(128) NOT NULL,
    -- What opportunity this creates, in prose. Deliberately not a path: the
    -- engine has to derive the route itself, and the harness matches on what it
    -- finds rather than on what the generator would have said.
    intent      TEXT         NOT NULL,
    expected_min_hops SMALLINT NOT NULL,
    expected_max_hops SMALLINT NOT NULL,
    -- How severe a successful instance should be, for rank-correlation scoring.
    expected_severity DECIMAL(4, 2) NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- One row per scenario instance actually planted in a given graph.
CREATE TABLE plant_log (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    graph_version_id INT UNSIGNED NOT NULL,
    scenario_code    VARCHAR(48)  NOT NULL,
    -- Where the opportunity starts and ends. Endpoints only -- never the route.
    entry_node_id    VARCHAR(64)  NOT NULL,
    goal_node_id     VARCHAR(64)  NOT NULL,
    notes            VARCHAR(1024) NOT NULL,
    PRIMARY KEY (id),
    KEY ix_plant_graph (graph_version_id, scenario_code),
    CONSTRAINT fk_plant_manifest FOREIGN KEY (graph_version_id) REFERENCES generation_manifest (graph_version_id) ON DELETE CASCADE,
    CONSTRAINT fk_plant_scenario FOREIGN KEY (scenario_code)    REFERENCES scenario (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- A negative control and its matched positive twin.
CREATE TABLE decoy_pattern (
    code                VARCHAR(48)  NOT NULL,
    name                VARCHAR(128) NOT NULL,
    -- The single attribute whose value separates the decoy from its twin.
    deciding_attribute  VARCHAR(128) NOT NULL,
    decoy_description   TEXT         NOT NULL,
    twin_description    TEXT         NOT NULL,
    -- Why the decoy is genuinely not traversable, in one sentence. This is the
    -- text shown next to the refusal, so it has to be defensible to a
    -- practitioner rather than merely plausible.
    rejection_rationale TEXT         NOT NULL,
    attack_id           VARCHAR(24)      NULL,
    sort_order          SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE decoy_instance (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    graph_version_id  INT UNSIGNED NOT NULL,
    decoy_code        VARCHAR(48)  NOT NULL,
    role              ENUM('decoy', 'twin') NOT NULL,
    -- The element that carries the deciding attribute.
    edge_id           VARCHAR(64)      NULL,
    node_id           VARCHAR(64)      NULL,
    -- What a correct engine must do with this instance.
    expected_outcome  ENUM('reject', 'accept') NOT NULL,
    deciding_value    VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    KEY ix_decoy_graph (graph_version_id, decoy_code),
    CONSTRAINT fk_decoy_manifest FOREIGN KEY (graph_version_id) REFERENCES generation_manifest (graph_version_id) ON DELETE CASCADE,
    CONSTRAINT fk_decoy_pattern  FOREIGN KEY (decoy_code)       REFERENCES decoy_pattern (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- The success probability the generator actually used when synthesising an edge.
--
-- The engine never reads this; it derives its own estimate from observable
-- attributes. Comparing the two gives a calibration curve, which answers a
-- question a ranking metric cannot: when the engine says seventy percent, does
-- it happen seventy percent of the time? A model can rank perfectly and still be
-- badly calibrated, and a badly calibrated probability is misleading precisely
-- where it is used for prioritisation.
CREATE TABLE true_edge_probability (
    graph_version_id INT UNSIGNED NOT NULL,
    edge_id          VARCHAR(64)  NOT NULL,
    p_true           DECIMAL(12, 11) NOT NULL,
    detectability_true DECIMAL(12, 11) NOT NULL,
    PRIMARY KEY (graph_version_id, edge_id),
    CONSTRAINT fk_truep_manifest FOREIGN KEY (graph_version_id) REFERENCES generation_manifest (graph_version_id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE metric_definition (
    code            VARCHAR(48)  NOT NULL,
    label           VARCHAR(96)  NOT NULL,
    description     TEXT         NOT NULL,
    -- What the number means and how to read it, shown on hover. A metric a
    -- viewer cannot interpret is decoration.
    interpretation  VARCHAR(512) NOT NULL,
    family          ENUM('discovery', 'ranking', 'calibration', 'remediation', 'performance') NOT NULL,
    higher_is_better TINYINT(1)  NOT NULL,
    format          ENUM('fraction', 'percent', 'count', 'milliseconds', 'score') NOT NULL,
    sort_order      SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE evaluation_run (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    analysis_run_id  INT UNSIGNED NOT NULL,
    -- Whether the engine was scored against the manifest or against the slow
    -- reference implementation. Both matter, and they catch different faults:
    -- the manifest catches missed opportunities, the oracle catches disagreement
    -- about what the rules mean.
    oracle_kind      ENUM('manifest', 'reference_engine') NOT NULL,
    -- Strict matching keys on the edge sequence; loose keys on the node
    -- sequence. Reporting both makes visible how often the engine finds the
    -- right route by the wrong mechanism.
    match_level      ENUM('edge_sequence', 'node_sequence') NOT NULL,
    scenarios_total  SMALLINT     NOT NULL,
    duration_ms      INT UNSIGNED NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_eval_analysis (analysis_run_id),
    CONSTRAINT fk_eval_analysis FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE evaluation_metric (
    evaluation_run_id INT UNSIGNED NOT NULL,
    metric_code       VARCHAR(48)  NOT NULL,
    value             DECIMAL(12, 6) NOT NULL,
    -- Numerator and denominator kept alongside the ratio, so a viewer can see
    -- that a recall of 1.0 came from nineteen of nineteen rather than one of one.
    numerator         DECIMAL(12, 4)   NULL,
    denominator       DECIMAL(12, 4)   NULL,
    PRIMARY KEY (evaluation_run_id, metric_code),
    CONSTRAINT fk_evalmetric_run    FOREIGN KEY (evaluation_run_id) REFERENCES evaluation_run (id) ON DELETE CASCADE,
    CONSTRAINT fk_evalmetric_metric FOREIGN KEY (metric_code)       REFERENCES metric_definition (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Per-scenario outcome, so a miss can be inspected rather than merely counted.
CREATE TABLE evaluation_case (
    evaluation_run_id INT UNSIGNED NOT NULL,
    seq               SMALLINT     NOT NULL,
    kind              ENUM('scenario', 'decoy', 'twin') NOT NULL,
    reference_code    VARCHAR(48)  NOT NULL,
    outcome           ENUM('true_positive', 'false_positive', 'true_negative', 'false_negative') NOT NULL,
    matched_path_id   CHAR(64)         NULL,
    -- For a miss: how far the engine got before losing the thread.
    detail            VARCHAR(1024) NOT NULL,
    PRIMARY KEY (evaluation_run_id, seq),
    KEY ix_evalcase_outcome (evaluation_run_id, outcome),
    CONSTRAINT fk_evalcase_run FOREIGN KEY (evaluation_run_id) REFERENCES evaluation_run (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
