-- 004_analysis_results
--
-- Output of a discovery run: the paths found, how each was scored, what was
-- reached, and -- just as importantly -- what was considered and refused.
--
-- The rejected_candidate table is not diagnostics. It is the product's central
-- claim made inspectable. Anything can report paths; the interesting question is
-- what a tool declines to report and whether it can say why. Every refusal here
-- names the rule and the specific precondition that failed, which is what turns
-- "we avoid false positives" from an assertion into something a judge can click.
--
-- Path identifiers are content hashes over the edge sequence, not autoincrement
-- integers. Edge ids rather than node ids, because two different credentials
-- between the same user and host are two genuinely different attacks and a
-- node-keyed identity would silently merge them. Content hashing means a path
-- keeps its id across a regeneration or a demo reset, so deep links survive and
-- the narration cache stays warm -- which matters because the alternative is a
-- live model call at the moment of maximum risk.

CREATE TABLE analysis_run (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    graph_version_id   INT UNSIGNED NOT NULL,
    scoring_version    VARCHAR(32)  NOT NULL,
    threat_model_code  VARCHAR(48)  NOT NULL,
    -- What this run was for. A simulation run is compared against its baseline.
    purpose            ENUM('baseline', 'simulation', 'verification', 'evaluation') NOT NULL,
    baseline_run_id    INT UNSIGNED     NULL,
    max_hops           SMALLINT     NOT NULL,
    top_k_per_pair     SMALLINT     NOT NULL,
    -- Counts, denormalized because every dashboard tile reads them.
    path_count         INT UNSIGNED NOT NULL DEFAULT 0,
    rejected_count     INT UNSIGNED NOT NULL DEFAULT 0,
    crown_jewels_reached SMALLINT   NOT NULL DEFAULT 0,
    max_risk_score     DECIMAL(4, 2)    NULL,
    -- Wall-clock, shown in the validation view. An engine that is correct but
    -- takes a minute is a different product from one that takes a second.
    duration_ms        INT UNSIGNED     NULL,
    status             ENUM('running', 'complete', 'failed') NOT NULL DEFAULT 'running',
    error_text         TEXT             NULL,
    started_at         DATETIME(6)  NOT NULL,
    finished_at        DATETIME(6)      NULL,
    PRIMARY KEY (id),
    KEY ix_run_graph (graph_version_id, purpose),
    KEY ix_run_baseline (baseline_run_id),
    CONSTRAINT fk_run_scoring FOREIGN KEY (scoring_version)   REFERENCES scoring_config (version),
    CONSTRAINT fk_run_threat  FOREIGN KEY (threat_model_code) REFERENCES threat_model (code),
    CONSTRAINT fk_run_base    FOREIGN KEY (baseline_run_id)   REFERENCES analysis_run (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE discovered_path (
    -- sha256 over the ordered edge-id sequence. Stable across regeneration.
    path_id         CHAR(64)     NOT NULL,
    analysis_run_id INT UNSIGNED NOT NULL,
    source_node_id  VARCHAR(64)  NOT NULL,
    target_node_id  VARCHAR(64)  NOT NULL,
    hop_count       SMALLINT     NOT NULL,
    -- Likelihood the whole chain succeeds: the product of per-hop success
    -- probabilities. Stored as the probability for display and as its negative
    -- log for ordering, because the log is what the search actually minimized
    -- and re-deriving it from a rounded probability would reorder ties.
    p_success       DECIMAL(12, 11) NOT NULL,
    neg_log_success DECIMAL(12, 6)  NOT NULL,
    -- Probability the attacker completes the chain unnoticed. Accumulated
    -- separately from success so the two can never be conflated.
    p_undetected    DECIMAL(12, 11) NOT NULL,
    -- Weakest single hop. Reported alongside the product, never instead of it.
    bottleneck_p    DECIMAL(12, 11) NOT NULL,
    bottleneck_hop  SMALLINT     NOT NULL,
    impact_score    DECIMAL(6, 4) NOT NULL,
    -- Normalized 0-10 display score.
    risk_score      DECIMAL(4, 2) NOT NULL,
    risk_tier_code  VARCHAR(24)  NOT NULL,
    target_is_crown_jewel TINYINT(1) NOT NULL DEFAULT 0,
    rank_in_run     INT UNSIGNED NOT NULL,
    PRIMARY KEY (analysis_run_id, path_id),
    KEY ix_path_rank   (analysis_run_id, rank_in_run),
    KEY ix_path_risk   (analysis_run_id, risk_score DESC),
    KEY ix_path_target (analysis_run_id, target_node_id),
    KEY ix_path_source (analysis_run_id, source_node_id),
    KEY ix_path_id     (path_id),
    CONSTRAINT fk_path_run FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE path_hop (
    analysis_run_id  INT UNSIGNED NOT NULL,
    path_id          CHAR(64)     NOT NULL,
    hop_no           SMALLINT     NOT NULL,
    src_node_id      VARCHAR(64)  NOT NULL,
    dst_node_id      VARCHAR(64)  NOT NULL,
    -- NULL for a non-traversal rule that grants a capability without moving.
    edge_id          VARCHAR(64)      NULL,
    technique_code   VARCHAR(48)  NOT NULL,
    rule_id          SMALLINT UNSIGNED NOT NULL,
    p_succ           DECIMAL(12, 11) NOT NULL,
    detectability    DECIMAL(12, 11) NOT NULL,
    -- This hop's share of the path's total -ln(p). Because the score is a sum of
    -- log terms, this value IS the hop's exact Shapley contribution rather than
    -- an approximation of it -- the attribution falls out of the arithmetic.
    neg_log_contribution DECIMAL(12, 6) NOT NULL,
    PRIMARY KEY (analysis_run_id, path_id, hop_no),
    CONSTRAINT fk_hop_path      FOREIGN KEY (analysis_run_id, path_id) REFERENCES discovered_path (analysis_run_id, path_id) ON DELETE CASCADE,
    CONSTRAINT fk_hop_technique FOREIGN KEY (technique_code) REFERENCES technique (code),
    CONSTRAINT fk_hop_rule      FOREIGN KEY (rule_id) REFERENCES rule (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Capabilities the attacker holds after each hop. This is the proof trace: it is
-- what lets the UI answer "why was this step possible" with the actual state
-- rather than a plausible story, and it is what the hallucination gate checks
-- narration against.
CREATE TABLE path_hop_capability (
    analysis_run_id INT UNSIGNED NOT NULL,
    path_id         CHAR(64)     NOT NULL,
    hop_no          SMALLINT     NOT NULL,
    capability_code VARCHAR(48)  NOT NULL,
    -- Node the capability is about. Empty string for globally-scoped
    -- capabilities rather than NULL, because this column is part of the primary
    -- key and MySQL will not accept a nullable key part.
    about_node_id   VARCHAR(64)  NOT NULL DEFAULT '',
    -- Whether this hop granted it, or it was already held.
    is_newly_gained TINYINT(1)   NOT NULL,
    PRIMARY KEY (analysis_run_id, path_id, hop_no, capability_code, about_node_id),
    CONSTRAINT fk_hopcap_hop FOREIGN KEY (analysis_run_id, path_id, hop_no) REFERENCES path_hop (analysis_run_id, path_id, hop_no) ON DELETE CASCADE,
    CONSTRAINT fk_hopcap_cap FOREIGN KEY (capability_code) REFERENCES capability_atom (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Per-factor breakdown behind a hop's probability: the baseline, then every
-- modifier that fired, with its log-odds term. The "why this score" panel reads
-- this table directly; no number in the UI is computed in the browser.
CREATE TABLE path_score_factor (
    analysis_run_id INT UNSIGNED NOT NULL,
    path_id         CHAR(64)     NOT NULL,
    hop_no          SMALLINT     NOT NULL,
    seq             SMALLINT     NOT NULL,
    factor_kind     ENUM('baseline', 'modifier', 'impact') NOT NULL,
    factor_code     VARCHAR(64)  NOT NULL,
    factor_label    VARCHAR(128) NOT NULL,
    -- The observed value that triggered this factor, for display.
    observed_value  VARCHAR(255)     NULL,
    beta            DECIMAL(8, 4)    NULL,
    -- Effect on the running probability after this factor was applied.
    p_after         DECIMAL(12, 11) NOT NULL,
    PRIMARY KEY (analysis_run_id, path_id, hop_no, seq),
    CONSTRAINT fk_factor_hop FOREIGN KEY (analysis_run_id, path_id, hop_no) REFERENCES path_hop (analysis_run_id, path_id, hop_no) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Candidates the search reached and refused.
--
-- A tool that reports everything reachable has no false negatives and no
-- credibility. This table is where the opposite claim is evidenced: each row
-- names the rule that could have fired, the precondition that did not hold, and
-- the attribute value responsible. When the candidate corresponds to a planted
-- decoy, decoy_code links it, which is how the evaluation harness scores
-- precision without hand-labelling.
CREATE TABLE rejected_candidate (
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    analysis_run_id  INT UNSIGNED NOT NULL,
    -- sha256 over the partial edge sequence, so repeated refusals collapse.
    signature        CHAR(64)     NOT NULL,
    src_node_id      VARCHAR(64)  NOT NULL,
    dst_node_id      VARCHAR(64)  NOT NULL,
    edge_id          VARCHAR(64)      NULL,
    rule_id          SMALLINT UNSIGNED NOT NULL,
    -- Which precondition row failed. NULL when the refusal came from a hard
    -- block in the scoring layer rather than from a rule precondition.
    precondition_seq SMALLINT         NULL,
    reason_code      VARCHAR(64)  NOT NULL,
    reason_text      VARCHAR(512) NOT NULL,
    observed_value   VARCHAR(255)     NULL,
    -- Set when this refusal matches a planted negative control.
    decoy_code       VARCHAR(48)      NULL,
    hop_depth        SMALLINT     NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rejected (analysis_run_id, signature, rule_id),
    KEY ix_rejected_reason (analysis_run_id, reason_code),
    KEY ix_rejected_decoy  (analysis_run_id, decoy_code),
    CONSTRAINT fk_rejected_run  FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id) ON DELETE CASCADE,
    CONSTRAINT fk_rejected_rule FOREIGN KEY (rule_id) REFERENCES rule (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Ranked cut candidates: removing this edge or node severs the most paths.
--
-- Chokepoints are computed as a greedy set cover over path coverage, not as
-- betweenness centrality. Betweenness answers which node is topologically
-- central, which is a different question from what to fix first. Set cover over
-- a submodular coverage function carries a (1 - 1/e) approximation guarantee,
-- and the resulting bound is stored so the UI can state the optimality gap
-- rather than implying the selection is optimal.
CREATE TABLE chokepoint (
    analysis_run_id   INT UNSIGNED NOT NULL,
    rank_in_run       SMALLINT     NOT NULL,
    kind              ENUM('edge', 'node') NOT NULL,
    target_id         VARCHAR(64)  NOT NULL,
    paths_covered     INT UNSIGNED NOT NULL,
    coverage_fraction DECIMAL(6, 5) NOT NULL,
    -- Cumulative coverage of this chokepoint plus all higher-ranked ones.
    cumulative_fraction DECIMAL(6, 5) NOT NULL,
    -- Upper bound on what an optimal selection of the same size could achieve.
    optimality_bound  DECIMAL(6, 5)    NULL,
    PRIMARY KEY (analysis_run_id, rank_in_run),
    KEY ix_chokepoint_target (analysis_run_id, target_id),
    CONSTRAINT fk_chokepoint_run FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE blast_radius_run (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    analysis_run_id  INT UNSIGNED NOT NULL,
    origin_node_id   VARCHAR(64)  NOT NULL,
    direction        ENUM('outbound', 'inbound', 'both') NOT NULL,
    max_depth        SMALLINT     NOT NULL,
    nodes_reached    INT UNSIGNED NOT NULL DEFAULT 0,
    crown_jewels_reached SMALLINT NOT NULL DEFAULT 0,
    severity_score   DECIMAL(4, 2)    NULL,
    created_at       DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_blast_origin (analysis_run_id, origin_node_id),
    CONSTRAINT fk_blast_run FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- One row per node the origin can reach. Reachability carries a probability, so
-- that a node reachable with p = 0.02 is not counted the same as one reachable
-- with p = 0.9 -- an unweighted blast radius overstates exposure badly on a
-- densely connected graph.
CREATE TABLE blast_reached_node (
    blast_run_id  INT UNSIGNED NOT NULL,
    node_id       VARCHAR(64)  NOT NULL,
    depth         SMALLINT     NOT NULL,
    p_reach       DECIMAL(12, 11) NOT NULL,
    is_crown_jewel TINYINT(1)  NOT NULL DEFAULT 0,
    -- The best path that gets here, so the UI can justify every reached node.
    witness_path_id CHAR(64)       NULL,
    PRIMARY KEY (blast_run_id, node_id),
    KEY ix_blast_depth (blast_run_id, depth),
    CONSTRAINT fk_reached_run FOREIGN KEY (blast_run_id) REFERENCES blast_radius_run (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
