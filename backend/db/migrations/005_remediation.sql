-- 005_remediation
--
-- Recommending, simulating, approving, applying and verifying fixes.
--
-- Two commitments shape these tables.
--
-- First, simulation is by re-derivation. A simulated fix produces a child graph
-- version and a full discovery run against it; the delta is then a set difference
-- between two real result sets. The tempting alternative -- patching the existing
-- path list to remove whatever touched the mutated edge -- is faster and wrong,
-- and it is wrong in a way nobody notices until someone checks. Because both runs
-- are recorded, anyone can check.
--
-- Second, a fix can create paths as well as remove them. Rotating a shared
-- credential redistributes the secret; segmenting a network invites a
-- compensating bastion; removing a group membership can strip a DENY that was
-- doing real work. simulation_path_delta therefore records additions, and the
-- verification step fails loudly when a fix produced paths the simulation did not
-- predict.

CREATE TABLE fix_type (
    code            VARCHAR(48)  NOT NULL,
    label           VARCHAR(96)  NOT NULL,
    description     TEXT         NOT NULL,
    -- The graph mutation this fix performs.
    mutation_kind   ENUM('remove_edge', 'remove_node', 'set_edge_attr', 'set_node_attr') NOT NULL,
    -- Which edge or node attribute the mutation writes, for attribute mutations.
    mutation_target_attr VARCHAR(128) NULL,
    mutation_value  JSON             NULL,
    -- Cost inputs to the priority formula. Held as data so the team can retune
    -- what "manual" costs without touching the ranking code.
    effort_value    DECIMAL(6, 3) NOT NULL,
    effort_label    VARCHAR(48)  NOT NULL,
    disruption_value DECIMAL(6, 3) NOT NULL,
    disruption_label VARCHAR(48) NOT NULL,
    -- Above this disruption value, applying requires a signed approval.
    requires_approval TINYINT(1) NOT NULL DEFAULT 0,
    -- What this fix defends against, for the remediation rationale text.
    d3fend_id       VARCHAR(32)      NULL,
    sort_order      SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE remediation_state (
    code        VARCHAR(24)  NOT NULL,
    label       VARCHAR(64)  NOT NULL,
    description VARCHAR(512) NOT NULL,
    is_terminal TINYINT(1)   NOT NULL DEFAULT 0,
    ui_color    CHAR(7)      NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Which state transitions are legal. Enforced in the service layer by reading
-- this table, so the lifecycle is inspectable rather than buried in conditionals.
CREATE TABLE remediation_transition (
    from_state VARCHAR(24) NOT NULL,
    to_state   VARCHAR(24) NOT NULL,
    label      VARCHAR(64) NOT NULL,
    -- Whether this transition needs a cryptographic approval to be recorded.
    needs_approval TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (from_state, to_state),
    CONSTRAINT fk_trans_from FOREIGN KEY (from_state) REFERENCES remediation_state (code),
    CONSTRAINT fk_trans_to   FOREIGN KEY (to_state)   REFERENCES remediation_state (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE recommendation (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    analysis_run_id  INT UNSIGNED NOT NULL,
    fix_type_code    VARCHAR(48)  NOT NULL,
    target_kind      ENUM('edge', 'node') NOT NULL,
    target_id        VARCHAR(64)  NOT NULL,
    -- Human-readable summary, generated from the fix type and target.
    title            VARCHAR(255) NOT NULL,
    rationale        TEXT         NOT NULL,
    -- Ranking inputs, stored so the priority number is reproducible.
    risk_before      DECIMAL(4, 2) NOT NULL,
    risk_after       DECIMAL(4, 2)    NULL,
    paths_eliminated INT UNSIGNED     NULL,
    total_paths      INT UNSIGNED NOT NULL,
    path_coverage    DECIMAL(6, 5)    NULL,
    effort_value     DECIMAL(6, 3) NOT NULL,
    disruption_value DECIMAL(6, 3) NOT NULL,
    priority_score   DECIMAL(10, 4)   NULL,
    -- Estimates come from the chokepoint pass; measured values replace them once
    -- a simulation has actually run. Kept distinct so the UI never presents an
    -- estimate as a measurement.
    is_measured      TINYINT(1)   NOT NULL DEFAULT 0,
    state_code       VARCHAR(24)  NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_rec_run      (analysis_run_id, priority_score DESC),
    KEY ix_rec_state    (state_code),
    KEY ix_rec_target   (analysis_run_id, target_id),
    CONSTRAINT fk_rec_run   FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id) ON DELETE CASCADE,
    CONSTRAINT fk_rec_fix   FOREIGN KEY (fix_type_code)   REFERENCES fix_type (code),
    CONSTRAINT fk_rec_state FOREIGN KEY (state_code)      REFERENCES remediation_state (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Collateral of applying a fix: access a service legitimately needs and would
-- lose, other identities sharing a credential being rotated, systems downstream
-- of a trust being severed. Surfaced before approval, not discovered after.
CREATE TABLE recommendation_dependency (
    recommendation_id INT UNSIGNED NOT NULL,
    seq               SMALLINT     NOT NULL,
    kind              ENUM('access_lost', 'shared_credential', 'downstream_service', 'policy_conflict') NOT NULL,
    affected_node_id  VARCHAR(64)      NULL,
    description       VARCHAR(512) NOT NULL,
    severity          ENUM('info', 'warning', 'blocking') NOT NULL,
    PRIMARY KEY (recommendation_id, seq),
    CONSTRAINT fk_dep_rec FOREIGN KEY (recommendation_id) REFERENCES recommendation (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE simulation (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    recommendation_id INT UNSIGNED NOT NULL,
    baseline_run_id   INT UNSIGNED NOT NULL,
    -- Full discovery run against the mutated child graph version.
    simulated_run_id  INT UNSIGNED NOT NULL,
    paths_removed     INT UNSIGNED NOT NULL DEFAULT 0,
    -- Non-zero here is a finding, not an error. Fixes can open paths.
    paths_added       INT UNSIGNED NOT NULL DEFAULT 0,
    paths_rescored    INT UNSIGNED NOT NULL DEFAULT 0,
    risk_before       DECIMAL(4, 2) NOT NULL,
    risk_after        DECIMAL(4, 2) NOT NULL,
    crown_jewels_before SMALLINT   NOT NULL,
    crown_jewels_after  SMALLINT   NOT NULL,
    -- sha256 over the sorted predicted-removed and predicted-added path id sets.
    -- Verification compares against this, so a simulation cannot be retro-fitted
    -- to whatever the apply step happened to produce.
    prediction_hash   CHAR(64)     NOT NULL,
    created_at        DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    KEY ix_sim_rec (recommendation_id),
    CONSTRAINT fk_sim_rec       FOREIGN KEY (recommendation_id) REFERENCES recommendation (id) ON DELETE CASCADE,
    CONSTRAINT fk_sim_baseline  FOREIGN KEY (baseline_run_id)   REFERENCES analysis_run (id),
    CONSTRAINT fk_sim_simulated FOREIGN KEY (simulated_run_id)  REFERENCES analysis_run (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE simulation_path_delta (
    simulation_id  INT UNSIGNED NOT NULL,
    path_id        CHAR(64)     NOT NULL,
    change_kind    ENUM('removed', 'added', 'rescored') NOT NULL,
    risk_before    DECIMAL(4, 2)    NULL,
    risk_after     DECIMAL(4, 2)    NULL,
    PRIMARY KEY (simulation_id, path_id),
    KEY ix_delta_change (simulation_id, change_kind),
    CONSTRAINT fk_delta_sim FOREIGN KEY (simulation_id) REFERENCES simulation (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE applied_fix (
    id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    recommendation_id   INT UNSIGNED NOT NULL,
    simulation_id       INT UNSIGNED     NULL,
    applied_by          VARCHAR(191) NOT NULL,
    graph_version_before INT UNSIGNED NOT NULL,
    graph_version_after  INT UNSIGNED NOT NULL,
    -- Exact prior state of the mutated edge or node, so rollback restores rather
    -- than reconstructs.
    rollback_payload    JSON         NOT NULL,
    -- Discovery re-run against the live graph after applying.
    verification_run_id INT UNSIGNED     NULL,
    -- Did reality match the prediction? Both numbers are displayed; a product
    -- that reports its own simulation accuracy is making a checkable claim.
    fidelity_exact_match TINYINT(1)      NULL,
    fidelity_jaccard    DECIMAL(6, 5)    NULL,
    unexpected_paths    INT UNSIGNED     NULL,
    state_code          VARCHAR(24)  NOT NULL,
    applied_at          DATETIME(6)  NOT NULL,
    verified_at         DATETIME(6)      NULL,
    rolled_back_at      DATETIME(6)      NULL,
    PRIMARY KEY (id),
    KEY ix_applied_rec   (recommendation_id),
    KEY ix_applied_state (state_code),
    CONSTRAINT fk_applied_rec    FOREIGN KEY (recommendation_id)    REFERENCES recommendation (id),
    CONSTRAINT fk_applied_sim    FOREIGN KEY (simulation_id)        REFERENCES simulation (id),
    CONSTRAINT fk_applied_before FOREIGN KEY (graph_version_before) REFERENCES graph_version (id),
    CONSTRAINT fk_applied_after  FOREIGN KEY (graph_version_after)  REFERENCES graph_version (id),
    CONSTRAINT fk_applied_verify FOREIGN KEY (verification_run_id)  REFERENCES analysis_run (id),
    CONSTRAINT fk_applied_state  FOREIGN KEY (state_code)           REFERENCES remediation_state (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Ordered chains of fixes for recurring patterns.
--
-- Ordering matters and is not cosmetic: revoking an exposed credential before
-- rotating its copies locks out the services still using it, so the playbook
-- encodes rotate-then-revoke. Steps are rows precisely so that reasoning like
-- this is visible and arguable rather than implicit in code.
CREATE TABLE playbook (
    code        VARCHAR(48)  NOT NULL,
    name        VARCHAR(128) NOT NULL,
    description TEXT         NOT NULL,
    -- What situation this playbook responds to, matched against findings.
    trigger_description VARCHAR(512) NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE playbook_step (
    playbook_code VARCHAR(48) NOT NULL,
    step_no       SMALLINT    NOT NULL,
    fix_type_code VARCHAR(48) NOT NULL,
    description   VARCHAR(512) NOT NULL,
    -- Why this step comes where it does.
    ordering_note VARCHAR(512)    NULL,
    PRIMARY KEY (playbook_code, step_no),
    CONSTRAINT fk_step_playbook FOREIGN KEY (playbook_code) REFERENCES playbook (code) ON DELETE CASCADE,
    CONSTRAINT fk_step_fix      FOREIGN KEY (fix_type_code) REFERENCES fix_type (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
