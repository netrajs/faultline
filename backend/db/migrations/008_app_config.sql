-- 008_app_config
--
-- Interface configuration, held in the database like everything else.
--
-- The rule for this project is that no value the application displays or
-- computes with is written into source. That covers the obvious things -- risk
-- weights, thresholds, technique definitions -- but it also covers navigation,
-- feature flags, layout defaults and the saved Cypher the Graph Explorer offers.
--
-- The frontend therefore ships with no fixture data and no fallback constants.
-- An empty database renders empty states rather than plausible-looking invented
-- numbers, which is the behaviour you want in a tool whose entire pitch is that
-- its numbers are traceable.

CREATE TABLE app_config (
    config_key  VARCHAR(96)  NOT NULL,
    value       TEXT         NOT NULL,
    value_type  ENUM('string', 'int', 'float', 'bool', 'json') NOT NULL,
    description VARCHAR(512) NOT NULL,
    -- Whether the value may be served to the browser. Anything touching
    -- credentials or internal endpoints stays server-side.
    is_public   TINYINT(1)   NOT NULL DEFAULT 1,
    -- Whether the Settings screen may change it at runtime.
    is_editable TINYINT(1)   NOT NULL DEFAULT 0,
    category    VARCHAR(48)  NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (config_key),
    KEY ix_config_category (category, sort_order)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


CREATE TABLE nav_item (
    code        VARCHAR(48)  NOT NULL,
    label       VARCHAR(64)  NOT NULL,
    route       VARCHAR(128) NOT NULL,
    icon        VARCHAR(64)  NOT NULL,
    description VARCHAR(255) NOT NULL,
    is_enabled  TINYINT(1)   NOT NULL DEFAULT 1,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Graph layout presets offered in the Explorer.
CREATE TABLE layout_preset (
    code        VARCHAR(48)  NOT NULL,
    label       VARCHAR(64)  NOT NULL,
    description VARCHAR(255) NOT NULL,
    -- Layout engine name and its parameters, passed through to the renderer.
    engine      VARCHAR(48)  NOT NULL,
    params      JSON         NOT NULL,
    -- Rough upper bound on node count where this layout stays usable, so the
    -- Explorer can warn instead of freezing.
    max_nodes   INT UNSIGNED NOT NULL,
    is_default  TINYINT(1)   NOT NULL DEFAULT 0,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Cypher the Graph Explorer offers as one-click queries.
--
-- One of these matters more than the rest. The naive reachability query --
-- variable-length matching from any user to any crown jewel -- is what a
-- reachability tool would call an attack path list, and it returns far more
-- results than the engine does. Running it live, against the same database, next
-- to the engine's answer is the clearest available demonstration of what
-- precondition-aware search buys: the difference between the two counts is the
-- false positives, and every one of them has a recorded reason.
--
-- It lives in a table rather than in a component so the comparison can be
-- adjusted without a rebuild, and so it is visibly part of the product rather
-- than a stunt wired into the demo.
CREATE TABLE saved_query (
    code        VARCHAR(48)  NOT NULL,
    label       VARCHAR(96)  NOT NULL,
    description TEXT         NOT NULL,
    cypher      TEXT         NOT NULL,
    -- What this query is for. 'contrast' marks the naive-reachability query
    -- whose whole purpose is to be wrong in an instructive way.
    purpose     ENUM('explore', 'contrast', 'diagnostic') NOT NULL,
    -- Bound parameters and their defaults.
    parameters  JSON         NOT NULL,
    is_enabled  TINYINT(1)   NOT NULL DEFAULT 1,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Steps of the walkthrough, so the demo sequence is data rather than a document
-- someone has to remember. Also drives an in-app guided mode.
CREATE TABLE demo_step (
    step_no     SMALLINT     NOT NULL,
    title       VARCHAR(128) NOT NULL,
    route       VARCHAR(128) NOT NULL,
    narration   TEXT         NOT NULL,
    -- Which evaluation criterion this step is meant to evidence.
    criterion   ENUM('path_correctness', 'risk_prioritization', 'explainability',
                     'remediation_impact', 'context') NOT NULL,
    expected_duration_seconds SMALLINT NOT NULL,
    PRIMARY KEY (step_no)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
