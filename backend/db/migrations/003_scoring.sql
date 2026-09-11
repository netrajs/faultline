-- 003_scoring
--
-- The risk model. Every constant the scorer uses lives here, versioned, so that
-- tuning a weight is a data change rather than a code change and so that any
-- score ever displayed can be reproduced by replaying the config it was computed
-- under.
--
-- The model in one paragraph
--
--   Risk has two axes and they are never blended inside the search. Likelihood is
--   the probability an attacker completes the chain: the product of per-hop
--   success probabilities. Impact is a property of what the chain reaches. The
--   search optimizes likelihood alone, because only likelihood is decomposable
--   over path prefixes; impact is applied once, at the end, when the path's target
--   is known.
--
-- Why a product rather than a maximum
--
--   A path is a conjunction. The attacker must succeed at every hop, so the
--   probability of the whole is the product of the parts. Taking the maximum over
--   per-hop risks -- a tempting simplification -- has zero partial derivative with
--   respect to every hop but one, which makes a six-hop chain score identically to
--   a one-hop version of its easiest step. It is also not decomposable over
--   prefixes, so Bellman's principle of optimality fails and no shortest-path
--   algorithm can optimize it: the system would rank by a formula it could not
--   search by.
--
--   Products underflow, so the engine works in log space: it minimizes the sum of
--   -ln(p) over hops, which is exactly equivalent to maximizing the product, and
--   which Dijkstra and A* handle correctly because -ln(p) is non-negative for
--   p <= 1. Path length is then penalized automatically and by the right amount,
--   which is why there is no hop-count decay term anywhere in this schema.
--
--   Log-additivity has a second payoff. Because the score is a sum of per-factor
--   log contributions, the Shapley attribution of each factor is exactly its own
--   term. The "why this score" breakdown is therefore not an approximation we
--   invented; it falls out of the arithmetic.
--
-- Why modifiers are applied in logit space
--
--   Multiplying a probability by a penalty can push it above 1, at which point
--   -ln(p) goes negative, Dijkstra's correctness guarantee is void, and negative
--   cycles become possible in a graph that deliberately contains trust cycles.
--   Applying modifiers additively in log-odds space instead --
--   logit(p') = logit(p) + sum(beta) -- can never leave the open interval (0,1),
--   composes commutatively, and yields per-factor log-odds contributions that are
--   directly reportable.

CREATE TABLE scoring_config (
    version        VARCHAR(32)  NOT NULL,
    label          VARCHAR(128) NOT NULL,
    description    TEXT         NOT NULL,
    -- Probabilities are clamped into this open interval after modifiers are
    -- applied. The lower bound keeps -ln(p) finite; the upper bound keeps a
    -- "certain" step from contributing exactly zero cost, which would create
    -- zero-weight cycles and enormous tie sets in the priority queue.
    p_clamp_min    DECIMAL(6, 5) NOT NULL,
    p_clamp_max    DECIMAL(6, 5) NOT NULL,
    -- Normalization denominator for the 0-10 display scale. Named, stored and
    -- versioned rather than hidden in code, because the original design had a
    -- formula whose maximum attainable value was 4.0 against display tiers that
    -- started "critical" at 9.0 -- no path could ever be rated critical, and
    -- nothing in the code said so.
    raw_max        DECIMAL(10, 6) NOT NULL,
    -- Relative weight of likelihood versus impact in the final display score.
    w_likelihood   DECIMAL(6, 4) NOT NULL,
    w_impact       DECIMAL(6, 4) NOT NULL,
    -- Whether the undetected-probability accumulator participates in the display
    -- score or is reported alongside it. Detection is tracked separately from
    -- success throughout, so it can never be double-counted the way a combined
    -- edge weight plus a hop-count decay term would double-count it.
    w_stealth      DECIMAL(6, 4) NOT NULL,
    is_active      TINYINT(1)   NOT NULL DEFAULT 0,
    active_flag    TINYINT(1)   GENERATED ALWAYS AS (IF(is_active = 1, 1, NULL)) STORED,
    created_at     DATETIME(6)  NOT NULL,
    PRIMARY KEY (version),
    UNIQUE KEY uq_scoring_active (active_flag)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Per-technique baseline probabilities, before any modifier is applied.
-- Separated from the technique catalogue so that retuning the model does not
-- mutate the description of what a technique is.
CREATE TABLE technique_baseline (
    scoring_version  VARCHAR(32)  NOT NULL,
    technique_code   VARCHAR(48)  NOT NULL,
    -- Probability the technique works given its preconditions are satisfied.
    base_p_succ      DECIMAL(6, 5) NOT NULL,
    -- Probability the SOC notices. Accumulated separately from success.
    base_detectability DECIMAL(6, 5) NOT NULL,
    -- Free-text justification for the numbers. Shown in the scoring inspector so
    -- a reviewer can challenge a specific value rather than the model as a whole.
    rationale        VARCHAR(1024) NOT NULL,
    PRIMARY KEY (scoring_version, technique_code),
    CONSTRAINT fk_tb_config    FOREIGN KEY (scoring_version) REFERENCES scoring_config (version) ON DELETE CASCADE,
    CONSTRAINT fk_tb_technique FOREIGN KEY (technique_code)  REFERENCES technique (code),
    CONSTRAINT ck_tb_psucc  CHECK (base_p_succ > 0 AND base_p_succ <= 1),
    CONSTRAINT ck_tb_detect CHECK (base_detectability >= 0 AND base_detectability <= 1)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Additive log-odds adjustments, applied when a condition holds on the edge, the
-- node, or an associated credential. Positive beta makes the step more likely to
-- succeed; negative beta makes it less likely.
--
-- A credential ninety days past rotation, shared across service accounts, sitting
-- in plaintext in a config file is three separate rows. Each contributes its own
-- log-odds term, and each appears as its own line in the score breakdown.
CREATE TABLE scoring_modifier (
    scoring_version VARCHAR(32)  NOT NULL,
    code            VARCHAR(64)  NOT NULL,
    label           VARCHAR(128) NOT NULL,
    description     VARCHAR(512) NOT NULL,
    -- Which object the condition inspects.
    applies_to      ENUM('edge', 'src_node', 'dst_node') NOT NULL,
    attr_path       VARCHAR(128) NOT NULL,
    operator        ENUM('eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'in', 'not_in', 'exists', 'absent') NOT NULL,
    value_json      JSON             NULL,
    -- Which accumulator this modifier adjusts.
    target          ENUM('p_succ', 'detectability') NOT NULL DEFAULT 'p_succ',
    beta            DECIMAL(8, 4) NOT NULL,
    -- A hard block short-circuits the rule: the transition is impossible, not
    -- merely unlikely. Phishing-resistant MFA against a credential-replay
    -- technique is a block, not a penalty, and modelling it as a smooth
    -- multiplier would quietly report attacks that cannot happen.
    is_hard_block   TINYINT(1)   NOT NULL DEFAULT 0,
    sort_order      SMALLINT     NOT NULL,
    PRIMARY KEY (scoring_version, code),
    CONSTRAINT fk_sm_config FOREIGN KEY (scoring_version) REFERENCES scoring_config (version) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Restricts a modifier to particular techniques. An empty set means it applies to
-- every technique. Credential age is irrelevant to a network-segmentation hop;
-- MFA strength is irrelevant to a vulnerability exploit.
CREATE TABLE scoring_modifier_scope (
    scoring_version VARCHAR(32) NOT NULL,
    modifier_code   VARCHAR(64) NOT NULL,
    technique_code  VARCHAR(48) NOT NULL,
    PRIMARY KEY (scoring_version, modifier_code, technique_code),
    CONSTRAINT fk_sms_modifier  FOREIGN KEY (scoring_version, modifier_code) REFERENCES scoring_modifier (scoring_version, code) ON DELETE CASCADE,
    CONSTRAINT fk_sms_technique FOREIGN KEY (technique_code) REFERENCES technique (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- The impact axis. Multipliers applied once, to the path's target, never inside
-- the search cost.
CREATE TABLE impact_weight (
    scoring_version VARCHAR(32) NOT NULL,
    dimension       ENUM('criticality', 'classification', 'crown_jewel') NOT NULL,
    code            VARCHAR(24) NOT NULL,
    weight          DECIMAL(6, 4) NOT NULL,
    PRIMARY KEY (scoring_version, dimension, code),
    CONSTRAINT fk_iw_config FOREIGN KEY (scoring_version) REFERENCES scoring_config (version) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Display bands for the normalized 0-10 score, including the colours the UI uses.
-- A migration test asserts that every band here is attainable by some
-- constructible path under the same scoring version -- an unreachable band is a
-- bug in the normalization, not a stylistic choice.
CREATE TABLE risk_tier (
    scoring_version VARCHAR(32)  NOT NULL,
    code            VARCHAR(24)  NOT NULL,
    label           VARCHAR(64)  NOT NULL,
    min_score       DECIMAL(4, 2) NOT NULL,
    max_score       DECIMAL(4, 2) NOT NULL,
    ui_color        CHAR(7)      NOT NULL,
    ui_bg_color     VARCHAR(32)  NOT NULL,
    action_text     VARCHAR(128) NOT NULL,
    sort_order      SMALLINT     NOT NULL,
    PRIMARY KEY (scoring_version, code),
    CONSTRAINT fk_rt_config FOREIGN KEY (scoring_version) REFERENCES scoring_config (version) ON DELETE CASCADE,
    CONSTRAINT ck_rt_range  CHECK (min_score >= 0 AND max_score <= 10 AND min_score < max_score)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
