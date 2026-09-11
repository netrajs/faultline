-- 006_audit_and_anchoring
--
-- The tamper-evident record, and the cryptographic governance around applying
-- fixes.
--
-- What a local hash chain actually proves
--
--   Very little, on its own. An attacker who can write to this database can
--   recompute every leaf and every link, and a verify endpoint that recomputes
--   the chain from the same database and returns "valid" is checking a structure
--   against itself. It will return green for a log that was rewritten wholesale.
--   That is worth stating plainly rather than papering over, because the fix is
--   cheap: periodically publish the Merkle root somewhere the attacker does not
--   control, and verify against that instead.
--
--   Anchoring bounds the damage. Anything committed before the last published
--   checkpoint cannot be altered without detection; only the window since that
--   checkpoint is malleable. The size of that window in seconds is a real
--   security property, so /api/audit/verify reports it as a number rather than
--   returning a boolean.
--
-- Why leaves are salted
--
--   Audit entries are low-entropy and guessable: an action code, a target id, a
--   timestamp, a scope. Publishing an unsalted Merkle root would let anyone
--   confirm a suspected entry by recomputing its hash -- which leaks the contents
--   of the identity graph through a structure whose entire purpose is to commit
--   to data without revealing it. A per-leaf random salt removes the guess-and-
--   confirm attack while preserving selective disclosure: releasing one salt
--   proves one entry without exposing any other.
--
-- Why approvals are signed off-box
--
--   faultline can revoke credentials, strip group memberships and disable
--   accounts. That is domain-admin-equivalent power, and a tool that finds
--   privilege-escalation paths should not itself be one. High-disruption fixes
--   therefore require an EIP-712 signature from a key this server never holds,
--   bound to the specific fix, the graph state it was simulated against, and a
--   validity window -- so an approval cannot be replayed against a different
--   graph or a different fix than the one the signer reviewed.

CREATE TABLE audit_action (
    code        VARCHAR(48)  NOT NULL,
    label       VARCHAR(96)  NOT NULL,
    description VARCHAR(512) NOT NULL,
    -- Actions that change the graph are held to a higher bar than reads.
    is_mutation TINYINT(1)   NOT NULL DEFAULT 0,
    ui_color    CHAR(7)      NOT NULL,
    sort_order  SMALLINT     NOT NULL,
    PRIMARY KEY (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- One append-only entry per recorded action. seq is the leaf index in the
-- Merkle tree and is never reused, never reordered and never deleted.
CREATE TABLE audit_entry (
    seq              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    action_code      VARCHAR(48)  NOT NULL,
    actor            VARCHAR(191) NOT NULL,
    target_kind      VARCHAR(32)      NULL,
    target_id        VARCHAR(64)      NULL,
    -- Canonical JSON of the action's parameters and outcome. Canonical means
    -- sorted keys and fixed float formatting, so the hash is reproducible.
    payload          JSON         NOT NULL,
    -- Context the entry was recorded under, so a replay can reproduce it.
    graph_version_id INT UNSIGNED     NULL,
    scoring_version  VARCHAR(32)      NULL,
    risk_before      DECIMAL(4, 2)    NULL,
    risk_after       DECIMAL(4, 2)    NULL,
    -- 16 bytes from a CSPRNG. Released only alongside an inclusion proof.
    salt             BINARY(16)   NOT NULL,
    -- leaf = sha256(0x00 || salt || canonical(entry)). The 0x00 domain-separation
    -- prefix distinguishes leaves from interior nodes, which are hashed with 0x01,
    -- following RFC 6962. Without it a leaf could be forged as an interior node.
    leaf_hash        BINARY(32)   NOT NULL,
    -- Running chain link, kept for cheap sequential verification independent of
    -- the Merkle structure.
    prev_hash        BINARY(32)       NULL,
    entry_hash       BINARY(32)   NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    PRIMARY KEY (seq),
    KEY ix_audit_action  (action_code, created_at),
    KEY ix_audit_actor   (actor, created_at),
    KEY ix_audit_target  (target_kind, target_id),
    KEY ix_audit_created (created_at),
    CONSTRAINT fk_audit_action FOREIGN KEY (action_code) REFERENCES audit_action (code)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- A published commitment to the log as of a given size.
CREATE TABLE merkle_checkpoint (
    epoch      INT UNSIGNED NOT NULL AUTO_INCREMENT,
    -- Number of leaves committed to. A consistency proof between two checkpoints
    -- shows the smaller log is a prefix of the larger -- which is what rules out
    -- history being rewritten between publications.
    tree_size  BIGINT UNSIGNED NOT NULL,
    root       BINARY(32)   NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    PRIMARY KEY (epoch),
    UNIQUE KEY uq_checkpoint_size (tree_size)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Result of publishing a checkpoint root outside this database.
--
-- Three modes, because a demo that depends on conference wifi is a demo that
-- fails. anvil is a local chain and always works; base-sepolia produces real
-- transaction hashes on a public testnet; replay serves previously recorded
-- receipts and is labelled as recorded in the interface, never passed off as
-- live. Ethereum Sepolia is deliberately not an option -- it is being retired,
-- and a contract whose explorer links die before judging is worse than no
-- contract at all.
CREATE TABLE anchor_receipt (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    checkpoint_epoch INT UNSIGNED NOT NULL,
    mode             ENUM('anvil', 'base-sepolia', 'polygon-amoy', 'replay') NOT NULL,
    chain_id         BIGINT UNSIGNED  NULL,
    contract_address VARCHAR(42)      NULL,
    tx_hash          VARCHAR(66)      NULL,
    block_number     BIGINT UNSIGNED  NULL,
    block_timestamp  DATETIME(6)      NULL,
    gas_used         BIGINT UNSIGNED  NULL,
    explorer_url     VARCHAR(512)     NULL,
    status           ENUM('pending', 'confirmed', 'failed', 'recorded') NOT NULL,
    error_text       TEXT             NULL,
    created_at       DATETIME(6)  NOT NULL,
    confirmed_at     DATETIME(6)      NULL,
    PRIMARY KEY (id),
    KEY ix_anchor_epoch  (checkpoint_epoch),
    KEY ix_anchor_status (status),
    CONSTRAINT fk_anchor_checkpoint FOREIGN KEY (checkpoint_epoch) REFERENCES merkle_checkpoint (epoch) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- An off-box signature authorizing a specific fix against a specific graph state.
--
-- Every field in the signed struct is load-bearing. Without the graph state root,
-- an approval reviewed against yesterday's graph could be applied to today's.
-- Without the simulation hash, a signer could be shown one predicted outcome and
-- a different one applied -- which is precisely how the large multisig incidents
-- of recent years worked. Without the validity window and nonce, an old approval
-- could be replayed.
CREATE TABLE remediation_approval (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    recommendation_id INT UNSIGNED NOT NULL,
    simulation_id     INT UNSIGNED     NULL,
    signer_address    VARCHAR(42)  NOT NULL,
    -- EIP-712 domain, stored so a verifier can reconstruct the digest exactly.
    domain_name       VARCHAR(64)  NOT NULL,
    domain_version    VARCHAR(16)  NOT NULL,
    domain_chain_id   BIGINT UNSIGNED NOT NULL,
    domain_verifying_contract VARCHAR(42) NULL,
    -- The signed struct.
    graph_state_root  BINARY(32)   NOT NULL,
    simulation_hash   CHAR(64)     NOT NULL,
    disruption_tier   VARCHAR(24)  NOT NULL,
    valid_after       DATETIME(6)  NOT NULL,
    valid_until       DATETIME(6)  NOT NULL,
    nonce             BIGINT UNSIGNED NOT NULL,
    -- 65-byte r,s,v signature, hex encoded.
    signature         VARCHAR(132) NOT NULL,
    -- The digest that was actually signed, recomputed and stored at verify time.
    typed_data_hash   BINARY(32)   NOT NULL,
    is_verified       TINYINT(1)   NOT NULL DEFAULT 0,
    verified_at       DATETIME(6)      NULL,
    created_at        DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_approval_nonce (signer_address, nonce),
    KEY ix_approval_rec (recommendation_id),
    CONSTRAINT fk_approval_rec FOREIGN KEY (recommendation_id) REFERENCES recommendation (id) ON DELETE CASCADE,
    CONSTRAINT fk_approval_sim FOREIGN KEY (simulation_id)     REFERENCES simulation (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;


-- Every verification attempt and what it found, so the interface can show a
-- history of integrity checks rather than only the latest answer.
CREATE TABLE verification_result (
    id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    checked_at          DATETIME(6)  NOT NULL,
    entries_checked     BIGINT UNSIGNED NOT NULL,
    chain_intact        TINYINT(1)   NOT NULL,
    -- Index of the first leaf whose recomputed hash disagrees. NULL when intact.
    first_divergent_seq BIGINT UNSIGNED NULL,
    -- Verified against a published root, not only against ourselves.
    anchor_epoch        INT UNSIGNED     NULL,
    anchor_matched      TINYINT(1)       NULL,
    inclusion_proof_ok  TINYINT(1)       NULL,
    consistency_proof_ok TINYINT(1)      NULL,
    -- Seconds since the last confirmed anchor: the window in which tampering
    -- would currently go undetected.
    tamper_window_seconds INT UNSIGNED   NULL,
    detail              JSON         NOT NULL,
    PRIMARY KEY (id),
    KEY ix_verification_time (checked_at),
    CONSTRAINT fk_verification_anchor FOREIGN KEY (anchor_epoch) REFERENCES merkle_checkpoint (epoch)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
