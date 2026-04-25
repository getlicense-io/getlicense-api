-- +goose Up

-- Recovery codes (PR-4.5): per-row storage with atomic
-- single-consumption semantics. Replaces the previous
-- identities.recovery_codes_enc blob (which was racy on lookup —
-- two concurrent requests for the SAME recovery code could both
-- pass the read, both delete from their local copy, and both
-- write back, redeeming a leaked code multiple times — and which
-- compared HMAC strings with `==`, leaking timing on first-byte
-- mismatch).
--
-- Lazy migration (Option D in spec §4.5): existing identities with
-- recovery_codes_enc non-null fall through to a legacy decrypt-
-- list-split path on first recovery-code use, after which their
-- remaining codes migrate to this table and the blob is cleared.
-- New TOTP enrollments write here directly. Once the legacy column
-- count hits zero a follow-up migration can drop
-- identities.recovery_codes_enc.
--
-- pgcrypto is enabled in 001_accounts.sql so gen_random_uuid()
-- works without re-declaring the extension.

CREATE TABLE recovery_codes (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id  uuid        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    code_hash    text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT NOW(),
    -- used_at stays NULL until a successful consume; the consume
    -- query DELETEs the row outright rather than UPDATEing used_at,
    -- so this column exists for audit / debugging only and is
    -- harmless to keep nullable. A future spec might switch to
    -- soft-delete via used_at if recovery-code audit becomes a need.
    used_at      timestamptz,

    -- One identity should never have the same hash twice. Enforces
    -- the invariant that ActivateTOTP generates unique codes AND
    -- makes the legacy-fallback Insert idempotent (paired with
    -- ON CONFLICT DO NOTHING in the InsertRecoveryCodes query).
    UNIQUE (identity_id, code_hash)
);

-- Identities are global (no tenant context). Like the parent
-- identities table, recovery_codes does NOT enable RLS — every
-- query targets a single identity_id explicitly via the
-- application-layer code path.

CREATE INDEX idx_recovery_codes_identity ON recovery_codes (identity_id);

-- +goose Down

DROP INDEX IF EXISTS idx_recovery_codes_identity;
DROP TABLE IF EXISTS recovery_codes;
