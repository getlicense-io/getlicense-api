-- +goose Up

-- JWT revocation infrastructure (PR-followup):
--
-- 1. revoked_jtis: per-token revocation. POST /v1/auth/logout adds
--    a row for the access JWT's jti. Verifier rejects any token
--    whose jti appears here. Rows are GC'd when the token's exp
--    passes (no point keeping a revocation for a dead token).
--
-- 2. identity_session_invalidations: bulk revocation. POST
--    /v1/auth/logout-all sets min_iat = NOW(); verifier rejects any
--    token issued before that timestamp. Captures "log me out
--    everywhere" without enumerating jtis.
--
-- Neither table is RLS-scoped — both are checked on every JWT verify
-- BEFORE any tenant context is established. Cross-tenant by design.

CREATE TABLE revoked_jtis (
    jti          uuid        PRIMARY KEY,
    identity_id  uuid        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    reason       text        NOT NULL DEFAULT 'logout',
    created_at   timestamptz NOT NULL DEFAULT NOW()
);

-- Background sweep deletes rows past expires_at; index makes it cheap.
CREATE INDEX idx_revoked_jtis_expires_at ON revoked_jtis (expires_at);

CREATE TABLE identity_session_invalidations (
    identity_id  uuid        PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
    min_iat      timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT NOW()
);

-- +goose Down

DROP TABLE IF EXISTS identity_session_invalidations;
DROP INDEX IF EXISTS idx_revoked_jtis_expires_at;
DROP TABLE IF EXISTS revoked_jtis;
