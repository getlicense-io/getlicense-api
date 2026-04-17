-- +goose Up

-- P3: validation staleness tolerance. Signed policy-level knob that tells
-- runtime SDKs how long they can trust a cached gl1 token before
-- re-checking the server. Null means "inherit server default" (env var
-- GETLICENSE_DEFAULT_VALIDATION_TTL_SEC, default 3600). Bounds enforced
-- at the DB for defense-in-depth; the service layer validates the same
-- range and returns a typed policy_invalid_ttl error for API callers.
ALTER TABLE policies
    ADD COLUMN validation_ttl_sec INTEGER,
    ADD CONSTRAINT policies_validation_ttl_sec_range
        CHECK (validation_ttl_sec IS NULL
               OR (validation_ttl_sec >= 60 AND validation_ttl_sec <= 2592000));

-- +goose Down
ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_validation_ttl_sec_range,
    DROP COLUMN IF EXISTS validation_ttl_sec;
