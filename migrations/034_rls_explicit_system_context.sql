-- +goose Up

-- PR-B (security): Make RLS bypass EXPLICIT instead of implicit.
--
-- Until this migration, every tenant-scoped policy used the
-- pattern:
--
--     NULLIF(current_setting('app.current_account_id', true), '') IS NULL
--     OR account_id = NULLIF(...)::uuid
--
-- The IS NULL branch was intended as an opt-in for background
-- jobs and bootstrap operations (signup, refresh, webhook
-- worker) that legitimately span tenants. In practice it ALSO
-- short-circuited the tenant predicate any time a handler
-- accidentally ran a repo call against the bare pool — i.e.
-- forgot WithTargetAccount. The semantics were fail-open:
-- a missed wrap leaked data across tenants instead of erroring.
--
-- This migration switches to fail-closed semantics. The new
-- predicate uses a CASE expression so the ELSE branch only
-- evaluates when system_context is NOT 'true':
--
--     CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
--          ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
--                                     '00000000-0000-0000-0000-000000000000')::uuid
--     END
--
-- The COALESCE substitutes a sentinel UUID when the GUC is
-- unset (current_setting with missing_ok=true returns NULL when
-- unset, which would otherwise cast to NULL and silently filter
-- all rows). The sentinel '00000000-0000-...' is a syntactically
-- valid UUID that cannot match any real row (UUIDv7 IDs always
-- have a nonzero timestamp prefix), so the predicate evaluates
-- to false for every row — fail-closed, zero rows returned.
--
-- We deliberately do NOT use a sentinel string that errors at
-- cast-time. PostgreSQL's planner inlines RLS predicates from
-- referenced tables (e.g. policy_entitlements RLS uses an EXISTS
-- on policies) and may evaluate the cast at plan time, even
-- under WithSystemContext, causing legitimate cross-tenant
-- queries to fail. The sentinel-UUID approach loses the runtime
-- diagnostic value of an error but preserves the security
-- invariant: no rows leak when the GUC is unset.
--
-- The bypass GUC `app.system_context` is set ONLY by the
-- explicit `TxManager.WithSystemContext` helper in
-- internal/db/tx.go. All other code paths must go through
-- WithTargetAccount, which sets `app.current_account_id`.
--
-- WHY CASE INSTEAD OF OR: Postgres does NOT short-circuit OR --
-- both arms are evaluated unconditionally. CASE WHEN/THEN/ELSE
-- evaluates only the matching branch, which is exactly what we
-- need so legitimate WithSystemContext callers don't trigger
-- the sentinel cast.
--
-- For env-scoped tables (licenses, machines, webhooks,
-- domain_events, webhook_endpoints, webhook_events) the
-- environment predicate is folded into the same CASE ELSE: the
-- system bypass is the WHEN branch; both account+env checks
-- live in the ELSE.
--
-- See `internal/db/tx.go:WithSystemContext` for the explicit
-- bypass helper and the inline list of legitimate callers
-- (background sweeps, signup/refresh, webhook worker pool,
-- middleware-level API key + JWT membership lookups).

-- account_memberships
DROP POLICY IF EXISTS tenant_account_memberships ON account_memberships;
CREATE POLICY tenant_account_memberships ON account_memberships
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- api_keys
DROP POLICY IF EXISTS tenant_api_keys ON api_keys;
CREATE POLICY tenant_api_keys ON api_keys
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- customers
DROP POLICY IF EXISTS customers_tenant ON customers;
CREATE POLICY customers_tenant ON customers
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- domain_events (env-scoped)
DROP POLICY IF EXISTS tenant_domain_events ON domain_events;
CREATE POLICY tenant_domain_events ON domain_events
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
                  AND environment = COALESCE(NULLIF(current_setting('app.current_environment', true), ''),
                                             '__rls_no_environment__')
        END
    );

-- entitlements
DROP POLICY IF EXISTS entitlements_tenant ON entitlements;
CREATE POLICY entitlements_tenant ON entitlements
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- environments
DROP POLICY IF EXISTS tenant_environments ON environments;
CREATE POLICY tenant_environments ON environments
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- grants (scoped by EITHER grantor or grantee account)
DROP POLICY IF EXISTS tenant_grants ON grants;
CREATE POLICY tenant_grants ON grants
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE grantor_account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                '00000000-0000-0000-0000-000000000000')::uuid
                  OR grantee_account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                   '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- invitations (scoped by created_by_account_id)
DROP POLICY IF EXISTS tenant_invitations ON invitations;
CREATE POLICY tenant_invitations ON invitations
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE created_by_account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                   '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- license_entitlements (scoped via licenses.account_id)
DROP POLICY IF EXISTS license_entitlements_tenant ON license_entitlements;
CREATE POLICY license_entitlements_tenant ON license_entitlements
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE EXISTS (
                 SELECT 1 FROM licenses
                  WHERE licenses.id = license_entitlements.license_id
                    AND licenses.account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                       '00000000-0000-0000-0000-000000000000')::uuid
             )
        END
    );

-- licenses (env-scoped)
DROP POLICY IF EXISTS tenant_licenses ON licenses;
CREATE POLICY tenant_licenses ON licenses
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
                  AND environment = COALESCE(NULLIF(current_setting('app.current_environment', true), ''),
                                             '__rls_no_environment__')
        END
    );

-- machines (env-scoped)
DROP POLICY IF EXISTS tenant_machines ON machines;
CREATE POLICY tenant_machines ON machines
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
                  AND environment = COALESCE(NULLIF(current_setting('app.current_environment', true), ''),
                                             '__rls_no_environment__')
        END
    );

-- policies
DROP POLICY IF EXISTS policies_tenant ON policies;
CREATE POLICY policies_tenant ON policies
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- policy_entitlements (scoped via policies.account_id)
DROP POLICY IF EXISTS policy_entitlements_tenant ON policy_entitlements;
CREATE POLICY policy_entitlements_tenant ON policy_entitlements
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE EXISTS (
                 SELECT 1 FROM policies
                  WHERE policies.id = policy_entitlements.policy_id
                    AND policies.account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                       '00000000-0000-0000-0000-000000000000')::uuid
             )
        END
    );

-- products
DROP POLICY IF EXISTS tenant_products ON products;
CREATE POLICY tenant_products ON products
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- roles (preset roles have account_id IS NULL — globally visible)
DROP POLICY IF EXISTS tenant_roles ON roles;
CREATE POLICY tenant_roles ON roles
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             WHEN account_id IS NULL THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

-- webhook_endpoints (env-scoped)
DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
                  AND environment = COALESCE(NULLIF(current_setting('app.current_environment', true), ''),
                                             '__rls_no_environment__')
        END
    );

-- webhook_events (env-scoped)
DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
CREATE POLICY tenant_webhook_events ON webhook_events
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                        '00000000-0000-0000-0000-000000000000')::uuid
                  AND environment = COALESCE(NULLIF(current_setting('app.current_environment', true), ''),
                                             '__rls_no_environment__')
        END
    );

-- +goose Down

-- Restore the previous fail-open NULLIF-based bypass for
-- rollback safety. New code (background sweeps, middleware
-- lookups) wrapped in WithSystemContext continues to work
-- because the IS NULL branch matches when the GUC is unset,
-- which is exactly what WithSystemContext leaves it as.

DROP POLICY IF EXISTS tenant_account_memberships ON account_memberships;
CREATE POLICY tenant_account_memberships ON account_memberships
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_api_keys ON api_keys;
CREATE POLICY tenant_api_keys ON api_keys
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS customers_tenant ON customers;
CREATE POLICY customers_tenant ON customers
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_domain_events ON domain_events;
CREATE POLICY tenant_domain_events ON domain_events
    USING (
        (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
         OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
        AND
        (NULLIF(current_setting('app.current_environment', true), '') IS NULL
         OR environment = current_setting('app.current_environment', true))
    );

DROP POLICY IF EXISTS entitlements_tenant ON entitlements;
CREATE POLICY entitlements_tenant ON entitlements
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_environments ON environments;
CREATE POLICY tenant_environments ON environments
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_grants ON grants;
CREATE POLICY tenant_grants ON grants
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR grantor_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
        OR grantee_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_invitations ON invitations;
CREATE POLICY tenant_invitations ON invitations
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR created_by_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS license_entitlements_tenant ON license_entitlements;
CREATE POLICY license_entitlements_tenant ON license_entitlements
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR EXISTS (
            SELECT 1 FROM licenses
             WHERE licenses.id = license_entitlements.license_id
               AND licenses.account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
        )
    );

DROP POLICY IF EXISTS tenant_licenses ON licenses;
CREATE POLICY tenant_licenses ON licenses
    USING (
        (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
         OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
        AND
        (NULLIF(current_setting('app.current_environment', true), '') IS NULL
         OR environment = current_setting('app.current_environment', true))
    );

DROP POLICY IF EXISTS tenant_machines ON machines;
CREATE POLICY tenant_machines ON machines
    USING (
        (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
         OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
        AND
        (NULLIF(current_setting('app.current_environment', true), '') IS NULL
         OR environment = current_setting('app.current_environment', true))
    );

DROP POLICY IF EXISTS policies_tenant ON policies;
CREATE POLICY policies_tenant ON policies
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS policy_entitlements_tenant ON policy_entitlements;
CREATE POLICY policy_entitlements_tenant ON policy_entitlements
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR EXISTS (
            SELECT 1 FROM policies
             WHERE policies.id = policy_entitlements.policy_id
               AND policies.account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
        )
    );

DROP POLICY IF EXISTS tenant_products ON products;
CREATE POLICY tenant_products ON products
    USING (
        NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_roles ON roles;
CREATE POLICY tenant_roles ON roles
    USING (
        account_id IS NULL
        OR NULLIF(current_setting('app.current_account_id', true), '') IS NULL
        OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints
    USING (
        (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
         OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
        AND
        (NULLIF(current_setting('app.current_environment', true), '') IS NULL
         OR environment = current_setting('app.current_environment', true))
    );

DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
CREATE POLICY tenant_webhook_events ON webhook_events
    USING (
        (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
         OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
        AND
        (NULLIF(current_setting('app.current_environment', true), '') IS NULL
         OR environment = current_setting('app.current_environment', true))
    );
