// Package db — constraint names referenced by error classification.
// Keep in sync with migrations/. A rename in SQL without a rename here
// yields silent misclassification. Add an entry here ONLY if a repo
// method classifies on that constraint name.
package db

const (
	// Unique constraints
	ConstraintAccountSlugUnique      = "accounts_slug_key"
	ConstraintIdentityEmailUnique    = "idx_identities_email"
	ConstraintCustomerEmailUnique    = "customers_account_email_ci"
	ConstraintEntitlementCodeUnique  = "entitlements_account_code_ci"
	ConstraintEnvironmentSlugUnique  = "environments_account_id_slug_key"
	ConstraintLicenseKeyHashUnique   = "licenses_key_hash_key"
	ConstraintAPIKeyHashUnique       = "api_keys_key_hash_key"
	ConstraintRefreshTokenHashUnique = "refresh_tokens_token_hash_key"
	ConstraintInvitationTokenUnique  = "invitations_token_hash_key"
	ConstraintPolicyDefaultUnique    = "policies_default_per_product" // partial index; surfaces via 23505
	ConstraintProductSlugUnique      = "products_account_id_slug_key"
	ConstraintGrantInvitationUnique  = "idx_grants_invitation_unique"

	// Foreign-key constraints (used by FK-RESTRICT classification on delete)
	ConstraintLicenseCustomerFK    = "licenses_customer_id_fkey"
	ConstraintLicensePolicyFK      = "licenses_policy_id_fkey"
	ConstraintMachineLicenseFK     = "machines_license_id_fkey"
	ConstraintPolicyEntitlementFK  = "policy_entitlements_entitlement_id_fkey"
	ConstraintLicenseEntitlementFK = "license_entitlements_entitlement_id_fkey"
	// FK from policies.product_id → products.id. Classified on Create so
	// POST /v1/products/:missing/policies returns 404 product_not_found
	// instead of a raw 23503 → 500.
	ConstraintPolicyProductFK = "policies_product_id_fkey"
)
