package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityPasswordHashNotInJSON(t *testing.T) {
	u := Identity{
		ID:               core.NewIdentityID(),
		Email:            "test@example.com",
		PasswordHash:     "supersecret",
		TOTPSecretEnc:    []byte("encrypted-totp-secret"),
		RecoveryCodesEnc: []byte("encrypted-recovery-codes"),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	b, err := json.Marshal(u)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	_, hasPasswordHash := out["password_hash"]
	assert.False(t, hasPasswordHash, "PasswordHash must not appear in JSON output")
	_, hasTOTPSecretEnc := out["totp_secret_enc"]
	assert.False(t, hasTOTPSecretEnc, "TOTPSecretEnc must not appear in JSON output")
	_, hasRecoveryCodesEnc := out["recovery_codes_enc"]
	assert.False(t, hasRecoveryCodesEnc, "RecoveryCodesEnc must not appear in JSON output")
	assert.Equal(t, "test@example.com", out["email"])
}

func TestProductPrivateKeyEncNotInJSON(t *testing.T) {
	p := Product{
		ID:            core.NewProductID(),
		AccountID:     core.NewAccountID(),
		Name:          "My Product",
		Slug:          "my-product",
		PublicKey:     "pubkey",
		PrivateKeyEnc: []byte("secret encrypted key"),
		ValidationTTL: 3600,
		GracePeriod:   86400,
		CreatedAt:     time.Now(),
	}

	b, err := json.Marshal(p)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	_, hasPrivKey := out["private_key_enc"]
	assert.False(t, hasPrivKey, "PrivateKeyEnc must not appear in JSON output")
	assert.Equal(t, "My Product", out["name"])
}

func TestAccountJSONRoundtrip(t *testing.T) {
	original := Account{
		ID:        core.NewAccountID(),
		Name:      "Acme Corp",
		Slug:      "acme-corp",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}

	b, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed Account
	require.NoError(t, json.Unmarshal(b, &parsed))

	assert.Equal(t, original.ID, parsed.ID)
	assert.Equal(t, original.Name, parsed.Name)
	assert.Equal(t, original.Slug, parsed.Slug)
	assert.Equal(t, original.CreatedAt, parsed.CreatedAt)
}

func TestRefreshTokenAllFieldsHidden(t *testing.T) {
	rt := RefreshToken{
		ID:         "some-token-id",
		IdentityID: core.NewIdentityID(),
		TokenHash:  "hashvalue",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	b, err := json.Marshal(rt)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(b))
}

func TestListResponseGeneric(t *testing.T) {
	accounts := []Account{
		{ID: core.NewAccountID(), Name: "Acme", Slug: "acme", CreatedAt: time.Now()},
		{ID: core.NewAccountID(), Name: "Globex", Slug: "globex", CreatedAt: time.Now()},
	}

	resp := ListResponse[Account]{
		Data: accounts,
		Pagination: Pagination{
			Limit:  10,
			Offset: 0,
			Total:  2,
		},
	}

	b, err := json.Marshal(resp)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	data, ok := out["data"].([]any)
	require.True(t, ok)
	assert.Len(t, data, 2)

	pagination, ok := out["pagination"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(10), pagination["limit"])
	assert.Equal(t, float64(0), pagination["offset"])
	assert.Equal(t, float64(2), pagination["total"])
}

func TestLicenseKeyHashNotInJSON(t *testing.T) {
	maxMachines := 3
	l := License{
		ID:          core.NewLicenseID(),
		AccountID:   core.NewAccountID(),
		ProductID:   core.NewProductID(),
		KeyPrefix:   "abc",
		KeyHash:     "secrethash",
		Token:       "sometoken",
		LicenseType: core.LicenseTypePerpetual,
		Status:      core.LicenseStatusActive,
		MaxMachines: &maxMachines,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	b, err := json.Marshal(l)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	_, hasKeyHash := out["key_hash"]
	assert.False(t, hasKeyHash, "KeyHash must not appear in JSON output")
	assert.Equal(t, "abc", out["key_prefix"])
}

func TestWebhookEndpointSigningSecretNotInJSON(t *testing.T) {
	ep := WebhookEndpoint{
		ID:            core.NewWebhookEndpointID(),
		AccountID:     core.NewAccountID(),
		URL:           "https://example.com/webhook",
		Events:        []core.EventType{core.EventTypeLicenseCreated},
		SigningSecret: "whsec_supersecret",
		Active:        true,
		CreatedAt:     time.Now(),
	}

	b, err := json.Marshal(ep)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	_, hasSecret := out["signing_secret"]
	assert.False(t, hasSecret, "SigningSecret must not appear in JSON output")
	assert.Equal(t, "https://example.com/webhook", out["url"])
}

func TestAPIKeyKeyHashNotInJSON(t *testing.T) {
	ak := APIKey{
		ID:          core.NewAPIKeyID(),
		AccountID:   core.NewAccountID(),
		Prefix:      "gl_live_",
		KeyHash:     "hashvalue",
		Scope:       core.APIKeyScopeAccountWide,
		Environment: "live",
		CreatedAt:   time.Now(),
	}

	b, err := json.Marshal(ak)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	_, hasKeyHash := out["key_hash"]
	assert.False(t, hasKeyHash, "KeyHash must not appear in JSON output")
}
