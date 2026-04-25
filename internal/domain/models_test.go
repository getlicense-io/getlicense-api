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

func TestLicenseKeyHashNotInJSON(t *testing.T) {
	l := License{
		ID:        core.NewLicenseID(),
		AccountID: core.NewAccountID(),
		ProductID: core.NewProductID(),
		PolicyID:  core.NewPolicyID(),
		KeyPrefix: "abc",
		KeyHash:   "secrethash",
		Token:     "sometoken",
		Status:    core.LicenseStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
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
		ID:                     core.NewWebhookEndpointID(),
		AccountID:              core.NewAccountID(),
		URL:                    "https://example.com/webhook",
		Events:                 []core.EventType{core.EventTypeLicenseCreated},
		SigningSecretEncrypted: []byte{0xde, 0xad, 0xbe, 0xef},
		Active:                 true,
		CreatedAt:              time.Now(),
	}

	b, err := json.Marshal(ep)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	_, hasSecret := out["signing_secret"]
	assert.False(t, hasSecret, "signing_secret must not appear in JSON output")
	_, hasEncrypted := out["signing_secret_encrypted"]
	assert.False(t, hasEncrypted, "signing_secret_encrypted bytes must not appear in JSON output")
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

func TestComputeInvitationStatus(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)
	acceptedAt := now.Add(-1 * time.Hour)

	t.Run("accepted wins over expiry", func(t *testing.T) {
		got := ComputeInvitationStatus(&acceptedAt, past, now)
		assert.Equal(t, "accepted", got)
	})
	t.Run("expired when not accepted and past expires_at", func(t *testing.T) {
		got := ComputeInvitationStatus(nil, past, now)
		assert.Equal(t, "expired", got)
	})
	t.Run("pending when not accepted and expires_at in future", func(t *testing.T) {
		got := ComputeInvitationStatus(nil, future, now)
		assert.Equal(t, "pending", got)
	})
	t.Run("pending at exact expires_at boundary (inclusive)", func(t *testing.T) {
		got := ComputeInvitationStatus(nil, now, now)
		assert.Equal(t, "pending", got)
	})
}
