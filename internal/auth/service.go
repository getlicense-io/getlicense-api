package auth

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service handles authentication and API key management.
type Service struct {
	txManager   domain.TxManager
	accounts    domain.AccountRepository
	users       domain.UserRepository
	apiKeys     domain.APIKeyRepository
	refreshTkns domain.RefreshTokenRepository
	masterKey   *crypto.MasterKey
}

// NewService constructs a new auth Service.
func NewService(
	txManager domain.TxManager,
	accounts domain.AccountRepository,
	users domain.UserRepository,
	apiKeys domain.APIKeyRepository,
	refreshTkns domain.RefreshTokenRepository,
	masterKey *crypto.MasterKey,
) *Service {
	return &Service{
		txManager:   txManager,
		accounts:    accounts,
		users:       users,
		apiKeys:     apiKeys,
		refreshTkns: refreshTkns,
		masterKey:   masterKey,
	}
}

// --- Request / Result types ---

type SignupRequest struct {
	AccountName string `json:"account_name" validate:"required,min=1,max=100"`
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
}

type SignupResult struct {
	Account *domain.Account `json:"account"`
	User    *domain.User    `json:"user"`
	APIKey  string          `json:"api_key"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type MeResult struct {
	User    *domain.User    `json:"user,omitempty"`
	Account *domain.Account `json:"account"`
}

type CreateAPIKeyRequest struct {
	Label       *string `json:"label"`
	Environment string  `json:"environment" validate:"required,oneof=live test"`
}

type CreateAPIKeyResult struct {
	APIKey *domain.APIKey `json:"api_key"`
	RawKey string         `json:"raw_key"`
}

// --- Methods ---

// Signup creates a new account, owner user, and an initial live API key.
func (s *Service) Signup(ctx context.Context, req SignupRequest) (*SignupResult, error) {
	var result *SignupResult

	err := s.txManager.WithTx(ctx, func(ctx context.Context) error {
		// Check email uniqueness.
		existing, err := s.users.GetByEmail(ctx, req.Email)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrEmailAlreadyExists, "An account with that email already exists")
		}

		// Hash password.
		passwordHash, err := crypto.HashPassword(req.Password)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to hash password")
		}

		now := time.Now().UTC()

		// Create account.
		account := &domain.Account{
			ID:        core.NewAccountID(),
			Name:      req.AccountName,
			Slug:      slugify(req.AccountName),
			CreatedAt: now,
		}
		if err := s.accounts.Create(ctx, account); err != nil {
			return err
		}

		// Create owner user.
		user := &domain.User{
			ID:           core.NewUserID(),
			AccountID:    account.ID,
			Email:        req.Email,
			PasswordHash: passwordHash,
			Role:         core.UserRoleOwner,
			CreatedAt:    now,
		}
		if err := s.users.Create(ctx, user); err != nil {
			return err
		}

		// Generate initial live API key.
		rawKey, prefix, err := crypto.GenerateAPIKey("live")
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate API key")
		}
		keyHash := crypto.HMACSHA256(s.masterKey.HMACKey, rawKey)

		apiKey := &domain.APIKey{
			ID:          core.NewAPIKeyID(),
			AccountID:   account.ID,
			Prefix:      prefix,
			KeyHash:     keyHash,
			Scope:       core.APIKeyScopeAccountWide,
			Environment: "live",
			CreatedAt:   now,
		}
		if err := s.apiKeys.Create(ctx, apiKey); err != nil {
			return err
		}

		result = &SignupResult{
			Account: account,
			User:    user,
			APIKey:  rawKey,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Login authenticates a user and returns JWT + refresh token.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	// Look up user by email — no tenant context needed.
	user, err := s.users.GetByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}

	// Verify password.
	if !crypto.VerifyPassword(user.PasswordHash, req.Password) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}

	// Sign JWT (15-minute TTL).
	accessToken, err := crypto.SignJWT(crypto.JWTClaims{
		UserID:    user.ID,
		AccountID: user.AccountID,
		Role:      user.Role,
	}, s.masterKey.JWTSigningKey, 15*time.Minute)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to sign access token")
	}

	// Generate refresh token and store it.
	var rawRefreshToken string
	txErr := s.txManager.WithTx(ctx, func(ctx context.Context) error {
		raw, err := crypto.GenerateRefreshToken()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate refresh token")
		}
		rawRefreshToken = raw
		tokenHash := crypto.HMACSHA256(s.masterKey.HMACKey, raw)

		id, err := uuid.NewV7()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate token ID")
		}

		rt := &domain.RefreshToken{
			ID:        id.String(),
			UserID:    user.ID,
			AccountID: user.AccountID,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		}
		return s.refreshTkns.Create(ctx, rt)
	})
	if txErr != nil {
		return nil, txErr
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

// Refresh validates a refresh token and issues a new token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	tokenHash := crypto.HMACSHA256(s.masterKey.HMACKey, refreshToken)

	// Look up the stored refresh token.
	stored, err := s.refreshTkns.GetByHash(ctx, tokenHash)
	if err != nil || stored == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired refresh token")
	}
	if time.Now().UTC().After(stored.ExpiresAt) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired refresh token")
	}

	// Delete the old token and issue new ones.
	var accessToken, newRawRefreshToken string
	txErr := s.txManager.WithTenant(ctx, stored.AccountID, func(ctx context.Context) error {
		// Delete the old refresh token.
		if err := s.refreshTkns.DeleteByHash(ctx, tokenHash); err != nil {
			return err
		}

		// Get the user with a fresh role.
		user, err := s.users.GetByID(ctx, stored.UserID)
		if err != nil || user == nil {
			return core.NewAppError(core.ErrAuthenticationRequired, "User not found")
		}

		// Sign new JWT.
		at, err := crypto.SignJWT(crypto.JWTClaims{
			UserID:    user.ID,
			AccountID: user.AccountID,
			Role:      user.Role,
		}, s.masterKey.JWTSigningKey, 15*time.Minute)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to sign access token")
		}
		accessToken = at

		// Generate new refresh token.
		raw, err := crypto.GenerateRefreshToken()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate refresh token")
		}
		newRawRefreshToken = raw
		newHash := crypto.HMACSHA256(s.masterKey.HMACKey, raw)

		id, err := uuid.NewV7()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate token ID")
		}

		rt := &domain.RefreshToken{
			ID:        id.String(),
			UserID:    user.ID,
			AccountID: user.AccountID,
			TokenHash: newHash,
			ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		}
		return s.refreshTkns.Create(ctx, rt)
	})
	if txErr != nil {
		return nil, txErr
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: newRawRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

// Logout invalidates a refresh token. Silent success if token not found.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := crypto.HMACSHA256(s.masterKey.HMACKey, refreshToken)
	_ = s.refreshTkns.DeleteByHash(ctx, tokenHash)
	return nil
}

// GetMe returns the account and optionally the user for the given IDs.
func (s *Service) GetMe(ctx context.Context, accountID core.AccountID, userID *core.UserID) (*MeResult, error) {
	var result *MeResult

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		account, err := s.accounts.GetByID(ctx, accountID)
		if err != nil || account == nil {
			return core.NewAppError(core.ErrAccountNotFound, "Account not found")
		}

		res := &MeResult{Account: account}

		if userID != nil {
			user, err := s.users.GetByID(ctx, *userID)
			if err != nil {
				return err
			}
			res.User = user
		}

		result = res
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAPIKey creates a new API key for the given account.
func (s *Service) CreateAPIKey(ctx context.Context, accountID core.AccountID, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	var result *CreateAPIKeyResult

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		rawKey, prefix, err := crypto.GenerateAPIKey(req.Environment)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate API key")
		}
		keyHash := crypto.HMACSHA256(s.masterKey.HMACKey, rawKey)

		apiKey := &domain.APIKey{
			ID:          core.NewAPIKeyID(),
			AccountID:   accountID,
			Prefix:      prefix,
			KeyHash:     keyHash,
			Scope:       core.APIKeyScopeAccountWide,
			Label:       req.Label,
			Environment: req.Environment,
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.apiKeys.Create(ctx, apiKey); err != nil {
			return err
		}

		result = &CreateAPIKeyResult{
			APIKey: apiKey,
			RawKey: rawKey,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListAPIKeys returns a paginated list of API keys for the given account.
func (s *Service) ListAPIKeys(ctx context.Context, accountID core.AccountID, limit, offset int) ([]domain.APIKey, int, error) {
	var keys []domain.APIKey
	var total int

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var err error
		keys, total, err = s.apiKeys.ListByAccount(ctx, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return keys, total, nil
}

// DeleteAPIKey deletes an API key by ID within the given account.
func (s *Service) DeleteAPIKey(ctx context.Context, accountID core.AccountID, id core.APIKeyID) error {
	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		return s.apiKeys.Delete(ctx, id)
	})
}

// --- Helpers ---

var (
	reNonAlphanumHyphen = regexp.MustCompile(`[^a-z0-9-]+`)
	reMultiHyphen       = regexp.MustCompile(`-{2,}`)
)

// slugify converts a name to a URL-friendly slug:
// lowercase, spaces to hyphens, strip non-alphanumeric (except hyphens),
// collapse consecutive hyphens, trim leading/trailing hyphens.
func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = reNonAlphanumHyphen.ReplaceAllString(s, "")
	s = reMultiHyphen.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}
