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

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
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

// Signup creates a new account, owner user, and an initial live API key.
func (s *Service) Signup(ctx context.Context, req SignupRequest) (*SignupResult, error) {
	// Hash password BEFORE the transaction to avoid holding a DB connection
	// during the CPU-intensive Argon2 operation.
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to hash password")
	}

	var result *SignupResult
	err = s.txManager.WithTx(ctx, func(ctx context.Context) error {
		existing, err := s.users.GetByEmail(ctx, req.Email)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrEmailAlreadyExists, "An account with that email already exists")
		}

		now := time.Now().UTC()

		account := &domain.Account{
			ID:        core.NewAccountID(),
			Name:      req.AccountName,
			Slug:      slugify(req.AccountName),
			CreatedAt: now,
		}
		if err := s.accounts.Create(ctx, account); err != nil {
			return err
		}

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

		_, rawKey, err := s.createAPIKeyRecord(ctx, account.ID, core.EnvironmentLive, nil)
		if err != nil {
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
	user, err := s.users.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}

	if !crypto.VerifyPassword(user.PasswordHash, req.Password) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}

	accessToken, err := s.signAccessToken(user)
	if err != nil {
		return nil, err
	}

	// Single INSERT — no transaction needed.
	rawRefresh, err := s.createRefreshToken(ctx, user.ID, user.AccountID)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
	}, nil
}

// Refresh validates a refresh token and issues a new token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	tokenHash := s.masterKey.HMAC(refreshToken)

	stored, err := s.refreshTkns.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if stored == nil || time.Now().UTC().After(stored.ExpiresAt) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired refresh token")
	}

	var accessToken, newRawRefresh string
	txErr := s.txManager.WithTenant(ctx, stored.AccountID, core.EnvironmentLive, func(ctx context.Context) error {
		if err := s.refreshTkns.DeleteByHash(ctx, tokenHash); err != nil {
			return err
		}

		user, err := s.users.GetByID(ctx, stored.UserID)
		if err != nil {
			return err
		}
		if user == nil {
			return core.NewAppError(core.ErrAuthenticationRequired, "User not found")
		}

		at, err := s.signAccessToken(user)
		if err != nil {
			return err
		}
		accessToken = at

		raw, err := s.createRefreshToken(ctx, user.ID, user.AccountID)
		if err != nil {
			return err
		}
		newRawRefresh = raw

		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: newRawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
	}, nil
}

// Logout invalidates a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := s.masterKey.HMAC(refreshToken)
	return s.refreshTkns.DeleteByHash(ctx, tokenHash)
}

// GetMe returns the account and optionally the user for the given IDs.
func (s *Service) GetMe(ctx context.Context, accountID core.AccountID, env core.Environment, userID *core.UserID) (*MeResult, error) {
	var result *MeResult

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		account, err := s.accounts.GetByID(ctx, accountID)
		if err != nil {
			return err
		}
		if account == nil {
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
func (s *Service) CreateAPIKey(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	reqEnv, err := core.ParseEnvironment(req.Environment)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid environment: must be \"live\" or \"test\"")
	}

	var result *CreateAPIKeyResult

	err = s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		apiKey, rawKey, err := s.createAPIKeyRecord(ctx, accountID, reqEnv, req.Label)
		if err != nil {
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
func (s *Service) ListAPIKeys(ctx context.Context, accountID core.AccountID, env core.Environment, limit, offset int) ([]domain.APIKey, int, error) {
	var keys []domain.APIKey
	var total int

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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
func (s *Service) DeleteAPIKey(ctx context.Context, accountID core.AccountID, env core.Environment, id core.APIKeyID) error {
	return s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		return s.apiKeys.Delete(ctx, id)
	})
}

// --- Private helpers ---

// signAccessToken creates a signed JWT for the given user.
func (s *Service) signAccessToken(user *domain.User) (string, error) {
	token, err := s.masterKey.SignJWT(crypto.JWTClaims{
		UserID:    user.ID,
		AccountID: user.AccountID,
		Role:      user.Role,
	}, accessTokenTTL)
	if err != nil {
		return "", core.NewAppError(core.ErrInternalError, "Failed to sign access token")
	}
	return token, nil
}

// createRefreshToken generates, hashes, and stores a new refresh token.
func (s *Service) createRefreshToken(ctx context.Context, userID core.UserID, accountID core.AccountID) (string, error) {
	raw, err := crypto.GenerateRefreshToken()
	if err != nil {
		return "", core.NewAppError(core.ErrInternalError, "Failed to generate refresh token")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return "", core.NewAppError(core.ErrInternalError, "Failed to generate token ID")
	}

	rt := &domain.RefreshToken{
		ID:        id.String(),
		UserID:    userID,
		AccountID: accountID,
		TokenHash: s.masterKey.HMAC(raw),
		ExpiresAt: time.Now().UTC().Add(refreshTokenTTL),
	}
	if err := s.refreshTkns.Create(ctx, rt); err != nil {
		return "", err
	}
	return raw, nil
}

// createAPIKeyRecord generates, hashes, and stores a new API key.
func (s *Service) createAPIKeyRecord(ctx context.Context, accountID core.AccountID, env core.Environment, label *string) (*domain.APIKey, string, error) {
	rawKey, prefix, err := crypto.GenerateAPIKey(env)
	if err != nil {
		return nil, "", core.NewAppError(core.ErrInternalError, "Failed to generate API key")
	}

	apiKey := &domain.APIKey{
		ID:          core.NewAPIKeyID(),
		AccountID:   accountID,
		Prefix:      prefix,
		KeyHash:     s.masterKey.HMAC(rawKey),
		Scope:       core.APIKeyScopeAccountWide,
		Label:       label,
		Environment: env,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.apiKeys.Create(ctx, apiKey); err != nil {
		return nil, "", err
	}
	return apiKey, rawKey, nil
}

var (
	reNonAlphanumHyphen = regexp.MustCompile(`[^a-z0-9-]+`)
	reMultiHyphen       = regexp.MustCompile(`-{2,}`)
)

func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = reNonAlphanumHyphen.ReplaceAllString(s, "")
	s = reMultiHyphen.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}
