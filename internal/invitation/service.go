package invitation

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/grant"
)

// invitationTTL is how long a freshly-issued invitation stays valid.
// 7 days matches the plan and gives recipients a reasonable window
// without indefinite exposure if the email is leaked.
const invitationTTL = 7 * 24 * time.Hour

// Service manages invitation issuance, preview, and acceptance for
// both membership and grant kinds. Membership invites create an
// AccountMembership in the grantor's account on accept; grant invites
// create an active Grant (via grant.Service) scoped to the accepting
// identity's current account.
type Service struct {
	txManager   domain.TxManager
	invitations domain.InvitationRepository
	identities  domain.IdentityRepository
	memberships domain.AccountMembershipRepository
	roles       domain.RoleRepository
	accounts    domain.AccountRepository
	masterKey   *crypto.MasterKey
	mailer      Mailer
	baseURL     string
	grants      *grant.Service
}

func NewService(
	txManager domain.TxManager,
	invitations domain.InvitationRepository,
	identities domain.IdentityRepository,
	memberships domain.AccountMembershipRepository,
	roles domain.RoleRepository,
	accounts domain.AccountRepository,
	masterKey *crypto.MasterKey,
	mailer Mailer,
	baseURL string,
	grants *grant.Service,
) *Service {
	return &Service{
		txManager:   txManager,
		invitations: invitations,
		identities:  identities,
		memberships: memberships,
		roles:       roles,
		accounts:    accounts,
		masterKey:   masterKey,
		mailer:      mailer,
		baseURL:     baseURL,
		grants:      grants,
	}
}

// CreateMembershipRequest is the body for POST /v1/accounts/:id/invitations
// when kind=membership. RoleSlug references a role by its preset slug
// (owner/admin/etc.).
type CreateMembershipRequest struct {
	Email    string `json:"email" validate:"required,email"`
	RoleSlug string `json:"role_slug" validate:"required"`
}

// CreateResult is returned from both CreateMembership and CreateGrant.
// AcceptURL is the link the issuer shows the recipient — in dev it's
// also logged to stdout by LogMailer.
type CreateResult struct {
	Invitation *domain.Invitation `json:"invitation"`
	AcceptURL  string             `json:"accept_url"`
}

// CreateMembership issues a membership-kind invitation. Runs inside
// the tenant's tx so the insert hits the correct RLS scope.
func (s *Service) CreateMembership(
	ctx context.Context,
	targetAccountID core.AccountID,
	env core.Environment,
	issuerIdentityID core.IdentityID,
	req CreateMembershipRequest,
) (*CreateResult, error) {
	role, err := s.roles.GetBySlug(ctx, nil, req.RoleSlug)
	if err != nil || role == nil {
		return nil, core.NewAppError(core.ErrRoleNotFound, "Role not found")
	}

	rawToken, err := crypto.GenerateInvitationToken()
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate invitation token")
	}
	tokenHash := s.masterKey.HMAC(rawToken)

	inv := &domain.Invitation{
		ID:                  core.NewInvitationID(),
		Kind:                domain.InvitationKindMembership,
		Email:               req.Email,
		TokenHash:           tokenHash,
		AccountID:           &targetAccountID,
		RoleID:              &role.ID,
		CreatedByIdentityID: issuerIdentityID,
		CreatedByAccountID:  targetAccountID,
		ExpiresAt:           time.Now().UTC().Add(invitationTTL),
		CreatedAt:           time.Now().UTC(),
	}

	err = s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		return s.invitations.Create(ctx, inv)
	})
	if err != nil {
		return nil, err
	}

	acceptURL := s.baseURL + "/invitations/" + rawToken
	// Mailer errors are logged by the mailer itself and do not block
	// the response — if email delivery fails, the issuer can still
	// share the accept URL out-of-band.
	_ = s.mailer.SendInvitation(ctx, req.Email, inv.Kind, acceptURL, nil)

	return &CreateResult{Invitation: inv, AcceptURL: acceptURL}, nil
}

// CreateGrant issues a grant-kind invitation with the supplied draft
// payload. Accepting the invitation unmarshals the draft into a
// grant.IssueRequest and creates an active grant under the inviter
// account — see Accept and acceptGrant for the accept-side flow.
func (s *Service) CreateGrant(
	ctx context.Context,
	issuerAccountID core.AccountID,
	env core.Environment,
	issuerIdentityID core.IdentityID,
	email string,
	draft json.RawMessage,
) (*CreateResult, error) {
	rawToken, err := crypto.GenerateInvitationToken()
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate invitation token")
	}
	tokenHash := s.masterKey.HMAC(rawToken)

	inv := &domain.Invitation{
		ID:                  core.NewInvitationID(),
		Kind:                domain.InvitationKindGrant,
		Email:               email,
		TokenHash:           tokenHash,
		GrantDraft:          draft,
		CreatedByIdentityID: issuerIdentityID,
		CreatedByAccountID:  issuerAccountID,
		ExpiresAt:           time.Now().UTC().Add(invitationTTL),
		CreatedAt:           time.Now().UTC(),
	}

	err = s.txManager.WithTargetAccount(ctx, issuerAccountID, env, func(ctx context.Context) error {
		return s.invitations.Create(ctx, inv)
	})
	if err != nil {
		return nil, err
	}

	acceptURL := s.baseURL + "/invitations/" + rawToken
	_ = s.mailer.SendInvitation(ctx, email, inv.Kind, acceptURL, nil)

	return &CreateResult{Invitation: inv, AcceptURL: acceptURL}, nil
}

// LookupResult is the unauthenticated preview shown on the acceptance
// page before the recipient logs in.
type LookupResult struct {
	Kind        domain.InvitationKind `json:"kind"`
	Email       string                `json:"email"`
	AccountName string                `json:"account_name,omitempty"`
	RoleName    string                `json:"role_name,omitempty"`
	ExpiresAt   time.Time             `json:"expires_at"`
}

// Lookup is the public preview endpoint. Takes the raw token from
// the URL (HMACs it internally) and returns a preview payload without
// revealing any authentication-sensitive fields.
func (s *Service) Lookup(ctx context.Context, rawToken string) (*LookupResult, error) {
	tokenHash := s.masterKey.HMAC(rawToken)
	inv, err := s.invitations.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
	}
	if inv.AcceptedAt != nil {
		return nil, core.NewAppError(core.ErrInvitationAlreadyUsed, "Invitation already used")
	}
	if time.Now().UTC().After(inv.ExpiresAt) {
		return nil, core.NewAppError(core.ErrInvitationExpired, "Invitation expired")
	}

	result := &LookupResult{
		Kind:      inv.Kind,
		Email:     inv.Email,
		ExpiresAt: inv.ExpiresAt,
	}
	if inv.AccountID != nil {
		if acct, _ := s.accounts.GetByID(ctx, *inv.AccountID); acct != nil {
			result.AccountName = acct.Name
		}
	}
	if inv.RoleID != nil {
		if role, _ := s.roles.GetByID(ctx, *inv.RoleID); role != nil {
			result.RoleName = role.Name
		}
	}
	return result, nil
}

// AcceptResult is returned from Accept. For kind=membership,
// MembershipID is populated. For kind=grant, GrantID is populated
// and points at the freshly issued + accepted grant row.
type AcceptResult struct {
	MembershipID *core.MembershipID `json:"membership_id,omitempty"`
	AccountID    core.AccountID     `json:"account_id"`
	GrantID      *core.GrantID      `json:"grant_id,omitempty"`
}

// Accept consumes an invitation token and applies it to the given
// identity. kind=membership creates an AccountMembership in the
// inviter's account. kind=grant unmarshals the draft, picks the
// accepting identity's oldest-joined membership as the grantee
// account, issues the grant under the grantor (the inviter's
// account), and auto-activates it. Both paths mark the invitation
// consumed on success.
func (s *Service) Accept(ctx context.Context, rawToken string, identityID core.IdentityID) (*AcceptResult, error) {
	tokenHash := s.masterKey.HMAC(rawToken)
	inv, err := s.invitations.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
	}
	if inv.AcceptedAt != nil {
		return nil, core.NewAppError(core.ErrInvitationAlreadyUsed, "Invitation already used")
	}
	if time.Now().UTC().After(inv.ExpiresAt) {
		return nil, core.NewAppError(core.ErrInvitationExpired, "Invitation expired")
	}

	// F-014: verify the authenticated identity is the intended recipient.
	// Without this check, anyone who obtains the invitation token can
	// accept it and join the target account — a complete BOLA.
	identity, err := s.identities.GetByID(ctx, identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Identity not found")
	}
	if !strings.EqualFold(identity.Email, inv.Email) {
		return nil, core.NewAppError(core.ErrPermissionDenied, "Invitation is for a different email address")
	}

	switch inv.Kind {
	case domain.InvitationKindMembership:
		return s.acceptMembership(ctx, inv, identityID)
	case domain.InvitationKindGrant:
		return s.acceptGrant(ctx, inv, identityID)
	default:
		return nil, core.NewAppError(core.ErrValidationError, "Unknown invitation kind")
	}
}

// acceptGrant handles kind=grant invitation acceptance. The grant_draft
// blob stored at invitation creation time carries the IssueRequest
// shape (minus grantee_account_id, which is resolved from the accepting
// identity's membership). The method issues a pending grant as the
// grantor, then immediately accepts it as the grantee, resulting in an
// active grant. The oldest-joined membership is picked as the grantee;
// a multi-account UX that prompts the user is a future dashboard concern.
// The invitation is marked consumed in the same flow.
func (s *Service) acceptGrant(ctx context.Context, inv *domain.Invitation, identityID core.IdentityID) (*AcceptResult, error) {
	var draft grant.IssueRequest
	if err := json.Unmarshal(inv.GrantDraft, &draft); err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Malformed grant invitation draft")
	}

	// Wire the invitation link so the database's partial unique index
	// (idx_grants_invitation_unique) enforces at-most-once grant creation
	// per invitation — a retry after a partial failure will hit the
	// unique violation instead of silently issuing a second grant.
	invID := inv.ID
	draft.InvitationID = &invID

	// Resolve the accepting identity's account. The oldest-joined
	// membership is picked as the grantee. A richer UX could let the user
	// choose from multiple memberships; that is a dashboard concern.
	memberships, err := s.memberships.ListByIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return nil, core.NewAppError(core.ErrValidationError, "Identity has no account to receive the grant")
	}
	granteeAccountID := memberships[0].AccountID

	// Override the draft's grantee with the accepting identity's account.
	// The original draft did not know which account would accept.
	draft.GranteeAccountID = granteeAccountID

	grantor := inv.CreatedByAccountID
	g, err := s.grants.Issue(ctx, grantor, core.EnvironmentLive, draft)
	if err != nil {
		// grant_repo.Create translates the unique-index violation on
		// idx_grants_invitation_unique into core.ErrInvitationAlreadyUsed,
		// so the typed error bubbles up with the correct HTTP 409 status.
		return nil, err
	}

	// Auto-accept: the grantee has accepted the invitation so the grant
	// transitions directly from pending → active.
	g, err = s.grants.Accept(ctx, granteeAccountID, core.EnvironmentLive, g.ID)
	if err != nil {
		return nil, err
	}

	// Mark the invitation consumed so it cannot be reused.
	if err := s.txManager.WithTargetAccount(ctx, inv.CreatedByAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		return s.invitations.MarkAccepted(ctx, inv.ID, time.Now().UTC())
	}); err != nil {
		return nil, err
	}

	return &AcceptResult{AccountID: granteeAccountID, GrantID: &g.ID}, nil
}

func (s *Service) acceptMembership(ctx context.Context, inv *domain.Invitation, identityID core.IdentityID) (*AcceptResult, error) {
	if inv.AccountID == nil || inv.RoleID == nil {
		return nil, core.NewAppError(core.ErrInternalError, "Malformed membership invitation")
	}

	var membershipID core.MembershipID
	err := s.txManager.WithTargetAccount(ctx, *inv.AccountID, core.EnvironmentLive, func(ctx context.Context) error {
		now := time.Now().UTC()

		existing, err := s.memberships.GetByIdentityAndAccount(ctx, identityID, *inv.AccountID)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrInvitationAlreadyUsed, "Already a member of this account")
		}

		m := &domain.AccountMembership{
			ID:                  core.NewMembershipID(),
			AccountID:           *inv.AccountID,
			IdentityID:          identityID,
			RoleID:              *inv.RoleID,
			Status:              domain.MembershipStatusActive,
			InvitedByIdentityID: &inv.CreatedByIdentityID,
			JoinedAt:            now,
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := s.memberships.Create(ctx, m); err != nil {
			return err
		}
		membershipID = m.ID
		return s.invitations.MarkAccepted(ctx, inv.ID, now)
	})
	if err != nil {
		return nil, err
	}
	return &AcceptResult{MembershipID: &membershipID, AccountID: *inv.AccountID}, nil
}
