package invitation

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
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
	txManager    domain.TxManager
	invitations  domain.InvitationRepository
	identities   domain.IdentityRepository
	memberships  domain.AccountMembershipRepository
	roles        domain.RoleRepository
	accounts     domain.AccountRepository
	grantRepo    domain.GrantRepository
	masterKey    *crypto.MasterKey
	mailer       Mailer
	dashboardURL string
	grants       *grant.Service
	audit        *audit.Writer
}

// NewService builds an invitation Service. auditWriter may be nil in
// tests; lifecycle methods nil-guard before recording.
func NewService(
	txManager domain.TxManager,
	invitations domain.InvitationRepository,
	identities domain.IdentityRepository,
	memberships domain.AccountMembershipRepository,
	roles domain.RoleRepository,
	accounts domain.AccountRepository,
	grantRepo domain.GrantRepository,
	masterKey *crypto.MasterKey,
	mailer Mailer,
	dashboardURL string,
	grants *grant.Service,
	auditWriter *audit.Writer,
) *Service {
	return &Service{
		txManager:    txManager,
		invitations:  invitations,
		identities:   identities,
		memberships:  memberships,
		roles:        roles,
		accounts:     accounts,
		grantRepo:    grantRepo,
		masterKey:    masterKey,
		mailer:       mailer,
		dashboardURL: dashboardURL,
		grants:       grants,
		audit:        auditWriter,
	}
}

// recordInvitationEvent serializes the payload and records the event
// via the audit writer. Errors are logged, not returned — audit
// failures must not fail the user-visible operation.
func (s *Service) recordInvitationEvent(
	ctx context.Context,
	attr audit.Attribution,
	eventType core.EventType,
	invID core.InvitationID,
	payload any,
) {
	if s.audit == nil {
		return
	}
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			slog.Error("audit: failed to marshal event payload", "event", eventType, "error", err)
			return
		}
		raw = b
	}
	if err := s.audit.Record(ctx, audit.EventFrom(attr, eventType, "invitation", invID.String(), raw)); err != nil {
		slog.Error("audit: failed to record event", "event", eventType, "error", err)
	}
}

// List returns cursor-paginated invitations created by accountID. Runs
// inside the account's tenant tx so the invitations RLS policy filters
// on created_by_account_id — callers do not need to pass the account
// down further. Environment is fixed to live because invitations are
// account-scoped, not environment-scoped.
func (s *Service) List(
	ctx context.Context,
	accountID core.AccountID,
	filter domain.InvitationListFilter,
	cursor core.Cursor,
	limit int,
) ([]domain.Invitation, bool, error) {
	var rows []domain.Invitation
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		rows, hasMore, err = s.invitations.ListByAccount(ctx, filter, cursor, limit)
		return err
	})
	return rows, hasMore, err
}

// Get returns a single invitation by id. The RLS policy on invitations
// filters by created_by_account_id, so a caller asking for an id they
// did not create sees ErrNoRows and the service returns a 404 — no
// explicit auth check at the service layer, no existence leak.
// Authorization beyond ownership (e.g. the target-email identity
// viewing via token) is the handler's concern.
func (s *Service) Get(
	ctx context.Context,
	accountID core.AccountID,
	id core.InvitationID,
) (*domain.Invitation, error) {
	var inv *domain.Invitation
	err := s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		inv, err = s.invitations.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if inv == nil {
			return core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return inv, nil
}

// CreateMembershipRequest is the body for POST /v1/accounts/:id/invitations
// when kind=membership. RoleSlug references a role by its preset slug
// (owner/admin/etc.).
type CreateMembershipRequest struct {
	Email    string `json:"email" validate:"required,email"`
	RoleSlug string `json:"role_slug" validate:"required"`
}

// CreateInvitationRequest is the combined body for POST /v1/accounts/:id/invitations.
// The OpenAPI schema for this endpoint is a oneOf — the server discriminates
// on the presence of RoleSlug (membership) vs GrantDraft (grant). A Kind
// field is accepted from clients as a hint but ignored; field presence is
// the canonical discriminator per the spec.
type CreateInvitationRequest struct {
	Email      string          `json:"email"`
	Kind       string          `json:"kind,omitempty"`
	RoleSlug   string          `json:"role_slug,omitempty"`
	GrantDraft json.RawMessage `json:"grant_draft,omitempty"`
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
	attr audit.Attribution,
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
		if err := s.invitations.Create(ctx, inv); err != nil {
			return err
		}
		s.recordInvitationEvent(ctx, attr, core.EventTypeInvitationCreated, inv.ID, map[string]any{
			"kind":      inv.Kind,
			"email":     inv.Email,
			"role_slug": req.RoleSlug,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	acceptURL := s.dashboardURL + "/invitations/" + rawToken
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
	attr audit.Attribution,
) (*CreateResult, error) {
	// Validate email format up-front via the customer-package canon.
	// Stored Email preserves issuer-supplied case (mail systems are
	// case-preserving on the local part); only the dup-guard lookup
	// uses the lowercased form.
	normEmail, err := customer.NormalizeEmail(email)
	if err != nil {
		return nil, core.NewAppError(core.ErrCustomerInvalidEmail, "Invalid email address")
	}

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
		// Extract product_id once; rejects early if the draft is malformed
		// (422) or missing product_id (422). This parse is also run in
		// acceptGrant for consistency; see parseGrantDraftProductID.
		productID, perr := parseGrantDraftProductID(draft)
		if perr != nil {
			return perr
		}

		// Duplicate guard: reject if a pending invitation OR an already-
		// accepted grant covers the same (issuer, email, product) triple.
		// Best-effort — a narrow race between check and insert is acceptable
		// because the accept-side idempotency guard in the DB (the
		// invitation_id unique index) still prevents double-grant creation.
		hasInv, err := s.invitations.HasActiveGrantInvitation(ctx, issuerAccountID, normEmail, productID)
		if err != nil {
			return err
		}
		if hasInv {
			return core.NewAppError(core.ErrInvitationAlreadyExists,
				"A pending grant invitation already exists for this product and recipient")
		}
		hasGrant, err := s.grantRepo.HasActiveGrantForProductEmail(ctx, issuerAccountID, normEmail, productID)
		if err != nil {
			return err
		}
		if hasGrant {
			return core.NewAppError(core.ErrInvitationAlreadyExists,
				"An active grant already exists for this product and recipient")
		}

		if err := s.invitations.Create(ctx, inv); err != nil {
			return err
		}
		s.recordInvitationEvent(ctx, attr, core.EventTypeInvitationCreated, inv.ID, map[string]any{
			"kind":  inv.Kind,
			"email": inv.Email,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	acceptURL := s.dashboardURL + "/invitations/" + rawToken
	_ = s.mailer.SendInvitation(ctx, email, inv.Kind, acceptURL, nil)

	return &CreateResult{Invitation: inv, AcceptURL: acceptURL}, nil
}

// ResendResult is the response shape for a successful resend.
// The caller receives the updated invitation (with the rotated
// token_hash already applied) and the new AcceptURL carrying the
// freshly-minted raw token. The old URL is invalidated the moment
// UpdateTokenHash commits.
type ResendResult struct {
	Invitation *domain.Invitation `json:"invitation"`
	AcceptURL  string             `json:"accept_url"`
}

// Resend regenerates the raw token for an unaccepted, unexpired
// invitation. The old accept URL is invalidated immediately by
// overwriting the stored token_hash — any request bearing the
// prior raw token will miss in GetByTokenHash and resolve to 404.
// expires_at is NOT shifted: the original 7-day window set at
// creation time is preserved, so a leaked-then-rotated invitation
// cannot be extended indefinitely by repeated Resend calls.
//
// Ownership is enforced two ways: the WithTargetAccount tx scopes
// the GetByID lookup via RLS on created_by_account_id, and the
// explicit CreatedByAccountID equality check guards against the
// nil/mismatch edge cases. A caller asking about an invitation
// they did not create sees 404 — no existence leak.
func (s *Service) Resend(
	ctx context.Context,
	accountID core.AccountID,
	id core.InvitationID,
	attr audit.Attribution,
) (*ResendResult, error) {
	var result *ResendResult

	err := s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		inv, err := s.invitations.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if inv == nil || inv.CreatedByAccountID != accountID {
			return core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
		}
		if inv.AcceptedAt != nil {
			return core.NewAppError(core.ErrInvitationAlreadyAccepted, "Invitation has already been accepted")
		}
		if time.Now().UTC().After(inv.ExpiresAt) {
			return core.NewAppError(core.ErrInvitationExpired, "Invitation has expired")
		}

		// Regenerate the raw token, hash it, persist the new hash.
		// Overwriting the stored hash is what invalidates the prior
		// accept URL — the old raw token's hash no longer matches
		// any row in GetByTokenHash.
		rawToken, err := crypto.GenerateInvitationToken()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate invitation token")
		}
		newHash := s.masterKey.HMAC(rawToken)
		if err := s.invitations.UpdateTokenHash(ctx, id, newHash); err != nil {
			return err
		}
		inv.TokenHash = newHash

		acceptURL := s.dashboardURL + "/invitations/" + rawToken
		// Mailer errors do not block the response; the issuer can
		// still share the URL out-of-band via the returned payload.
		_ = s.mailer.SendInvitation(ctx, inv.Email, inv.Kind, acceptURL, nil)

		s.recordInvitationEvent(ctx, attr, core.EventTypeInvitationResent, inv.ID, map[string]any{
			"kind":  inv.Kind,
			"email": inv.Email,
		})

		result = &ResendResult{Invitation: inv, AcceptURL: acceptURL}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Revoke hard-deletes an unaccepted invitation. The invitation.revoked
// domain event is recorded BEFORE the DELETE so the event's resource_id
// references a real invitation row at the time of write — after the
// DELETE the row is gone and a downstream reader dereferencing
// resource_id would see a dangling id.
//
// Accepted invitations cannot be revoked: the membership / grant side
// effect already happened and undoing requires a separate removal flow
// (DELETE /v1/memberships/:id or grant revoke). Expired pending
// invitations ARE deletable — Revoke doubles as the cleanup path, so
// the service only blocks on AcceptedAt != nil, not on ExpiresAt.
//
// Ownership is enforced two ways: the WithTargetAccount tx scopes the
// GetByID lookup via RLS on created_by_account_id, and the explicit
// CreatedByAccountID equality check guards the nil/mismatch edge
// cases. A caller asking about an invitation they did not create sees
// 404 — no existence leak.
func (s *Service) Revoke(
	ctx context.Context,
	accountID core.AccountID,
	id core.InvitationID,
	attr audit.Attribution,
) error {
	return s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		inv, err := s.invitations.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if inv == nil || inv.CreatedByAccountID != accountID {
			return core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
		}
		if inv.AcceptedAt != nil {
			return core.NewAppError(core.ErrInvitationAlreadyAccepted, "Invitation has already been accepted")
		}

		// Emit BEFORE the delete so resource_id still references a real
		// invitation row at the time of write.
		s.recordInvitationEvent(ctx, attr, core.EventTypeInvitationRevoked, inv.ID, map[string]any{
			"kind":  inv.Kind,
			"email": inv.Email,
		})

		return s.invitations.Delete(ctx, id)
	})
}

// LookupResult is the unauthenticated preview shown on the acceptance
// page before the recipient logs in.
//
// GrantorAccount embeds the inviter account as a {id, name, slug}
// summary. For kind=grant the inviter IS the grantor; for kind=membership
// it's the account the invitee will join. Populated whenever the
// invitation row has a non-nil account_id, which is true on every
// kind in v1. AccountName is preserved for backward compatibility.
type LookupResult struct {
	Kind           domain.InvitationKind  `json:"kind"`
	Email          string                 `json:"email"`
	AccountName    string                 `json:"account_name,omitempty"`
	GrantorAccount *domain.AccountSummary `json:"grantor_account,omitempty"`
	RoleName       string                 `json:"role_name,omitempty"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// Lookup is the public preview endpoint. Takes the raw token from
// the URL (HMACs it internally) and returns a preview payload without
// revealing any authentication-sensitive fields. Runs under
// WithSystemContext (PR-B / migration 034) — the caller is
// unauthenticated, so the invitations / roles RLS lookup needs an
// explicit cross-tenant bypass.
func (s *Service) Lookup(ctx context.Context, rawToken string) (*LookupResult, error) {
	tokenHash := s.masterKey.HMAC(rawToken)
	var result *LookupResult
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		inv, err := s.invitations.GetByTokenHash(ctx, tokenHash)
		if err != nil {
			return err
		}
		if inv == nil {
			return core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
		}
		if inv.AcceptedAt != nil {
			return core.NewAppError(core.ErrInvitationAlreadyUsed, "Invitation already used")
		}
		if time.Now().UTC().After(inv.ExpiresAt) {
			return core.NewAppError(core.ErrInvitationExpired, "Invitation expired")
		}

		out := &LookupResult{
			Kind:      inv.Kind,
			Email:     inv.Email,
			ExpiresAt: inv.ExpiresAt,
		}
		if inv.AccountID != nil {
			if acct, _ := s.accounts.GetByID(ctx, *inv.AccountID); acct != nil {
				out.AccountName = acct.Name
				out.GrantorAccount = &domain.AccountSummary{
					ID:   acct.ID,
					Name: acct.Name,
					Slug: acct.Slug,
				}
			}
		}
		// Grant-kind invites have inv.AccountID = nil (the inviter is in
		// CreatedByAccountID). Populate account_name and grantor_account from
		// the inviter so the unauthenticated preview page can render
		// "selling for {Vendor}". Channels v1 backend.
		if inv.AccountID == nil && inv.Kind == domain.InvitationKindGrant {
			if acct, _ := s.accounts.GetByID(ctx, inv.CreatedByAccountID); acct != nil {
				out.AccountName = acct.Name
				out.GrantorAccount = &domain.AccountSummary{
					ID:   acct.ID,
					Name: acct.Name,
					Slug: acct.Slug,
				}
			}
		}
		if inv.RoleID != nil {
			if role, _ := s.roles.GetByID(ctx, *inv.RoleID); role != nil {
				out.RoleName = role.Name
			}
		}
		result = out
		return nil
	}); err != nil {
		return nil, err
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
func (s *Service) Accept(ctx context.Context, rawToken string, identityID core.IdentityID, attr audit.Attribution) (*AcceptResult, error) {
	tokenHash := s.masterKey.HMAC(rawToken)
	// Initial invitation lookup + identity check span tenants (the
	// invitation row lives in the inviter's account; the accepting
	// identity is global). PR-B (migration 034) made the RLS bypass
	// explicit — wrap in WithSystemContext.
	var (
		inv      *domain.Invitation
		identity *domain.Identity
	)
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		i, err := s.invitations.GetByTokenHash(ctx, tokenHash)
		if err != nil {
			return err
		}
		if i == nil {
			return core.NewAppError(core.ErrInvitationNotFound, "Invitation not found")
		}
		if i.AcceptedAt != nil {
			return core.NewAppError(core.ErrInvitationAlreadyUsed, "Invitation already used")
		}
		if time.Now().UTC().After(i.ExpiresAt) {
			return core.NewAppError(core.ErrInvitationExpired, "Invitation expired")
		}
		inv = i

		id, err := s.identities.GetByID(ctx, identityID)
		if err != nil {
			return err
		}
		identity = id
		return nil
	}); err != nil {
		return nil, err
	}

	// F-014: verify the authenticated identity is the intended recipient.
	// Without this check, anyone who obtains the invitation token can
	// accept it and join the target account — a complete BOLA.
	if identity == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Identity not found")
	}
	if !strings.EqualFold(identity.Email, inv.Email) {
		return nil, core.NewAppError(core.ErrPermissionDenied, "Invitation is for a different email address")
	}

	switch inv.Kind {
	case domain.InvitationKindMembership:
		return s.acceptMembership(ctx, inv, identityID, attr)
	case domain.InvitationKindGrant:
		return s.acceptGrant(ctx, inv, identityID, attr)
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
func (s *Service) acceptGrant(ctx context.Context, inv *domain.Invitation, identityID core.IdentityID, attr audit.Attribution) (*AcceptResult, error) {
	var draft grant.IssueRequest
	if err := json.Unmarshal(inv.GrantDraft, &draft); err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Malformed grant invitation draft")
	}
	// Defense in depth: validate product_id via the shared helper. If a
	// draft was inserted before this validation existed (pre-Task 18 invitations
	// in the DB), this guarantees acceptGrant fails with a clear error
	// rather than creating a grant with a zero product_id.
	if _, err := parseGrantDraftProductID(inv.GrantDraft); err != nil {
		return nil, err
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
	// PR-B (migration 034) — the cross-account membership lookup needs
	// an explicit RLS bypass.
	var memberships []domain.AccountMembership
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		ms, lerr := s.memberships.ListByIdentity(ctx, identityID)
		if lerr != nil {
			return lerr
		}
		memberships = ms
		return nil
	}); err != nil {
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

	// Build a grant-event attribution: the grant row lives under the
	// grantor's tenant, but the acting party is the accepting identity
	// (operating under the grantee account). Preserve the original
	// request/identity attribution fields so audit logs link the
	// grant event back to the HTTP request that triggered it.
	grantAttr := attr
	grantAttr.AccountID = grantor
	grantAttr.Environment = core.EnvironmentLive
	acting := granteeAccountID
	grantAttr.ActingAccountID = &acting

	g, err := s.grants.Issue(ctx, grantor, core.EnvironmentLive, draft, grantAttr)
	if err != nil {
		// grant_repo.Create translates the unique-index violation on
		// idx_grants_invitation_unique into core.ErrInvitationAlreadyUsed,
		// so the typed error bubbles up with the correct HTTP 409 status.
		return nil, err
	}

	// Auto-accept: the grantee has accepted the invitation so the grant
	// transitions directly from pending → active. grants.Accept runs
	// inside the grantee's tenant tx, so swap the audit tenant to match.
	acceptAttr := grantAttr
	acceptAttr.AccountID = granteeAccountID
	g, err = s.grants.Accept(ctx, granteeAccountID, core.EnvironmentLive, g.ID, acceptAttr)
	if err != nil {
		return nil, err
	}

	// Mark the invitation consumed so it cannot be reused. Record the
	// invitation.accepted event in the same tx so it commits atomically
	// with the consume. The invitation row lives under the inviter's
	// tenant (inv.CreatedByAccountID) — the event's account_id must
	// match so the RLS policy selects it under the inviter's audit log
	// rather than the accepting identity's default account.
	invitationAttr := attr
	invitationAttr.AccountID = inv.CreatedByAccountID
	invitationAttr.Environment = core.EnvironmentLive
	if err := s.txManager.WithTargetAccount(ctx, inv.CreatedByAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		if err := s.invitations.MarkAccepted(ctx, inv.ID, time.Now().UTC()); err != nil {
			return err
		}
		s.recordInvitationEvent(ctx, invitationAttr, core.EventTypeInvitationAccepted, inv.ID, map[string]any{
			"kind":     inv.Kind,
			"grant_id": g.ID.String(),
		})
		return nil
	}); err != nil {
		return nil, err
	}

	return &AcceptResult{AccountID: granteeAccountID, GrantID: &g.ID}, nil
}

func (s *Service) acceptMembership(ctx context.Context, inv *domain.Invitation, identityID core.IdentityID, attr audit.Attribution) (*AcceptResult, error) {
	if inv.AccountID == nil || inv.RoleID == nil {
		return nil, core.NewAppError(core.ErrInternalError, "Malformed membership invitation")
	}

	// Override the event's tenant so the row lands under the inviter's
	// account (where the invitation itself lives), not the accepting
	// identity's default acting account.
	invitationAttr := attr
	invitationAttr.AccountID = *inv.AccountID
	invitationAttr.Environment = core.EnvironmentLive

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
		if err := s.invitations.MarkAccepted(ctx, inv.ID, now); err != nil {
			return err
		}
		s.recordInvitationEvent(ctx, invitationAttr, core.EventTypeInvitationAccepted, inv.ID, map[string]any{
			"kind":          inv.Kind,
			"membership_id": membershipID.String(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &AcceptResult{MembershipID: &membershipID, AccountID: *inv.AccountID}, nil
}

// parseGrantDraftProductID extracts product_id from the grant draft
// JSON. Used by both CreateGrant (duplicate guard) and acceptGrant
// (issue-time application). Centralized so both sites validate shape
// identically. Returns ErrValidationError on malformed or missing
// product_id.
func parseGrantDraftProductID(draft json.RawMessage) (core.ProductID, error) {
	var partial struct {
		ProductID core.ProductID `json:"product_id"`
	}
	if err := json.Unmarshal(draft, &partial); err != nil {
		return core.ProductID{}, core.NewAppError(core.ErrValidationError,
			"Invalid grant_draft: "+err.Error())
	}
	var zero core.ProductID
	if partial.ProductID == zero {
		return core.ProductID{}, core.NewAppError(core.ErrValidationError,
			"grant_draft.product_id is required")
	}
	return partial.ProductID, nil
}
