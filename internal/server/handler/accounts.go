package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/account"
	"github.com/getlicense-io/getlicense-api/internal/core"
)

// AccountHandler exposes the read-only account lookup endpoint used by
// sharing UIs to render counterparty summaries.
type AccountHandler struct {
	svc *account.Service
}

// NewAccountHandler constructs an AccountHandler backed by the given
// account service.
func NewAccountHandler(svc *account.Service) *AccountHandler {
	return &AccountHandler{svc: svc}
}

// GetSummary serves GET /v1/accounts/:account_id and returns a
// *domain.AccountSummary. The service enforces visibility: the caller
// must have a membership on the target account (identity auth) or hold
// an active/pending/suspended grant counterparty relationship with it.
// Everything else — including "no such account" — collapses to 404
// (ErrAccountNotFound) so the endpoint cannot be used to probe for
// account existence.
//
// API-key callers have no IdentityID; passing a zero IdentityID here is
// safe because the service's membership branch will simply not match,
// and authorization falls through to the grant-counterparty branch.
func (h *AccountHandler) GetSummary(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	id, err := core.ParseAccountID(c.Params("account_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid account_id")
	}
	var identityID core.IdentityID
	if auth.IdentityID != nil {
		identityID = *auth.IdentityID
	}
	summary, err := h.svc.GetSummary(c.Context(), id, auth.ActingAccountID, identityID)
	if err != nil {
		return err
	}
	return c.JSON(summary)
}
