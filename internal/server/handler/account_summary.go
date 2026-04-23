package handler

import (
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// toAccountSummary is the ONLY place AccountSummary values are constructed
// outside of repository JOINs. Guarantees the {id, name, slug} shape —
// never leaks additional fields to counterparties.
func toAccountSummary(a *domain.Account) *domain.AccountSummary {
	if a == nil {
		return nil
	}
	return &domain.AccountSummary{
		ID:   a.ID,
		Name: a.Name,
		Slug: a.Slug,
	}
}

// scrubGrantForReader removes grantor-only fields (label, metadata)
// when the caller is not the grantor. Called on every grant-serializing
// code path so the grantee never sees the grantor's private annotations.
func scrubGrantForReader(g *domain.Grant, reader core.AccountID) *domain.Grant {
	if g == nil || g.GrantorAccountID == reader {
		return g
	}
	clone := *g
	clone.Label = nil
	clone.Metadata = nil
	return &clone
}

// scrubGrantsForReader applies scrubGrantForReader element-wise.
func scrubGrantsForReader(grants []domain.Grant, reader core.AccountID) []domain.Grant {
	if len(grants) == 0 {
		return grants
	}
	out := make([]domain.Grant, len(grants))
	for i, g := range grants {
		out[i] = *scrubGrantForReader(&g, reader)
	}
	return out
}
