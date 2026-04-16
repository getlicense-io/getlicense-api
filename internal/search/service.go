package search

import (
	"context"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

const defaultPerTypeLimit = 10

// Result holds the aggregated search results across resource types.
type Result struct {
	Licenses  []domain.License  `json:"licenses,omitempty"`
	Machines  []domain.Machine  `json:"machines,omitempty"`
	Customers []domain.Customer `json:"customers,omitempty"`
	Products  []domain.Product  `json:"products,omitempty"`
}

// Service coordinates parallel sub-queries across resource types.
type Service struct {
	licenses  domain.LicenseRepository
	machines  domain.MachineRepository
	customers domain.CustomerRepository
	products  domain.ProductRepository
	tx        domain.TxManager
}

// NewService creates a new search Service.
func NewService(
	tx domain.TxManager,
	licenses domain.LicenseRepository,
	machines domain.MachineRepository,
	customers domain.CustomerRepository,
	products domain.ProductRepository,
) *Service {
	return &Service{
		tx:        tx,
		licenses:  licenses,
		machines:  machines,
		customers: customers,
		products:  products,
	}
}

// Search parses the DSL query, fans out sub-queries in parallel for
// each matching resource type, and returns the combined results.
// Each sub-query runs inside its own WithTargetAccount tx for RLS scoping.
func (s *Service) Search(ctx context.Context, accountID core.AccountID, env core.Environment, query string, types []string, limit int) (*Result, error) {
	pq, err := Parse(query)
	if err != nil {
		return nil, err
	}

	// Merge explicit types from the DSL with the `types` query param.
	activeTypes := resolveTypes(pq.Types, types)

	perType := limit
	if perType <= 0 || perType > defaultPerTypeLimit {
		perType = defaultPerTypeLimit
	}

	g, gctx := errgroup.WithContext(ctx)
	var mu sync.Mutex
	result := &Result{}

	if shouldSearch(activeTypes, "license") {
		g.Go(func() error {
			return s.tx.WithTargetAccount(gctx, accountID, env, func(txCtx context.Context) error {
				filters := buildLicenseFilters(pq)
				items, _, err := s.licenses.List(txCtx, filters, core.Cursor{}, perType)
				if err != nil {
					return err
				}
				mu.Lock()
				result.Licenses = items
				mu.Unlock()
				return nil
			})
		})
	}

	if shouldSearch(activeTypes, "customer") {
		g.Go(func() error {
			return s.tx.WithTargetAccount(gctx, accountID, env, func(txCtx context.Context) error {
				filter := buildCustomerFilter(pq)
				items, _, err := s.customers.List(txCtx, accountID, filter, core.Cursor{}, perType)
				if err != nil {
					return err
				}
				mu.Lock()
				result.Customers = items
				mu.Unlock()
				return nil
			})
		})
	}

	if shouldSearch(activeTypes, "product") {
		g.Go(func() error {
			return s.tx.WithTargetAccount(gctx, accountID, env, func(txCtx context.Context) error {
				q := productSearchTerm(pq)
				if q == "" {
					return nil
				}
				items, err := s.products.Search(txCtx, q, perType)
				if err != nil {
					return err
				}
				mu.Lock()
				result.Products = items
				mu.Unlock()
				return nil
			})
		})
	}

	if shouldSearch(activeTypes, "machine") {
		g.Go(func() error {
			return s.tx.WithTargetAccount(gctx, accountID, env, func(txCtx context.Context) error {
				q := machineSearchTerm(pq)
				if q == "" {
					return nil
				}
				items, err := s.machines.Search(txCtx, q, perType)
				if err != nil {
					return err
				}
				mu.Lock()
				result.Machines = items
				mu.Unlock()
				return nil
			})
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return result, nil
}

// resolveTypes merges the DSL types and query-param types into a
// deduplicated set. Empty = search all types.
func resolveTypes(dslTypes, paramTypes []string) map[string]bool {
	if len(dslTypes) == 0 && len(paramTypes) == 0 {
		return nil // nil = all types
	}
	m := make(map[string]bool)
	for _, t := range dslTypes {
		m[t] = true
	}
	for _, t := range paramTypes {
		m[t] = true
	}
	return m
}

// shouldSearch returns true if the given type is in the active set
// (nil = all types).
func shouldSearch(active map[string]bool, typ string) bool {
	if active == nil {
		return true
	}
	return active[typ]
}

// buildLicenseFilters maps parsed DSL filters to the existing
// LicenseListFilters shape.
func buildLicenseFilters(pq *ParsedQuery) domain.LicenseListFilters {
	var f domain.LicenseListFilters

	// Bare word routes to Q (prefix/substring on key_prefix + customer name/email).
	if pq.Bare != "" {
		f.Q = pq.Bare
	}

	// Explicit field filters.
	if v, ok := pq.Filters["key"]; ok {
		f.Q = v
	}
	if v, ok := pq.Filters["email"]; ok {
		// email filter also uses Q (which matches customer email via EXISTS).
		if f.Q == "" {
			f.Q = v
		}
	}
	if v, ok := pq.Filters["status"]; ok {
		f.Status = core.LicenseStatus(v)
	}
	if v, ok := pq.Filters["customer_id"]; ok {
		cid, err := core.ParseCustomerID(v)
		if err == nil {
			f.CustomerID = &cid
		}
	}
	return f
}

// buildCustomerFilter maps parsed DSL filters to CustomerListFilter.
func buildCustomerFilter(pq *ParsedQuery) domain.CustomerListFilter {
	var f domain.CustomerListFilter

	// Bare word routes to email (primary field).
	if pq.Bare != "" {
		f.Email = pq.Bare
	}

	if v, ok := pq.Filters["email"]; ok {
		f.Email = v
	}
	if v, ok := pq.Filters["name"]; ok {
		f.Name = v
	}
	return f
}

// productSearchTerm extracts the search term for products from the
// parsed query. Returns empty string if no term applies.
func productSearchTerm(pq *ParsedQuery) string {
	if v, ok := pq.Filters["slug"]; ok {
		return v
	}
	if v, ok := pq.Filters["name"]; ok {
		return v
	}
	if pq.Bare != "" {
		return pq.Bare
	}
	return ""
}

// machineSearchTerm extracts the search term for machines.
func machineSearchTerm(pq *ParsedQuery) string {
	if v, ok := pq.Filters["fingerprint"]; ok {
		return v
	}
	if v, ok := pq.Filters["hostname"]; ok {
		return v
	}
	if pq.Bare != "" {
		return pq.Bare
	}
	return ""
}

// ValidateTypes checks that all type strings in the comma-separated
// list are known. Returns a cleaned slice and an error if any are
// unknown.
func ValidateTypes(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !validTypes[p] {
			return nil, core.NewAppError(core.ErrValidationError,
				"unknown search type \""+p+"\"; valid types: license, machine, customer, product")
		}
		out = append(out, p)
	}
	return out, nil
}
