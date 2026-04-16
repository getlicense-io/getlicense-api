package search

import (
	"fmt"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// validTypes enumerates the resource types the search DSL accepts.
var validTypes = map[string]bool{
	"license":  true,
	"machine":  true,
	"customer": true,
	"product":  true,
}

// allowedFields lists the whitelisted filter fields per type and the
// primary field used when a bare word (no `field:` prefix) is provided.
var allowedFields = map[string]map[string]bool{
	"license":  {"key": true, "email": true, "customer_id": true, "status": true},
	"machine":  {"fingerprint": true, "hostname": true, "license_id": true},
	"customer": {"email": true, "name": true},
	"product":  {"slug": true, "name": true},
}

// ParsedQuery is the output of the DSL parser.
type ParsedQuery struct {
	Types   []string          // empty = all types
	Filters map[string]string // field -> value
	Bare    string            // bare word (no field prefix)
}

// Parse tokenizes the raw query string and returns a ParsedQuery.
//
// Rules:
//   - Tokens are whitespace-separated.
//   - "type:X" restricts search to type X. Multiple type: tokens are supported.
//   - "field:value" sets a filter on a specific field.
//   - Bare words (no colon) set Bare (last one wins).
//   - Empty or whitespace-only input is rejected.
//   - Unknown types are rejected.
//   - Unknown fields are rejected after types are resolved.
func Parse(q string) (*ParsedQuery, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, core.NewAppError(core.ErrValidationError, "search query must not be empty")
	}

	pq := &ParsedQuery{
		Filters: make(map[string]string),
	}

	tokens := strings.Fields(q)
	for _, tok := range tokens {
		idx := strings.IndexByte(tok, ':')
		if idx < 0 {
			// Bare word.
			pq.Bare = tok
			continue
		}
		field := tok[:idx]
		value := tok[idx+1:]

		if field == "type" {
			if !validTypes[value] {
				return nil, core.NewAppError(core.ErrValidationError,
					fmt.Sprintf("unknown search type %q; valid types: license, machine, customer, product", value))
			}
			pq.Types = append(pq.Types, value)
			continue
		}

		// Accumulate as a filter; validation against allowedFields happens
		// after all tokens are parsed so we know the final type set.
		pq.Filters[field] = value
	}

	// Validate filters against whitelisted fields.
	if err := validateFilters(pq); err != nil {
		return nil, err
	}

	return pq, nil
}

// validateFilters checks every filter key against the allowed fields for
// the resolved type set. If no types are specified, the field must be
// valid for at least one type.
func validateFilters(pq *ParsedQuery) error {
	for field := range pq.Filters {
		if len(pq.Types) > 0 {
			// Field must be valid for at least one of the specified types.
			ok := false
			for _, t := range pq.Types {
				if allowedFields[t][field] {
					ok = true
					break
				}
			}
			if !ok {
				return core.NewAppError(core.ErrValidationError,
					fmt.Sprintf("unknown filter %q for type(s) %s; valid fields: %s",
						field, strings.Join(pq.Types, ","), validFieldsFor(pq.Types)))
			}
		} else {
			// No type restriction: field must exist in at least one type.
			ok := false
			for _, fields := range allowedFields {
				if fields[field] {
					ok = true
					break
				}
			}
			if !ok {
				return core.NewAppError(core.ErrValidationError,
					fmt.Sprintf("unknown filter %q; valid fields: key, email, customer_id, status, fingerprint, hostname, license_id, slug, name", field))
			}
		}
	}
	return nil
}

// validFieldsFor returns a comma-separated list of valid fields for the
// given type slice. Used in error messages.
func validFieldsFor(types []string) string {
	seen := make(map[string]bool)
	var fields []string
	for _, t := range types {
		for f := range allowedFields[t] {
			if !seen[f] {
				seen[f] = true
				fields = append(fields, f)
			}
		}
	}
	return strings.Join(fields, ", ")
}
