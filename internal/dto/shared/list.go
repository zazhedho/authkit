// Package shared holds the request shapes every module's dto package uses.
package shared

// ListRequest is a paged, filtered and ordered list query. The handlers build
// it from the HTTP query string, so services stay independent of HTTP and of
// the query framework.
type ListRequest struct {
	Search         string
	Filters        map[string]any
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
	Offset         int
}

// ListPolicy bounds how many rows one list request may return. A module's
// repository and its handler both read the same policy, so the page size the
// repository applies is the one the handler reports in the response.
type ListPolicy struct {
	// MaxLimit caps the page size.
	MaxLimit int
	// AllowAll honors limit=-1 as "every row". Only small reference lists that
	// a UI needs whole (roles, permissions, menus) turn it on.
	AllowAll bool
}

// DefaultMaxLimit is the page-size cap of every list.
const DefaultMaxLimit = 100

var (
	// PagedList is the policy of lists that stay paged: users, audits, configs.
	PagedList = ListPolicy{MaxLimit: DefaultMaxLimit}
	// ReferenceList is the policy of small reference lists that a UI loads
	// whole with limit=-1: roles, permissions, menus.
	ReferenceList = ListPolicy{MaxLimit: DefaultMaxLimit, AllowAll: true}
)
