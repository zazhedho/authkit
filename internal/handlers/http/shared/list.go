package shared

import "github.com/zazhedho/gokit"

// listFields is the shape every dto/<module>.ListRequest shares.
type listFields = struct {
	Search         string
	Filters        map[string]any
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
	Offset         int
}

// ListRequest converts the parsed query into a module's dto ListRequest, e.g.
// ListRequest[dtouser.ListRequest](params).
func ListRequest[T ~listFields](params gokit.BaseParams) T {
	return T(listFields{
		Search:         params.Search,
		Filters:        params.Filters,
		OrderBy:        params.OrderBy,
		OrderDirection: params.OrderDirection,
		Page:           params.Page,
		Limit:          params.Limit,
		Offset:         params.Offset,
	})
}
