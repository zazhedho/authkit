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

// BaseParams converts a dto/<module>.ListRequest into the gokit query the
// generic repository runs.
func BaseParams[T ~listFields](req T) gokit.BaseParams {
	f := listFields(req)
	return gokit.BaseParams{
		Search:         f.Search,
		Filters:        f.Filters,
		OrderBy:        f.OrderBy,
		OrderDirection: f.OrderDirection,
		Page:           f.Page,
		Limit:          f.Limit,
		Offset:         f.Offset,
	}
}
