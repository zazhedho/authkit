package shared

import (
	"github.com/zazhedho/gokit"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
)

// BaseParams converts a list request into the gokit query the generic
// repository runs.
func BaseParams(req dtoshared.ListRequest) gokit.BaseParams {
	return gokit.BaseParams{
		Search:         req.Search,
		Filters:        req.Filters,
		OrderBy:        req.OrderBy,
		OrderDirection: req.OrderDirection,
		Page:           req.Page,
		Limit:          req.Limit,
		Offset:         req.Offset,
	}
}
