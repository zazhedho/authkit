package shared

import (
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	"github.com/zazhedho/gokit"
)

// ListRequest converts the parsed query into the dto every module's service
// takes.
func ListRequest(params gokit.BaseParams) dtoshared.ListRequest {
	return dtoshared.ListRequest{
		Search:         params.Search,
		Filters:        params.Filters,
		OrderBy:        params.OrderBy,
		OrderDirection: params.OrderDirection,
		Page:           params.Page,
		Limit:          params.Limit,
		Offset:         params.Offset,
	}
}
