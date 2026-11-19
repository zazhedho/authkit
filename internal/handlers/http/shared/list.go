package shared

import (
	"github.com/zazhedho/gokit"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
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

// PageSize is the page size the repository applies to params under policy: the
// value pagination metadata must report, instead of the raw requested limit.
// The zero policy means dtoshared.PagedList.
func PageSize(policy dtoshared.ListPolicy, params gokit.BaseParams) int {
	if policy == (dtoshared.ListPolicy{}) {
		policy = dtoshared.PagedList
	}
	return gokit.QueryOptions{MaxLimit: policy.MaxLimit, AllowAll: policy.AllowAll}.PageSize(params)
}
