package role

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
