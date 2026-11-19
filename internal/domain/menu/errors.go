package menu

import "errors"

var (
	ErrNotFound = errors.New("menu not found")
	// ErrInvalidParent is returned for a parent_id that is not a UUID, does not
	// exist, is the item itself or would make the tree loop.
	ErrInvalidParent = errors.New("invalid menu parent")
)
