package role

import "errors"

var (
	ErrNotFound  = errors.New("role not found")
	ErrDuplicate = errors.New("role already exists")
)
