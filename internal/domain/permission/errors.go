package permission

import "errors"

var (
	ErrNotFound  = errors.New("permission not found")
	ErrDuplicate = errors.New("permission already exists")
)
