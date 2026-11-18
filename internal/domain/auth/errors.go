package auth

import "errors"

var (
	ErrNotFound  = errors.New("blacklisted token not found")
	ErrDuplicate = errors.New("token already blacklisted")
)
