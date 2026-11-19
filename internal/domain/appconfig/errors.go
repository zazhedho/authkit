package appconfig

import "errors"

var (
	ErrNotFound = errors.New("app config not found")
	// ErrInvalidValue is returned for a value that does not fit the key's type.
	ErrInvalidValue = errors.New("invalid app config value")
)
