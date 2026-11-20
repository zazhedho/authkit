// Package shared holds helpers the repositories use to turn driver errors into
// domain errors.
package shared

import (
	"errors"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"
)

// translated reports the driver error's text, so stored audit messages stay
// the same, while errors.Is matches both the domain error and the driver one.
type translated struct {
	domain error
	cause  error
	msg    string
}

func (e *translated) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return e.cause.Error()
}
func (e *translated) Unwrap() []error { return []error{e.domain, e.cause} }

func wrap(domain, cause error) error {
	if domain == nil {
		return cause
	}
	return &translated{domain: domain, cause: cause}
}

// Gorm maps gorm.ErrRecordNotFound (a read, update or delete that matched no
// row) and ErrDuplicatedKey to the domain errors; others pass through. A nil
// domain error leaves that case untranslated.
func Gorm(err, notFound, duplicate error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gokit.ErrNotFound):
		return wrap(notFound, err)
	case errors.Is(err, gorm.ErrDuplicatedKey):
		return wrap(duplicate, err)
	}
	return err
}

// Redis maps redis.Nil to the given domain error.
func Redis(err, notFound error) error {
	if err != nil && errors.Is(err, redis.Nil) {
		return wrap(notFound, err)
	}
	return err
}

// RedisMsg is Redis for callers that already report their own message for a
// miss: the text stays msg while the chain gains the domain error.
func RedisMsg(err, notFound error, msg string) error {
	if err != nil && errors.Is(err, redis.Nil) {
		return &translated{domain: notFound, cause: err, msg: msg}
	}
	return err
}
