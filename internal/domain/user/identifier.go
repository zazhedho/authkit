package user

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
)

var (
	nonDigits = regexp.MustCompile(`\D+`)
	leadZero  = regexp.MustCompile(`^0`)
	plus62    = regexp.MustCompile(`^\+62`)
)

// NormalizePhoneTo62 strips everything but digits (keeping a leading "+") and
// rewrites a leading 0 or +62 to 62, the form phone numbers are stored in.
func NormalizePhoneTo62(phoneInput string) string {
	var prefix, numberToClean string

	if strings.HasPrefix(phoneInput, "+") {
		prefix = "+"
		numberToClean = phoneInput[1:]
	} else {
		numberToClean = phoneInput
	}

	sanitized := prefix + nonDigits.ReplaceAllString(numberToClean, "")

	normalized := leadZero.ReplaceAllString(sanitized, "62")
	return plus62.ReplaceAllString(normalized, "62")
}

// SanitizeEmail returns the trimmed, lower-cased address, or "" when it is not
// a bare, valid address.
func SanitizeEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ""
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return ""
	}
	return parsed.Address
}

// ResolveLoginIdentifier picks the login identifier (falling back to email)
// and returns it as a sanitized email or a normalized phone number.
func ResolveLoginIdentifier(identifier, email string) (string, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		identifier = strings.TrimSpace(email)
	}

	if identifier == "" {
		return "", errors.New("identifier or email is required")
	}

	if strings.Contains(identifier, "@") {
		sanitizedEmail := SanitizeEmail(identifier)
		if _, err := mail.ParseAddress(sanitizedEmail); err != nil {
			return "", errors.New("identifier must be a valid email or phone number")
		}
		return sanitizedEmail, nil
	}

	normalizedPhone := NormalizePhoneTo62(identifier)
	if len(normalizedPhone) < 9 || len(normalizedPhone) > 15 {
		return "", errors.New("identifier must be a valid email or phone number")
	}

	return normalizedPhone, nil
}
