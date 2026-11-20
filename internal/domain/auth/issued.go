package auth

import "time"

// IssuedAtMillis is when a token was issued, in milliseconds: the private
// iat_ms claim, else the registered iat (seconds).
func IssuedAtMillis(claims map[string]any) int64 {
	if ms, ok := claims["iat_ms"].(float64); ok && ms > 0 {
		return int64(ms)
	}
	iat, _ := claims["iat"].(float64)
	return int64(iat) * 1000
}

// RevokedBy reports whether a token issued at or before cutoff is void. A token
// issued after the cut-off (the caller's re-issued one) stays valid.
func RevokedBy(claims map[string]any, cutoff time.Time) bool {
	return IssuedAtMillis(claims) <= cutoff.UnixMilli()
}
