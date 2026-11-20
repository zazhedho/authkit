package shared

// ImpersonationClaims is the identity an impersonation started from, plus the
// actor's session ID and access-token hash (either may be empty). The service
// passes it and the token issuer records it, so both share this one shape.
type ImpersonationClaims struct {
	OriginalUserID   string
	OriginalUsername string
	OriginalRole     string
	ActorSessionID   string
	ActorTokenHash   string
}
