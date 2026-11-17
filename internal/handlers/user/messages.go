package handleruser

// Messages that used to live in gokit and are specific to authentication.
const (
	// MsgCredential is the message returned for a failed credential check.
	MsgCredential = "Invalid Credentials. Please input the correct email or phone and password, then try again." //nolint:gosec // message text, not a credential
	// InvalidCred is the response title for a failed credential check.
	InvalidCred = "Invalid email, phone, or password" //nolint:gosec // message text, not a credential
	// ErrHashPassword is the text of bcrypt's mismatch error.
	ErrHashPassword = "crypto/bcrypt: hashedPassword is not the hash of the given password" //nolint:gosec // message text, not a credential
)
