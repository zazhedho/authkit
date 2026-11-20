package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

func generateOTP() (string, error) {
	upperBound := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// otpPurpose scopes a code to registration, so a hash made for one purpose
// never verifies for another.
const otpPurpose = "register"

// hashOTP is HMAC-SHA256(secret, purpose + email + code): bound to the address
// and the purpose, so a stolen hash cannot be replayed for another email.
func hashOTP(email, code, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(otpPurpose + email + code))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyOTP(email, code, hashed, secret string) bool {
	return hmac.Equal([]byte(hashOTP(email, code, secret)), []byte(hashed))
}
