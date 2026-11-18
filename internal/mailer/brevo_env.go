package mailer

import (
	"strconv"
	"time"

	"github.com/zazhedho/gokit"
)

// NewBrevoSenderFromEnv reads the SMTP_* environment variables (plus RESET_SUBJECT,
// AUTH_EMAIL_APP_NAME and OTP_TTL) and builds a sender through NewBrevoSender. It is a startup helper; request-time
// code never reads the environment.
func NewBrevoSenderFromEnv() (*BrevoSender, error) {
	port := 0
	if value := gokit.GetEnv("SMTP_PORT", ""); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			port = parsed
		}
	}

	sender, err := NewBrevoSender(BrevoConfig{
		Host:         gokit.GetEnv("SMTP_HOST", ""),
		Port:         port,
		User:         gokit.GetEnv("SMTP_USER", ""),
		Pass:         gokit.GetEnv("SMTP_PASS", ""),
		From:         gokit.GetEnv("SMTP_FROM", ""),
		OTPSubject:   gokit.GetEnv("SMTP_SUBJECT", ""),
		ResetSubject: gokit.GetEnv("RESET_SUBJECT", ""),
		AppName:      gokit.GetEnv("AUTH_EMAIL_APP_NAME", ""),
	})
	if err != nil {
		return nil, err
	}
	sender.TTL = gokit.DurationFromEnv([]string{"OTP_TTL", "OTP_TTL_SECONDS"}, 5*time.Minute)
	return sender, nil
}
