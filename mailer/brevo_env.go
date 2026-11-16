package mailer

import (
	"strconv"
	"time"

	"github.com/zazhedho/gokit/utils"
)

// NewBrevoSenderFromEnv reads the legacy SMTP_* environment variables and
// builds a sender through NewBrevoSender. It is a startup helper; request-time
// code never reads the environment.
func NewBrevoSenderFromEnv() (*BrevoSender, error) {
	port := 0
	if value := utils.GetEnv("SMTP_PORT", ""); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			port = parsed
		}
	}

	sender, err := NewBrevoSender(BrevoConfig{
		Host:         utils.GetEnv("SMTP_HOST", ""),
		Port:         port,
		User:         utils.GetEnv("SMTP_USER", ""),
		Pass:         utils.GetEnv("SMTP_PASS", ""),
		From:         utils.GetEnv("SMTP_FROM", ""),
		OTPSubject:   utils.GetEnv("SMTP_SUBJECT", ""),
		ResetSubject: utils.GetEnv("RESET_SUBJECT", ""),
		AppName:      utils.GetEnv("AUTH_EMAIL_APP_NAME", ""),
	})
	if err != nil {
		return nil, err
	}
	sender.TTL = utils.DurationFromEnv([]string{"OTP_TTL", "OTP_TTL_SECONDS"}, 5*time.Minute)
	return sender, nil
}
