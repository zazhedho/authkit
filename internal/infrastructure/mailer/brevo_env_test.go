package mailer

import (
	"testing"
	"time"
)

func TestNewBrevoSenderFromEnvValidatesRequiredConfig(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_PASS", "")
	t.Setenv("SMTP_FROM", "")

	if _, err := NewBrevoSenderFromEnv(); err == nil {
		t.Fatal("expected missing credentials error")
	}
}

func TestNewBrevoSenderFromEnvAppliesDefaults(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "bad-port")
	t.Setenv("SMTP_USER", "")
	t.Setenv("SMTP_PASS", "secret")
	t.Setenv("SMTP_FROM", "Starter <noreply@example.com>")
	t.Setenv("SMTP_SUBJECT", "")
	t.Setenv("RESET_SUBJECT", "")
	t.Setenv("AUTH_EMAIL_APP_NAME", "")
	t.Setenv("OTP_TTL", "7m")

	sender, err := NewBrevoSenderFromEnv()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if sender.Port != defaultSMTPPort || sender.User != "apikey" || sender.Subject != "Your Registration OTP" {
		t.Fatalf("unexpected sender defaults: %+v", sender)
	}
	if sender.TTL != 7*time.Minute {
		t.Fatalf("expected TTL from env, got %v", sender.TTL)
	}
}
