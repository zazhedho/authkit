package mailer

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zazhedho/gokit"
)

func TestNewBrevoSenderValidatesRequiredConfig(t *testing.T) {
	full := BrevoConfig{Host: "smtp.example.com", Pass: "fake-pass", From: "noreply@example.com"}
	if _, err := NewBrevoSender(full); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	for name, mutate := range map[string]func(*BrevoConfig){
		"host": func(c *BrevoConfig) { c.Host = "" },
		"pass": func(c *BrevoConfig) { c.Pass = "" },
		"from": func(c *BrevoConfig) { c.From = "" },
	} {
		cfg := full
		mutate(&cfg)
		if _, err := NewBrevoSender(cfg); err == nil {
			t.Fatalf("expected missing %s error", name)
		}
	}
}

func TestNewBrevoSenderAppliesDefaults(t *testing.T) {
	sender, err := NewBrevoSender(BrevoConfig{Host: "smtp.example.com", Pass: "fake-pass", From: "Starter <noreply@example.com>"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if sender.Port != defaultSMTPPort || sender.User != "apikey" || sender.Subject != "Your Registration OTP" ||
		sender.ResetSubject != "Reset Your Password" || sender.AppName != "Account Verification" || sender.TTL != 5*time.Minute {
		t.Fatalf("unexpected sender defaults: %+v", sender)
	}
}

func TestNewBrevoSenderKeepsExplicitValues(t *testing.T) {
	sender, err := NewBrevoSender(BrevoConfig{
		Host: "smtp.example.com", Port: 2525, User: "mailer", Pass: "fake-pass", From: "noreply@example.com",
		OTPSubject: "Code", ResetSubject: "Reset", AppName: "My App",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if sender.Port != 2525 || sender.User != "mailer" || sender.Subject != "Code" || sender.ResetSubject != "Reset" || sender.AppName != "My App" {
		t.Fatalf("explicit values were overwritten: %+v", sender)
	}
}

func TestBuildMailerMessagesEscapeHTMLAndIncludeFallbackMinutes(t *testing.T) {
	otp := string(buildOTPMessage("from@example.com", "to@example.com", "Subject", "<App>", "123456", 0))
	if !strings.Contains(otp, "&lt;App&gt;") || !strings.Contains(otp, "expires in 5 minutes") {
		t.Fatalf("unexpected otp message: %s", otp)
	}

	reset := string(buildPasswordResetMessage("from@example.com", "to@example.com", "Reset", "<App>", "token", "", 0))
	if !strings.Contains(reset, "&lt;App&gt;") || !strings.Contains(reset, "Reset token: token") || !strings.Contains(reset, "expires in 15 minutes") {
		t.Fatalf("unexpected reset message: %s", reset)
	}

	resetWithURL := string(buildPasswordResetMessage("from@example.com", "to@example.com", "Reset", "App", "token", "https://example.com/reset", time.Minute))
	if !strings.Contains(resetWithURL, "Reset Password") || !strings.Contains(resetWithURL, "https://example.com/reset") {
		t.Fatalf("unexpected reset URL message: %s", resetWithURL)
	}
}

func TestBuildOTPMessageStatesConfiguredTTL(t *testing.T) {
	msg := string(buildOTPMessage("from@example.com", "to@example.com", "Subject", "App", "123456", 10*time.Minute))
	if strings.Count(msg, "expires in 10 minutes") != 2 || strings.Contains(msg, "5 minutes") {
		t.Fatalf("otp message does not state the configured 10 minutes:\n%s", msg)
	}
}

func TestBrevoSenderOTPUsesArgumentTTLAndFallsBack(t *testing.T) {
	s := &BrevoSender{From: "a@example.com", Subject: "S", AppName: "App", TTL: 7 * time.Minute}
	if got := string(s.otpMessage("to@example.com", "123456", "", 10*time.Minute)); !strings.Contains(got, "expires in 10 minutes") {
		t.Fatalf("argument TTL not used:\n%s", got)
	}
	if got := string(s.otpMessage("to@example.com", "123456", "", 0)); !strings.Contains(got, "expires in 7 minutes") {
		t.Fatalf("fallback TTL not used:\n%s", got)
	}
}

func TestMIMEBoundaryIsAuthkitScoped(t *testing.T) {
	msg := string(buildOTPMessage("a@example.com", "b@example.com", "S", "App", "1", time.Minute))
	if !strings.Contains(msg, "boundary=authkit-mail-boundary") || strings.Contains(msg, "starter-kit") {
		t.Fatalf("unexpected boundary:\n%s", msg)
	}
}

func TestExtractEmailAndDurationFromEnv(t *testing.T) {
	if got := extractEmail("Starter <noreply@example.com>"); got != "noreply@example.com" {
		t.Fatalf("unexpected extracted email: %q", got)
	}
	if got := extractEmail("noreply@example.com"); got != "noreply@example.com" {
		t.Fatalf("unexpected plain email: %q", got)
	}

	t.Setenv("DURATION_A", "")
	t.Setenv("DURATION_B", "120")
	if got := gokit.DurationFromEnv([]string{"DURATION_A", "DURATION_B"}, time.Minute); got != 120*time.Second {
		t.Fatalf("expected duration from seconds, got %v", got)
	}
}

func TestBrevoSenderSendMethodsReturnSMTPError(t *testing.T) {
	sender := &BrevoSender{
		Host:         "127.0.0.1",
		Port:         1,
		User:         "apikey",
		Pass:         "secret",
		From:         "Starter <noreply@example.com>",
		Subject:      "OTP",
		ResetSubject: "",
		TTL:          time.Minute,
		AppName:      "Starter",
	}

	if err := sender.SendOTP("to@example.com", "123456", "", 0); err == nil {
		t.Fatal("expected otp smtp error")
	}
	if err := sender.SendPasswordReset("to@example.com", "token", "", "", 0); err == nil {
		t.Fatal("expected reset smtp error")
	}
}

func TestMessagesCarryDateAndAUniqueMessageID(t *testing.T) {
	a := string(buildOTPMessage("Starter <noreply@example.com>", "to@example.com", "OTP", "App", "123456", time.Minute))
	b := string(buildOTPMessage("Starter <noreply@example.com>", "to@example.com", "OTP", "App", "123456", time.Minute))
	for _, header := range []string{"Date: ", "Message-ID: <"} {
		if !strings.Contains(a, header) {
			t.Errorf("message lacks the %q header", header)
		}
	}
	if !strings.Contains(a, "@example.com>") {
		t.Error("Message-ID must use the sender's domain")
	}
	idOf := func(m string) string {
		i := strings.Index(m, "Message-ID: ")
		return m[i : i+strings.Index(m[i:], "\r\n")]
	}
	if idOf(a) == idOf(b) {
		t.Error("two messages must not share a Message-ID")
	}
}

func TestSendGivesUpOnAStalledServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { // accepts and never speaks
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	sender := &BrevoSender{Host: "127.0.0.1", Port: port, From: "noreply@example.com", Pass: "x", SendTimeout: 300 * time.Millisecond}

	start := time.Now()
	err = sender.SendOTP("to@example.com", "123456", "App", time.Minute)
	if err == nil {
		t.Fatal("a server that never answers must be an error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("send took %v, the timeout did not apply", elapsed)
	}
}

func TestSendRejectsLineBreaksInAddresses(t *testing.T) {
	sender := &BrevoSender{Host: "127.0.0.1", Port: 1, From: "noreply@example.com", Pass: "x"}
	if err := sender.SendOTP("a@example.com\r\nBcc: evil@example.com", "1", "App", time.Minute); err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("err = %v, want a line-break rejection", err)
	}
}
