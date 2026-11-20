package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

const defaultSMTPPort = 587

type BrevoSender struct {
	Host         string
	Port         int
	User         string
	Pass         string
	From         string
	Subject      string
	ResetSubject string
	TTL          time.Duration
	AppName      string
	// SendTimeout bounds one send; zero means 30 seconds.
	SendTimeout time.Duration
}

// BrevoConfig is the explicit SMTP configuration for BrevoSender. Host, Pass
// and From are required; the remaining fields fall back to defaults.
type BrevoConfig struct {
	Host         string
	Port         int
	User, Pass   string
	From         string
	OTPSubject   string
	ResetSubject string
	AppName      string
}

// NewBrevoSender validates cfg and applies defaults; the e-mailed OTP validity
// defaults to five minutes only when SendOTP gets a non-positive ttl.
func NewBrevoSender(cfg BrevoConfig) (*BrevoSender, error) {
	if cfg.Host == "" || cfg.Pass == "" || cfg.From == "" {
		return nil, fmt.Errorf("smtp credentials not configured")
	}

	port := cfg.Port
	if port <= 0 {
		port = defaultSMTPPort
	}
	user := cfg.User
	if user == "" {
		user = "apikey"
	}
	subject := cfg.OTPSubject
	if subject == "" {
		subject = "Your Registration OTP"
	}
	resetSubject := cfg.ResetSubject
	if resetSubject == "" {
		resetSubject = "Reset Your Password"
	}
	appName := cfg.AppName
	if appName == "" {
		appName = "Account Verification"
	}

	return &BrevoSender{
		Host:         cfg.Host,
		Port:         port,
		User:         user,
		Pass:         cfg.Pass,
		From:         cfg.From,
		Subject:      subject,
		ResetSubject: resetSubject,
		TTL:          5 * time.Minute,
		AppName:      appName,
	}, nil
}

// SendOTP sends the code, stating ttl as its validity. When ttl is not
// positive the sender's own TTL field is used.
func (s *BrevoSender) SendOTP(ctx context.Context, to, code, appName string, ttl time.Duration) error {
	return s.send(ctx, to, s.otpMessage(to, code, appName, ttl))
}

func (s *BrevoSender) otpMessage(to, code, appName string, ttl time.Duration) []byte {
	if strings.TrimSpace(appName) == "" {
		appName = s.AppName
	}
	if ttl <= 0 {
		ttl = s.TTL
	}
	return buildOTPMessage(s.From, to, s.Subject, appName, code, ttl)
}

func (s *BrevoSender) SendPasswordReset(ctx context.Context, to, token, appName, resetURL string, ttl time.Duration) error {
	if strings.TrimSpace(appName) == "" {
		appName = s.AppName
	}
	subject := s.ResetSubject
	if subject == "" {
		subject = "Reset Your Password"
	}
	msg := buildPasswordResetMessage(s.From, to, subject, appName, token, resetURL, ttl)
	return s.send(ctx, to, msg)
}

const (
	// dialTimeout bounds connecting to the SMTP server.
	dialTimeout = 10 * time.Second
	// defaultSendTimeout bounds one whole send, so a stalled server cannot hold
	// a request (or a background goroutine) forever.
	defaultSendTimeout = 30 * time.Second
)

// ErrTLSRequired is returned when a non-loopback SMTP server does not offer STARTTLS.
var ErrTLSRequired = errors.New("mailer: SMTP server does not offer STARTTLS")

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *BrevoSender) send(ctx context.Context, to string, msg []byte) error {
	timeout := s.SendTimeout
	if timeout <= 0 {
		timeout = defaultSendTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.sendContext(ctx, to, msg)
}

// sendContext delivers msg within ctx: the dial, the whole SMTP conversation and
// the connection's read and write deadlines all end with it.
func (s *BrevoSender) sendContext(ctx context.Context, to string, msg []byte) error {
	if hasLineBreak(to) || hasLineBreak(s.From) {
		return errors.New("mailer: address contains a line break")
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mailer: dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// Closing the connection when ctx ends unblocks any read or write.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: %w", err)
	}
	defer func() { _ = client.Close() }()

	// OTP codes and reset links must never travel in clear text, so a missing
	// STARTTLS (possibly stripped by an attacker) is fatal except on loopback.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("mailer: starttls: %w", err)
		}
	} else if !isLoopbackHost(s.Host) {
		return ErrTLSRequired
	}
	if ok, _ := client.Extension("AUTH"); ok {
		if err := client.Auth(smtp.PlainAuth("", s.User, s.Pass, s.Host)); err != nil {
			return fmt.Errorf("mailer: auth: %w", err)
		}
	}
	if err := client.Mail(extractEmail(s.From)); err != nil {
		return fmt.Errorf("mailer: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mailer: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("mailer: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: %w", err)
	}
	return client.Quit()
}

func hasLineBreak(s string) bool { return strings.ContainsAny(s, "\r\n") }

func buildOTPMessage(from, to, subject, appName, code string, ttl time.Duration) []byte {
	minutes := int(ttl.Minutes())
	if minutes <= 0 {
		minutes = 5
	}

	safeAppName := html.EscapeString(appName)
	textBody := fmt.Sprintf("Your registration verification code is: %s\nThis code expires in %d minutes.\nIf you did not register, ignore this email.\n", code, minutes)
	htmlBody := fmt.Sprintf(`<p>Hello,</p><p>Use this code to complete your %s registration:</p><h1 style="letter-spacing:6px">%s</h1><p>This code expires in %d minutes.</p><p>If you did not register, ignore this email.</p>`, safeAppName, html.EscapeString(code), minutes)
	return buildMultipartMessage(from, to, subject, textBody, htmlBody)
}

func buildPasswordResetMessage(from, to, subject, appName, token, resetURL string, ttl time.Duration) []byte {
	minutes := int(ttl.Minutes())
	if minutes <= 0 {
		minutes = 15
	}

	safeAppName := html.EscapeString(appName)
	textBody := fmt.Sprintf("We received a password reset request for %s.\n", safeAppName)
	actionHTML := fmt.Sprintf(`<p>Use this reset token:</p><p style="word-break:break-all">%s</p>`, html.EscapeString(token))
	if strings.TrimSpace(resetURL) != "" {
		textBody += fmt.Sprintf("Reset link: %s\n", resetURL)
		actionHTML = fmt.Sprintf(`<p><a href="%s">Reset Password</a></p><p>If the link does not work, copy this URL:<br><span style="word-break:break-all">%s</span></p>`, html.EscapeString(resetURL), html.EscapeString(resetURL))
	} else {
		textBody += fmt.Sprintf("Reset token: %s\n", token)
	}
	textBody += fmt.Sprintf("This request expires in %d minutes.\nIf you did not request this, ignore this email.\n", minutes)
	htmlBody := fmt.Sprintf(`<p>We received a password reset request for %s.</p>%s<p>This request expires in %d minutes.</p><p>If you did not request this, ignore this email.</p>`, safeAppName, actionHTML, minutes)
	return buildMultipartMessage(from, to, subject, textBody, htmlBody)
}

func buildMultipartMessage(from, to, subject, textBody, htmlBody string) []byte {
	boundary := "authkit-mail-boundary"

	var buf bytes.Buffer
	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + to + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("Message-ID: " + newMessageID(from) + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: multipart/alternative; boundary=" + boundary + "\r\n\r\n")
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	buf.WriteString(textBody + "\r\n")
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
	buf.WriteString(htmlBody + "\r\n")
	buf.WriteString("--" + boundary + "--")
	return buf.Bytes()
}

// newMessageID makes a unique Message-ID on the sender's domain.
func newMessageID(from string) string {
	domain := "localhost"
	if addr := extractEmail(from); strings.Contains(addr, "@") {
		domain = addr[strings.LastIndex(addr, "@")+1:]
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return "<" + hex.EncodeToString(id) + "@" + domain + ">"
}

func extractEmail(from string) string {
	start := strings.IndexByte(from, '<')
	end := strings.IndexByte(from, '>')
	if start >= 0 && end > start {
		return from[start+1 : end]
	}
	return from
}
