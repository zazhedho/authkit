// Package googleid verifies Google ID tokens offline against Google's cached
// signing keys.
package googleid

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Identity is what a verified ID token says about the Google account.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Audience      string
}

// Verification failures. A failed key fetch is returned as its own error.
var (
	ErrNotConfigured = errors.New("googleid: no client ids configured")
	ErrInvalidToken  = errors.New("googleid: invalid token")
	ErrNoEmail       = errors.New("googleid: token has no usable email")
)

// googleCertsURL serves Google's current signing keys as a JWKS.
var googleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

const (
	defaultCertsTTL = time.Hour
	// minCertsRefetch bounds how often an unknown kid may trigger a fetch, so
	// forged tokens cannot make every login hit Google.
	minCertsRefetch = time.Minute
)

var googleIssuers = map[string]struct{}{"accounts.google.com": {}, "https://accounts.google.com": {}}

type googleKeySet struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
	fetchedAt time.Time
	failedAt  time.Time
	flight    *flight
	client    *http.Client
}

// flight is one fetch in progress; callers that arrive meanwhile wait for it.
type flight struct {
	done chan struct{}
	err  error
}

var googleKeys = &googleKeySet{client: &http.Client{Timeout: 10 * time.Second}}

// ErrKeysUnavailable means Google's signing keys could not be fetched; it is a
// server-side problem, not a bad token.
var ErrKeysUnavailable = errors.New("googleid: signing keys unavailable")

// fetchBackoff is how long after a failed fetch logins fail fast instead of
// trying Google again.
const fetchBackoff = 30 * time.Second

// fetchTimeout bounds one JWKS request.
const fetchTimeout = 10 * time.Second

// key fetches the JWKS when the cache is empty, expired or lacks the kid, at
// most once per minCertsRefetch and not again for fetchBackoff after a failure.
// The mutex is not held during the request; callers share one fetch.
func (g *googleKeySet) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	g.mu.Lock()
	now := time.Now()
	if key, ok := g.keys[kid]; ok && now.Before(g.expiresAt) {
		g.mu.Unlock()
		return key, nil
	}
	stale := g.keys == nil || now.After(g.expiresAt) || now.Sub(g.fetchedAt) >= minCertsRefetch
	backingOff := !g.failedAt.IsZero() && now.Sub(g.failedAt) < fetchBackoff
	if g.flight == nil && (!stale || backingOff) {
		key, ok := g.keys[kid]
		g.mu.Unlock()
		switch {
		case ok:
			return key, nil // keep serving a known key through a Google outage
		case backingOff:
			return nil, ErrKeysUnavailable
		}
		return nil, ErrInvalidToken
	}

	f := g.flight
	leader := f == nil
	if leader {
		f = &flight{done: make(chan struct{})}
		g.flight = f
	}
	g.mu.Unlock()

	if leader {
		// Detached: the caller leaving must not fail the fetch for the waiters.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		err := g.fetch(fetchCtx)
		cancel()
		g.mu.Lock()
		if err != nil {
			g.failedAt = time.Now()
		} else {
			g.failedAt = time.Time{}
		}
		g.flight, f.err = nil, err
		g.mu.Unlock()
		close(f.done)
	} else {
		select {
		case <-f.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	g.mu.Lock()
	key, ok := g.keys[kid]
	g.mu.Unlock()
	switch {
	case ok:
		return key, nil
	case f.err != nil:
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, f.err)
	}
	return nil, ErrInvalidToken
}

func (g *googleKeySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleCertsURL, nil)
	if err != nil {
		return err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("google certs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("google certs: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("google certs: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return fmt.Errorf("google certs: no usable keys")
	}
	now := time.Now()
	g.mu.Lock()
	g.keys, g.fetchedAt, g.expiresAt = keys, now, now.Add(maxAge(resp.Header.Get("Cache-Control")))
	g.mu.Unlock()
	return nil
}

func maxAge(cacheControl string) time.Duration {
	for _, part := range strings.Split(cacheControl, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
	}
	return defaultCertsTTL
}

// Verify checks an ID token: RS256 signature, issuer, audience, expiry and a
// verified email.
func Verify(ctx context.Context, idToken string, clientIDs []string) (Identity, error) {
	if strings.TrimSpace(idToken) == "" {
		return Identity{}, ErrInvalidToken
	}
	allowed := allowedAudiences(clientIDs)
	if len(allowed) == 0 {
		return Identity{}, ErrNotConfigured
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return googleKeys.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			return Identity{}, err
		}
		return Identity{}, ErrInvalidToken
	}

	iss, _ := claims["iss"].(string)
	if _, ok := googleIssuers[iss]; !ok {
		return Identity{}, ErrInvalidToken
	}
	aud, err := claims.GetAudience()
	if err != nil {
		return Identity{}, ErrInvalidToken
	}
	audOK := false
	for _, a := range aud {
		if _, ok := allowed[strings.TrimSpace(a)]; ok {
			audOK = true
		}
	}
	if !audOK {
		return Identity{}, ErrInvalidToken
	}

	info := Identity{
		Audience: aud[0],
		Email:    claimString(claims, "email"),
		Name:     claimString(claims, "name"),
		Picture:  claimString(claims, "picture"),
		Subject:  claimString(claims, "sub"),
	}
	switch v := claims["email_verified"].(type) {
	case bool:
		info.EmailVerified = v
	case string:
		info.EmailVerified = strings.EqualFold(v, "true")
	}
	if !info.EmailVerified || info.Subject == "" {
		return Identity{}, ErrInvalidToken
	}
	if addr, err := mail.ParseAddress(info.Email); err != nil || addr.Address != info.Email {
		return Identity{}, ErrNoEmail
	}
	return info, nil
}

func claimString(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return strings.TrimSpace(v)
}

func allowedAudiences(clientIDs []string) map[string]struct{} {
	values := make(map[string]struct{}, len(clientIDs))
	for _, item := range clientIDs {
		if normalized := strings.TrimSpace(item); normalized != "" {
			values[normalized] = struct{}{}
		}
	}
	return values
}
