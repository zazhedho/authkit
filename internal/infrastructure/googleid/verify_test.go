package googleid

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type googleFixture struct {
	key   *rsa.PrivateKey
	kid   string
	hits  atomic.Int32
	certs *httptest.Server
}

func newGoogleFixture(t *testing.T) *googleFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &googleFixture{key: key, kid: "kid-1"}
	f.certs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": f.kid, "kty": "RSA", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(f.certs.Close)

	origURL, origKeys := googleCertsURL, googleKeys
	googleCertsURL = f.certs.URL
	googleKeys = &googleKeySet{client: f.certs.Client()}
	t.Cleanup(func() { googleCertsURL, googleKeys = origURL, origKeys })
	return f
}

func (f *googleFixture) token(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": "client-1", "sub": "sub-1",
		"email": "jane@example.com", "email_verified": true, "name": "Jane",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	signed, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestGoogleIDTokenIsVerifiedOfflineAndKeysAreCached(t *testing.T) {
	f := newGoogleFixture(t)
	for i := 0; i < 3; i++ {
		info, err := Verify(context.Background(), f.token(t, nil), []string{"client-1"})
		if err != nil || info.Subject != "sub-1" || info.Email != "jane@example.com" {
			t.Fatalf("info=%+v err=%v", info, err)
		}
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times, want 1 (cached)", n)
	}
}

func TestGoogleIDTokenRejections(t *testing.T) {
	f := newGoogleFixture(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]struct {
		mutate func(jwt.MapClaims)
		want   error
	}{
		"wrong audience":        {func(c jwt.MapClaims) { c["aud"] = "someone-else" }, ErrInvalidToken},
		"wrong issuer":          {func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }, ErrInvalidToken},
		"expired":               {func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, ErrInvalidToken},
		"no expiry":             {func(c jwt.MapClaims) { delete(c, "exp") }, ErrInvalidToken},
		"email not verified":    {func(c jwt.MapClaims) { c["email_verified"] = false }, ErrInvalidToken},
		"missing subject":       {func(c jwt.MapClaims) { delete(c, "sub") }, ErrInvalidToken},
		"missing email":         {func(c jwt.MapClaims) { c["email"] = "" }, ErrNoEmail},
		"string email_verified": {func(c jwt.MapClaims) { c["email_verified"] = "true" }, nil},
	}
	for name, c := range cases {
		_, err := Verify(context.Background(), f.token(t, c.mutate), []string{"client-1"})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}

	// A token signed by another key, and an HS256 token, are rejected.
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "accounts.google.com", "aud": "client-1", "sub": "x", "email": "a@example.com", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix()})
	forged.Header["kid"] = f.kid
	signed, _ := forged.SignedString(other)
	if _, err := Verify(context.Background(), signed, []string{"client-1"}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("forged signature: %v", err)
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "accounts.google.com", "aud": "client-1", "exp": time.Now().Add(time.Hour).Unix()})
	hs.Header["kid"] = f.kid
	hsSigned, _ := hs.SignedString([]byte("secret"))
	if _, err := Verify(context.Background(), hsSigned, []string{"client-1"}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("HS256 token: %v", err)
	}
	if _, err := Verify(context.Background(), "x", nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no client ids: %v", err)
	}
}

func TestGoogleUnknownKidRefetchIsRateLimited(t *testing.T) {
	f := newGoogleFixture(t)
	if _, err := Verify(context.Background(), f.token(t, nil), []string{"client-1"}); err != nil {
		t.Fatal(err)
	}
	f.kid = "rotated"
	for i := 0; i < 5; i++ {
		_, _ = Verify(context.Background(), f.token(t, nil), []string{"client-1"})
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("unknown kid caused %d fetches, want the initial one only", n)
	}
}

func TestVerifyLocalValidationBranches(t *testing.T) {
	if _, err := Verify(context.Background(), " ", []string{"client-a"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token for empty input, got %v", err)
	}
	if _, err := Verify(context.Background(), "token", nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected not configured without audiences, got %v", err)
	}
	if _, err := Verify(context.Background(), "token", []string{" ", ""}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected not configured with only blank audiences, got %v", err)
	}
	audiences := allowedAudiences([]string{"client-a", " client-b ", "", "client-c"})
	if len(audiences) != 3 {
		t.Fatalf("expected 3 audiences, got %#v", audiences)
	}
}

// A slow certs endpoint must not serialize logins on the key set's mutex, and
// concurrent logins share one fetch.
func TestConcurrentVerifiesShareOneFetchAndDoNotHoldTheMutex(t *testing.T) {
	f := newGoogleFixture(t)
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		f.certs.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(slow.Close)
	googleCertsURL = slow.URL
	googleKeys = &googleKeySet{client: slow.Client()}

	token := f.token(t, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Verify(context.Background(), token, []string{"client-1"})
			errs <- err
		}()
	}
	time.Sleep(100 * time.Millisecond) // every caller is now waiting on the one fetch
	if !googleKeys.mu.TryLock() {
		t.Fatal("the mutex is held during the HTTP request")
	}
	googleKeys.mu.Unlock()
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
}

// After a failed fetch, logins fail fast for a while instead of each waiting on
// a dead endpoint.
func TestFailedFetchBacksOff(t *testing.T) {
	var hits atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(down.Close)
	f := newGoogleFixture(t)
	googleCertsURL = down.URL
	googleKeys = &googleKeySet{client: down.Client()}

	token := f.token(t, nil)
	for range 5 {
		_, err := Verify(context.Background(), token, []string{"client-1"})
		if !errors.Is(err, ErrKeysUnavailable) {
			t.Fatalf("err = %v, want ErrKeysUnavailable", err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d fetches during the backoff, want 1", n)
	}
}
