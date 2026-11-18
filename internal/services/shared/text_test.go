package shared

import (
	"strings"
	"testing"
)

func TestNewIDIsUUIDv7(t *testing.T) {
	id, other := NewID(), NewID()
	if len(id) != 36 || id[14] != '7' {
		t.Fatalf("expected a UUID v7, got %q", id)
	}
	if id == other {
		t.Fatalf("expected distinct ids, got %q twice", id)
	}
}

func TestJSONAndStringHelpers(t *testing.T) {
	if got := JsonEncode(map[string]string{"name": "Jane"}); !strings.Contains(got, "Jane") {
		t.Fatalf("unexpected JSON encoding: %q", got)
	}
	if NormalizePayload(struct {
		Name string `json:"name"`
	}{Name: "Jane"}) == nil {
		t.Fatal("expected normalized payload")
	}
	if got := JsonEncode(make(chan int)); got != "" {
		t.Fatalf("expected empty string for unsupported JSON value, got %q", got)
	}
	ch := make(chan int)
	if NormalizePayload(ch) != ch {
		t.Fatal("expected unsupported payload to be returned unchanged")
	}
	if got, ok := NormalizePayload(nil).(map[string]any); !ok || len(got) != 0 {
		t.Fatalf("expected nil to become an empty map, got %#v", NormalizePayload(nil))
	}
}

func TestTitleCase(t *testing.T) {
	// Expected values are the output of golang.org/x/text/cases.Title for
	// English, which gokit.TitleCase wrapped.
	tests := [][2]string{
		{"jane doe", "Jane Doe"},
		{"JANE DOE", "Jane Doe"},
		{"o'neil", "O'neil"},
		{"mcDONALD", "Mcdonald"},
		{"jean-luc picard", "Jean-Luc Picard"},
		{"john   smith", "John   Smith"},
		{"3rd street", "3Rd Street"},
		{"ΟΔΟΣ ΣΟΦΟΣ", "Οδος Σοφος"},
		{"ßtraße", "Sstraße"},
		{"İSTANBUL", "İstanbul"},
		{"élodie ÉMILE", "Élodie Émile"},
		{"李 小龍 smith", "李 小龍 Smith"},
		{"a.b.c", "A.b.c"},
		{"o''neil", "O''Neil"},
		{"l’été", "L’été"},
		{"x_y z", "X_y Z"},
		{"hello\tworld\nfoo", "Hello\tWorld\nFoo"},
		{"", ""},
		{"  lead trail  ", "  Lead Trail  "},
		{"ŉ x", "ʼN X"},
		{"ǆungla", "ǅungla"},
		{"ΐ", "Ϊ́"},
		{"ab1cd 2ef", "Ab1cd 2Ef"},
		{"rock'n'roll", "Rock'n'roll"},
		{"ｆｕｌｌ ｗｉｄｔｈ", "Ｆｕｌｌ Ｗｉｄｔｈ"},
	}
	for _, tt := range tests {
		if got := TitleCase(tt[0]); got != tt[1] {
			t.Errorf("TitleCase(%q) = %q, want %q", tt[0], got, tt[1])
		}
	}
}

func TestNormalizeKeyHumanizeAndTitleHumanized(t *testing.T) {
	if got := NormalizeKey("  MiXed Key "); got != "mixed key" {
		t.Fatalf("unexpected key: %q", got)
	}
	if got := HumanizeKey("  reset_password-flow  now "); got != "reset password flow now" {
		t.Fatalf("unexpected humanized key: %q", got)
	}
	if got := HumanizeKey("   "); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
	if got := TitleHumanized("user_LOGIN-failed"); got != "User Login Failed" {
		t.Fatalf("unexpected title: %q", got)
	}
	if got := TitleHumanized(""); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestStripHTML(t *testing.T) {
	tests := map[string]string{
		"<b>Hello</b>   &amp; <i>world</i>":               "Hello & world",
		"a<script>alert(1)</script>b":                     "a b",
		"x<STYLE type=\"text/css\">p{color:red}</style>y": "x y",
		"<script\n>multi\nline</script> kept":             "kept",
		"plain text":                                      "plain text",
		"1 &lt; 2":                                        "1 < 2",
		"":                                                "",
	}
	for in, want := range tests {
		if got := StripHTML(in); got != want {
			t.Errorf("StripHTML(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInterfaceString(t *testing.T) {
	if got := InterfaceString(nil); got != "" {
		t.Fatalf("expected empty nil string, got %q", got)
	}
	if got := InterfaceString("text"); got != "text" {
		t.Fatalf("expected string as is, got %q", got)
	}
	if got := InterfaceString([]byte("bytes")); got != "bytes" {
		t.Fatalf("expected bytes string, got %q", got)
	}
	if got := InterfaceString(map[string]string{"a": "b"}); got != `{"a":"b"}` {
		t.Fatalf("expected JSON string, got %q", got)
	}
	if got := InterfaceString(12); got != "12" {
		t.Fatalf("expected JSON number, got %q", got)
	}
}

func TestNormalizeUUIDPointer(t *testing.T) {
	if got := NormalizeUUIDPointer(""); got != nil {
		t.Fatalf("expected nil for empty input, got %v", *got)
	}
	if got := NormalizeUUIDPointer("not-a-uuid"); got != nil {
		t.Fatalf("expected nil for invalid uuid, got %v", *got)
	}

	id := "550e8400-e29b-41d4-a716-446655440000"
	got := NormalizeUUIDPointer(" " + id + " ")
	if got == nil || *got != id {
		t.Fatalf("expected normalized uuid pointer, got %v", got)
	}
}

func TestRedactSensitivePayload(t *testing.T) {
	payload := struct {
		Email        string         `json:"email"`
		Password     string         `json:"password"`
		OTPCode      string         `json:"otp_code"`
		AccessToken  string         `json:"access_token"`
		RefreshToken string         `json:"refresh_token"`
		Metadata     map[string]any `json:"metadata"`
	}{
		Email:        "jane@example.com",
		Password:     "secret123",
		OTPCode:      "123456",
		AccessToken:  "access-secret",
		RefreshToken: "refresh-secret",
		Metadata: map[string]any{
			"client_secret": "nested-secret",
			"provider":      "google",
		},
	}

	got, ok := RedactSensitivePayload(payload).(map[string]any)
	if !ok {
		t.Fatalf("expected normalized map, got %T", got)
	}
	for _, key := range []string{"password", "otp_code", "access_token", "refresh_token"} {
		if got[key] != "[REDACTED]" {
			t.Fatalf("expected %s to be redacted, got %v", key, got[key])
		}
	}
	if got["email"] != "jane@example.com" {
		t.Fatalf("expected safe field to remain visible, got %v", got["email"])
	}

	metadata, ok := got["metadata"].(map[string]any)
	if !ok || metadata["client_secret"] != "[REDACTED]" || metadata["provider"] != "google" {
		t.Fatalf("unexpected nested redaction result: %v", got["metadata"])
	}
}

func TestRedactSensitiveValueWalksSlicesAndKeepsScalars(t *testing.T) {
	got, ok := RedactSensitiveValue([]any{
		map[string]any{"Password": "x", "name": "n"},
		"plain",
		[]any{map[string]any{"otp": "1"}},
	}).([]any)
	if !ok || len(got) != 3 {
		t.Fatalf("unexpected result: %#v", got)
	}
	if first := got[0].(map[string]any); first["Password"] != "[REDACTED]" || first["name"] != "n" {
		t.Fatalf("unexpected first element: %#v", first)
	}
	if got[1] != "plain" {
		t.Fatalf("expected scalar to pass through, got %#v", got[1])
	}
	if inner := got[2].([]any)[0].(map[string]any); inner["otp"] != "[REDACTED]" {
		t.Fatalf("expected nested otp redaction, got %#v", inner)
	}
	if !IsSensitiveKey(" Refresh_Token ") || IsSensitiveKey("email") {
		t.Fatal("unexpected sensitive key detection")
	}
}
