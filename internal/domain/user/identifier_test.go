package user

import "testing"

type login struct{ Identifier, Email string }

func TestResolveLoginIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		req     login
		want    string
		wantErr string
	}{
		{
			name: "email identifier",
			req:  login{Identifier: " Jane.Doe@Example.COM "},
			want: "jane.doe@example.com",
		},
		{
			name: "email fallback",
			req:  login{Email: " Jane.Doe@Example.COM "},
			want: "jane.doe@example.com",
		},
		{
			name: "phone identifier",
			req:  login{Identifier: "0812-3456-7890"},
			want: "6281234567890",
		},
		{
			name:    "empty identifier",
			req:     login{},
			wantErr: "identifier or email is required",
		},
		{
			name:    "invalid identifier",
			req:     login{Identifier: "randomtext"},
			wantErr: "identifier must be a valid email or phone number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveLoginIdentifier(tt.req.Identifier, tt.req.Email)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("expected error %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected identifier %q, got %q", tt.want, got)
			}
		})
	}
}

func TestNormalizePhoneAndEmail(t *testing.T) {
	if got := NormalizePhoneTo62("+62 812-3456-789"); got != "628123456789" {
		t.Fatalf("unexpected phone normalization: %q", got)
	}
	if got := NormalizePhoneTo62("0812 3456 789"); got != "628123456789" {
		t.Fatalf("unexpected phone normalization: %q", got)
	}
	if got := NormalizePhoneTo62("+0812"); got != "+0812" {
		t.Fatalf("unexpected phone normalization: %q", got)
	}
	if got := SanitizeEmail(" Jane.Doe@Example.COM "); got != "jane.doe@example.com" {
		t.Fatalf("unexpected email sanitization: %q", got)
	}
	for _, bad := range []string{"", "  ", "not-an-email", "Jane <jane@example.com>"} {
		if got := SanitizeEmail(bad); got != "" {
			t.Fatalf("SanitizeEmail(%q) = %q, want empty", bad, got)
		}
	}
}
