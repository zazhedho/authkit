package auth

import (
	"testing"
	"time"
)

func TestRevokedByUsesMillisecondsAndIncludesTheCutoffInstant(t *testing.T) {
	cutoff := time.UnixMilli(1_700_000_000_500)
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"issued earlier in the same second", map[string]any{"iat": float64(1_700_000_000), "iat_ms": float64(1_700_000_000_100)}, true},
		{"issued at the cut-off instant", map[string]any{"iat_ms": float64(1_700_000_000_500)}, true},
		{"issued after in the same second", map[string]any{"iat": float64(1_700_000_000), "iat_ms": float64(1_700_000_000_501)}, false},
		{"seconds only, same second", map[string]any{"iat": float64(1_700_000_000)}, true},
		{"seconds only, later second", map[string]any{"iat": float64(1_700_000_001)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RevokedBy(tt.claims, cutoff); got != tt.want {
				t.Fatalf("RevokedBy = %v, want %v", got, tt.want)
			}
		})
	}
}
