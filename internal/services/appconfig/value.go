package appconfig

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

func parseString(raw, fallback string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	return value
}

func parseBool(raw string, fallback bool) (bool, error) {
	value := serviceshared.NormalizeKey(raw)
	if value == "" {
		return fallback, nil
	}

	switch value {
	case "1", "true", "yes", "y", "on", "enabled":
		return true, nil
	case "0", "false", "no", "n", "off", "disabled":
		return false, nil
	default:
		return fallback, fmt.Errorf("%w: boolean expected, got %q", domainappconfig.ErrInvalidValue, raw)
	}
}

func parseInt(raw string, fallback int) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback, fmt.Errorf("%w: integer expected, got %q", domainappconfig.ErrInvalidValue, raw)
	}
	return parsed, nil
}

func parseDuration(raw string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback, fmt.Errorf("%w: duration expected, got %q", domainappconfig.ErrInvalidValue, raw)
	}
	return parsed, nil
}

func parseJSON(raw string, target any) error {
	value := strings.TrimSpace(raw)
	if value == "" || target == nil {
		return nil
	}
	return json.Unmarshal([]byte(value), target)
}
