package session

import "time"

// Session is the session domain type: session.
type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	DeviceInfo   string    `json:"device_info,omitempty"`
	IP           string    `json:"ip,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	LoginAt      time.Time `json:"login_at"`
	LastActivity time.Time `json:"last_activity"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Info is the session domain type: session info.
type Info struct {
	SessionID        string    `json:"session_id"`
	DeviceInfo       string    `json:"device_info"`
	IP               string    `json:"ip"`
	LoginAt          time.Time `json:"login_at"`
	LastActivity     time.Time `json:"last_activity"`
	IsCurrentSession bool      `json:"is_current_session"`
}

// RequestMeta is the session domain type: request meta.
type RequestMeta struct {
	IP         string `json:"ip,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	DeviceInfo string `json:"device_info,omitempty"`
}
