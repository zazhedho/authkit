package auth

import "time"

// TableName returns the database table name GORM uses for Blacklist.
func (Blacklist) TableName() string {
	return "blacklist"
}

// Blacklist is the auth domain type: blacklist.
type Blacklist struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Token     string    `gorm:"not null; unique" json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
}
