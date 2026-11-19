package role

import (
	"time"

	"gorm.io/gorm"
)

// TableName returns the database table name GORM uses for Role.
func (Role) TableName() string {
	return "roles"
}

// Role is the role domain type: role.
type Role struct {
	ID          string         `json:"id" gorm:"column:id;primaryKey"`
	Name        string         `json:"name" gorm:"column:name;unique"`
	DisplayName string         `json:"display_name" gorm:"column:display_name"`
	Description string         `json:"description,omitempty" gorm:"column:description"`
	IsSystem    bool           `json:"is_system" gorm:"column:is_system;default:false"`
	CreatedAt   time.Time      `json:"created_at" gorm:"column:created_at"`
	UpdatedAt   *time.Time     `json:"updated_at,omitempty" gorm:"column:updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// TableName returns the database table name GORM uses for RolePermission.
func (Permission) TableName() string {
	return "role_permissions"
}

// Permission is the role domain type: role permission.
type Permission struct {
	ID           string    `json:"id" gorm:"column:id;primaryKey"`
	RoleID       string    `json:"role_id" gorm:"column:role_id"`
	PermissionID string    `json:"permission_id" gorm:"column:permission_id"`
	CreatedAt    time.Time `json:"created_at" gorm:"column:created_at"`
}

// TableName returns the database table name GORM uses for RoleMenu.
func (Menu) TableName() string {
	return "role_menus"
}

// Menu is the role domain type: role menu.
type Menu struct {
	ID         string    `json:"id" gorm:"column:id;primaryKey"`
	RoleID     string    `json:"role_id" gorm:"column:role_id"`
	MenuItemID string    `json:"menu_item_id" gorm:"column:menu_item_id"`
	CreatedAt  time.Time `json:"created_at" gorm:"column:created_at"`
}
