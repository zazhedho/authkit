package role

type Create struct {
	Name        string `json:"name" binding:"required,min=3,max=50"`
	DisplayName string `json:"display_name" binding:"required,min=3,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
}

type Update struct {
	DisplayName string `json:"display_name" binding:"omitempty,min=3,max=100"`
	// Description is left unchanged when omitted; an empty string clears it.
	Description *string `json:"description" binding:"omitempty,max=500"`
}

type AssignPermissions struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

type WithDetails struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description"`
	IsSystem      bool     `json:"is_system"`
	PermissionIDs []string `json:"permission_ids"`
	MenuIDs       []string `json:"menu_ids"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
}
