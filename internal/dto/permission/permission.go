package permission

// Create is the permission request body for permission create.
type Create struct {
	Name        string `json:"name" binding:"required,min=3,max=100"`
	DisplayName string `json:"display_name" binding:"required,min=3,max=150"`
	Description string `json:"description" binding:"omitempty,max=500"`
	Resource    string `json:"resource" binding:"required,min=2,max=50"`
	Action      string `json:"action" binding:"required,min=2,max=50"`
}

// Update is the permission request body for permission update.
type Update struct {
	DisplayName string `json:"display_name" binding:"omitempty,min=3,max=150"`
	Description string `json:"description" binding:"omitempty,max=500"`
	Resource    string `json:"resource" binding:"omitempty,min=2,max=50"`
	Action      string `json:"action" binding:"omitempty,min=2,max=50"`
}
