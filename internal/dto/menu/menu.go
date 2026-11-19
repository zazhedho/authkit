package menu

// Update is the menu request body for menu update.
type Update struct {
	DisplayName string  `json:"display_name" binding:"omitempty,min=2,max=100"`
	Path        string  `json:"path" binding:"omitempty,max=255"`
	Icon        string  `json:"icon" binding:"omitempty,max=50"`
	ParentID    *string `json:"parent_id" binding:"omitempty"`
	OrderIndex  *int    `json:"order_index" binding:"omitempty"`
	IsActive    *bool   `json:"is_active" binding:"omitempty"`
}
