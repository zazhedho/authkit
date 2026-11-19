package appconfig

// UpdateAppConfig is the appconfig request body for update app config.
type UpdateAppConfig struct {
	Value    string `json:"value" binding:"required"`
	IsActive *bool  `json:"is_active" binding:"omitempty"`
}
