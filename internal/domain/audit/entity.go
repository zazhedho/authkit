package audit

import "time"

// TableName returns the database table name GORM uses for AuditTrail.
func (Trail) TableName() string {
	return "audit_trails"
}

// Trail is the audit domain type: audit trail.
type Trail struct {
	ID           string    `json:"id" gorm:"column:id;primaryKey"`
	OccurredAt   time.Time `json:"occurred_at" gorm:"column:occurred_at"`
	ActorUserID  *string   `json:"actor_user_id,omitempty" gorm:"column:actor_user_id"`
	ActorRole    string    `json:"actor_role,omitempty" gorm:"column:actor_role"`
	Action       string    `json:"action" gorm:"column:action"`
	Resource     string    `json:"resource" gorm:"column:resource"`
	ResourceID   string    `json:"resource_id,omitempty" gorm:"column:resource_id"`
	Status       string    `json:"status" gorm:"column:status"`
	Message      string    `json:"message,omitempty" gorm:"column:message"`
	ErrorMessage string    `json:"error_message,omitempty" gorm:"column:error_message"`
	RequestID    string    `json:"request_id,omitempty" gorm:"column:request_id"`
	IPAddress    string    `json:"ip_address,omitempty" gorm:"column:ip_address"`
	UserAgent    string    `json:"user_agent,omitempty" gorm:"column:user_agent"`
	BeforeData   string    `json:"before_data,omitempty" gorm:"column:before_data"`
	AfterData    string    `json:"after_data,omitempty" gorm:"column:after_data"`
	Metadata     string    `json:"metadata,omitempty" gorm:"column:metadata"`
	CreatedAt    time.Time `json:"created_at" gorm:"column:created_at"`
}

// AuditEvent is the audit domain type: audit event.
type AuditEvent struct { //nolint:revive // public API type (authkit.AuditEvent); renaming it is a breaking change
	OccurredAt   time.Time
	ActorUserID  string
	ActorRole    string
	Action       string
	Resource     string
	ResourceID   string
	Status       string
	Message      string
	ErrorMessage string
	RequestID    string
	IPAddress    string
	UserAgent    string
	BeforeData   any
	AfterData    any
	Metadata     map[string]any
}

const (
	// ActionCreate is the action create constant.
	ActionCreate = "create"
	// ActionUpdate is the action update constant.
	ActionUpdate = "update"
	// ActionDelete is the action delete constant.
	ActionDelete = "delete"
	// ActionAssign is the action assign constant.
	ActionAssign = "assign"
	// ActionLogin is the action login constant.
	ActionLogin = "login"
	// ActionLogout is the action logout constant.
	ActionLogout = "logout"
	// ActionRefresh is the action refresh constant.
	ActionRefresh = "refresh"
)

const (
	// StatusSuccess is the status success constant.
	StatusSuccess = "success"
	// StatusFailed is the status failed constant.
	StatusFailed = "failed"
)
