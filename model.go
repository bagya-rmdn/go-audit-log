package auditlog

import "time"

// AuditLog represents a single user action captured by the audit middleware.
// Append-only — rows are never updated or soft-deleted.
type AuditLog struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"                          json:"id"`
	CreatedAt   time.Time `gorm:"column:created_at;type:timestamp(6);not null;default:now()"  json:"created_at"`
	UserID      string    `gorm:"column:user_id;type:varchar(255);not null;default:''"        json:"user_id"`
	Email       string    `gorm:"column:email;type:varchar(255);not null;default:''"          json:"email"`
	RoleID      string    `gorm:"column:role_id;type:varchar(255);not null;default:''"        json:"role_id"`
	Method      string    `gorm:"column:method;type:varchar(10);not null"                     json:"method"`
	MenuPath    string    `gorm:"column:menu_path;type:text;not null;default:''"              json:"menu_path"`
	APIPath     string    `gorm:"column:api_path;type:text;not null"                          json:"api_path"`
	ClientIP    string    `gorm:"column:client_ip;type:varchar(45);not null"                  json:"client_ip"`
	RequestBody string    `gorm:"column:request_body;type:text"                               json:"request_body"`
	ServiceName string    `gorm:"column:service_name;type:varchar(100);not null;default:''"   json:"service_name"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
