package repository

import (
	"github.com/bagya-rmdn/go-audit-log/internal/domain"
	"gorm.io/gorm"
)

type postgresRepository struct {
	db *gorm.DB
}

func NewPostgresRepository(db *gorm.DB) Storage {
	// SkipDefaultTransaction removes the implicit BEGIN/COMMIT wrapping each insert.
	return &postgresRepository{
		db: db.Session(&gorm.Session{SkipDefaultTransaction: true}),
	}
}

// Save uses raw Exec instead of Create to avoid the RETURNING clause that
// GORM adds by default on PostgreSQL, which forces a round-trip to retrieve
// the generated ID. Audit log inserts are fire-and-forget; we don't need it.
func (r *postgresRepository) Save(entry *domain.AuditLog) error {
	return r.db.Exec(
		`INSERT INTO audit_logs
			(user_id, email, role_id, method, menu_path, api_path, client_ip, request_body, service_name, created_at)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.UserID, entry.Email, entry.RoleID,
		entry.Method, entry.MenuPath, entry.APIPath,
		entry.ClientIP, entry.RequestBody, entry.ServiceName,
		entry.CreatedAt,
	).Error
}
