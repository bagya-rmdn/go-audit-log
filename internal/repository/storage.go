package repository

import "github.com/bagya-rmdn/go-audit-log/internal/domain"

// Storage is the write-only persistence contract for audit entries.
// Implementations must be safe for concurrent use.
type Storage interface {
	Save(entry *domain.AuditLog) error
}
