package auditlog

// Storage is the write-only persistence contract for audit entries.
// Implementations must be safe for concurrent use.
type Storage interface {
	Save(entry *AuditLog) error
}
