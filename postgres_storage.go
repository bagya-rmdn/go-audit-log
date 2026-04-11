package auditlog

import "gorm.io/gorm"

type postgresStorage struct {
	db *gorm.DB
}

func newPostgresStorage(db *gorm.DB) Storage {
	return &postgresStorage{db: db}
}

func (s *postgresStorage) Save(entry *AuditLog) error {
	return s.db.Create(entry).Error
}
