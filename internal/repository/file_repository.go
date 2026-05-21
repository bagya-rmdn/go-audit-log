package repository

import (
	"encoding/json"
	"fmt"

	"github.com/bagya-rmdn/go-audit-log/internal/domain"
	"gopkg.in/natefinch/lumberjack.v2"
)

type fileRepository struct {
	logger *lumberjack.Logger
}

// FileConfig holds file rotation settings for the file storage backend.
type FileConfig struct {
	LogFilePath     string
	MaxSizeMB       int
	MaxBackups      int
	MaxAgeDays      int
	CompressRotated bool
}

func NewFileRepository(cfg FileConfig) (Storage, error) {
	if cfg.LogFilePath == "" {
		return nil, fmt.Errorf("auditlog: LogFilePath must not be empty")
	}

	maxSize := cfg.MaxSizeMB
	if maxSize == 0 {
		maxSize = 20
	}
	maxBackups := cfg.MaxBackups
	if maxBackups == 0 {
		maxBackups = 10
	}
	maxAge := cfg.MaxAgeDays
	if maxAge == 0 {
		maxAge = 30
	}

	return &fileRepository{
		logger: &lumberjack.Logger{
			Filename:   cfg.LogFilePath,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     maxAge,
			Compress:   cfg.CompressRotated,
		},
	}, nil
}

func (r *fileRepository) Save(entry *domain.AuditLog) error {
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("auditlog: marshal: %w", err)
	}
	b = append(b, '\n')
	_, err = r.logger.Write(b)
	return err
}
