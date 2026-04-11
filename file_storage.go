package auditlog

import (
	"encoding/json"
	"fmt"

	"gopkg.in/natefinch/lumberjack.v2"
)

type fileStorage struct {
	logger *lumberjack.Logger
}

func newFileStorage(cfg Config) (Storage, error) {
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

	return &fileStorage{
		logger: &lumberjack.Logger{
			Filename:   cfg.LogFilePath,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     maxAge,
			Compress:   cfg.CompressRotated,
		},
	}, nil
}

// Save marshals entry as a compact JSON line and writes it to the log file.
// lumberjack.Logger is goroutine-safe via its internal mutex.
func (s *fileStorage) Save(entry *AuditLog) error {
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("auditlog: marshal: %w", err)
	}
	b = append(b, '\n')
	_, err = s.logger.Write(b)
	return err
}
