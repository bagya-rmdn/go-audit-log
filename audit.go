package auditlog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Config holds all configuration for the Auditor.
// At least one of DB or LogFilePath must be set.
type Config struct {
	// DB is the GORM database connection. If nil, postgres storage is skipped.
	DB *gorm.DB

	// ServiceName is written to every audit_logs row to identify the source service.
	ServiceName string

	// LogFilePath is the path for the audit log file (JSON lines).
	// If empty, file storage is skipped.
	LogFilePath     string
	MaxSizeMB       int  // default 20
	MaxBackups      int  // default 10
	MaxAgeDays      int  // default 30
	CompressRotated bool // default true

	// BodySizeLimit caps the number of request body bytes captured.
	// 0 means no limit. Recommended: 4096.
	BodySizeLimit int64

	// Context key names matching what your JWT middleware sets via c.Set().
	// Defaults: "userID", "email", "roleID" — matching github.com/kokolopo/jwt-utility.
	UserIDKey string
	EmailKey  string
	RoleIDKey string
}

// Auditor captures and persists audit log entries via Gin middleware.
type Auditor struct {
	storage Storage
	cfg     Config
}

// Migrate creates or updates the audit_logs table schema.
// Call once at service startup before New().
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&AuditLog{})
}

// New validates cfg, wires up the configured storage backends, and returns
// a ready-to-use Auditor. Returns an error if neither DB nor LogFilePath is set.
func New(cfg Config) (*Auditor, error) {
	// apply defaults
	if cfg.UserIDKey == "" {
		cfg.UserIDKey = "userID"
	}
	if cfg.EmailKey == "" {
		cfg.EmailKey = "email"
	}
	if cfg.RoleIDKey == "" {
		cfg.RoleIDKey = "roleID"
	}
	if cfg.MaxSizeMB == 0 {
		cfg.MaxSizeMB = 20
	}
	if cfg.MaxBackups == 0 {
		cfg.MaxBackups = 10
	}
	if cfg.MaxAgeDays == 0 {
		cfg.MaxAgeDays = 30
	}

	var backends []Storage

	if cfg.DB != nil {
		backends = append(backends, newPostgresStorage(cfg.DB))
	}

	if cfg.LogFilePath != "" {
		fs, err := newFileStorage(cfg)
		if err != nil {
			return nil, fmt.Errorf("auditlog: file storage: %w", err)
		}
		backends = append(backends, fs)
	}

	if len(backends) == 0 {
		return nil, errors.New("auditlog: at least one of DB or LogFilePath must be configured")
	}

	return &Auditor{
		storage: newMultiStorage(backends...),
		cfg:     cfg,
	}, nil
}

// Middleware returns a gin.HandlerFunc that captures the incoming request and
// asynchronously persists an AuditLog entry after the downstream handlers finish.
//
// Must be registered AFTER AuthMiddleware so that userID/email/roleID are
// already present in the Gin context.
//
//	auth := r.Group("", middleware.AuthMiddleware())
//	auth.Use(auditor.Middleware())
func (a *Auditor) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read and restore the request body so downstream handlers can still read it.
		var bodyBytes []byte
		if c.Request.Body != nil {
			reader := io.Reader(c.Request.Body)
			if a.cfg.BodySizeLimit > 0 {
				reader = io.LimitReader(c.Request.Body, a.cfg.BodySizeLimit)
			}
			bodyBytes, _ = io.ReadAll(reader)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Let all downstream handlers (including the JWT middleware and route handler) run.
		c.Next()

		entry := &AuditLog{
			CreatedAt:   time.Now().UTC(),
			UserID:      stringFromCtx(c, a.cfg.UserIDKey),
			Email:       stringFromCtx(c, a.cfg.EmailKey),
			RoleID:      stringFromCtx(c, a.cfg.RoleIDKey),
			Method:      c.Request.Method,
			MenuPath:    c.GetHeader("X-Menu-Path"),
			APIPath:     c.Request.URL.Path,
			ClientIP:    c.ClientIP(),
			RequestBody: string(bodyBytes),
			ServiceName: a.cfg.ServiceName,
		}

		// Fire-and-forget: do not add latency to the HTTP response.
		go func() {
			_ = a.storage.Save(entry)
		}()
	}
}

// stringFromCtx extracts a string value from the Gin context by key.
// Returns "" if the key is absent or the value is not a string.
func stringFromCtx(c *gin.Context, key string) string {
	val, exists := c.Get(key)
	if !exists {
		return ""
	}
	s, _ := val.(string)
	return s
}
