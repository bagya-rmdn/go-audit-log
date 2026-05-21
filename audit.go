package auditlog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bagya-rmdn/go-audit-log/internal/domain"
	"github.com/bagya-rmdn/go-audit-log/internal/repository"
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

	// SensitivePaths is a list of path prefixes whose request body will NOT be
	// logged (body is stored as empty string). Use this for routes that handle
	// credentials or PII, e.g. login, change-password.
	// Example: []string{"/auth/login", "/auth/change-password", "/auth/reset-password"}
	SensitivePaths []string
}

// Auditor captures and persists audit log entries via Gin middleware.
type Auditor struct {
	storage repository.Storage
	cfg     Config
}

// Migrate creates or updates the audit_logs table schema.
// Call once at service startup before New().
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&domain.AuditLog{})
}

// New validates cfg, wires up the configured storage backends, and returns
// a ready-to-use Auditor. Returns an error if neither DB nor LogFilePath is set.
func New(cfg Config) (*Auditor, error) {
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

	var backends []repository.Storage

	if cfg.DB != nil {
		backends = append(backends, repository.NewPostgresRepository(cfg.DB))
	}

	if cfg.LogFilePath != "" {
		fs, err := repository.NewFileRepository(repository.FileConfig{
			LogFilePath:     cfg.LogFilePath,
			MaxSizeMB:       cfg.MaxSizeMB,
			MaxBackups:      cfg.MaxBackups,
			MaxAgeDays:      cfg.MaxAgeDays,
			CompressRotated: cfg.CompressRotated,
		})
		if err != nil {
			return nil, fmt.Errorf("auditlog: file storage: %w", err)
		}
		backends = append(backends, fs)
	}

	if len(backends) == 0 {
		return nil, errors.New("auditlog: at least one of DB or LogFilePath must be configured")
	}

	return &Auditor{
		storage: repository.NewMultiRepository(backends...),
		cfg:     cfg,
	}, nil
}

// Middleware returns a gin.HandlerFunc that captures the incoming request and
// asynchronously persists an AuditLog entry after the downstream handlers finish.
//
// Safe to use on both public and JWT-protected routes. On public routes
// (no JWT), UserID/Email/RoleID will be stored as empty string.
// Routes listed in Config.SensitivePaths will have their body omitted.
//
//	// On protected routes — user context is captured from JWT claims
//	auth := r.Group("", middleware.AuthMiddleware())
//	auth.Use(auditor.Middleware())
//
//	// On public routes — user context will be empty, body still captured
//	// unless the path is in SensitivePaths
//	public := r.Group("/auth")
//	public.Use(auditor.Middleware())
func (a *Auditor) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sensitive := a.isSensitivePath(c.Request.URL.Path)

		var bodyBytes []byte
		if !sensitive && c.Request.Body != nil {
			reader := io.Reader(c.Request.Body)
			if a.cfg.BodySizeLimit > 0 {
				reader = io.LimitReader(c.Request.Body, a.cfg.BodySizeLimit)
			}
			bodyBytes, _ = io.ReadAll(reader)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		c.Next()

		entry := &domain.AuditLog{
			CreatedAt:   time.Now().UTC(),
			UserID:      stringFromCtx(c, a.cfg.UserIDKey),
			Email:       stringFromCtx(c, a.cfg.EmailKey),
			RoleID:      stringFromCtx(c, a.cfg.RoleIDKey),
			Method:      c.Request.Method,
			MenuPath:    c.GetHeader("Referer"),
			APIPath:     c.Request.URL.Path,
			ClientIP:    c.ClientIP(),
			RequestBody: string(bodyBytes),
			ServiceName: a.cfg.ServiceName,
		}

		go func() {
			_ = a.storage.Save(entry)
		}()
	}
}

func (a *Auditor) isSensitivePath(path string) bool {
	for _, prefix := range a.cfg.SensitivePaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// stringFromCtx extracts a value from the Gin context by key and converts it to string.
// Uses fmt.Sprintf as fallback to handle non-string types (e.g. int32 RoleID from JWT claims).
func stringFromCtx(c *gin.Context, key string) string {
	val, exists := c.Get(key)
	if !exists {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", val)
}
