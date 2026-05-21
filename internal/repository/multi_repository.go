package repository

import (
	"errors"

	"github.com/bagya-rmdn/go-audit-log/internal/domain"
)

type multiRepository struct {
	backends []Storage
}

func NewMultiRepository(backends ...Storage) Storage {
	return &multiRepository{backends: backends}
}

// Save calls every backend sequentially. All backends are called even if one
// returns an error. All non-nil errors are joined and returned together.
func (r *multiRepository) Save(entry *domain.AuditLog) error {
	var errs []error
	for _, b := range r.backends {
		if err := b.Save(entry); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
