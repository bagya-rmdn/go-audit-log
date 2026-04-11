package auditlog

import "errors"

type multiStorage struct {
	backends []Storage
}

func newMultiStorage(backends ...Storage) Storage {
	return &multiStorage{backends: backends}
}

// Save calls every backend sequentially. All backends are called even if one
// returns an error. All non-nil errors are joined and returned together.
func (s *multiStorage) Save(entry *AuditLog) error {
	var errs []error
	for _, b := range s.backends {
		if err := b.Save(entry); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
