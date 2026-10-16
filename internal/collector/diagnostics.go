package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
)

// Diagnostics holds collection warnings and errors.
type Diagnostics struct {
	PermissionErrors []string `json:"permission_errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

type diagnosticsTracker struct {
	permissionErrors []string
	warnings         []string
}

func (d *diagnosticsTracker) surfacePermissionDenied(surface, reason string) {
	d.permissionErrors = append(d.permissionErrors,
		"surface "+surface+" skipped: "+reason)
}

func (d *diagnosticsTracker) surfaceWarning(surface, reason string) {
	d.warnings = append(d.warnings,
		"surface "+surface+": "+reason)
}

func (d *diagnosticsTracker) toDiagnostics() *Diagnostics {
	if len(d.permissionErrors) == 0 && len(d.warnings) == 0 {
		return nil
	}
	return &Diagnostics{
		PermissionErrors: d.permissionErrors,
		Warnings:         d.warnings,
	}
}

func safeDiagError(err error) string {
	var apiErr *jumpcloud.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("HTTP %d", apiErr.StatusCode)
	}
	return "unexpected error"
}

func isDenied(err error) bool {
	return errors.Is(err, jumpcloud.ErrPermissionDenied) ||
		errors.Is(err, jumpcloud.ErrUnauthorized)
}

func isOrgValidationError(err error) bool {
	var ve *jumpcloud.OrgValidationError
	return errors.As(err, &ve)
}
