package main

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/collector"
	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "jumpcloud",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects JumpCloud identity, access, and device posture metrics",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()

	orgID, err := getOptionalString(cfg, "org_id")
	if err != nil {
		return componentsdk.NewConfigError("org_id: %s", err)
	}

	maxAgeHours, err := getOptionalWholeNumber(cfg, "max_observation_age_hours", 1, 8760)
	if err != nil {
		return componentsdk.NewConfigError("max_observation_age_hours: %s", err)
	}

	config := collector.Config{
		OrgID:             orgID,
		MaxObservationAge: time.Duration(maxAgeHours) * time.Hour,
		OnStatus:          ctx.Status,
	}

	apiKey := ctx.Secret("JUMPCLOUD_API_KEY")
	if apiKey == "" {
		return componentsdk.NewConfigError("JUMPCLOUD_API_KEY is required")
	}

	client := jumpcloud.NewClient(apiKey, config.OrgID)
	c := collector.New(config, client)

	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return classifyError(err)
	}

	artifacts := []componentsdk.CollectedArtifact{
		{
			Data: posture,
			Path: "artifacts/jumpcloud.json",
		},
	}

	if idpPosture := posture.ToIDPPosture(); idpPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data:   idpPosture,
			Schema: "evidencepack/idp-posture@v1",
			Path:   "artifacts/jumpcloud.idp-posture.json",
		})
	}

	if endpointPosture := posture.ToEndpointPosture(); endpointPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data:   endpointPosture,
			Schema: "evidencepack/endpoint-posture@v1",
			Path:   "artifacts/jumpcloud.endpoint-posture.json",
		})
	}

	return ctx.Emit(artifacts)
}

// classifyError maps collection errors to SDK error types using sanitized
// messages. Response bodies are not included to avoid leaking untrusted
// API content to logs.
func classifyError(err error) error {
	if errors.Is(err, jumpcloud.ErrUnauthorized) {
		return componentsdk.NewAuthError("JumpCloud API key is unauthorized")
	}
	if errors.Is(err, jumpcloud.ErrPermissionDenied) {
		return componentsdk.NewAuthError("JumpCloud API key lacks required permissions")
	}

	var orgErr *jumpcloud.OrgValidationError
	if errors.As(err, &orgErr) {
		return componentsdk.NewConfigError("organization: %s", orgErr.Error())
	}

	var apiErr *jumpcloud.APIError
	if errors.As(err, &apiErr) {
		return componentsdk.NewNetworkError("JumpCloud API returned HTTP %d", apiErr.StatusCode)
	}

	return componentsdk.NewNetworkError("collection failed: %v", sanitizeErrorMessage(err))
}

// sanitizeErrorMessage returns a safe error description that does not include
// response bodies or credential-bearing URLs.
func sanitizeErrorMessage(err error) string {
	var apiErr *jumpcloud.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("HTTP %d", apiErr.StatusCode)
	}
	return err.Error()
}

// getOptionalString extracts a string config value, returning an error if
// the key exists but is not a string (e.g. a numeric org_id would silently
// drop tenant selection).
func getOptionalString(cfg map[string]any, key string) (string, error) {
	if cfg == nil {
		return "", nil
	}
	raw, exists := cfg[key]
	if !exists || raw == nil {
		return "", nil
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("must be a string, got %T", raw)
	}
	return v, nil
}

// getOptionalWholeNumber extracts a whole number within [min, max]. Zero
// means the key was absent. Config arrives as JSON, so numbers are float64.
func getOptionalWholeNumber(cfg map[string]any, key string, min, max int) (int, error) {
	raw, exists := cfg[key]
	if !exists || raw == nil {
		return 0, nil
	}
	var v float64
	switch n := raw.(type) {
	case float64:
		v = n
	case int:
		v = float64(n)
	default:
		return 0, fmt.Errorf("must be a number, got %T", raw)
	}
	if v != math.Trunc(v) || v < float64(min) || v > float64(max) {
		return 0, fmt.Errorf("must be a whole number from %d to %d", min, max)
	}
	return int(v), nil
}
