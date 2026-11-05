package collector

import (
	"fmt"
	"math"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/docs/schema"
	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

// apiKeyEnv is the variable the API key arrives in, which epack.yaml lists
// under secrets.
const apiKeyEnv = "JUMPCLOUD_API_KEY"

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Collects JumpCloud identity, access, and device posture metrics",
		Schemas:     schema.Schemas(),
		Methods:     schema.Methods(),
		TraceMap:    schema.TraceMap,
		Writes:      []string{idpPostureSchema, endpointPostureSchema},
	}
}

// Run is the collector's handler. It fails only for invalid configuration,
// a rejected API key, or a failed read of the users. Otherwise it emits what
// it collected with a gap recorded for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()

	orgID, err := getOptionalString(cfg, "org_id")
	if err != nil {
		return componentsdk.NewConfigError("org_id: %s", err)
	}

	maxAgeHours, err := getOptionalWholeNumber(cfg, "max_observation_age_hours", 1, 8760)
	if err != nil {
		return componentsdk.NewConfigError("max_observation_age_hours: %s", err)
	}

	apiKey := ctx.Secret(apiKeyEnv)
	if apiKey == "" {
		return componentsdk.NewConfigError("%s is required", apiKeyEnv)
	}

	config := Config{
		OrgID:             orgID,
		MaxObservationAge: time.Duration(maxAgeHours) * time.Hour,
		OnStatus:          ctx.Status,
		OnProgress:        ctx.Progress,
		Recorder:          componentsdk.Records(ctx),
		Now:               func() time.Time { return componentsdk.Now(ctx) },
		Selected:          func(at componentsdk.Location) bool { return componentsdk.Selected(ctx, at) },
	}
	httpClient := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts: []string{jumpcloud.ConsoleHost, jumpcloud.InsightsHost},
	})
	client := jumpcloud.NewClient(httpClient, apiKey, orgID)

	posture, err := New(config, client).Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	return ctx.Emit(Artifacts(posture))
}

// Artifacts returns the detailed artifact and each normalized artifact the
// run could build.
func Artifacts(posture *OrgPosture) []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(detailedPath, posture, componentsdk.ArtifactMeta{}),
	}
	if idpPosture := posture.ToIDPPosture(); idpPosture != nil {
		artifacts = append(artifacts, componentsdk.JSONArtifact(idpPosturePath, idpPosture,
			componentsdk.ArtifactMeta{Schema: idpPostureSchema}))
	}
	if endpointPosture := posture.ToEndpointPosture(); endpointPosture != nil {
		artifacts = append(artifacts, componentsdk.JSONArtifact(endpointPosturePath, endpointPosture,
			componentsdk.ArtifactMeta{Schema: endpointPostureSchema}))
	}
	return artifacts
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
