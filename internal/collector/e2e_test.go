//go:build e2e
// +build e2e

// End-to-end tests that make real requests to the JumpCloud API.
//
// Run with:
//
//	go test -tags=e2e -v ./internal/collector/...
//
// Required environment variables:
//
//	JUMPCLOUD_API_KEY    API key with read access
//
// Optional environment variables:
//
//	JUMPCLOUD_E2E_ORG_ID  organization ID for MSP scenarios
//	JUMPCLOUD_E2E_LEVEL   trust | audit | internal (default trust)

package collector

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

func e2eLevel() componentsdk.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("JUMPCLOUD_E2E_LEVEL"))) {
	case "audit":
		return componentsdk.LevelAudit
	case "internal":
		return componentsdk.LevelInternal
	default:
		return componentsdk.LevelTrust
	}
}

func getE2EConfig(t *testing.T) (Config, *jumpcloud.Client) {
	t.Helper()

	apiKey := os.Getenv("JUMPCLOUD_API_KEY")
	if apiKey == "" {
		t.Skip("JUMPCLOUD_API_KEY not set; skipping e2e test")
	}

	orgID := strings.TrimSpace(os.Getenv("JUMPCLOUD_E2E_ORG_ID"))

	cfg := Config{
		OrgID: orgID,
	}
	client := jumpcloud.NewClient(apiKey, orgID)
	return cfg, client
}

func collectE2E(t *testing.T, level componentsdk.Level) *OrgPosture {
	t.Helper()
	cfg, client := getE2EConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	c := New(cfg, client)
	posture, err := c.Collect(ctx, level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture
}

func TestE2E_RealJumpCloudCollection(t *testing.T) {
	level := e2eLevel()
	posture := collectE2E(t, level)

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", posture.SchemaVersion, SchemaVersion)
	}
	if posture.CollectedAtLevel != string(level) {
		t.Errorf("collected_at_level = %q, want %q", posture.CollectedAtLevel, level)
	}
	if _, err := time.Parse(time.RFC3339, posture.CollectedAt); err != nil {
		t.Errorf("collected_at %q is not RFC3339: %v", posture.CollectedAt, err)
	}

	assertPercentE2E(t, "authentication.mfa_coverage_pct", posture.Authentication.MFACoveragePct)

	if level.AtLeast(componentsdk.LevelAudit) {
		if posture.UserInventory == nil {
			t.Error("user_inventory should be present at audit level")
		}
	} else {
		if posture.UserInventory != nil {
			t.Error("user_inventory must NOT be present at trust level")
		}
	}

	data, _ := json.MarshalIndent(posture, "", "  ")
	t.Logf("collection complete at level=%s\n%s", level, string(data))
}

func TestE2E_OutputValidJSON(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, field := range []string{
		"schema_version", "collected_at", "collected_at_level",
		"users", "authentication",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required top-level field: %s", field)
		}
	}
}

func TestE2E_IDPPostureTransformation(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	normalized := posture.ToIDPPosture()
	if normalized == nil {
		t.Skip("no users in org; skipping IDP posture test")
	}
	if normalized.Provider != "jumpcloud" {
		t.Errorf("provider = %q, want jumpcloud", normalized.Provider)
	}
	if normalized.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", normalized.SchemaVersion, SchemaVersion)
	}

	assertPercentFloatE2E(t, "user_security.mfa_coverage_pct", normalized.UserSecurity.MFACoveragePct)

	data, _ := json.MarshalIndent(normalized, "", "  ")
	t.Logf("IDP posture:\n%s", string(data))
}

func TestE2E_EndpointPosture(t *testing.T) {
	level := e2eLevel()
	posture := collectE2E(t, level)

	ep := posture.ToEndpointPosture()
	if ep == nil {
		t.Skip("device discovery unavailable; skipping endpoint posture test")
	}
	for path, cov := range ep.MetricCoverage {
		total := cov.PassingDevicesCount + cov.FailingDevicesCount + cov.UnknownDevicesCount + cov.NotApplicableDevicesCount
		if ep.Scope.DiscoveryComplete && total != ep.Scope.ObservedDevicesCount {
			t.Errorf("%s coverage sums to %d, want %d devices", path, total, ep.Scope.ObservedDevicesCount)
		}
	}
	if !level.AtLeast(componentsdk.LevelAudit) && (len(ep.Devices) > 0 || ep.Inventories != nil) {
		t.Error("trust level must not include device inventory")
	}

	data, _ := json.MarshalIndent(ep, "", "  ")
	t.Logf("endpoint posture:\n%s", string(data))
}

func TestE2E_DiagnosticsAreSafe(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	if posture.Diagnostics == nil {
		t.Log("no diagnostics emitted (all surfaces accessible)")
		return
	}

	for _, msg := range posture.Diagnostics.PermissionErrors {
		if strings.Contains(msg, "jca_") || strings.Contains(strings.ToLower(msg), "api key") {
			t.Errorf("diagnostic permission_error may contain a secret: %q", msg)
		}
	}
	for _, msg := range posture.Diagnostics.Warnings {
		if strings.Contains(msg, "jca_") || strings.Contains(strings.ToLower(msg), "api key") {
			t.Errorf("diagnostic warning may contain a secret: %q", msg)
		}
	}

	t.Logf("diagnostics: %d permission_errors, %d warnings",
		len(posture.Diagnostics.PermissionErrors), len(posture.Diagnostics.Warnings))
}

func assertPercentE2E(t *testing.T, name string, v float64) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s should be in [0,100], got %v", name, v)
	}
}

func assertPercentFloatE2E(t *testing.T, name string, v float64) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s should be in [0,100], got %v", name, v)
	}
}
