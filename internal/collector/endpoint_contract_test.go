package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// compileEndpointSchema compiles the SDK's endpoint-posture schema, which
// Emit checks the artifact against.
func compileEndpointSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw := componentsdk.NormalizedSchemaJSON(endpointPostureSchema)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("endpoint-posture.json", doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	schema, err := c.Compile("endpoint-posture.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

// TestEndpoint_OutputMeetsContract serializes the artifact for a spread of
// scenarios and checks it against the JSON Schema and the coverage rules the
// schema cannot express.
func TestEndpoint_OutputMeetsContract(t *testing.T) {
	schema := compileEndpointSchema(t)
	recent := insightTime(testNow.Add(-time.Hour))
	fresh := testNow.Add(-time.Hour)

	mixedFleet := func(level componentsdk.Level) endpointInputs {
		in := inputs(level,
			macWithFDE("m1", boolPtr(true), fresh),
			macWithFDE("m2", boolPtr(false), fresh),
			macWithFDE("m3", nil, testNow.Add(-72*time.Hour)),
			windowsSystem("w1", fresh),
			jumpcloud.System{ID: "l1", OS: "Ubuntu", LastContact: rfc(fresh)},
		)
		in.bitlocker = bitlockerSource(jumpcloud.InsightBitLocker{SystemID: "w1", CollectionTime: recent,
			DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)})
		in.alf = newInsightSource([]jumpcloud.InsightALF{{SystemID: "m1", CollectionTime: recent, GlobalState: intPtr(1)}}, false,
			func(r jumpcloud.InsightALF) string { return r.SystemID })
		in.products = productSource(jumpcloud.InsightWindowsSecurityProduct{SystemID: "w1", CollectionTime: recent,
			Type: strPtr("Antivirus"), State: strPtr("On"), SignaturesUpToDate: f64Ptr(1)})
		in.insightUsers = newInsightSource([]jumpcloud.InsightUser{
			{SystemID: "m1", CollectionTime: recent, Username: strPtr("alice"), UID: strPtr("501"), Admin: boolPtr(true)},
		}, false, func(r jumpcloud.InsightUser) string { return r.SystemID })
		return in
	}

	scenarios := map[string]endpointInputs{
		"trust":    mixedFleet(componentsdk.LevelTrust),
		"audit":    mixedFleet(componentsdk.LevelAudit),
		"internal": mixedFleet(componentsdk.LevelInternal),
		"empty":    inputs(componentsdk.LevelAudit),
		"partial": func() endpointInputs {
			in := mixedFleet(componentsdk.LevelAudit)
			in.serverTotal = 50
			return in
		}(),
		"denied and capped": func() endpointInputs {
			in := mixedFleet(componentsdk.LevelInternal)
			in.products = &insightSource[jumpcloud.InsightWindowsSecurityProduct]{err: &jumpcloud.APIError{StatusCode: 403}}
			in.bitlocker.capped = true
			return in
		}(),
	}

	for name, in := range scenarios {
		t.Run(name, func(t *testing.T) {
			ep := buildEndpointPosture(in)
			data, err := json.Marshal(ep)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var doc any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Fatalf("schema violation: %v\n%s", err, data)
			}
			for _, problem := range contractProblems(ep, in.level) {
				t.Error(problem)
			}
		})
	}
}

func TestEndpoint_SchemaRejectsFleetValuesWhenDiscoveryIncomplete(t *testing.T) {
	schema := compileEndpointSchema(t)
	partial := `{"schema_version":"1.0.0","collected_at":"2026-10-22T00:00:00Z","provider":"jumpcloud",
		"scope":{"discovery_complete":false,"observed_device_count":1,"description":"provider_visible_devices","max_observation_age_seconds":604800},
		"metric_coverage":{},"availability":[]}`
	for name, extra := range map[string]string{
		"fleet totals":   `"fleet":{"device_count":1}`,
		"a percentage":   `"hardening":{"disk_encryption_pct":100}`,
		"coverage entry": `"metric_coverage":{"hardening.disk_encryption_pct":{"passing_device_count":1,"failing_device_count":0,"unknown_device_count":0,"not_applicable_device_count":0}}`,
	} {
		var doc map[string]any
		if err := json.Unmarshal([]byte(partial), &doc); err != nil {
			t.Fatal(err)
		}
		var add map[string]any
		if err := json.Unmarshal([]byte("{"+extra+"}"), &add); err != nil {
			t.Fatal(err)
		}
		for k, v := range add {
			doc[k] = v
		}
		if err := schema.Validate(doc); err == nil {
			t.Errorf("schema accepted %s on an incomplete discovery", name)
		}
	}

	var ok map[string]any
	if err := json.Unmarshal([]byte(partial), &ok); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(ok); err != nil {
		t.Errorf("schema rejected a valid incomplete-discovery artifact: %v", err)
	}
}

func TestEndpoint_SchemaRequiresCoverageForEveryPercentage(t *testing.T) {
	schema := compileEndpointSchema(t)
	base := `{"schema_version":"1.0.0","collected_at":"2026-10-22T00:00:00Z","provider":"jumpcloud",
		"scope":{"discovery_complete":true,"observed_device_count":1,"description":"provider_visible_devices","max_observation_age_seconds":604800},
		"metric_coverage":{},"availability":[]}`
	coverage := `{"passing_device_count":1,"failing_device_count":0,"unknown_device_count":0,"not_applicable_device_count":0}`
	doc := func(extra string) map[string]any {
		t.Helper()
		var d map[string]any
		if err := json.Unmarshal([]byte(base), &d); err != nil {
			t.Fatal(err)
		}
		if extra != "" {
			var add map[string]any
			if err := json.Unmarshal([]byte("{"+extra+"}"), &add); err != nil {
				t.Fatal(err)
			}
			for k, v := range add {
				d[k] = v
			}
		}
		return d
	}

	rejected := map[string]string{
		"disk encryption without coverage": `"hardening":{"disk_encryption_pct":100}`,
		"edr health without coverage":      `"protection":{"edr_healthy_pct":50}`,
		"compliance without coverage":      `"compliance":{"compliant_pct":90,"basis":"provider_reported"}`,
		"coverage for a different metric": `"hardening":{"disk_encryption_pct":100},
			"metric_coverage":{"hardening.firewall_enabled_pct":` + coverage + `}`,
	}
	for name, extra := range rejected {
		if err := schema.Validate(doc(extra)); err == nil {
			t.Errorf("schema accepted %s", name)
		}
	}

	accepted := map[string]string{
		"omitted metric with no coverage": "",
		"percentage with its coverage": `"hardening":{"disk_encryption_pct":100},
			"metric_coverage":{"hardening.disk_encryption_pct":` + coverage + `}`,
		"coverage for an unemitted percentage": `"metric_coverage":{"hardening.firewall_enabled_pct":` + coverage + `}`,
	}
	for name, extra := range accepted {
		if err := schema.Validate(doc(extra)); err != nil {
			t.Errorf("schema rejected %s: %v", name, err)
		}
	}
}

func contractProblems(ep *EndpointPosture, level componentsdk.Level) []string {
	var problems []string
	values := map[string]Percentage{}
	if ep.Hardening != nil {
		values["hardening.disk_encryption_pct"] = ep.Hardening.DiskEncryptionPct
		values["hardening.firewall_enabled_pct"] = ep.Hardening.FirewallEnabledPct
	}
	if ep.Protection != nil {
		values["protection.antimalware_installed_pct"] = ep.Protection.AntimalwareInstalledPct
		values["protection.antimalware_healthy_pct"] = ep.Protection.AntimalwareHealthyPct
	}
	explained := map[string]bool{}
	for _, a := range ep.Availability {
		explained[a.Path] = true
	}
	devices := len(ep.controlsByDevice)

	if !ep.discovered() {
		if ep.Fleet != nil || ep.Hardening != nil || ep.Protection != nil || len(ep.MetricCoverage) > 0 {
			problems = append(problems, "incomplete discovery must omit fleet, percentages, and coverage")
		}
	}

	audit := level.AtLeast(componentsdk.LevelAudit)
	for _, m := range measuredMetrics {
		cov, hasCov := ep.MetricCoverage[m.path]
		value := values[m.path]
		if value.Value != nil && audit && !hasCov {
			problems = append(problems, m.path+": percentage without coverage")
		}
		if value.Value == nil && !explained[m.path] && devices > 0 {
			problems = append(problems, m.path+": omitted without an availability entry")
		}
		if !hasCov {
			continue
		}
		total := cov.PassingDevicesCount + cov.FailingDevicesCount + cov.UnknownDevicesCount + cov.NotApplicableDevicesCount
		if total != devices {
			problems = append(problems, fmt.Sprintf("%s: coverage covers %d devices, scope has %d", m.path, total, devices))
		}
		var want *float64
		if evaluated := cov.PassingDevicesCount + cov.FailingDevicesCount; evaluated > 0 {
			v := math.Floor(float64(cov.PassingDevicesCount) * 100 / float64(evaluated))
			want = &v
		}
		switch {
		case want == nil && value.Value != nil:
			problems = append(problems, m.path+": percentage emitted with nothing evaluated")
		case want != nil && (value.Value == nil || *value.Value != *want):
			problems = append(problems, fmt.Sprintf("%s: percentage does not match coverage", m.path))
		}
	}

	if !audit {
		data, _ := json.Marshal(ep)
		if len(ep.Devices) > 0 || len(ep.MetricCoverage) > 0 || strings.Contains(string(data), `"device_id"`) {
			problems = append(problems, "trust output must not carry device identity or coverage")
		}
	}
	for _, d := range ep.Devices {
		if d.LocalAdminAccounts != nil && !level.AtLeast(componentsdk.LevelInternal) {
			problems = append(problems, "local admin accounts below internal level")
		}
	}
	return problems
}
