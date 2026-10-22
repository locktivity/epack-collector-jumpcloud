package collector

import (
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

// testdata/endpoint-posture-v1.schema.json mirrors the shared contract in
// locktivity docs/specs/endpoint-posture. Keep the two in sync.
func compileEndpointSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	schema, err := c.Compile("testdata/endpoint-posture-v1.schema.json")
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
		"scope":{"discovery_complete":false,"observed_devices_count":1,"description":"provider_visible_devices","max_observation_age_seconds":604800},
		"metric_coverage":{},"availability":[]}`
	for name, extra := range map[string]string{
		"fleet totals":   `"fleet":{"devices_count":1}`,
		"a percentage":   `"hardening":{"disk_encryption_pct":100}`,
		"coverage entry": `"metric_coverage":{"hardening.disk_encryption_pct":{"passing_devices_count":1,"failing_devices_count":0,"unknown_devices_count":0,"not_applicable_devices_count":0}}`,
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

func contractProblems(ep *EndpointPosture, level componentsdk.Level) []string {
	var problems []string
	values := map[string]*float64{}
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

	if !ep.Scope.DiscoveryComplete {
		if ep.Fleet != nil || ep.Hardening != nil || ep.Protection != nil || len(ep.MetricCoverage) > 0 {
			problems = append(problems, "incomplete discovery must omit fleet, percentages, and coverage")
		}
	}

	for _, m := range measuredMetrics {
		cov, hasCov := ep.MetricCoverage[m.path]
		value := values[m.path]
		if value != nil && !hasCov {
			problems = append(problems, m.path+": percentage without coverage")
		}
		if value == nil && !explained[m.path] && ep.Scope.ObservedDevicesCount > 0 {
			problems = append(problems, m.path+": omitted without an availability entry")
		}
		if !hasCov {
			continue
		}
		total := cov.PassingDevicesCount + cov.FailingDevicesCount + cov.UnknownDevicesCount + cov.NotApplicableDevicesCount
		if total != ep.Scope.ObservedDevicesCount {
			problems = append(problems, fmt.Sprintf("%s: coverage covers %d devices, scope has %d", m.path, total, ep.Scope.ObservedDevicesCount))
		}
		var want *float64
		if evaluated := cov.PassingDevicesCount + cov.FailingDevicesCount; evaluated > 0 {
			v := math.Round(float64(cov.PassingDevicesCount)*10000/float64(evaluated)) / 100
			want = &v
		}
		switch {
		case want == nil && value != nil:
			problems = append(problems, m.path+": percentage emitted with nothing evaluated")
		case want != nil && (value == nil || *value != *want):
			problems = append(problems, fmt.Sprintf("%s: percentage does not match coverage", m.path))
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		data, _ := json.Marshal(ep)
		if len(ep.Devices) > 0 || ep.Inventories != nil || strings.Contains(string(data), `"device_id"`) {
			problems = append(problems, "trust output must not carry device identity")
		}
	}
	for _, d := range ep.Devices {
		if d.LocalAdminAccounts != nil && !level.AtLeast(componentsdk.LevelInternal) {
			problems = append(problems, "local admin accounts below internal level")
		}
	}
	return problems
}
