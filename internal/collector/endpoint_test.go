package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

var testNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func boolPtr(v bool) *bool      { return &v }
func intPtr(v int) *int         { return &v }
func strPtr(v string) *string   { return &v }
func f64Ptr(v float64) *float64 { return &v }
func rfc(t time.Time) string    { return t.Format(time.RFC3339) }
func insightTime(t time.Time) string {
	return t.In(time.FixedZone("EDT", -4*3600)).Format("2006-01-02 15:04:05 -0700")
}

func macWithFDE(id string, active *bool, lastContact time.Time) jumpcloud.System {
	return jumpcloud.System{ID: id, Hostname: "host-" + id, OS: "Mac OS X", OSFamily: "darwin",
		LastContact: rfc(lastContact), FDE: &jumpcloud.SystemFDE{Active: active}}
}

func windowsSystem(id string, lastContact time.Time) jumpcloud.System {
	return jumpcloud.System{ID: id, Hostname: "host-" + id, OS: "Windows", OSFamily: "windows", LastContact: rfc(lastContact)}
}

func inputs(level componentsdk.Level, systems ...jumpcloud.System) endpointInputs {
	return endpointInputs{systems: systems, serverTotal: len(systems), level: level, now: testNow, maxAge: 24 * time.Hour}
}

func bitlockerSource(rows ...jumpcloud.InsightBitLocker) *insightSource[jumpcloud.InsightBitLocker] {
	return newInsightSource(rows, false, func(r jumpcloud.InsightBitLocker) string { return r.SystemID })
}

func productSource(rows ...jumpcloud.InsightWindowsSecurityProduct) *insightSource[jumpcloud.InsightWindowsSecurityProduct] {
	return newInsightSource(rows, false, func(r jumpcloud.InsightWindowsSecurityProduct) string { return r.SystemID })
}

func availabilityHas(ep *EndpointPosture, path, reason string) bool {
	return slices.ContainsFunc(ep.Availability, func(a AvailabilityEntry) bool { return a.Path == path && a.Reason == reason })
}

// The brief's worked example: 170 pass, 5 fail, 5 unknown.
func TestEndpoint_DenominatorExample(t *testing.T) {
	fresh := testNow.Add(-time.Hour)
	var systems []jumpcloud.System
	for i := range 170 {
		systems = append(systems, macWithFDE(fmt.Sprintf("p%03d", i), boolPtr(true), fresh))
	}
	for i := range 5 {
		systems = append(systems, macWithFDE(fmt.Sprintf("f%03d", i), boolPtr(false), fresh))
	}
	for i := range 5 {
		systems = append(systems, macWithFDE(fmt.Sprintf("s%03d", i), boolPtr(true), testNow.Add(-72*time.Hour)))
	}

	ep := buildEndpointPosture(inputs(componentsdk.LevelTrust, systems...))

	if ep.Hardening == nil || ep.Hardening.DiskEncryptionPct == nil {
		t.Fatal("disk_encryption_pct should be emitted")
	}
	if got := *ep.Hardening.DiskEncryptionPct; got != 97.14 {
		t.Errorf("disk_encryption_pct = %v, want 97.14", got)
	}
	cov := ep.MetricCoverage["hardening.disk_encryption_pct"]
	want := MetricCoverage{PassingDevicesCount: 170, FailingDevicesCount: 5, UnknownDevicesCount: 5}
	if cov != want {
		t.Errorf("coverage = %+v, want %+v", cov, want)
	}
	evaluated := cov.PassingDevicesCount + cov.FailingDevicesCount
	coverage := round2(float64(evaluated) / float64(evaluated+cov.UnknownDevicesCount) * 100)
	if coverage != 97.22 {
		t.Errorf("evaluation coverage = %v, want 97.22", coverage)
	}
	if !availabilityHas(ep, "hardening.disk_encryption_pct", reasonStale) {
		t.Error("stale devices should produce a stale availability entry")
	}
}

func TestEndpoint_TinyEvaluatedSubsetKeepsUnknownsVisible(t *testing.T) {
	fresh := testNow.Add(-time.Hour)
	systems := []jumpcloud.System{macWithFDE("a", boolPtr(true), fresh)}
	for i := range 99 {
		systems = append(systems, macWithFDE(fmt.Sprintf("u%02d", i), nil, fresh))
	}

	ep := buildEndpointPosture(inputs(componentsdk.LevelTrust, systems...))

	if got := *ep.Hardening.DiskEncryptionPct; got != 100 {
		t.Errorf("disk_encryption_pct = %v, want 100", got)
	}
	cov := ep.MetricCoverage["hardening.disk_encryption_pct"]
	if cov.PassingDevicesCount != 1 || cov.UnknownDevicesCount != 99 {
		t.Errorf("coverage = %+v, want 1 passing and 99 unknown", cov)
	}
}

func TestEndpoint_ZeroEvaluatedOmitsPercentage(t *testing.T) {
	ep := buildEndpointPosture(inputs(componentsdk.LevelTrust, macWithFDE("a", nil, testNow.Add(-time.Hour))))

	if ep.Hardening != nil && ep.Hardening.DiskEncryptionPct != nil {
		t.Error("disk_encryption_pct must be omitted when nothing was evaluated")
	}
	if _, ok := ep.MetricCoverage["hardening.disk_encryption_pct"]; !ok {
		t.Error("coverage entry should still report the unknown device")
	}
	if !availabilityHas(ep, "hardening.disk_encryption_pct", reasonUnsupported) {
		t.Error("an omitted percentage needs an availability explanation")
	}
}

func TestEndpoint_ZeroDevices(t *testing.T) {
	ep := buildEndpointPosture(inputs(componentsdk.LevelTrust))

	if !ep.Scope.DiscoveryComplete {
		t.Error("an empty, fully fetched fleet is complete")
	}
	if ep.Fleet == nil || ep.Fleet.DevicesCount == nil || *ep.Fleet.DevicesCount != 0 {
		t.Fatal("devices_count should be a known zero")
	}
	if ep.Hardening != nil || ep.Protection != nil {
		t.Error("no percentages for an empty fleet")
	}

	data, _ := json.Marshal(ep)
	if !strings.Contains(string(data), `"devices_count":0`) {
		t.Errorf("known zero must survive serialization: %s", data)
	}
}

func TestEndpoint_PartialDiscoveryOmitsFleetWideValues(t *testing.T) {
	in := inputs(componentsdk.LevelAudit, macWithFDE("a", boolPtr(true), testNow.Add(-time.Hour)))
	in.serverTotal = 10

	ep := buildEndpointPosture(in)

	if ep.Scope.DiscoveryComplete {
		t.Error("discovery_complete should be false")
	}
	if ep.Scope.ObservedDevicesCount != 1 {
		t.Errorf("observed_devices_count = %d, want 1", ep.Scope.ObservedDevicesCount)
	}
	if ep.Fleet != nil || ep.Hardening != nil || ep.Protection != nil || len(ep.MetricCoverage) != 0 {
		t.Error("fleet totals, percentages, and coverage must be omitted for a partial fleet")
	}
	for _, path := range []string{"fleet", "hardening.disk_encryption_pct", "protection.antimalware_healthy_pct"} {
		if !availabilityHas(ep, path, reasonPartial) {
			t.Errorf("missing partial availability for %s", path)
		}
	}
	if meta := ep.Inventories[inventoryDevices]; meta.CollectionComplete {
		t.Error("device inventory must be marked incomplete")
	}
}

func TestEndpoint_DuplicateSystemRowsCountOnce(t *testing.T) {
	sys := macWithFDE("a", boolPtr(true), testNow.Add(-time.Hour))
	in := inputs(componentsdk.LevelTrust, sys, sys)
	in.serverTotal = 1

	ep := buildEndpointPosture(in)

	if *ep.Fleet.DevicesCount != 1 || ep.MetricCoverage["hardening.disk_encryption_pct"].PassingDevicesCount != 1 {
		t.Errorf("duplicate rows should be one device: fleet=%d", *ep.Fleet.DevicesCount)
	}
}

func TestEndpoint_FDEFalseIsFailureMissingIsUnknown(t *testing.T) {
	fresh := testNow.Add(-time.Hour)
	ep := buildEndpointPosture(inputs(componentsdk.LevelTrust,
		macWithFDE("off", boolPtr(false), fresh),
		macWithFDE("missing", nil, fresh),
		jumpcloud.System{ID: "nofde", OS: "Mac OS X", LastContact: rfc(fresh)},
	))

	want := MetricCoverage{FailingDevicesCount: 1, UnknownDevicesCount: 2}
	if got := ep.MetricCoverage["hardening.disk_encryption_pct"]; got != want {
		t.Errorf("coverage = %+v, want %+v", got, want)
	}
	if *ep.Hardening.DiskEncryptionPct != 0 {
		t.Error("a known 0% must be emitted, not omitted")
	}
}

func TestEndpoint_BitLockerMapping(t *testing.T) {
	recent := insightTime(testNow.Add(-2 * time.Hour))
	cases := []struct {
		name string
		rows []jumpcloud.InsightBitLocker
		fde  *bool
		want string
	}{
		{"fully encrypted and protected", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}}, nil, statePass},
		{"suspended protection fails", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(1)}}, boolPtr(true), stateFail},
		{"encryption in progress fails", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(2)}}, nil, stateFail},
		{"protection status unknown", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(2), ConversionStatus: intPtr(1)}}, nil, stateUnknown},
		{"unknown protection with an unrecognized conversion code", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(2), ConversionStatus: intPtr(9)}}, nil, stateUnknown},
		{"protected C: does not pass an unprotected OS volume elsewhere", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)},
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("D:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(0)}}, nil, stateUnknown},
		{"every volume protected passes", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)},
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("D:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}}, nil, statePass},
		{"every volume unprotected fails", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(0)},
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("D:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(0)}}, nil, stateFail},
		{"a volume with only stale readings blocks a pass", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("D:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)},
			{SystemID: "w", CollectionTime: insightTime(testNow.Add(-48 * time.Hour)), DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}}, nil, stateUnknown},
		{"conflicting rows at the same time are unknown", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)},
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(0)}}, nil, stateUnknown},
		{"latest row wins over an older one", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: insightTime(testNow.Add(-5 * time.Hour)), DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(0)},
			{SystemID: "w", CollectionTime: recent, DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}}, nil, statePass},
		{"stale row falls back to an fde failure", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: insightTime(testNow.Add(-48 * time.Hour)), DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}}, boolPtr(false), stateFail},
		{"stale row with fde active stays unknown", []jumpcloud.InsightBitLocker{
			{SystemID: "w", CollectionTime: insightTime(testNow.Add(-48 * time.Hour)), DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}}, boolPtr(true), stateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := windowsSystem("w", testNow.Add(-time.Hour))
			sys.FDE = &jumpcloud.SystemFDE{Active: tc.fde}
			in := inputs(componentsdk.LevelTrust, sys)
			in.bitlocker = bitlockerSource(tc.rows...)

			got := evalDiskEncryption(&in.systems[0], "windows", in)
			if got.state != tc.want {
				t.Errorf("state = %q, want %q", got.state, tc.want)
			}
		})
	}
}

func TestEndpoint_ObservedAtComesFromTelemetry(t *testing.T) {
	observed := testNow.Add(-2 * time.Hour)
	sys := windowsSystem("w", testNow.Add(-time.Hour))
	in := inputs(componentsdk.LevelAudit, sys)
	in.bitlocker = bitlockerSource(jumpcloud.InsightBitLocker{SystemID: "w", CollectionTime: insightTime(observed),
		DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)})

	ep := buildEndpointPosture(in)

	got := ep.Devices[0].Controls[controlDiskEncryption]
	if got.ObservedAt != rfc(observed) {
		t.Errorf("observed_at = %q, want %q normalized to UTC", got.ObservedAt, rfc(observed))
	}
	mac := buildEndpointPosture(inputs(componentsdk.LevelAudit, macWithFDE("m", boolPtr(true), testNow.Add(-time.Hour))))
	if obs := mac.Devices[0].Controls[controlDiskEncryption]; obs.ObservedAt != "" {
		t.Errorf("fde has no observation time; observed_at must not be fabricated, got %q", obs.ObservedAt)
	}
}

func TestParseObservationTime(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"2026-10-16T10:00:00Z", true},
		{"2026-10-16T10:00:00.123Z", true},
		{"2026-10-16 06:00:00 -0400", true},
		{"2026-10-16 10:00:00", false},
		{"2026-10-17T10:00:00Z", false},
		{"not a time", false},
		{"", false},
	}
	for _, tc := range cases {
		got, ok := parseObservationTime(tc.in, testNow)
		if ok != tc.ok {
			t.Errorf("parseObservationTime(%q) ok = %v, want %v", tc.in, ok, tc.ok)
		}
		if ok && got.Location() != time.UTC {
			t.Errorf("parseObservationTime(%q) should normalize to UTC", tc.in)
		}
	}
}

func TestEndpoint_FirewallMapping(t *testing.T) {
	recent := insightTime(testNow.Add(-time.Hour))
	for state, want := range map[int]string{0: stateFail, 1: statePass, 2: statePass, 7: stateUnknown} {
		in := inputs(componentsdk.LevelTrust)
		in.alf = newInsightSource([]jumpcloud.InsightALF{{SystemID: "m", CollectionTime: recent, GlobalState: intPtr(state)}}, false,
			func(r jumpcloud.InsightALF) string { return r.SystemID })
		if got := evalFirewall(&jumpcloud.System{ID: "m"}, "macos", in); got.state != want {
			t.Errorf("alf global_state %d = %q, want %q", state, got.state, want)
		}
	}
	for health, want := range map[string]string{"Good": statePass, "Poor": stateFail, "Snoozed": stateUnknown, "Not Monitored": stateUnknown} {
		in := inputs(componentsdk.LevelTrust)
		in.wsc = newInsightSource([]jumpcloud.InsightWindowsSecurityCenter{{SystemID: "w", CollectionTime: recent, Firewall: strPtr(health)}}, false,
			func(r jumpcloud.InsightWindowsSecurityCenter) string { return r.SystemID })
		if got := evalFirewall(&jumpcloud.System{ID: "w"}, "windows", in); got.state != want {
			t.Errorf("wsc firewall %q = %q, want %q", health, got.state, want)
		}
	}
	if got := evalFirewall(&jumpcloud.System{ID: "l"}, "linux", inputs(componentsdk.LevelTrust)); got.state != stateUnknown {
		t.Errorf("linux firewall has no verified source; got %q", got.state)
	}
}

func TestEndpoint_AntimalwareMapping(t *testing.T) {
	recent := insightTime(testNow.Add(-time.Hour))
	av := func(state *string, sig *float64) jumpcloud.InsightWindowsSecurityProduct {
		return jumpcloud.InsightWindowsSecurityProduct{SystemID: "w", CollectionTime: recent, Type: strPtr("Antivirus"), State: state, SignaturesUpToDate: sig}
	}
	firewallOnly := jumpcloud.InsightWindowsSecurityProduct{SystemID: "w", CollectionTime: recent, Type: strPtr("Firewall"), State: strPtr("On")}

	cases := []struct {
		name                       string
		rows                       []jumpcloud.InsightWindowsSecurityProduct
		wantInstalled, wantHealthy string
	}{
		{"healthy antivirus", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("On"), f64Ptr(1))}, statePass, statePass},
		{"antivirus off", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("Off"), f64Ptr(1))}, statePass, stateFail},
		{"outdated signatures", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("On"), f64Ptr(0))}, statePass, stateFail},
		{"signature state unknown", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("On"), nil)}, statePass, stateUnknown},
		{"one healthy product among several", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("Off"), f64Ptr(0)), av(strPtr("On"), f64Ptr(1))}, statePass, statePass},
		{"fresh enumeration without antivirus", []jumpcloud.InsightWindowsSecurityProduct{firewallOnly}, stateFail, stateFail},
		{"osquery Unknown state is not unhealthy", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("Unknown"), f64Ptr(1))}, statePass, stateUnknown},
		{"snoozed antivirus is unhealthy", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("Snoozed"), f64Ptr(1))}, statePass, stateFail},
		{"missing product type does not prove absence", []jumpcloud.InsightWindowsSecurityProduct{firewallOnly,
			{SystemID: "w", CollectionTime: recent, State: strPtr("On"), SignaturesUpToDate: f64Ptr(1)}}, stateUnknown, stateUnknown},
		{"an unclassified product blocks an all-unhealthy verdict", []jumpcloud.InsightWindowsSecurityProduct{av(strPtr("Off"), f64Ptr(0)),
			{SystemID: "w", CollectionTime: recent, Type: strPtr("Something Else"), State: strPtr("On")}}, statePass, stateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(componentsdk.LevelTrust)
			in.products = productSource(tc.rows...)
			installed, healthy := evalAntimalware(&jumpcloud.System{ID: "w"}, "windows", in)
			if installed.state != tc.wantInstalled || healthy.state != tc.wantHealthy {
				t.Errorf("installed=%q healthy=%q, want %q %q", installed.state, healthy.state, tc.wantInstalled, tc.wantHealthy)
			}
		})
	}

	in := inputs(componentsdk.LevelTrust)
	in.products = productSource()
	if installed, _ := evalAntimalware(&jumpcloud.System{ID: "w"}, "windows", in); installed.state != stateUnknown {
		t.Errorf("a missing Insights row is unknown, not a failure; got %q", installed.state)
	}
	if installed, _ := evalAntimalware(&jumpcloud.System{ID: "m"}, "macos", in); installed.state != stateUnknown {
		t.Errorf("macOS antimalware has no verified source; got %q", installed.state)
	}
}

func TestEndpoint_CappedTelemetryMarksMissingRowsPartial(t *testing.T) {
	in := inputs(componentsdk.LevelTrust, windowsSystem("w", testNow.Add(-time.Hour)))
	in.bitlocker = newInsightSource[jumpcloud.InsightBitLocker](nil, true, func(r jumpcloud.InsightBitLocker) string { return r.SystemID })

	got := evalDiskEncryption(&in.systems[0], "windows", in)
	if got.state != stateUnknown || got.reason != reasonPartial {
		t.Errorf("got %+v, want unknown/partial", got)
	}
}

func TestEndpoint_CappedProductTableIsPartialNotZero(t *testing.T) {
	recent := insightTime(testNow.Add(-time.Hour))
	in := inputs(componentsdk.LevelTrust, windowsSystem("w", testNow.Add(-time.Hour)))
	in.products = newInsightSource([]jumpcloud.InsightWindowsSecurityProduct{
		{SystemID: "w", CollectionTime: recent, Type: strPtr("Firewall"), State: strPtr("On")},
	}, true, func(r jumpcloud.InsightWindowsSecurityProduct) string { return r.SystemID })

	ep := buildEndpointPosture(in)

	if ep.Protection != nil {
		t.Errorf("a capped table must not produce antivirus percentages: %+v", ep.Protection)
	}
	for _, path := range []string{"protection.antimalware_installed_pct", "protection.antimalware_healthy_pct"} {
		if !availabilityHas(ep, path, reasonPartial) {
			t.Errorf("missing partial availability for %s", path)
		}
		if cov := ep.MetricCoverage[path]; cov.UnknownDevicesCount != 1 {
			t.Errorf("%s coverage = %+v, want the device unknown", path, cov)
		}
	}
}

func TestEndpoint_DuplicateRecordsReconcileIndependentOfOrder(t *testing.T) {
	older := macWithFDE("d", boolPtr(true), testNow.Add(-6*time.Hour))
	newer := macWithFDE("d", boolPtr(false), testNow.Add(-time.Hour))

	for name, systems := range map[string][]jumpcloud.System{
		"older first": {older, newer},
		"newer first": {newer, older},
	} {
		in := inputs(componentsdk.LevelTrust, systems...)
		in.serverTotal = 1
		ep := buildEndpointPosture(in)
		if got := ep.MetricCoverage["hardening.disk_encryption_pct"]; got.FailingDevicesCount != 1 || got.PassingDevicesCount != 0 {
			t.Errorf("%s: the newest record should decide, got %+v", name, got)
		}
	}

	seen := testNow.Add(-time.Hour)
	a, b := macWithFDE("d", boolPtr(true), seen), macWithFDE("d", boolPtr(false), seen)
	for name, systems := range map[string][]jumpcloud.System{"a first": {a, b}, "b first": {b, a}} {
		in := inputs(componentsdk.LevelTrust, systems...)
		in.serverTotal = 1
		ep := buildEndpointPosture(in)
		if got := ep.MetricCoverage["hardening.disk_encryption_pct"]; got.UnknownDevicesCount != 1 {
			t.Errorf("%s: equally fresh conflicting records should be unknown, got %+v", name, got)
		}
		if !availabilityHas(ep, "hardening.disk_encryption_pct", reasonSourceError) {
			t.Errorf("%s: conflicting records should be explained", name)
		}
	}
}

func TestEndpoint_ConflictingOSRecordsCannotBypassBitLocker(t *testing.T) {
	seen := testNow.Add(-time.Hour)
	win := windowsSystem("d", seen)
	win.FDE = &jumpcloud.SystemFDE{Active: boolPtr(true)}
	mac := macWithFDE("d", boolPtr(true), seen)
	suspended := bitlockerSource(jumpcloud.InsightBitLocker{SystemID: "d", CollectionTime: insightTime(seen),
		DriveLetter: strPtr("C:"), ProtectionStatus: intPtr(0), ConversionStatus: intPtr(1)})

	alone := inputs(componentsdk.LevelTrust, win)
	alone.bitlocker = suspended
	if got := buildEndpointPosture(alone).MetricCoverage["hardening.disk_encryption_pct"]; got.FailingDevicesCount != 1 {
		t.Fatalf("the Windows record alone should fail on suspended BitLocker, got %+v", got)
	}

	for name, systems := range map[string][]jumpcloud.System{"windows first": {win, mac}, "macos first": {mac, win}} {
		in := inputs(componentsdk.LevelTrust, systems...)
		in.serverTotal = 1
		in.bitlocker = suspended
		ep := buildEndpointPosture(in)

		if ep.Hardening != nil && ep.Hardening.DiskEncryptionPct != nil {
			t.Errorf("%s: an OS conflict must not produce an encryption percentage, got %v", name, *ep.Hardening.DiskEncryptionPct)
		}
		if got := ep.MetricCoverage["hardening.disk_encryption_pct"]; got != (MetricCoverage{UnknownDevicesCount: 1}) {
			t.Errorf("%s: coverage = %+v, want the device unknown", name, got)
		}
		for _, path := range []string{"hardening.disk_encryption_pct", "hardening.firewall_enabled_pct", "protection.antimalware_installed_pct"} {
			if !availabilityHas(ep, path, reasonSourceError) {
				t.Errorf("%s: %s should explain the conflict as a source_error", name, path)
			}
		}
	}
}

func endpointMock() *mockClient {
	recent := insightTime(time.Now().Add(-time.Hour))
	seen := rfc(time.Now().Add(-30 * time.Minute))
	return &mockClient{
		users: []jumpcloud.SystemUser{{ID: "u1", Username: "alice", State: "ACTIVATED"}},
		org:   &jumpcloud.Organization{ID: "org-1"},
		systems: []jumpcloud.System{
			{ID: "s-mac", Hostname: "alice-mbp", OS: "Mac OS X", OSFamily: "darwin", Version: "15.1", LastContact: seen,
				FDE: &jumpcloud.SystemFDE{Active: boolPtr(true)}, PrimarySystemUser: &jumpcloud.PrimarySystemUserRef{ID: "u1"},
				MDM: &jumpcloud.SystemMDM{Vendor: "internal", Internal: &jumpcloud.MDMInternal{DeviceID: "d1"}}},
			{ID: "s-win", Hostname: "bob-pc", OS: "Windows", OSFamily: "windows", LastContact: seen},
		},
		alf: []jumpcloud.InsightALF{{SystemID: "s-mac", CollectionTime: recent, GlobalState: intPtr(1)}},
		bitlocker: []jumpcloud.InsightBitLocker{{SystemID: "s-win", CollectionTime: recent, DriveLetter: strPtr("C:"),
			ProtectionStatus: intPtr(1), ConversionStatus: intPtr(1)}},
		wsc: []jumpcloud.InsightWindowsSecurityCenter{{SystemID: "s-win", CollectionTime: recent, Firewall: strPtr("Good")}},
		products: []jumpcloud.InsightWindowsSecurityProduct{{SystemID: "s-win", CollectionTime: recent,
			Type: strPtr("Antivirus"), State: strPtr("On"), SignaturesUpToDate: f64Ptr(1)}},
		insightUsers: []jumpcloud.InsightUser{
			{SystemID: "s-mac", CollectionTime: recent, Username: strPtr("alice"), UID: strPtr("501"), Admin: boolPtr(true)},
			{SystemID: "s-mac", CollectionTime: recent, Username: strPtr("guest"), UID: strPtr("502"), Admin: boolPtr(false)},
			{SystemID: "s-win", CollectionTime: recent, Username: strPtr("bob"), Admin: nil},
		},
	}
}

func collectEndpoint(t *testing.T, m *mockClient, level componentsdk.Level) (*OrgPosture, *EndpointPosture) {
	t.Helper()
	posture, err := New(Config{}, m).Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	ep := posture.ToEndpointPosture()
	if ep == nil {
		t.Fatal("endpoint posture should be emitted")
	}
	return posture, ep
}

func TestCollect_EndpointTrustHasNoDeviceIdentity(t *testing.T) {
	_, ep := collectEndpoint(t, endpointMock(), componentsdk.LevelTrust)

	data, _ := json.Marshal(ep)
	out := string(data)
	for _, leak := range []string{"s-mac", "s-win", "alice", "bob-pc", "alice-mbp", `"devices":`, `"inventories"`, "501"} {
		if strings.Contains(out, leak) {
			t.Errorf("trust output must not contain %q: %s", leak, out)
		}
	}
	if ep.OrganizationID != "org-1" {
		t.Errorf("organization_id = %q, want org-1", ep.OrganizationID)
	}
	if *ep.Fleet.MDMEnrolledDevicesCount != 1 || *ep.Fleet.ManagedDevicesCount != 2 {
		t.Errorf("fleet = %+v", ep.Fleet)
	}
	if ep.Fleet.DevicesByOS["macos"] != 1 || ep.Fleet.DevicesByOS["windows"] != 1 {
		t.Errorf("devices_by_os = %v", ep.Fleet.DevicesByOS)
	}
	if *ep.Hardening.DiskEncryptionPct != 100 || *ep.Hardening.FirewallEnabledPct != 100 {
		t.Errorf("hardening = %+v", ep.Hardening)
	}
}

func TestCollect_EndpointLevelGating(t *testing.T) {
	m := endpointMock()
	_, ep := collectEndpoint(t, m, componentsdk.LevelAudit)
	if len(ep.Devices) != 2 {
		t.Fatalf("audit should include 2 devices, got %d", len(ep.Devices))
	}
	if slices.Contains(m.insightCalls, "users") {
		t.Error("local accounts must not be fetched below internal")
	}
	mac := ep.Devices[0]
	if mac.DeviceID != "s-mac" || mac.AssignedUser == nil || mac.AssignedUser.Login != "alice" {
		t.Errorf("mac device = %+v", mac)
	}
	if mac.OSVersion != "15.1" || mac.OSFamily != "macos" || mac.LocalAdminAccounts != nil {
		t.Errorf("mac device detail = %+v", mac)
	}

	_, ep = collectEndpoint(t, endpointMock(), componentsdk.LevelInternal)
	admins := ep.Devices[0].LocalAdminAccounts
	if admins == nil || len(*admins) != 1 || (*admins)[0].Username != "alice" {
		t.Errorf("mac local admins = %+v, want only alice", admins)
	}
	if win := ep.Devices[1].LocalAdminAccounts; win != nil {
		t.Errorf("an account without an admin flag leaves the device unclassified; windows admins = %+v", *win)
	}
	if ep.Inventories[inventoryLocalAdmins].CollectionComplete {
		t.Error("local admin inventory must be incomplete while a device is unclassified")
	}
	if !availabilityHas(ep, inventoryLocalAdmins, reasonPartial) {
		t.Error("unclassified devices should be explained in availability")
	}

	m = endpointMock()
	m.insightUsers = append(m.insightUsers[:2], jumpcloud.InsightUser{SystemID: "s-win", CollectionTime: m.insightUsers[0].CollectionTime,
		Username: strPtr("bob"), Admin: boolPtr(false)})
	_, ep = collectEndpoint(t, m, componentsdk.LevelInternal)
	if win := ep.Devices[1].LocalAdminAccounts; win == nil || len(*win) != 0 {
		t.Errorf("classified accounts with no admins should be an empty list, got %v", win)
	}
	if !ep.Inventories[inventoryLocalAdmins].CollectionComplete {
		t.Error("every device classified should mark the local admin inventory complete")
	}
}

func TestCollect_EndpointOnlyFetchesTablesForPresentFamilies(t *testing.T) {
	m := endpointMock()
	m.systems = m.systems[:1]
	collectEndpoint(t, m, componentsdk.LevelTrust)

	if !slices.Equal(m.insightCalls, []string{"alf"}) {
		t.Errorf("insight calls = %v, want only alf for a macOS-only fleet", m.insightCalls)
	}
}

func TestCollect_EndpointSurvivesEmptyAndPartialUsers(t *testing.T) {
	m := endpointMock()
	m.users = nil
	posture, ep := collectEndpoint(t, m, componentsdk.LevelTrust)
	if posture.ToIDPPosture() != nil {
		t.Error("no users should suppress the IDP artifact")
	}
	if ep.Fleet == nil || *ep.Fleet.DevicesCount != 2 {
		t.Error("device evidence must not depend on user discovery")
	}

	m = endpointMock()
	m.userTotal = 50
	posture, ep = collectEndpoint(t, m, componentsdk.LevelTrust)
	if posture.ToIDPPosture() != nil {
		t.Error("partial users should suppress the IDP artifact")
	}
	if ep.Hardening == nil {
		t.Error("partial users must not suppress device percentages")
	}
}

func TestCollect_EndpointDeniedInsightsDegrade(t *testing.T) {
	m := endpointMock()
	m.wscErr = &jumpcloud.APIError{StatusCode: 403}
	m.productsErr = &jumpcloud.APIError{StatusCode: 500}

	posture, ep := collectEndpoint(t, m, componentsdk.LevelTrust)

	if posture.ToIDPPosture() == nil {
		t.Error("a denied Insights table must not erase IDP evidence")
	}
	if !availabilityHas(ep, "hardening.firewall_enabled_pct", reasonPermissionDenied) {
		t.Error("denied firewall telemetry should be explained")
	}
	if !availabilityHas(ep, "protection.antimalware_installed_pct", reasonSourceError) {
		t.Error("failed product telemetry should be a source_error")
	}
	if ep.Protection != nil {
		t.Errorf("no antimalware percentage without readings: %+v", ep.Protection)
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.PermissionErrors) == 0 {
		t.Error("detailed diagnostics should record the denied table")
	}
}

func TestCollect_EndpointUnauthorizedInsightsIsFatal(t *testing.T) {
	m := endpointMock()
	m.bitlockerErr = &jumpcloud.APIError{StatusCode: 401}
	if _, err := New(Config{}, m).Collect(context.Background(), componentsdk.LevelTrust); err == nil {
		t.Fatal("401 on telemetry should abort collection")
	}
}

func TestCollect_EndpointOmittedWhenSystemsFail(t *testing.T) {
	m := endpointMock()
	m.systemsErr = &jumpcloud.APIError{StatusCode: 403}
	posture, err := New(Config{}, m).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if posture.ToEndpointPosture() != nil {
		t.Error("no device discovery means no endpoint artifact")
	}
}

func TestEndpoint_TruncationKeepsAggregatesStable(t *testing.T) {
	fresh := testNow.Add(-time.Hour)
	systems := make([]jumpcloud.System, 0, MaxDevices+5)
	for i := range MaxDevices + 5 {
		systems = append(systems, macWithFDE(fmt.Sprintf("d%06d", i), boolPtr(i%2 == 0), fresh))
	}

	ep := buildEndpointPosture(inputs(componentsdk.LevelAudit, systems...))

	if len(ep.Devices) != MaxDevices {
		t.Errorf("devices = %d, want %d", len(ep.Devices), MaxDevices)
	}
	if *ep.Fleet.DevicesCount != MaxDevices+5 {
		t.Errorf("devices_count = %d, want full population", *ep.Fleet.DevicesCount)
	}
	cov := ep.MetricCoverage["hardening.disk_encryption_pct"]
	if cov.PassingDevicesCount+cov.FailingDevicesCount != MaxDevices+5 {
		t.Errorf("coverage should count every device, got %+v", cov)
	}
	meta := ep.Inventories[inventoryDevices]
	if !meta.OutputTruncated || meta.ReturnedRowsCount != MaxDevices || *meta.DroppedRowsCount != 5 || !meta.CollectionComplete {
		t.Errorf("inventory meta = %+v", meta)
	}
}

func TestEndpoint_UnmeasuredMetricsAreExplained(t *testing.T) {
	ep := buildEndpointPosture(inputs(componentsdk.LevelTrust, macWithFDE("a", boolPtr(true), testNow.Add(-time.Hour))))
	for _, a := range unmeasuredAvailability {
		if !availabilityHas(ep, a.Path, a.Reason) {
			t.Errorf("missing availability %s/%s", a.Path, a.Reason)
		}
	}
}

func TestOSFamily(t *testing.T) {
	cases := map[[2]string]string{
		{"darwin", "Mac OS X"}: "macos",
		{"", "Mac OS X"}:       "macos",
		{"windows", ""}:        "windows",
		{"", "Windows"}:        "windows",
		{"", "Ubuntu"}:         "linux",
		{"", "iPadOS"}:         "ipados",
		{"", "iOS"}:            "ios",
		{"", "Android"}:        "android",
		{"", "Plan 9"}:         "other",
		{"", ""}:               "unknown",
	}
	for in, want := range cases {
		if got := osFamily(&jumpcloud.System{OSFamily: in[0], OS: in[1]}); got != want {
			t.Errorf("osFamily(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
