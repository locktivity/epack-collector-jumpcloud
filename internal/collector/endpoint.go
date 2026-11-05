package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

const (
	EndpointSchemaVersion = "1.0.0"
	scopeProviderVisible  = "provider_visible_devices"
	maxClockSkew          = 5 * time.Minute

	controlDiskEncryption       = "disk_encryption"
	controlFirewall             = "firewall"
	controlAntimalwareInstalled = "antimalware_installed"
	controlAntimalwareHealthy   = "antimalware_healthy"

	inventoryLocalAdmins = "devices[].local_admin_accounts"
)

type endpointMetric struct {
	path    string
	control string
	// pointer is the metric's JSON pointer in the endpoint artifact, and
	// summary is the pointer of its summary in the detailed artifact.
	pointer string
	summary string
}

var measuredMetrics = []endpointMetric{
	{"hardening.disk_encryption_pct", controlDiskEncryption, "/hardening/disk_encryption_pct", "/device_controls/disk_encryption"},
	{"hardening.firewall_enabled_pct", controlFirewall, "/hardening/firewall_enabled_pct", "/device_controls/firewall"},
	{"protection.antimalware_installed_pct", controlAntimalwareInstalled, "/protection/antimalware_installed_pct", "/device_controls/antimalware_installed"},
	{"protection.antimalware_healthy_pct", controlAntimalwareHealthy, "/protection/antimalware_healthy_pct", "/device_controls/antimalware_healthy"},
}

// unmeasuredEndpointValues are the endpoint values the collector never
// writes, each with its gap's code and reason. The code is unsupported for a
// value JumpCloud does not report and not_read for one it reports in a call
// the collector does not make. path is the availability path, or "" for an
// audit-level count the availability list does not name.
var unmeasuredEndpointValues = []struct {
	pointer, path string
	code          componentsdk.Code
	reason        string
}{
	{"/compliance/compliant_pct", "compliance.compliant_pct", componentsdk.CodeNotRead,
		"JumpCloud's Google EMM device API reports whether each Android device complies with its policy, which this collector does not read."},
	{"/hardening/screen_lock_compliant_pct", "hardening.screen_lock_compliant_pct", componentsdk.CodeNotRead,
		"JumpCloud's Apple MDM device API reports whether each Apple device's passcode meets its policy, which this collector does not read."},
	{"/patching/os_baseline_compliant_pct", "patching.os_baseline_compliant_pct", componentsdk.CodeUnsupported,
		"JumpCloud does not report whether a device's operating system meets a baseline."},
	{"/patching/os_supported_pct", "patching.os_supported_pct", componentsdk.CodeUnsupported, noOSSupport},
	{"/patching/unsupported_os_count", "", componentsdk.CodeUnsupported, noOSSupport},
	{"/protection/edr_healthy_pct", "protection.edr_healthy_pct", componentsdk.CodeUnsupported, noEDR},
	{"/protection/edr_installed_pct", "protection.edr_installed_pct", componentsdk.CodeUnsupported, noEDR},
}

const (
	noOSSupport = "JumpCloud does not report whether a device's operating system version still gets security updates."
	noEDR       = "JumpCloud does not report whether an EDR agent is installed or healthy."
	// noSource is the reason for a measured control no device in the fleet
	// has a JumpCloud source for.
	noSource = "No device in the fleet has a source JumpCloud reports for this control."
	// noDiskEncryptionSource is the reason for disk encryption when no
	// device has a reading and some run macOS or Linux.
	noDiskEncryptionSource = "JumpCloud's System Insights disk_encryption table reports disk encryption on macOS and Linux, which this collector does not read."
	// noVerdict is the reason for a measured control that has fresh System
	// Insights readings when none of them is a pass or a fail.
	noVerdict = "System Insights has fresh readings for this control, but none of them is a clear pass or fail."
)

// unmeasuredAvailability lists the availability entries of the values in
// unmeasuredEndpointValues.
var unmeasuredAvailability = func() []AvailabilityEntry {
	var out []AvailabilityEntry
	for _, u := range unmeasuredEndpointValues {
		if u.path != "" {
			out = append(out, AvailabilityEntry{Path: u.path, Reason: availabilityReason(u.code), Message: u.reason})
		}
	}
	return out
}()

// availabilityReason is the availability reason for a value with no
// reading. It matches the value's gap code. A not_read value's message
// includes the JumpCloud API that reports it.
func availabilityReason(code componentsdk.Code) string {
	if code == componentsdk.CodeNotRead {
		return reasonNotRead
	}
	return reasonUnsupported
}

// unjudged reports whether a device has a fresh System Insights reading for
// the control that is neither a pass nor a fail. An unknown reading has an
// observation time only when it comes from a System Insights row.
func unjudged(devices []evaluatedDevice, control string) bool {
	for _, d := range devices {
		if r := d.controls[control]; r.state == stateUnknown && !r.observedAt.IsZero() {
			return true
		}
	}
	return false
}

// noSourceCode is the gap code for a measured control that no device in
// the fleet has a reading for. JumpCloud's System Insights disk_encryption
// table covers macOS and Linux, so disk encryption on a fleet with such a
// device is not_read. Every other case is unsupported.
func noSourceCode(control string, devices []evaluatedDevice) componentsdk.Code {
	if control != controlDiskEncryption {
		return componentsdk.CodeUnsupported
	}
	for _, d := range devices {
		if d.family == "macos" || d.family == "linux" {
			return componentsdk.CodeNotRead
		}
	}
	return componentsdk.CodeUnsupported
}

// noSourceReason is the gap reason for a measured control with code.
func noSourceReason(code componentsdk.Code) string {
	if code == componentsdk.CodeNotRead {
		return noDiskEncryptionSource
	}
	return noSource
}

// insightSource holds one System Insights table grouped by system ID, and
// how complete the read was. err is the error the read failed with, and
// capped is true when the collector's row limit stopped it.
type insightSource[T any] struct {
	byDevice map[string][]T
	capped   bool
	err      error
	op       string
}

func newInsightSource[T any](rows []T, capped bool, key func(T) string) *insightSource[T] {
	src := &insightSource[T]{byDevice: make(map[string][]T), capped: capped}
	for _, r := range rows {
		if k := key(r); k != "" {
			src.byDevice[k] = append(src.byDevice[k], r)
		}
	}
	return src
}

// failure returns why the table's rows could not all be read, or nil. A
// read the row limit stopped returns a too_large error.
func (s *insightSource[T]) failure() error {
	switch {
	case s == nil:
		return nil
	case s.err != nil:
		return s.err
	case s.capped:
		return capped(s.op, jumpcloud.MaxInsightRows)
	}
	return nil
}

// missingReason explains why a device has no row in this table.
func (s *insightSource[T]) missingReason() string {
	switch {
	case s == nil:
		return ""
	case s.err != nil && isDenied(s.err):
		return reasonPermissionDenied
	case s.err != nil:
		return reasonSourceError
	case s.capped:
		return reasonPartial
	}
	return ""
}

// unread returns the unknown reading of a device whose rows this table
// could not provide because the read failed or was cut short.
func (s *insightSource[T]) unread() controlResult {
	return controlResult{state: stateUnknown, reason: s.missingReason(), err: s.failure()}
}

func fetchInsight[T any](ctx context.Context, diag *diagnosticsTracker, surface, op string,
	fetch func(context.Context) ([]T, bool, error), key func(T) string) *insightSource[T] {
	rows, capped, err := fetch(ctx)
	if err != nil {
		recordSurfaceError(diag, surface, err)
		return &insightSource[T]{err: err, op: op}
	}
	if capped {
		diag.surfaceWarning(surface, "results capped at internal limit; device telemetry may be incomplete")
	}
	src := newInsightSource(rows, capped, key)
	src.op = op
	return src
}

type endpointInputs struct {
	systems     []jumpcloud.System
	serverTotal int
	users       []jumpcloud.SystemUser
	orgID       string
	level       componentsdk.Level
	now         time.Time
	maxAge      time.Duration

	conflicts map[string]recordConflict

	bitlocker    *insightSource[jumpcloud.InsightBitLocker]
	alf          *insightSource[jumpcloud.InsightALF]
	wsc          *insightSource[jumpcloud.InsightWindowsSecurityCenter]
	products     *insightSource[jumpcloud.InsightWindowsSecurityProduct]
	insightUsers *insightSource[jumpcloud.InsightUser]
}

// fetchEndpointTelemetry reads the System Insights tables the endpoint
// artifact needs. Tables are only requested for OS families present in the
// fleet. A denied or failing table leaves the readings that need it out,
// with a gap.
func (c *Collector) fetchEndpointTelemetry(ctx context.Context, diag *diagnosticsTracker, in *endpointInputs) {
	families := make(map[string]bool)
	for i := range in.systems {
		families[osFamily(&in.systems[i])] = true
	}

	if families["windows"] {
		c.status("Fetching Windows device telemetry")
		in.bitlocker = fetchInsight(ctx, diag, "system_insights.bitlocker_info", jumpcloud.OpListBitLocker, c.client.ListBitLockerInfo,
			func(r jumpcloud.InsightBitLocker) string { return r.SystemID })
		in.wsc = fetchInsight(ctx, diag, "system_insights.windows_security_center", jumpcloud.OpListWindowsSecurityCenter, c.client.ListWindowsSecurityCenter,
			func(r jumpcloud.InsightWindowsSecurityCenter) string { return r.SystemID })
		in.products = fetchInsight(ctx, diag, "system_insights.windows_security_products", jumpcloud.OpListWindowsSecurityProducts, c.client.ListWindowsSecurityProducts,
			func(r jumpcloud.InsightWindowsSecurityProduct) string { return r.SystemID })
	}
	if families["macos"] {
		c.status("Fetching macOS device telemetry")
		in.alf = fetchInsight(ctx, diag, "system_insights.alf", jumpcloud.OpListALF, c.client.ListALF,
			func(r jumpcloud.InsightALF) string { return r.SystemID })
	}
	if in.level.AtLeast(componentsdk.LevelInternal) {
		c.status("Fetching local accounts")
		in.insightUsers = fetchInsight(ctx, diag, "system_insights.users", jumpcloud.OpListInsightUsers, c.client.ListInsightUsers,
			func(r jumpcloud.InsightUser) string { return r.SystemID })
	}
}

type controlResult struct {
	state      string
	observedAt time.Time
	reason     string
	// err is set when the reading is unknown because a table it needs
	// could not be read. Such a reading is left out with a gap.
	err error
}

func unknownBecause(reason string) controlResult {
	return controlResult{state: stateUnknown, reason: reason}
}

type evaluatedDevice struct {
	system   *jumpcloud.System
	family   string
	controls map[string]controlResult
}

// observations returns the device's readings, leaving out each one a
// failed table read left unknown.
func (d evaluatedDevice) observations() map[string]ControlObservation {
	out := make(map[string]ControlObservation, len(d.controls))
	for name, r := range d.controls {
		if r.err != nil {
			continue
		}
		obs := ControlObservation{State: r.state}
		if !r.observedAt.IsZero() {
			obs.ObservedAt = r.observedAt.UTC().Format(time.RFC3339)
		}
		out[name] = obs
	}
	return out
}

// buildEndpointPosture assembles the endpoint artifact from data already
// fetched for the detailed artifact. It is independent of user discovery,
// so an empty or partial user population never suppresses device evidence.
// It records no gaps. The collector records them from unread and
// truncatedDevices.
func buildEndpointPosture(in endpointInputs) *EndpointPosture {
	systems, conflicts := reconcileSystems(in.systems, in.now)
	in.conflicts = conflicts
	shortfall := systemsShortfall(len(in.systems), len(systems), in.serverTotal)
	complete := shortfall == nil
	audit := in.level.AtLeast(componentsdk.LevelAudit)

	ep := &EndpointPosture{
		SchemaVersion: EndpointSchemaVersion,
		CollectedAt:   in.now.Format(time.RFC3339),
		Provider:      "jumpcloud",
		Scope: EndpointScope{
			DiscoveryComplete:        discoveryComplete(shortfall),
			Description:              scopeProviderVisible,
			MaxObservationAgeSeconds: int64(in.maxAge / time.Second),
		},
		Availability: []AvailabilityEntry{},
		coverage:     map[string]MetricCoverage{},
		unread:       map[string]unreadControl{},
		noSource:     map[string]componentsdk.Code{},
	}
	if audit {
		observed := len(systems)
		ep.Scope.ObservedDeviceCount = &observed
		ep.OrganizationID = in.orgID
	}

	devices := make([]evaluatedDevice, 0, len(systems))
	for _, s := range systems {
		devices = append(devices, evaluateDevice(s, in))
	}

	ep.controlsByDevice = make(map[string]map[string]ControlObservation, len(devices))
	for _, d := range devices {
		ep.controlsByDevice[d.system.ID] = d.observations()
		for name, r := range d.controls {
			if r.err == nil {
				continue
			}
			u := ep.unread[name]
			if u.devices == nil {
				u = unreadControl{devices: map[string]error{}, first: r.err}
			}
			u.devices[d.system.ID] = r.err
			ep.unread[name] = u
		}
	}

	if complete {
		applyFleetMetrics(ep, devices, audit)
	} else {
		ep.Availability = append(ep.Availability, AvailabilityEntry{Path: "fleet", Reason: reasonPartial})
		for _, m := range measuredMetrics {
			ep.Availability = append(ep.Availability, AvailabilityEntry{Path: m.path, Reason: reasonPartial})
		}
	}
	ep.Availability = append(ep.Availability, unmeasuredAvailability...)

	if audit {
		applyDeviceInventory(ep, devices, in)
	}

	sort.SliceStable(ep.Availability, func(i, j int) bool {
		if ep.Availability[i].Path != ep.Availability[j].Path {
			return ep.Availability[i].Path < ep.Availability[j].Path
		}
		return ep.Availability[i].Reason < ep.Availability[j].Reason
	})
	return ep
}

// discoveryComplete says whether every system was listed, given the
// systems list's shortfall. It is false when the collector's row limit
// stopped the list. A list that ends early or repeats a device leaves it
// unknown, so it is nil. The collector records the shortfall's gap on it.
func discoveryComplete(shortfall error) *bool {
	switch {
	case shortfall == nil:
		return boolPtr(true)
	case componentsdk.Classify(shortfall) == componentsdk.CodeTooLarge:
		return boolPtr(false)
	}
	return nil
}

// discovered reports whether every system was listed.
func (ep *EndpointPosture) discovered() bool {
	return ep.Scope.DiscoveryComplete != nil && *ep.Scope.DiscoveryComplete
}

// reconcileSystems collapses duplicate records for one device ID without
// letting input order decide the result. The record with the newest valid
// lastContact wins. Without a single newest record, fields the candidates
// disagree on are cleared to unknown, and the returned conflicts record which
// fields disagreed so evaluators do not mistake a cleared field for absence.
func reconcileSystems(systems []jumpcloud.System, now time.Time) ([]*jumpcloud.System, map[string]recordConflict) {
	groups := make(map[string][]*jumpcloud.System)
	for i := range systems {
		if s := &systems[i]; s.ID != "" {
			groups[s.ID] = append(groups[s.ID], s)
		}
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]*jumpcloud.System, 0, len(ids))
	conflicts := make(map[string]recordConflict)
	for _, id := range ids {
		candidates := newestRecords(groups[id], now)
		if len(candidates) == 1 {
			out = append(out, candidates[0])
			continue
		}
		sort.Slice(candidates, func(i, j int) bool { return canonicalJSON(candidates[i]) < canonicalJSON(candidates[j]) })
		merged := *candidates[0]
		var conflict recordConflict
		if !agree(candidates, fdeState) {
			merged.FDE = nil
			conflict.fde = true
		}
		if !agree(candidates, func(s *jumpcloud.System) string { return fmt.Sprint(s.HasMDM()) }) {
			merged.MDM = nil
		}
		if !agree(candidates, osFamily) {
			merged.OS, merged.OSFamily = "", ""
			conflict.os = true
		}
		if conflict != (recordConflict{}) {
			conflicts[id] = conflict
		}
		out = append(out, &merged)
	}
	return out, conflicts
}

// recordConflict marks fields that equally fresh duplicate records disagreed on.
type recordConflict struct {
	fde bool
	os  bool
}

func newestRecords(records []*jumpcloud.System, now time.Time) []*jumpcloud.System {
	var newest []*jumpcloud.System
	var at time.Time
	for _, r := range records {
		t, ok := parseObservationTime(r.LastContact, now)
		switch {
		case !ok:
		case newest == nil || t.After(at):
			newest, at = []*jumpcloud.System{r}, t
		case t.Equal(at):
			newest = append(newest, r)
		}
	}
	if newest == nil {
		return records
	}
	return newest
}

func agree(records []*jumpcloud.System, value func(*jumpcloud.System) string) bool {
	for _, r := range records[1:] {
		if value(r) != value(records[0]) {
			return false
		}
	}
	return true
}

func fdeState(s *jumpcloud.System) string {
	if s.FDE == nil || s.FDE.Active == nil {
		return "unknown"
	}
	return fmt.Sprint(*s.FDE.Active)
}

func canonicalJSON(s *jumpcloud.System) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func evaluateDevice(s *jumpcloud.System, in endpointInputs) evaluatedDevice {
	family := osFamily(s)
	installed, healthy := evalAntimalware(s, family, in)
	controls := map[string]controlResult{
		controlDiskEncryption:       evalDiskEncryption(s, family, in),
		controlFirewall:             evalFirewall(s, family, in),
		controlAntimalwareInstalled: installed,
		controlAntimalwareHealthy:   healthy,
	}
	if in.conflicts[s.ID].os {
		for name, r := range controls {
			if r.state == stateUnknown && r.reason == "" {
				r.reason = reasonSourceError
				controls[name] = r
			}
		}
	}
	return evaluatedDevice{system: s, family: family, controls: controls}
}

// applyFleetMetrics writes the fleet totals and each measured control's
// percentage. A control with any reading a failed table read left out has
// no percentage or coverage. The counts and coverage are written from the
// audit level.
func applyFleetMetrics(ep *EndpointPosture, devices []evaluatedDevice, audit bool) {
	total := len(devices)
	mdm := 0
	byOS := map[string]int{}
	for _, d := range devices {
		if d.system.HasMDM() {
			mdm++
		}
		byOS[d.family]++
	}
	present := total > 0
	ep.Fleet = &EndpointFleet{
		DevicesPresent: &present,
		MDMEnrolledPct: known(componentsdk.Percent(mdm, total, componentsdk.RoundDown)),
	}
	if audit {
		// Every V1 system record is a device registered with JumpCloud
		// through its agent or MDM, so each one is managed.
		managed := total
		ep.Fleet.DeviceCount = &total
		ep.Fleet.ManagedDeviceCount = &managed
		ep.Fleet.MDMEnrolledDeviceCount = &mdm
		if total > 0 {
			ep.Fleet.DevicesByOS = byOS
		}
		ep.MetricCoverage = map[string]MetricCoverage{}
	}

	hardening := &EndpointHardening{}
	protection := &EndpointProtection{}
	for _, m := range measuredMetrics {
		cov, reasons := tallyControl(devices, m.control)
		ep.coverage[m.path] = cov
		for _, r := range reasons {
			ep.Availability = append(ep.Availability, AvailabilityEntry{Path: m.path, Reason: r})
		}
		if len(ep.unread[m.control].devices) > 0 {
			continue
		}
		if audit {
			ep.MetricCoverage[m.path] = cov
		}
		value := endpointPct(cov, total)
		switch {
		case value.Read || len(reasons) > 0 || total == 0:
		case unjudged(devices, m.control):
			ep.Availability = append(ep.Availability, AvailabilityEntry{
				Path: m.path, Reason: reasonSourceError, Message: noVerdict,
			})
		default:
			code := noSourceCode(m.control, devices)
			ep.noSource[m.path] = code
			ep.Availability = append(ep.Availability, AvailabilityEntry{
				Path: m.path, Reason: availabilityReason(code), Message: noSourceReason(code),
			})
		}
		switch m.path {
		case "hardening.disk_encryption_pct":
			hardening.DiskEncryptionPct = value
		case "hardening.firewall_enabled_pct":
			hardening.FirewallEnabledPct = value
		case "protection.antimalware_installed_pct":
			protection.AntimalwareInstalledPct = value
		case "protection.antimalware_healthy_pct":
			protection.AntimalwareHealthyPct = value
		}
	}
	if hardening.DiskEncryptionPct.Read || hardening.FirewallEnabledPct.Read {
		ep.Hardening = hardening
	}
	if protection.AntimalwareInstalledPct.Read || protection.AntimalwareHealthyPct.Read {
		ep.Protection = protection
	}
}

// endpointPct is passing over evaluated devices, rounded down as the
// endpoint-posture schema says. It is null for a fleet with no devices, and
// left out when devices exist but none passed or failed.
func endpointPct(c MetricCoverage, devices int) Percentage {
	if devices == 0 {
		return Percentage{Read: true}
	}
	evaluated := c.PassingDevicesCount + c.FailingDevicesCount
	if evaluated == 0 {
		return Percentage{}
	}
	return known(componentsdk.Percent(c.PassingDevicesCount, evaluated, componentsdk.RoundDown))
}

// tallyControl partitions devices for one control and returns the distinct
// reasons behind unknown readings, sorted for stable output.
func tallyControl(devices []evaluatedDevice, control string) (MetricCoverage, []string) {
	var cov MetricCoverage
	reasonSet := make(map[string]bool)
	for _, d := range devices {
		r := d.controls[control]
		switch r.state {
		case statePass:
			cov.PassingDevicesCount++
		case stateFail:
			cov.FailingDevicesCount++
		case stateNotApplicable:
			cov.NotApplicableDevicesCount++
		default:
			cov.UnknownDevicesCount++
			if r.reason != "" {
				reasonSet[r.reason] = true
			}
		}
	}
	reasons := make([]string, 0, len(reasonSet))
	for r := range reasonSet {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return cov, reasons
}

// coveragePct is passing over evaluated (passing + failing) for the
// detailed artifact. It is nil when nothing was evaluated, so a fleet of
// unknowns never reads as 0% or 100%.
func coveragePct(c MetricCoverage) *float64 {
	evaluated := c.PassingDevicesCount + c.FailingDevicesCount
	if evaluated == 0 {
		return nil
	}
	v := round2(float64(c.PassingDevicesCount) / float64(evaluated) * 100)
	return &v
}

func applyDeviceInventory(ep *EndpointPosture, devices []evaluatedDevice, in endpointInputs) {
	logins := make(map[string]string, len(in.users))
	for _, u := range in.users {
		logins[u.ID] = u.Username
	}
	internal := in.level.AtLeast(componentsdk.LevelInternal)

	rows := make([]EndpointDevice, 0, len(devices))
	unclassified := 0
	for _, d := range devices {
		s := d.system
		row := EndpointDevice{
			DeviceID:        s.ID,
			Hostname:        s.Hostname,
			OSFamily:        d.family,
			OSName:          s.OS,
			OSVersion:       s.OSVersionString(),
			ManagementState: "managed",
			InScope:         true,
			CreatedAt:       formatObservation(s.Created, in.now),
			LastSeenAt:      formatObservation(s.LastContact, in.now),
		}
		if s.PrimarySystemUser != nil && s.PrimarySystemUser.ID != "" {
			row.AssignedUser = &AssignedUser{UserID: s.PrimarySystemUser.ID, Login: logins[s.PrimarySystemUser.ID]}
		}
		row.Controls = ep.controlsByDevice[s.ID]
		if internal {
			row.LocalAdminAccounts = localAdmins(s.ID, in)
			if row.LocalAdminAccounts == nil {
				unclassified++
			}
		}
		rows = append(rows, row)
	}

	kept := rows
	if len(rows) > MaxDevices {
		kept = rows[:MaxDevices]
	}
	ep.truncatedDevices = len(rows) - len(kept)
	ep.Devices = kept

	if internal {
		switch sourceReason := in.insightUsers.missingReason(); {
		case sourceReason != "":
			ep.Availability = append(ep.Availability, AvailabilityEntry{Path: inventoryLocalAdmins, Reason: sourceReason})
		case unclassified > 0:
			ep.Availability = append(ep.Availability, AvailabilityEntry{
				Path: inventoryLocalAdmins, Reason: reasonPartial,
				Message: "some devices have no current account list or accounts without an admin flag",
			})
		}
	}
}

// --- Control evaluation ---
//
// Every judge enumerates the states it recognizes as passing and failing.
// Anything else stays unknown, including values osquery reports as
// "Unknown". A table that failed or hit the row limit gives no reading, and
// the reading is left out with a gap. Rows beyond the limit could hold a
// newer observation or the row that decides the result.

// evalDiskEncryption uses BitLocker on Windows because it distinguishes
// suspended protection, which the agent's fde.active flag does not. Without
// a usable BitLocker reading, a fresh fde.active=false is still a failure.
func evalDiskEncryption(s *jumpcloud.System, family string, in endpointInputs) controlResult {
	// Conflicting OS records leave no way to choose between the BitLocker and
	// fde.active evaluators, and the wrong one can pass suspended protection.
	if in.conflicts[s.ID].os {
		return unknownBecause(reasonSourceError)
	}
	if family != "windows" {
		return fdeResult(s, in)
	}
	r := evalBitLocker(s.ID, in)
	if !r.observedAt.IsZero() {
		return r
	}
	if fde := fdeResult(s, in); fde.state == stateFail {
		return fde
	}
	return r
}

// fdeResult reads the agent's fde.active flag. The flag carries no
// observation time, so it is accepted only from devices whose last agent
// contact is within the age limit, and no observed_at is reported.
func fdeResult(s *jumpcloud.System, in endpointInputs) controlResult {
	if in.conflicts[s.ID].fde {
		return unknownBecause(reasonSourceError)
	}
	if !isFresh(s.LastContact, in) {
		return unknownBecause(reasonStale)
	}
	if s.FDE == nil || s.FDE.Active == nil {
		return unknownBecause("")
	}
	if *s.FDE.Active {
		return controlResult{state: statePass}
	}
	return controlResult{state: stateFail}
}

// evalBitLocker never guesses which volume holds Windows. BitLocker lists
// every encryptable volume, the OS volume among them, so the device passes
// only when every volume's latest reading passes and fails only when every
// one fails. A mix, such as a protected data volume beside an unprotected
// one, is unknown.
func evalBitLocker(systemID string, in endpointInputs) controlResult {
	src := in.bitlocker
	if src == nil {
		return unknownBecause("")
	}
	if src.failure() != nil {
		return src.unread()
	}
	rows := src.byDevice[systemID]
	if len(rows) == 0 {
		return unknownBecause("")
	}

	byVolume := make(map[string][]jumpcloud.InsightBitLocker)
	for _, r := range rows {
		byVolume[bitlockerVolumeKey(r)] = append(byVolume[bitlockerVolumeKey(r)], r)
	}
	state := ""
	staleVolume := false
	var observed time.Time
	for _, volumeRows := range byVolume {
		v := fromRows(volumeRows, in, func(r jumpcloud.InsightBitLocker) string { return r.CollectionTime }, judgeBitLocker)
		if v.observedAt.IsZero() {
			staleVolume = true
			continue
		}
		if v.observedAt.After(observed) {
			observed = v.observedAt
		}
		switch {
		case state == "":
			state = v.state
		case state != v.state:
			state = stateUnknown
		}
	}
	if observed.IsZero() {
		return unknownBecause(reasonStale)
	}
	if staleVolume {
		return controlResult{state: stateUnknown, observedAt: observed, reason: reasonStale}
	}
	return controlResult{state: state, observedAt: observed}
}

func bitlockerVolumeKey(r jumpcloud.InsightBitLocker) string {
	if r.DeviceID != nil && strings.TrimSpace(*r.DeviceID) != "" {
		return strings.TrimSpace(*r.DeviceID)
	}
	if r.DriveLetter != nil {
		return strings.ToUpper(strings.TrimSpace(*r.DriveLetter))
	}
	return ""
}

// judgeBitLocker passes only a fully encrypted volume with protection on.
// Protection off (including suspended) fails, as do the recognized
// not-fully-encrypted conversion states. Protection status 2 (unknown) and
// unrecognized codes stay unknown.
func judgeBitLocker(r jumpcloud.InsightBitLocker) string {
	ps, cs := r.ProtectionStatus, r.ConversionStatus
	if ps != nil && *ps == 1 && cs != nil && *cs == 1 {
		return statePass
	}
	if ps != nil && *ps == 0 {
		return stateFail
	}
	if cs != nil {
		switch *cs {
		case 0, 2, 3, 4, 5:
			return stateFail
		}
	}
	return stateUnknown
}

func evalFirewall(s *jumpcloud.System, family string, in endpointInputs) controlResult {
	switch family {
	case "macos":
		return fromInsight(in.alf, s.ID, in, func(r jumpcloud.InsightALF) string { return r.CollectionTime }, judgeALF)
	case "windows":
		return fromInsight(in.wsc, s.ID, in, func(r jumpcloud.InsightWindowsSecurityCenter) string { return r.CollectionTime }, judgeWSCFirewall)
	}
	return unknownBecause("")
}

func judgeALF(r jumpcloud.InsightALF) string {
	if r.GlobalState == nil {
		return stateUnknown
	}
	switch *r.GlobalState {
	case 0:
		return stateFail
	case 1, 2:
		return statePass
	}
	return stateUnknown
}

// judgeWSCFirewall maps Windows Security Center health. Only Good and Poor
// are definitive. Snoozed, Not Monitored, and Error are unknown.
func judgeWSCFirewall(r jumpcloud.InsightWindowsSecurityCenter) string {
	if r.Firewall == nil {
		return stateUnknown
	}
	switch strings.ToLower(strings.TrimSpace(*r.Firewall)) {
	case "good":
		return statePass
	case "poor":
		return stateFail
	}
	return stateUnknown
}

// productKind classifies a Windows Security Center product row. Rows with a
// missing or unrecognized type are unclassified, so they could be antivirus.
func productKind(r jumpcloud.InsightWindowsSecurityProduct) string {
	if r.Type == nil {
		return ""
	}
	switch k := strings.ToLower(strings.TrimSpace(*r.Type)); k {
	case "antivirus", "firewall", "antispyware":
		return k
	}
	return ""
}

// productHealth is pass for a product that is on with current signatures,
// fail for one that is off, snoozed, expired, or has outdated signatures,
// and unknown otherwise.
func productHealth(r jumpcloud.InsightWindowsSecurityProduct) string {
	state := ""
	if r.State != nil {
		state = strings.ToLower(strings.TrimSpace(*r.State))
	}
	sig := r.SignaturesUpToDate
	if state == "on" && sig != nil && *sig == 1 {
		return statePass
	}
	switch {
	case state == "off" || state == "snoozed" || state == "expired":
		return stateFail
	case sig != nil && *sig == 0:
		return stateFail
	}
	return stateUnknown
}

// evalAntimalware reads the products registered with Windows Security
// Center. Absence, or every antivirus product being unhealthy, needs a
// complete, fully classified snapshot of the device's products.
func evalAntimalware(s *jumpcloud.System, family string, in endpointInputs) (controlResult, controlResult) {
	if family != "windows" {
		return unknownBecause(""), unknownBecause("")
	}
	src := in.products
	if src.failure() != nil {
		return src.unread(), src.unread()
	}
	if src == nil || len(src.byDevice[s.ID]) == 0 {
		return unknownBecause(""), unknownBecause("")
	}
	latest, at, ok := latestFresh(src.byDevice[s.ID], func(r jumpcloud.InsightWindowsSecurityProduct) string { return r.CollectionTime }, in)
	if !ok {
		return unknownBecause(reasonStale), unknownBecause(reasonStale)
	}

	unclassified := 0
	var antivirus []jumpcloud.InsightWindowsSecurityProduct
	for _, r := range latest {
		switch productKind(r) {
		case "antivirus":
			antivirus = append(antivirus, r)
		case "":
			unclassified++
		}
	}

	pass := controlResult{state: statePass, observedAt: at}
	fail := controlResult{state: stateFail, observedAt: at}
	unknown := controlResult{state: stateUnknown, observedAt: at}

	if len(antivirus) == 0 {
		if unclassified > 0 {
			return unknown, unknown
		}
		return fail, fail
	}

	allFailing := unclassified == 0
	for _, r := range antivirus {
		switch productHealth(r) {
		case statePass:
			return pass, pass
		case stateUnknown:
			allFailing = false
		}
	}
	if allFailing {
		return pass, fail
	}
	return pass, unknown
}

// localAdmins lists accounts positively flagged as local administrators. A
// device with any account whose admin flag is missing returns nil, which is
// unknown, because an unclassified account could be an administrator. A
// table that failed or hit the row limit also returns nil, and the
// collector records a gap for each device.
func localAdmins(systemID string, in endpointInputs) *[]LocalAdminAccount {
	src := in.insightUsers
	if src == nil || src.failure() != nil {
		return nil
	}
	latest, _, ok := latestFresh(src.byDevice[systemID], func(r jumpcloud.InsightUser) string { return r.CollectionTime }, in)
	if !ok {
		return nil
	}
	admins := []LocalAdminAccount{}
	for _, r := range latest {
		if r.Admin == nil {
			return nil
		}
		if !*r.Admin {
			continue
		}
		var a LocalAdminAccount
		if r.UID != nil {
			a.AccountID = *r.UID
		}
		if r.Username != nil {
			a.Username = *r.Username
		}
		admins = append(admins, a)
	}
	sort.Slice(admins, func(i, j int) bool { return admins[i].Username < admins[j].Username })
	return &admins
}

// fromInsight evaluates a single-reading control for a device from a table.
func fromInsight[T any](src *insightSource[T], systemID string, in endpointInputs, ts func(T) string, judge func(T) string) controlResult {
	if src == nil {
		return unknownBecause("")
	}
	if src.failure() != nil {
		return src.unread()
	}
	rows := src.byDevice[systemID]
	if len(rows) == 0 {
		return unknownBecause("")
	}
	return fromRows(rows, in, ts, judge)
}

// fromRows judges the latest fresh rows. Rows sharing the latest timestamp
// that disagree yield unknown rather than picking one.
func fromRows[T any](rows []T, in endpointInputs, ts func(T) string, judge func(T) string) controlResult {
	latest, at, ok := latestFresh(rows, ts, in)
	if !ok {
		return unknownBecause(reasonStale)
	}
	state := ""
	for _, r := range latest {
		s := judge(r)
		if state == "" {
			state = s
		} else if state != s {
			return controlResult{state: stateUnknown, observedAt: at}
		}
	}
	return controlResult{state: state, observedAt: at}
}

// --- Observation time handling ---

// observationLayouts accepts RFC3339 and the "2006-01-02 15:04:05 -0700"
// form System Insights uses. Times without a zone are rejected as
// unverifiable.
var observationLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 -07:00",
	"2006-01-02 15:04:05.999999999 -0700",
}

func parseObservationTime(s string, now time.Time) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range observationLayouts {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if t.After(now.Add(maxClockSkew)) {
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	return time.Time{}, false
}

func isFresh(s string, in endpointInputs) bool {
	t, ok := parseObservationTime(s, in.now)
	return ok && in.now.Sub(t) <= in.maxAge
}

func formatObservation(s string, now time.Time) string {
	t, ok := parseObservationTime(s, now)
	if !ok {
		return ""
	}
	return t.Format(time.RFC3339)
}

// latestFresh returns every row sharing the newest valid, in-window
// observation time.
func latestFresh[T any](rows []T, ts func(T) string, in endpointInputs) ([]T, time.Time, bool) {
	var latest []T
	var at time.Time
	for _, r := range rows {
		t, ok := parseObservationTime(ts(r), in.now)
		if !ok || in.now.Sub(t) > in.maxAge {
			continue
		}
		switch {
		case latest == nil || t.After(at):
			latest, at = []T{r}, t
		case t.Equal(at):
			latest = append(latest, r)
		}
	}
	return latest, at, latest != nil
}

// --- OS normalization ---

func osFamily(s *jumpcloud.System) string {
	switch strings.ToLower(strings.TrimSpace(s.OSFamily)) {
	case "darwin", "macos":
		return "macos"
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "ios":
		return "ios"
	case "ipados":
		return "ipados"
	case "android":
		return "android"
	case "chromeos":
		return "chromeos"
	}

	os := strings.ToLower(strings.TrimSpace(s.OS))
	switch {
	case os == "":
		return "unknown"
	case os == "ipados":
		return "ipados"
	case os == "ios":
		return "ios"
	case os == "android":
		return "android"
	case strings.Contains(os, "mac os") || strings.Contains(os, "macos"):
		return "macos"
	case strings.Contains(os, "windows"):
		return "windows"
	case strings.Contains(os, "chrome"):
		return "chromeos"
	case containsAny(os, "linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "amazon", "rocky", "alma", "suse"):
		return "linux"
	}
	return "other"
}

// deviceControlsFrom copies the endpoint artifact's control coverage into the
// detailed artifact, so both report identical figures. A control with any
// reading a failed table read left out has no summary.
func deviceControlsFrom(ep *EndpointPosture) *DeviceControls {
	dc := &DeviceControls{
		DiscoveryComplete:        ep.Scope.DiscoveryComplete,
		MaxObservationAgeSeconds: ep.Scope.MaxObservationAgeSeconds,
	}
	if !ep.discovered() {
		return dc
	}
	summary := func(m endpointMetric) *ControlSummary {
		cov, ok := ep.coverage[m.path]
		if !ok || len(ep.unread[m.control].devices) > 0 {
			return nil
		}
		return &ControlSummary{
			PassingPct:                coveragePct(cov),
			PassingDevicesCount:       cov.PassingDevicesCount,
			FailingDevicesCount:       cov.FailingDevicesCount,
			UnknownDevicesCount:       cov.UnknownDevicesCount,
			NotApplicableDevicesCount: cov.NotApplicableDevicesCount,
		}
	}
	dc.DiskEncryption = summary(measuredMetrics[0])
	dc.Firewall = summary(measuredMetrics[1])
	dc.AntimalwareInstalled = summary(measuredMetrics[2])
	dc.AntimalwareHealthy = summary(measuredMetrics[3])
	return dc
}
