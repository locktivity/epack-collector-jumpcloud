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

	inventoryDevices     = "devices"
	inventoryLocalAdmins = "devices[].local_admin_accounts"
)

type endpointMetric struct {
	path    string
	control string
}

var measuredMetrics = []endpointMetric{
	{"hardening.disk_encryption_pct", controlDiskEncryption},
	{"hardening.firewall_enabled_pct", controlFirewall},
	{"protection.antimalware_installed_pct", controlAntimalwareInstalled},
	{"protection.antimalware_healthy_pct", controlAntimalwareHealthy},
}

// unmeasuredAvailability lists contract metrics this collector never emits.
// Screen lock and EDR have no verified JumpCloud source; compliance and
// patching need a named baseline that this collector does not define.
var unmeasuredAvailability = []AvailabilityEntry{
	{Path: "compliance.compliant_pct", Reason: reasonNotConfigured},
	{Path: "hardening.screen_lock_compliant_pct", Reason: reasonUnsupported},
	{Path: "patching.os_baseline_compliant_pct", Reason: reasonNotConfigured},
	{Path: "patching.os_supported_pct", Reason: reasonNotConfigured},
	{Path: "protection.edr_healthy_pct", Reason: reasonUnsupported},
	{Path: "protection.edr_installed_pct", Reason: reasonUnsupported},
}

// insightSource holds one System Insights table grouped by system ID, plus
// how complete the fetch was.
type insightSource[T any] struct {
	byDevice map[string][]T
	capped   bool
	err      error
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

func fetchInsight[T any](ctx context.Context, diag *diagnosticsTracker, surface string,
	fetch func(context.Context) ([]T, bool, error), key func(T) string) (*insightSource[T], error) {
	rows, capped, err := fetch(ctx)
	if err != nil {
		if isFatal(err) {
			return nil, err
		}
		recordSurfaceError(diag, surface, err)
		return &insightSource[T]{err: err}, nil
	}
	if capped {
		diag.surfaceWarning(surface, "results capped at internal limit; device telemetry may be incomplete")
	}
	return newInsightSource(rows, capped, key), nil
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
// fleet. Denied or failing tables degrade to unknown readings; only fatal
// errors abort.
func (c *Collector) fetchEndpointTelemetry(ctx context.Context, diag *diagnosticsTracker, in *endpointInputs) error {
	families := make(map[string]bool)
	for i := range in.systems {
		families[osFamily(&in.systems[i])] = true
	}

	var err error
	if families["windows"] {
		c.status("Fetching Windows device telemetry")
		in.bitlocker, err = fetchInsight(ctx, diag, "system_insights.bitlocker_info", c.client.ListBitLockerInfo,
			func(r jumpcloud.InsightBitLocker) string { return r.SystemID })
		if err != nil {
			return err
		}
		in.wsc, err = fetchInsight(ctx, diag, "system_insights.windows_security_center", c.client.ListWindowsSecurityCenter,
			func(r jumpcloud.InsightWindowsSecurityCenter) string { return r.SystemID })
		if err != nil {
			return err
		}
		in.products, err = fetchInsight(ctx, diag, "system_insights.windows_security_products", c.client.ListWindowsSecurityProducts,
			func(r jumpcloud.InsightWindowsSecurityProduct) string { return r.SystemID })
		if err != nil {
			return err
		}
	}
	if families["macos"] {
		c.status("Fetching macOS device telemetry")
		in.alf, err = fetchInsight(ctx, diag, "system_insights.alf", c.client.ListALF,
			func(r jumpcloud.InsightALF) string { return r.SystemID })
		if err != nil {
			return err
		}
	}
	if in.level.AtLeast(componentsdk.LevelInternal) {
		c.status("Fetching local accounts")
		in.insightUsers, err = fetchInsight(ctx, diag, "system_insights.users", c.client.ListInsightUsers,
			func(r jumpcloud.InsightUser) string { return r.SystemID })
		if err != nil {
			return err
		}
	}
	return nil
}

type controlResult struct {
	state      string
	observedAt time.Time
	reason     string
}

func unknownBecause(reason string) controlResult {
	return controlResult{state: stateUnknown, reason: reason}
}

type evaluatedDevice struct {
	system   *jumpcloud.System
	family   string
	controls map[string]controlResult
}

func (d evaluatedDevice) observations() map[string]ControlObservation {
	out := make(map[string]ControlObservation, len(d.controls))
	for name, r := range d.controls {
		obs := ControlObservation{State: r.state}
		if !r.observedAt.IsZero() {
			obs.ObservedAt = r.observedAt.UTC().Format(time.RFC3339)
		}
		out[name] = obs
	}
	return out
}

// buildEndpointPosture assembles the endpoint artifact from data already
// fetched for the detailed artifact. It is independent of user discovery:
// an empty or partial user population never suppresses device evidence.
func buildEndpointPosture(in endpointInputs) *EndpointPosture {
	systems, conflicts := reconcileSystems(in.systems, in.now)
	in.conflicts = conflicts
	complete := len(systems) >= in.serverTotal

	ep := &EndpointPosture{
		SchemaVersion:  EndpointSchemaVersion,
		CollectedAt:    in.now.Format(time.RFC3339),
		Provider:       "jumpcloud",
		OrganizationID: in.orgID,
		Scope: EndpointScope{
			DiscoveryComplete:        complete,
			ObservedDevicesCount:     len(systems),
			Description:              scopeProviderVisible,
			MaxObservationAgeSeconds: int64(in.maxAge / time.Second),
		},
		MetricCoverage: map[string]MetricCoverage{},
		Availability:   []AvailabilityEntry{},
	}

	devices := make([]evaluatedDevice, 0, len(systems))
	for _, s := range systems {
		devices = append(devices, evaluateDevice(s, in))
	}

	ep.controlsByDevice = make(map[string]map[string]ControlObservation, len(devices))
	for _, d := range devices {
		ep.controlsByDevice[d.system.ID] = d.observations()
	}

	if complete {
		applyFleetMetrics(ep, devices)
	} else {
		ep.Availability = append(ep.Availability, AvailabilityEntry{Path: "fleet", Reason: reasonPartial})
		for _, m := range measuredMetrics {
			ep.Availability = append(ep.Availability, AvailabilityEntry{Path: m.path, Reason: reasonPartial})
		}
	}
	ep.Availability = append(ep.Availability, unmeasuredAvailability...)

	if in.level.AtLeast(componentsdk.LevelAudit) {
		applyDeviceInventory(ep, devices, in, complete)
	}

	sort.SliceStable(ep.Availability, func(i, j int) bool {
		if ep.Availability[i].Path != ep.Availability[j].Path {
			return ep.Availability[i].Path < ep.Availability[j].Path
		}
		return ep.Availability[i].Reason < ep.Availability[j].Reason
	})
	return ep
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

func applyFleetMetrics(ep *EndpointPosture, devices []evaluatedDevice) {
	total := len(devices)
	mdm := 0
	byOS := make(map[string]int)
	for _, d := range devices {
		if d.system.HasMDM() {
			mdm++
		}
		byOS[d.family]++
	}
	// Every V1 system record is a device registered with JumpCloud through
	// its agent or MDM, so each one is affirmatively managed.
	managed := total
	ep.Fleet = &EndpointFleet{
		DevicesCount:            &total,
		ManagedDevicesCount:     &managed,
		MDMEnrolledDevicesCount: &mdm,
	}
	if len(byOS) > 0 {
		ep.Fleet.DevicesByOS = byOS
	}

	hardening := &EndpointHardening{}
	protection := &EndpointProtection{}
	for _, m := range measuredMetrics {
		cov, reasons := tallyControl(devices, m.control)
		ep.MetricCoverage[m.path] = cov
		value := coveragePct(cov)
		for _, r := range reasons {
			ep.Availability = append(ep.Availability, AvailabilityEntry{Path: m.path, Reason: r})
		}
		if value == nil && len(reasons) == 0 && total > 0 {
			ep.Availability = append(ep.Availability, AvailabilityEntry{
				Path: m.path, Reason: reasonUnsupported,
				Message: "no in-scope device has a supported source for this control",
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
	if hardening.DiskEncryptionPct != nil || hardening.FirewallEnabledPct != nil {
		ep.Hardening = hardening
	}
	if protection.AntimalwareInstalledPct != nil || protection.AntimalwareHealthyPct != nil {
		ep.Protection = protection
	}
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

// coveragePct is passing over evaluated (passing + failing). Nil when nothing
// was evaluated, so a fleet of unknowns never reads as 0% or 100%.
func coveragePct(c MetricCoverage) *float64 {
	evaluated := c.PassingDevicesCount + c.FailingDevicesCount
	if evaluated == 0 {
		return nil
	}
	v := round2(float64(c.PassingDevicesCount) / float64(evaluated) * 100)
	return &v
}

func applyDeviceInventory(ep *EndpointPosture, devices []evaluatedDevice, in endpointInputs, complete bool) {
	logins := make(map[string]string, len(in.users))
	for _, u := range in.users {
		logins[u.ID] = u.Username
	}
	internal := in.level.AtLeast(componentsdk.LevelInternal)

	rows := make([]EndpointDevice, 0, len(devices))
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
		row.Controls = d.observations()
		if internal {
			row.LocalAdminAccounts = localAdmins(s.ID, in)
		}
		rows = append(rows, row)
	}

	total := len(rows)
	kept := rows
	if total > MaxDevices {
		kept = rows[:MaxDevices]
	}
	dropped := total - len(kept)
	ep.Devices = kept
	ep.Inventories = map[string]InventoryMeta{
		inventoryDevices: {
			CollectionComplete: complete,
			OutputTruncated:    dropped > 0,
			ReturnedRowsCount:  len(kept),
			TotalRowsCount:     &total,
			DroppedRowsCount:   &dropped,
		},
	}

	if internal {
		returned := 0
		for _, r := range kept {
			if r.LocalAdminAccounts != nil {
				returned += len(*r.LocalAdminAccounts)
			}
		}
		unclassified := 0
		for _, r := range rows {
			if r.LocalAdminAccounts == nil {
				unclassified++
			}
		}
		sourceReason := in.insightUsers.missingReason()
		ep.Inventories[inventoryLocalAdmins] = InventoryMeta{
			CollectionComplete: complete && in.insightUsers != nil && sourceReason == "" && unclassified == 0,
			OutputTruncated:    dropped > 0,
			ReturnedRowsCount:  returned,
		}
		switch {
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
// Anything else, including values osquery reports as "Unknown", stays
// unknown. Readings from a capped table are unknown: rows beyond the cap
// could hold a newer observation or the row that decides the result.

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
	if src.err != nil || src.capped {
		return unknownBecause(src.missingReason())
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
// are definitive; Snoozed, Not Monitored, and Error are unknown.
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
	if src == nil || src.err != nil || src.capped || len(src.byDevice[s.ID]) == 0 {
		reason := src.missingReason()
		return unknownBecause(reason), unknownBecause(reason)
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
// device with any account whose admin flag is missing returns nil
// (unknown), because an unclassified account could be an administrator.
func localAdmins(systemID string, in endpointInputs) *[]LocalAdminAccount {
	src := in.insightUsers
	if src == nil || src.err != nil || src.capped {
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
	rows := src.byDevice[systemID]
	if src.err != nil || src.capped || len(rows) == 0 {
		return unknownBecause(src.missingReason())
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
// detailed artifact, so both report identical figures.
func deviceControlsFrom(ep *EndpointPosture) *DeviceControls {
	dc := &DeviceControls{
		DiscoveryComplete:        ep.Scope.DiscoveryComplete,
		MaxObservationAgeSeconds: ep.Scope.MaxObservationAgeSeconds,
	}
	if !ep.Scope.DiscoveryComplete {
		return dc
	}
	summary := func(path string) *ControlSummary {
		cov, ok := ep.MetricCoverage[path]
		if !ok {
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
	dc.DiskEncryption = summary("hardening.disk_encryption_pct")
	dc.Firewall = summary("hardening.firewall_enabled_pct")
	dc.AntimalwareInstalled = summary("protection.antimalware_installed_pct")
	dc.AntimalwareHealthy = summary("protection.antimalware_healthy_pct")
	return dc
}
