package collector

import (
	"fmt"

	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

// The collector's name, the paths of its artifacts in the pack, and the
// schema IDs of its normalized artifacts. The paths are the ones
// componentsdk.ArtifactPath gives, and the SDK moves them for a run
// configured under another name.
const (
	collectorName = "jumpcloud"

	idpPostureSchema      = "evidencepack/idp-posture@v1"
	endpointPostureSchema = "evidencepack/endpoint-posture@v1"

	detailedPath        = "artifacts/jumpcloud.details.json"
	idpPosturePath      = "artifacts/jumpcloud.idp-posture.json"
	endpointPosturePath = "artifacts/jumpcloud.endpoint-posture.json"
)

// gapLog records each value the collector leaves out of an artifact in the
// run's recorder. The SDK writes the gaps into the collector result. Its
// methods mark themselves with Recorder.Helper, so each gap's source names
// the line that called them.
type gapLog struct {
	rec   *componentsdk.Recorder
	level componentsdk.Level
}

func newGapLog(rec *componentsdk.Recorder, level componentsdk.Level) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec, level: level}
}

func (l *gapLog) audit() bool { return l.level.AtLeast(componentsdk.LevelAudit) }

func detailed(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: detailedPath, Pointer: pointer}
}

func idp(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: idpPosturePath, Pointer: pointer}
}

func endpoint(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: endpointPosturePath, Pointer: pointer}
}

// notCollected records the values at the locations as left out because of
// err.
func (l *gapLog) notCollected(err error, at ...componentsdk.Location) {
	l.rec.Helper()
	for _, loc := range at {
		l.rec.NotCollected(loc, err)
	}
}

// partial records the rollups or lists at the locations as read in part,
// with unmeasured of the items they cover left out because of err.
func (l *gapLog) partial(unmeasured int, err error, at ...componentsdk.Location) {
	l.rec.Helper()
	for _, loc := range at {
		l.rec.Partial(loc, unmeasured, err)
	}
}

// unsupported records the value at loc as one JumpCloud does not report,
// with reason.
func (l *gapLog) unsupported(loc componentsdk.Location, reason string) {
	l.rec.Helper()
	l.rec.NotCollectedCode(loc, componentsdk.CodeUnsupported, reason)
}

// unread records the value at loc as left out with code and reason. The
// code is unsupported for a value JumpCloud does not report, and not_read
// for one it reports in a call the collector does not make.
func (l *gapLog) unread(loc componentsdk.Location, code componentsdk.Code, reason string) {
	l.rec.Helper()
	l.rec.NotCollectedCode(loc, code, reason)
}

// invalid records the value at loc as left out because JumpCloud's answer
// was not what the collector expects, with detail.
func (l *gapLog) invalid(loc componentsdk.Location, detail string) {
	l.rec.Helper()
	l.rec.NotCollectedCode(loc, componentsdk.CodeInvalidResponse, detail)
}

// inventory records a detailed inventory list at pointer as read in part.
// That is the case when its source list fell short of the total JumpCloud
// reported, or when the collector cut the rows at limit.
func (l *gapLog) inventory(cut bool, dropped, limit int, shortfall error, unmeasured int, pointer string) {
	l.rec.Helper()
	switch {
	case shortfall != nil:
		l.partial(unmeasured, shortfall, detailed(pointer))
	case cut:
		l.partial(dropped, truncated(pointer, limit, dropped), detailed(pointer))
	}
}

// mirror records at a normalized value the gap that covers the detailed
// value it copies, if any.
func (l *gapLog) mirror(fromPointer string, to componentsdk.Location) {
	l.rec.Mirror(detailed(fromPointer), to)
}

// shortfall is the error for a list that held fewer rows than JumpCloud
// reported. When the collector's own row limit stopped the read, its code
// is too_large. A list that ends early is an invalid response.
func shortfall(op string, read, total, limit int) error {
	if read >= limit {
		return componentsdk.CodeError(componentsdk.CodeTooLarge,
			fmt.Errorf("%s: read the first %d of %d rows, the most the collector reads", op, read, total))
	}
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse,
		fmt.Errorf("%s: the list ended after %d of the %d rows JumpCloud reported", op, read, total))
}

// capped is the error for a list the collector stopped reading at its own
// row limit.
func capped(op string, limit int) error {
	return componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("%s: read the first %d rows, the most the collector reads", op, limit))
}

// truncated is the error for an inventory cut to the collector's own row
// limit.
func truncated(list string, kept, dropped int) error {
	return componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("%s: kept the first %d rows and left out %d", list, kept, dropped))
}

// listShortfall returns the shortfall error for a V1 list, or nil when it
// was read in full.
func listShortfall(op string, read, total int) error {
	if read >= total {
		return nil
	}
	return shortfall(op, read, total, jumpcloud.MaxResults)
}

// systemsShortfall returns the shortfall error for the systems list, or nil
// when it held as many distinct device IDs as the total JumpCloud reported.
// A list that repeats a row can reach the total while missing a system.
func systemsShortfall(rows, distinct, total int) error {
	if err := listShortfall(jumpcloud.OpListSystems, rows, total); err != nil {
		return err
	}
	if distinct >= total {
		return nil
	}
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf(
		"%s: JumpCloud reported %d systems and listed %d distinct device IDs",
		jumpcloud.OpListSystems, total, distinct))
}

// rowPointer addresses a field of one row of an array.
func rowPointer(array string, index int, field string) string {
	return fmt.Sprintf("%s/%d/%s", array, index, field)
}
