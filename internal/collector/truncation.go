package collector

import "sort"

const (
	MaxUsers       = 20000
	MaxDevices     = 20000
	MaxAuditEvents = 5000
)

func truncateUsers(rows []UserRow) ([]UserRow, bool, int) {
	if len(rows) <= MaxUsers {
		return rows, false, 0
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Username < rows[j].Username
	})
	dropped := len(rows) - MaxUsers
	return rows[:MaxUsers], true, dropped
}

func truncateDevices(rows []DeviceRow) ([]DeviceRow, bool, int) {
	if len(rows) <= MaxDevices {
		return rows, false, 0
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Hostname < rows[j].Hostname
	})
	dropped := len(rows) - MaxDevices
	return rows[:MaxDevices], true, dropped
}

func truncateAuditEvents(rows []AuditEventRow) ([]AuditEventRow, bool, int) {
	if len(rows) <= MaxAuditEvents {
		return rows, false, 0
	}
	dropped := len(rows) - MaxAuditEvents
	return rows[:MaxAuditEvents], true, dropped
}
