package core

// MachineStatus is the lifecycle state of a machine activation under
// the L2 lease model. Machines transition: active → stale → dead via
// the background expire_leases job, and dead → active on resurrection
// (re-activation with the same fingerprint reuses the same machine row).
type MachineStatus string

const (
	// MachineStatusActive means the lease is current. Counts against
	// the license's max_machines.
	MachineStatusActive MachineStatus = "active"

	// MachineStatusStale means the lease has expired but the grace
	// window has not. Still counts against max_machines so a lapsed
	// client can resurrect by checking in. Validate/checkin returns
	// expired until the lease is renewed.
	MachineStatusStale MachineStatus = "stale"

	// MachineStatusDead means the grace window has elapsed. Does NOT
	// count against max_machines. The row persists for audit history;
	// re-activation with the same fingerprint resurrects it.
	MachineStatusDead MachineStatus = "dead"
)

// IsValid reports whether s is a known machine status value.
func (s MachineStatus) IsValid() bool {
	switch s {
	case MachineStatusActive, MachineStatusStale, MachineStatusDead:
		return true
	}
	return false
}
