// Package licensing manages license and machine lifecycles: create
// (with policy + customer + entitlement resolution), bulk create,
// validate, activate (issuing a gl2 lease token), checkin (renewing
// the lease), deactivate, suspend, revoke, reinstate, freeze (snap-
// shotting effective overrides), and attach-policy. Behavioural
// decisions read effective values via policy.Resolve, never raw
// policy fields.
package licensing
