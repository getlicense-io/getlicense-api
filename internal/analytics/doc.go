// Package analytics provides read-only KPI snapshots and daily event
// buckets aggregated across licenses, machines, customers, and grants.
// All queries run inside WithTargetAccount transactions so RLS scopes
// the read to the requested account+environment.
package analytics
