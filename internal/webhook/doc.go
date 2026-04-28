// Package webhook implements the durable outbox dispatcher: endpoint
// CRUD, signing-secret rotation with a grace window, atomic per-event
// enqueue, FOR UPDATE SKIP LOCKED claim with claim-token guards, a
// bounded worker pool with retry/backoff (1m, 5m, 30m, 2h, 12h, 24h),
// SSRF-safe HTTP delivery with HMAC-SHA256 signing, and the delivery
// log (with redeliver).
package webhook
