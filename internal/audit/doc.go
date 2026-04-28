// Package audit records domain mutations as immutable domain_events
// with three-ID attribution (acting account, identity, api_key or
// grant). Writer.Record is called synchronously inside the originating
// service transaction so persistence is atomic with the mutation.
package audit
