// Package domain holds business contracts: model types (Account,
// Product, License, Policy, Customer, Grant, ...) and the repository
// interfaces consumed by the service layer. The package is pure
// types and contracts — no implementation, no I/O, no side effects.
// The TxManager interface lives here too; its implementation lives
// in internal/db.
package domain
