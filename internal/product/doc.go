// Package product manages products: CRUD with Ed25519 keypair
// generation (private key encrypted at rest with an AAD bound to
// the product ID) and auto-creation of a "Default" policy on
// product creation, inside the same transaction.
package product
