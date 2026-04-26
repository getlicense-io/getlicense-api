package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// migrateLegacyAEADBlobs ports any pre-PR-C ciphertexts (written
// without AAD) to the new AAD-required format. One-shot, runs at
// startup, idempotent.
//
// For each row in each affected column the helper:
//  1. Tries the AAD-required Decrypt with the correct AAD. Success →
//     row is already migrated, skip.
//  2. On failure, tries DecryptLegacyNoAAD against the same bytes.
//  3. Re-encrypts the recovered plaintext with the AAD-required path
//     and writes back.
//
// Recovery codes are an exception: the legacy blob is decoded and the
// per-code hashes are inserted into the recovery_codes table, then the
// blob is cleared. After this migration runs successfully the lazy
// fallback path in identity.Service is dead code.
//
// Reads + writes run inside WithSystemContext so the migration sees
// rows across every tenant — webhook_endpoints and products carry
// RLS policies that would otherwise filter them to the (non-existent)
// caller account. Errors abort startup so a partial migration cannot
// leave the system in a half-encrypted state.
func migrateLegacyAEADBlobs(ctx context.Context, pool *pgxpool.Pool, txm domain.TxManager, mk *crypto.MasterKey) error {
	if err := migrateWebhookSigningSecrets(ctx, txm, mk); err != nil {
		return fmt.Errorf("migrate webhook signing secrets: %w", err)
	}
	if err := migrateTOTPSecrets(ctx, pool, mk); err != nil {
		return fmt.Errorf("migrate TOTP secrets: %w", err)
	}
	if err := migrateProductPrivateKeys(ctx, txm, mk); err != nil {
		return fmt.Errorf("migrate product private keys: %w", err)
	}
	if err := migrateRecoveryCodes(ctx, pool, mk); err != nil {
		return fmt.Errorf("migrate recovery codes: %w", err)
	}
	return nil
}

type webhookRow struct {
	id        core.WebhookEndpointID
	plaintext []byte
}

func migrateWebhookSigningSecrets(ctx context.Context, txm domain.TxManager, mk *crypto.MasterKey) error {
	var pending []webhookRow

	if err := txm.WithSystemContext(ctx, func(ctx context.Context) error {
		q := db.Conn(ctx, nil)
		rows, err := q.Query(ctx, `
			SELECT id, signing_secret_encrypted
			FROM webhook_endpoints
			WHERE signing_secret_encrypted IS NOT NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var pgID pgtype.UUID
			var blob []byte
			if err := rows.Scan(&pgID, &blob); err != nil {
				return err
			}
			id := core.WebhookEndpointID(pgID.Bytes)
			aad := crypto.WebhookSigningSecretAAD(id)
			if _, err := mk.Decrypt(blob, aad); err == nil {
				continue
			}
			plaintext, err := mk.DecryptLegacyNoAAD(blob)
			if err != nil {
				return fmt.Errorf("legacy decrypt webhook_endpoints[%s]: %w", id, err)
			}
			pending = append(pending, webhookRow{id: id, plaintext: plaintext})
		}
		return rows.Err()
	}); err != nil {
		return err
	}

	for _, p := range pending {
		aad := crypto.WebhookSigningSecretAAD(p.id)
		ct, err := mk.Encrypt(p.plaintext, aad)
		if err != nil {
			return fmt.Errorf("re-encrypt webhook_endpoints[%s]: %w", p.id, err)
		}
		if err := txm.WithSystemContext(ctx, func(ctx context.Context) error {
			q := db.Conn(ctx, nil)
			_, err := q.Exec(ctx,
				`UPDATE webhook_endpoints SET signing_secret_encrypted = $1 WHERE id = $2`,
				ct, pgtype.UUID{Bytes: p.id, Valid: true},
			)
			return err
		}); err != nil {
			return fmt.Errorf("write webhook_endpoints[%s]: %w", p.id, err)
		}
	}
	if len(pending) > 0 {
		slog.Info("crypto: migrated webhook signing secrets to AAD format", "count", len(pending))
	}
	return nil
}

type totpRow struct {
	id        core.IdentityID
	plaintext []byte
}

// identities has no RLS (cross-tenant table) so the bare pool is fine.
func migrateTOTPSecrets(ctx context.Context, pool *pgxpool.Pool, mk *crypto.MasterKey) error {
	rows, err := pool.Query(ctx, `
		SELECT id, totp_secret_enc
		FROM identities
		WHERE totp_secret_enc IS NOT NULL`)
	if err != nil {
		return err
	}

	var pending []totpRow
	for rows.Next() {
		var pgID pgtype.UUID
		var blob []byte
		if err := rows.Scan(&pgID, &blob); err != nil {
			rows.Close()
			return err
		}
		id := core.IdentityID(pgID.Bytes)
		aad := crypto.TOTPSecretAAD(id)
		if _, err := mk.Decrypt(blob, aad); err == nil {
			continue
		}
		plaintext, err := mk.DecryptLegacyNoAAD(blob)
		if err != nil {
			rows.Close()
			return fmt.Errorf("legacy decrypt identities[%s].totp_secret_enc: %w", id, err)
		}
		pending = append(pending, totpRow{id: id, plaintext: plaintext})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, p := range pending {
		aad := crypto.TOTPSecretAAD(p.id)
		ct, err := mk.Encrypt(p.plaintext, aad)
		if err != nil {
			return fmt.Errorf("re-encrypt identities[%s].totp_secret_enc: %w", p.id, err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE identities SET totp_secret_enc = $1, updated_at = NOW() WHERE id = $2`,
			ct, pgtype.UUID{Bytes: p.id, Valid: true},
		); err != nil {
			return fmt.Errorf("write identities[%s].totp_secret_enc: %w", p.id, err)
		}
	}
	if len(pending) > 0 {
		slog.Info("crypto: migrated TOTP secrets to AAD format", "count", len(pending))
	}
	return nil
}

type productRow struct {
	id        core.ProductID
	plaintext []byte
}

func migrateProductPrivateKeys(ctx context.Context, txm domain.TxManager, mk *crypto.MasterKey) error {
	var pending []productRow

	if err := txm.WithSystemContext(ctx, func(ctx context.Context) error {
		q := db.Conn(ctx, nil)
		rows, err := q.Query(ctx, `
			SELECT id, private_key_enc
			FROM products
			WHERE private_key_enc IS NOT NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var pgID pgtype.UUID
			var blob []byte
			if err := rows.Scan(&pgID, &blob); err != nil {
				return err
			}
			id := core.ProductID(pgID.Bytes)
			aad := crypto.ProductPrivateKeyAAD(id)
			if _, err := mk.Decrypt(blob, aad); err == nil {
				continue
			}
			plaintext, err := mk.DecryptLegacyNoAAD(blob)
			if err != nil {
				return fmt.Errorf("legacy decrypt products[%s].private_key_enc: %w", id, err)
			}
			pending = append(pending, productRow{id: id, plaintext: plaintext})
		}
		return rows.Err()
	}); err != nil {
		return err
	}

	for _, p := range pending {
		aad := crypto.ProductPrivateKeyAAD(p.id)
		ct, err := mk.Encrypt(p.plaintext, aad)
		if err != nil {
			return fmt.Errorf("re-encrypt products[%s].private_key_enc: %w", p.id, err)
		}
		if err := txm.WithSystemContext(ctx, func(ctx context.Context) error {
			q := db.Conn(ctx, nil)
			_, err := q.Exec(ctx,
				`UPDATE products SET private_key_enc = $1 WHERE id = $2`,
				ct, pgtype.UUID{Bytes: p.id, Valid: true},
			)
			return err
		}); err != nil {
			return fmt.Errorf("write products[%s].private_key_enc: %w", p.id, err)
		}
	}
	if len(pending) > 0 {
		slog.Info("crypto: migrated product private keys to AAD format", "count", len(pending))
	}
	return nil
}

type recoveryRow struct {
	id     core.IdentityID
	hashes []string
}

// migrateRecoveryCodes is the eager port of the legacy
// identities.recovery_codes_enc blob into the per-row recovery_codes
// table. After this run the lazy fallback in identity.Service is
// unreachable.
//
// Idempotency: the per-row INSERT uses ON CONFLICT DO NOTHING so a
// partial previous run that wrote rows but failed before clearing the
// blob is safe to retry. The row format is: hashes joined by newline,
// stripped of empty entries.
//
// Both identities and recovery_codes are cross-tenant tables with no
// RLS so the bare pool is fine.
func migrateRecoveryCodes(ctx context.Context, pool *pgxpool.Pool, mk *crypto.MasterKey) error {
	rows, err := pool.Query(ctx, `
		SELECT id, recovery_codes_enc
		FROM identities
		WHERE recovery_codes_enc IS NOT NULL`)
	if err != nil {
		return err
	}

	var pending []recoveryRow
	for rows.Next() {
		var pgID pgtype.UUID
		var blob []byte
		if err := rows.Scan(&pgID, &blob); err != nil {
			rows.Close()
			return err
		}
		id := core.IdentityID(pgID.Bytes)
		// Recovery code blobs were always written without AAD (no
		// per-code AAD ever existed). Always go through the legacy
		// path; it is the only valid format for this column.
		plaintext, err := mk.DecryptLegacyNoAAD(blob)
		if err != nil {
			rows.Close()
			return fmt.Errorf("legacy decrypt identities[%s].recovery_codes_enc: %w", id, err)
		}
		hashes := splitRecoveryHashes(string(plaintext))
		pending = append(pending, recoveryRow{id: id, hashes: hashes})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	if len(pending) == 0 {
		return nil
	}

	for _, p := range pending {
		// Insert per-row hashes inside a single tx so the clear-blob
		// UPDATE is atomic with the INSERTs. ON CONFLICT DO NOTHING
		// makes the INSERT idempotent against a previous partial run.
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for identities[%s]: %w", p.id, err)
		}
		// Bulk insert via UNNEST so we issue one statement regardless
		// of code count.
		if len(p.hashes) > 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO recovery_codes (identity_id, code_hash)
				SELECT $1::uuid, unnest($2::text[])
				ON CONFLICT (identity_id, code_hash) DO NOTHING`,
				pgtype.UUID{Bytes: p.id, Valid: true}, p.hashes,
			); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("insert recovery_codes for identities[%s]: %w", p.id, err)
			}
		}
		if _, err := tx.Exec(ctx,
			`UPDATE identities SET recovery_codes_enc = NULL, updated_at = NOW() WHERE id = $1`,
			pgtype.UUID{Bytes: p.id, Valid: true},
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("clear recovery_codes_enc for identities[%s]: %w", p.id, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit recovery codes migration for identities[%s]: %w", p.id, err)
		}
	}
	slog.Info("crypto: migrated recovery code blobs into per-row table", "count", len(pending))
	return nil
}

// splitRecoveryHashes parses the legacy serialization (hashes joined
// by '\n') and drops any empty entries left behind by previous
// re-serializations.
func splitRecoveryHashes(stored string) []string {
	parts := strings.Split(stored, "\n")
	out := make([]string, 0, len(parts))
	for _, h := range parts {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}
