-- Placeholder query. sqlc v1.29.0 errors on a queries/ dir with no
-- .sql files, so this bootstraps the generate pipeline before real
-- queries land in later tasks. Remove or replace in Task 2+.

-- name: Ping :one
SELECT 1::int AS ok;
