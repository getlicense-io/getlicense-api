# Package Layout (Updated)

The plan at `2026-04-11-getlicense-api-go-v2.md` references `core.TxManager`, `core.ProductRepository`, `core.Account`, etc. After the restructure, these live in different packages:

| Plan reference | Actual location | Import |
|---|---|---|
| `core.TxManager` | `domain.TxManager` | `internal/domain` |
| `core.AccountRepository` | `domain.AccountRepository` | `internal/domain` |
| `core.Account`, `core.Product`, etc. | `domain.Account`, `domain.Product` | `internal/domain` |
| `core.UpdateProductParams` | `domain.UpdateProductParams` | `internal/domain` |
| `core.ListResponse` | `domain.ListResponse` | `internal/domain` |
| `core.Pagination` | `domain.Pagination` | `internal/domain` |
| `core.AccountID`, `core.ProductID`, etc. | `core.AccountID` (unchanged) | `internal/core` |
| `core.ErrorCode`, `core.AppError` | unchanged | `internal/core` |
| `core.LicenseType`, `core.UserRole`, etc. | unchanged | `internal/core` |

When implementing remaining tasks, substitute `domain.` for `core.` when referencing models, repository interfaces, or TxManager.
