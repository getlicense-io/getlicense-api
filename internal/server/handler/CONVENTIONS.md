# Handler conventions

## HTTP response status codes for mutation endpoints

We use the following rules consistently:

| Pattern | Status | Body |
|---|---|---|
| Create returns the new resource | `201 Created` | JSON of the created resource |
| Update returns the new state | `200 OK` | JSON of the updated resource |
| Delete / deactivate / no-echo mutations | `204 No Content` | Empty |
| Async / queued operation accepted | `202 Accepted` | Optional JSON envelope |

**Never** use `200 OK` with an empty body — return `204` instead. The
HTTP spec reserves `200` for responses that have a meaningful body.

Examples in this repo:
- `POST /v1/products` → 201 + Product
- `PATCH /v1/products/:id` → 200 + Product (the updated state is useful)
- `DELETE /v1/products/:id` → 204
- `POST /v1/policies/:id/entitlements` → 204 (attach is a write the
  client doesn't need echoed; they can `GET` to see the new set)

When in doubt, check the existing handler for the same resource family.
