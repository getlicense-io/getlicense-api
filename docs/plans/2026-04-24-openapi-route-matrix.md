# OpenAPI Route Matrix

| Status | Method | Path | Operation ID | Route Handler | Auth | Tests | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| matched | POST | `/v1/auth/signup` | `signup` | `AuthHandler.Signup` | `public+signupLimit` | TBD | `internal/server/routes.go:33` |
| matched | POST | `/v1/auth/login` | `login` | `AuthHandler.Login` | `public` | TBD | `internal/server/routes.go:34` |
| matched | POST | `/v1/auth/refresh` | `refreshToken` | `AuthHandler.Refresh` | `public` | TBD | `internal/server/routes.go:36` |
| matched | POST | `/v1/auth/logout` | `logout` | `AuthHandler.Logout` | `public` | TBD | `internal/server/routes.go:37` |
| matched | GET | `/v1/auth/me` | `getMe` | `AuthHandler.Me` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:38` |
| matched | POST | `/v1/products` | `createProduct` | `ProductHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:53` |
| matched | GET | `/v1/products` | `listProducts` | `ProductHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:54` |
| matched | GET | `/v1/products/{id}` | `getProduct` | `ProductHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:55` |
| matched | PATCH | `/v1/products/{id}` | `updateProduct` | `ProductHandler.Update` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:56` |
| matched | DELETE | `/v1/products/{id}` | `deleteProduct` | `ProductHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:57` |
| matched | GET | `/v1/products/{id}/licenses` | `listLicensesByProduct` | `LicenseHandler.ListByProduct` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:66` |
| matched | POST | `/v1/products/{id}/licenses` | `createLicense` | `LicenseHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:67` |
| matched | DELETE | `/v1/products/{id}/licenses` | `bulkRevokeLicensesByProduct` | `LicenseHandler.BulkRevokeByProduct` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:69` |
| matched | POST | `/v1/products/{id}/licenses/bulk` | `bulkCreateLicenses` | `LicenseHandler.BulkCreate` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:68` |
| matched | GET | `/v1/licenses` | `listLicenses` | `LicenseHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:114` |
| matched | GET | `/v1/licenses/{id}` | `getLicense` | `LicenseHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:115` |
| matched | PATCH | `/v1/licenses/{id}` | `updateLicense` | `LicenseHandler.Update` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:116` |
| matched | DELETE | `/v1/licenses/{id}` | `revokeLicense` | `LicenseHandler.Revoke` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:117` |
| matched | POST | `/v1/licenses/{id}/suspend` | `suspendLicense` | `LicenseHandler.Suspend` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:118` |
| matched | POST | `/v1/licenses/{id}/reinstate` | `reinstateLicense` | `LicenseHandler.Reinstate` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:119` |
| matched | POST | `/v1/licenses/{id}/activate` | `activateMachine` | `LicenseHandler.Activate` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:120` |
| matched | POST | `/v1/licenses/{id}/deactivate` | `deactivateMachine` | `LicenseHandler.Deactivate` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:121` |
| matched | POST | `/v1/licenses/{id}/freeze` | `freezeLicense` | `LicenseHandler.Freeze` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:123` |
| matched | POST | `/v1/licenses/{id}/attach-policy` | `attachLicensePolicy` | `LicenseHandler.AttachPolicy` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:124` |
| matched | GET | `/v1/products/{id}/policies` | `listProductPolicies` | `PolicyHandler.ListByProduct` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:75` |
| matched | POST | `/v1/products/{id}/policies` | `createProductPolicy` | `PolicyHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:76` |
| matched | GET | `/v1/policies/{id}` | `getPolicy` | `PolicyHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:91` |
| matched | PATCH | `/v1/policies/{id}` | `updatePolicy` | `PolicyHandler.Update` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:92` |
| matched | DELETE | `/v1/policies/{id}` | `deletePolicy` | `PolicyHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:93` |
| matched | POST | `/v1/policies/{id}/set-default` | `setDefaultPolicy` | `PolicyHandler.SetDefault` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:94` |
| matched | POST | `/v1/licenses/{id}/machines/{fingerprint}/checkin` | `checkinMachine` | `LicenseHandler.Checkin` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:122` |
| matched | GET | `/v1/entitlements` | `listEntitlements` | `EntitlementHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:83` |
| matched | POST | `/v1/entitlements` | `createEntitlement` | `EntitlementHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:84` |
| matched | GET | `/v1/entitlements/{id}` | `getEntitlement` | `EntitlementHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:85` |
| matched | PATCH | `/v1/entitlements/{id}` | `updateEntitlement` | `EntitlementHandler.Update` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:86` |
| matched | DELETE | `/v1/entitlements/{id}` | `deleteEntitlement` | `EntitlementHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:87` |
| matched | GET | `/v1/policies/{id}/entitlements` | `listPolicyEntitlements` | `EntitlementHandler.ListPolicyEntitlements` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:96` |
| matched | POST | `/v1/policies/{id}/entitlements` | `attachPolicyEntitlements` | `EntitlementHandler.AttachPolicyEntitlements` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:97` |
| matched | PUT | `/v1/policies/{id}/entitlements` | `replacePolicyEntitlements` | `EntitlementHandler.ReplacePolicyEntitlements` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:98` |
| matched | DELETE | `/v1/policies/{id}/entitlements/{code}` | `detachPolicyEntitlement` | `EntitlementHandler.DetachPolicyEntitlement` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:99` |
| matched | GET | `/v1/licenses/{id}/entitlements` | `listLicenseEntitlements` | `EntitlementHandler.ListLicenseEntitlements` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:126` |
| matched | POST | `/v1/licenses/{id}/entitlements` | `attachLicenseEntitlements` | `EntitlementHandler.AttachLicenseEntitlements` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:127` |
| matched | PUT | `/v1/licenses/{id}/entitlements` | `replaceLicenseEntitlements` | `EntitlementHandler.ReplaceLicenseEntitlements` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:128` |
| matched | DELETE | `/v1/licenses/{id}/entitlements/{code}` | `detachLicenseEntitlement` | `EntitlementHandler.DetachLicenseEntitlement` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:129` |
| matched | GET | `/v1/customers` | `listCustomers` | `CustomerHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:105` |
| matched | POST | `/v1/customers` | `createCustomer` | `CustomerHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:106` |
| matched | GET | `/v1/customers/{id}` | `getCustomer` | `CustomerHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:107` |
| matched | PATCH | `/v1/customers/{id}` | `updateCustomer` | `CustomerHandler.Update` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:108` |
| matched | DELETE | `/v1/customers/{id}` | `deleteCustomer` | `CustomerHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:109` |
| matched | GET | `/v1/customers/{id}/licenses` | `listCustomerLicenses` | `CustomerHandler.ListLicenses` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:110` |
| matched | GET | `/v1/grants/{grant_id}/customers` | `listGrantCustomers` | `GrantHandler.ListCustomers` | `authMw+mgmtLimit+ResolveGrant` | TBD | `internal/server/routes.go:247` |
| matched | POST | `/v1/validate` | `validateLicense` | `ValidateHandler.Validate` | `public+validateLimit` | TBD | `internal/server/routes.go:133` |
| matched | POST | `/v1/api-keys` | `createAPIKey` | `APIKeyHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:138` |
| matched | GET | `/v1/api-keys` | `listAPIKeys` | `APIKeyHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:139` |
| matched | DELETE | `/v1/api-keys/{id}` | `deleteAPIKey` | `APIKeyHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:140` |
| matched | POST | `/v1/webhooks` | `createWebhook` | `WebhookHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:145` |
| matched | GET | `/v1/webhooks` | `listWebhooks` | `WebhookHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:146` |
| matched | DELETE | `/v1/webhooks/{id}` | `deleteWebhook` | `WebhookHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:147` |
| matched | GET | `/v1/webhooks/{id}/deliveries` | `listWebhookDeliveries` | `WebhookHandler.ListDeliveries` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:149` |
| matched | GET | `/v1/webhooks/{id}/deliveries/{delivery_id}` | `getWebhookDelivery` | `WebhookHandler.GetDelivery` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:150` |
| matched | POST | `/v1/webhooks/{id}/deliveries/{delivery_id}/redeliver` | `redeliverWebhook` | `WebhookHandler.Redeliver` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:151` |
| matched | POST | `/v1/auth/login/totp` | `loginStep2TOTP` | `AuthHandler.LoginTOTP` | `public` | TBD | `internal/server/routes.go:35` |
| matched | POST | `/v1/auth/switch` | `switchAccount` | `AuthHandler.Switch` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:39` |
| matched | POST | `/v1/identity/totp/enroll` | `enrollTOTP` | `IdentityHandler.EnrollTOTP` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:44` |
| matched | POST | `/v1/identity/totp/activate` | `activateTOTP` | `IdentityHandler.ActivateTOTP` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:45` |
| matched | POST | `/v1/identity/totp/disable` | `disableTOTP` | `IdentityHandler.DisableTOTP` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:46` |
| matched | GET | `/v1/environments` | `listEnvironments` | `EnvironmentHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:173` |
| matched | POST | `/v1/environments` | `createEnvironment` | `EnvironmentHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:174` |
| matched | DELETE | `/v1/environments/{id}` | `deleteEnvironment` | `EnvironmentHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:175` |
| matched | GET | `/v1/invitations/{token}/lookup` | `lookupInvitation` | `InvitationHandler.Lookup` | `public` | TBD | `internal/server/routes.go:190` |
| matched | POST | `/v1/invitations/{token}/accept` | `acceptInvitation` | `InvitationHandler.Accept` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:193` |
| matched | GET | `/v1/accounts/{account_id}/invitations` | `listInvitations` | `InvitationHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:200` |
| matched | POST | `/v1/accounts/{account_id}/invitations` | `createInvitation` | `InvitationHandler.Create` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:199` |
| matched | GET | `/v1/invitations/{invitation_id}` | `getInvitation` | `InvitationHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:205` |
| matched | DELETE | `/v1/invitations/{invitation_id}` | `revokeInvitation` | `InvitationHandler.Delete` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:207` |
| matched | POST | `/v1/invitations/{invitation_id}/resend` | `resendInvitation` | `InvitationHandler.Resend` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:206` |
| matched | GET | `/v1/accounts/{account_id}` | `getAccount` | `AccountHandler.GetSummary` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:184` |
| matched | GET | `/v1/accounts/{account_id}/grants` | `listGrantsByGrantor` | `GrantHandler.ListByGrantor` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:216` |
| matched | POST | `/v1/accounts/{account_id}/grants` | `issueGrant` | `GrantHandler.Issue` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:217` |
| matched | POST | `/v1/accounts/{account_id}/grants/{grant_id}/revoke` | `revokeGrant` | `GrantHandler.Revoke` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:219` |
| matched | POST | `/v1/accounts/{account_id}/grants/{grant_id}/suspend` | `suspendGrant` | `GrantHandler.Suspend` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:220` |
| matched | POST | `/v1/accounts/{account_id}/grants/{grant_id}/reinstate` | `reinstateGrant` | `GrantHandler.Reinstate` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:221` |
| matched | PATCH | `/v1/accounts/{account_id}/grants/{grant_id}` | `updateGrant` | `GrantHandler.Update` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:218` |
| matched | GET | `/v1/accounts/{account_id}/received-grants` | `listReceivedGrants` | `GrantHandler.ListReceived` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:226` |
| matched | GET | `/v1/grants/received` | `listGrantsByGrantee` | `GrantHandler.ListByGrantee` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:236` |
| matched | GET | `/v1/grants/{grant_id}` | `getGrant` | `GrantHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:237` |
| matched | POST | `/v1/grants/{grant_id}/accept` | `acceptGrant` | `GrantHandler.Accept` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:238` |
| matched | POST | `/v1/grants/{grant_id}/leave` | `leaveGrant` | `GrantHandler.Leave` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:241` |
| matched | POST | `/v1/grants/{grant_id}/licenses` | `createLicenseUnderGrant` | `GrantHandler.CreateLicense` | `authMw+mgmtLimit+ResolveGrant` | TBD | `internal/server/routes.go:242` |
| matched | GET | `/v1/events` | `listEvents` | `EventHandler.List` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:156` |
| matched | GET | `/v1/events/{id}` | `getEvent` | `EventHandler.Get` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:157` |
| matched | GET | `/v1/metrics` | `getMetrics` | `MetricsHandler.Snapshot` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:161` |
| matched | GET | `/v1/search` | `globalSearch` | `SearchHandler.Search` | `authMw+mgmtLimit` | TBD | `internal/server/routes.go:165` |

## Task 4 Handler Contract Review

- Reviewed handler request parsing, response status codes, response body exposure, auth/RBAC gates, and grant account scoping against `api/openapi.yaml`.
- Confirmed cursor pagination handlers use the documented default `limit=50` and bounds `1..200` via `cursorParams`.
- Confirmed path UUID parameters are parsed with typed `core.Parse*ID` helpers or explicit token/fingerprint string handling where OpenAPI documents string path parameters.
- Fixed entitlement attach/replace status drift: `attachPolicyEntitlements`, `replacePolicyEntitlements`, `attachLicenseEntitlements`, and `replaceLicenseEntitlements` now return documented `200` instead of `204`; `e2e/scenarios/22_entitlements.hurl` now asserts the documented status.
- Fixed `setDefaultPolicy` response documentation drift by documenting the existing `Policy` response body in OpenAPI; runtime and existing Hurl assertions already returned and consumed that body.
