# RBAC for openHAB — Requirements

## 1. Problem Statement

openHAB's current access model is all-or-nothing: you're either an admin with full control, or a regular user who can see and command everything. 

This is a problem for multi-user households and shared environments. The `visibleTo` mechanism in the UI is just cosmetics — the REST API happily serves all data regardless.

### Where We Are Today

| Aspect | Current State |
|--------|--------------|
| Auth standard | RFC 6749 Authorization Code + RFC 7636 PKCE, but with non-standard JWT format (iss/aud are just `"openhab"`, no `typ: at+jwt` header) and quirky client handling (`client_id` must equal `redirect_uri`) |
| OAuth2 compliance | No discovery endpoint, no JWKS, no introspection (RFC 7662). There's a non-standard logout (`POST /rest/auth/logout`) that kills refresh tokens but doesn't follow RFC 7009. Scopes exist in tokens but nobody checks them. |
| External IdP | Not supported |
| Roles | 2 hardcoded constants (`administrator`, `user`). The core/console/JAAS layer actually accepts arbitrary role strings — only the REST `UserResource` rejects non-standard ones. |
| Resource-level access control | None |
| Custom roles | They technically work at the core, console, and JAAS levels (via `openhab:users add`, `ManagedUserBackingEngine.addRole()`, direct JSON DB edits). REST `UserResource` is the only thing that validates against a hardcoded `Set.of(Role.ADMIN, Role.USER)`. `@RolesAllowed` and `isUserInRole()` match any string in the user's role set. |
| Item filtering | None — all items visible to all authenticated users |
| Page filtering | Client-side only (`visibleTo`) |
| SSE/Events | No user-identity filtering, just topic-based subscription |
| Servlet security | `ChartServlet`, `IconServlet`, `AudioServlet` have zero auth. `AuthenticationHandler` is disabled by default. |
| Rule execution | No user identity. Username shows up in the event `source` field for auditing, but the rule engine never uses it for access decisions. |
| Android app | HTTP Basic Auth only — no OAuth2, no PKCE. Supports API tokens (`oh.*`) via username field (heuristic: >50 chars). Zero role awareness. |
| openHAB Cloud | Runs its own OAuth2 AS (oauth2orize) for Google Home/Alexa. The Socket.IO channel to the local instance authenticates by openHAB UUID+secret — individual user credentials never reach local openHAB. User identity stays at the cloud middleware layer (`req.user.getOpenhab()`). Own user DB (MongoDB), own role model (`master`/`staff`). Cloud-issued tokens are non-expiring 256-char hex strings (not JWT). |


## 2. Goals

### Must Have

1. **Resource-level authorization** — restrict which Items, Things, Pages, Rules, and Sitemaps a user can access based on their permissions.
2. **Custom roles** — let admins define roles beyond the built-in `administrator` and `user`.
3. **Granular permissions** — read, command, write/admin per resource or resource group.
4. **Server-side enforcement** — all access control happens on the server. Client-side filtering is a nice-to-have, not a substitute.
5. **Event stream filtering** — SSE and WebSocket only deliver events for resources the user is allowed to see.

### Should Have

6. **Backward compatibility** — existing installs keep working as-is. RBAC is opt-in.
7. **Semantic model integration** — use the existing model (Locations, Equipment, Properties) for permission inheritance so you don't have to assign permissions item-by-item.
8. **Rule execution context** — rules triggered by a user action should run within that user's permission scope (or a configurable service identity).
9. **Servlet security** — bring ChartServlet, IconServlet, AudioServlet under the same auth framework as REST.
10. **UI enforcement** — Main UI handles 403s gracefully and only requests resources the user can access.
11. **Separation of duties** — mutual exclusion constraints on roles to prevent conflicting assignments.
12. **Time-bound access** — role assignments that expire automatically.
13. **Emergency access** — break-glass mechanism for safety-critical situations (this is a smart home, fires happen).
14. **Delegated administration** — non-admin users managing permissions within a defined scope (parents managing kids' access).


## 3. Functional Requirements

### FR-1: OAuth2 Authorization Server

| ID | Requirement |
|----|-------------|
| FR-1.1 | Implement a proper OAuth2 AS per [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749). |
| FR-1.2 | Support Authorization Code (with PKCE per [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)), Client Credentials, and Refresh Token grants. |
| FR-1.3 | Issue standard JWT access tokens per [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068). |
| FR-1.4 | Support token introspection per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662). |
| FR-1.5 | Support token revocation per [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009). |
| FR-1.6 | Expose an OIDC Discovery document (`.well-known/openid-configuration`) per [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html). |
| FR-1.7 | Publish a JWKS endpoint (`/oauth2/jwks`) with the public signing keys. |
| FR-1.8 | Map OAuth2 scopes to RBAC permissions (e.g., `items:read`, `items:command`, `things:admin`). |
| FR-1.9 | Keep the existing API token mechanism (`oh.*`) working as a non-expiring Client Credentials equivalent with configurable scopes. |

### FR-2: External Identity Provider — Full Replacement

| ID | Requirement |
|----|-------------|
| FR-2.1 | Support replacing the built-in auth server entirely with an external OAuth2/OIDC IdP (Keycloak, Authentik, Google, Azure AD, etc.). |
| FR-2.2 | In external IdP mode, openHAB acts purely as an OAuth2 Resource Server — validates tokens against the IdP's JWKS and doesn't issue tokens itself. |
| FR-2.3 | Disable the built-in login page, token endpoint, and user registration when external IdP is active. UI redirects to the IdP for login. |
| FR-2.4 | Map external IdP users to openHAB roles via configurable claim-to-role mappings (e.g., IdP group `openhab-admins` → role `administrator`). Support multiple claim sources: realm roles, client roles, groups, custom claims. |
| FR-2.5 | Optionally support hybrid mode (local + IdP users coexist), but full replacement is the primary use case. |
| FR-2.6 | Configure via a PID-based service config (standard openHAB pattern). Minimum: issuer URL, client ID, role claim path. |
| FR-2.7 | In external IdP mode, local user management isn't required. Identity and roles come entirely from the access token claims. |
| FR-2.8 | UI supports the full OIDC login flow: redirect → authenticate → callback with auth code → token exchange. |

### FR-3: OAuth2 Client Registration

| ID | Requirement |
|----|-------------|
| FR-3.1 | Support registered OAuth2 clients (Main UI, mobile apps, third-party integrations). |
| FR-3.2 | Each client has: `client_id`, optional `client_secret`, allowed `grant_types`, allowed `redirect_uris`, allowed `scopes`. |
| FR-3.3 | Main UI is a pre-registered public client (no secret) using Authorization Code + PKCE. |
| FR-3.4 | Admins can register additional OAuth2 clients via REST API and UI. |
| FR-3.5 | Dynamic Client Registration per [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) is optional. |

### FR-4: Custom Role Management

| ID | Requirement |
|----|-------------|
| FR-4.1 | Admins can create, update, and delete custom roles via REST API and Karaf console. |
| FR-4.2 | A role has a unique name, an optional description, and a set of permissions. |
| FR-4.3 | Built-in roles `administrator` and `user` can't be deleted. |
| FR-4.4 | The `administrator` role always has full access — can't be restricted. |
| FR-4.5 | Users can have multiple roles. Effective permissions = union of all role permissions. |
| FR-4.6 | Roles stored in JSON DB (same as everything else in openHAB). |

### FR-5: Permission Model

| ID | Requirement |
|----|-------------|
| FR-5.1 | Permissions are tuples: `(resource-type, resource-selector, action)`. |
| FR-5.2 | Resource types: `item`, `thing`, `page`, `rule`, `sitemap`, `transformation`. |
| FR-5.3 | Resource selectors: specific ID, group/tag pattern, semantic location, or wildcard (`*`). |
| FR-5.4 | Actions: `read` (view state), `command` (send commands/updates), `admin` (CRUD). |
| FR-5.5 | `admin` implies `command`, which implies `read` (hierarchical). |
| FR-5.6 | Deny-by-default when RBAC is enabled — if nothing grants access, access is denied. |
| FR-5.7 | Additive-only model (allow-only). No explicit deny rules. Effective permissions = union of all grants. To restrict someone, you just don't grant. This keeps things predictable. |
| FR-5.8 | Global toggle to enable/disable RBAC. When off, behavior is identical to today. |
| FR-5.9 | Effective permission = intersection of token scopes AND role-based permissions. Both must allow it. |

### FR-6: Permission Inheritance

| ID | Requirement |
|----|-------------|
| FR-6.1 | Permissions on a group Item propagate to all direct and transitive members (unless a more specific grant exists on the child). |
| FR-6.2 | Permissions on a semantic Location propagate to all Equipment and Points within it. |
| FR-6.3 | Explicit permission on a child takes precedence over inherited ones (most-specific-wins). Since the model is additive-only, a more specific grant defines the effective permission rather than accumulating with inherited grants. |
| FR-6.4 | Permissions on a Thing propagate to all Items linked to that Thing's channels. |

### FR-7: REST API Enforcement

| ID | Requirement |
|----|-------------|
| FR-7.1 | GET endpoints filter results to only include authorized resources. |
| FR-7.2 | POST/PUT/DELETE return 403 for unauthorized resources. |
| FR-7.3 | Commanding an item the user can't `command` → 403. |
| FR-7.4 | Requesting a specific resource the user can't `read` → 404 (avoids information leakage). |
| FR-7.5 | SSE event stream filtered per user's permissions. |
| FR-7.6 | Servlets (Chart, Icon, Audio) check authorization before serving content. |
| FR-7.7 | Standard `Authorization: Bearer <token>` is the primary auth method. |

### FR-8: UI Integration

| ID | Requirement |
|----|-------------|
| FR-8.1 | Main UI only requests resources the user can access (don't fire requests just to get 403s back). |
| FR-8.2 | `visibleTo` keeps working as a cosmetic layer on top of RBAC. |
| FR-8.3 | UI provides admin interface for managing roles and permissions. |
| FR-8.4 | Widgets referencing unauthorized items degrade gracefully (placeholder or hidden, not error). |
| FR-8.5 | Overview page (semantic model tabs) only shows locations/equipment the user can access. |
| FR-8.6 | Main UI uses OAuth2 Authorization Code + PKCE for login. |

### FR-9: Mobile App Compatibility

| ID | Requirement |
|----|-------------|
| FR-9.1 | Android and iOS apps keep working with HTTP Basic Auth (username/password and API tokens in username field) during a transition period. |
| FR-9.2 | Apps should migrate to OAuth2 Authorization Code + PKCE. Standard flow must work in mobile browser/WebView with app-specific redirect URIs. |
| FR-9.3 | With RBAC on, apps must handle filtered responses and 403s gracefully — no crashes, no unexplained empty screens. |
| FR-9.4 | API tokens (`oh.*`) via Basic Auth username (empty password) must keep working — the Android app depends on it. |

### FR-10: openHAB Cloud Integration

| ID | Requirement |
|----|-------------|
| FR-10.1 | When requests come through the cloud, the local instance needs to know which user is making the request. Today the Socket.IO channel authenticates by UUID+secret and doesn't forward individual user identity. |
| FR-10.2 | Implement a trusted-proxy mechanism: local openHAB trusts user identity assertions from a configured cloud instance without needing per-user OAuth2 tokens. |
| FR-10.3 | RBAC enforcement applies to cloud-proxied requests based on the asserted user identity. |
| FR-10.4 | The cloud's existing OAuth2 (for Google Home/Alexa) stays independent. The new core OAuth2 AS doesn't replace it, but scope/permission models should be compatible for future unification. |
| FR-10.5 | Cloud user identity mapping: the cloud needs a way to assert user identity to local openHAB. Config for mapping cloud users to local users/roles is required. |

### FR-11: Rule Execution Context

| ID | Requirement |
|----|-------------|
| FR-11.1 | Rules triggered by user actions run with the triggering user's permissions by default. |
| FR-11.2 | Rules can be configured to run as a "system" identity with full permissions. |
| FR-11.3 | If a rule tries to access items outside the triggering user's permissions, it fails gracefully with a logged warning. |

### FR-12: Administration & Auditability

| ID | Requirement |
|----|-------------|
| FR-12.1 | REST endpoint to query effective permissions for a user on a specific resource. |
| FR-12.2 | Simulation/dry-run endpoint: "what would happen if role X were assigned to user Y?" without applying changes. |
| FR-12.3 | Permission changes logged to the event bus. |
| FR-12.4 | Karaf console commands for managing roles and permissions. |
| FR-12.5 | Token issuance and revocation events are logged. |

### FR-13: Separation of Duties

| ID | Requirement |
|----|-------------|
| FR-13.1 | Admins can define **Static Separation of Duty (SSoD)** constraints: a set of mutually exclusive roles that can't all be assigned to the same user. |
| FR-13.2 | Enforced at assignment time. Conflicting assignment → clear error message. |
| FR-13.3 | Stored in JSON DB alongside role definitions. |
| FR-13.4 | Manageable via REST API and Karaf console. |
| FR-13.5 | The `administrator` role can't be part of any SSoD constraint — it has full access anyway, so constraining its co-assignment is pointless. |

### FR-14: Time-Bound Role Assignments

| ID | Requirement |
|----|-------------|
| FR-14.1 | Role assignments can optionally have a validity period (start and end date/time). |
| FR-14.2 | Outside the validity window, the assignment is treated as non-existent. |
| FR-14.3 | Expired assignments are kept for audit but marked inactive. Background job or lazy eval handles deactivation. |
| FR-14.4 | REST API and UI support specifying validity periods on assignment. |
| FR-14.5 | Optional time-of-day schedules on permissions (e.g., "command allowed 07:00–23:00") — nice to have, can be deferred. |

### FR-15: Break-Glass / Emergency Access

| ID | Requirement |
|----|-------------|
| FR-15.1 | A break-glass mechanism exists for emergencies where restricted users need temporary elevated access. |
| FR-15.2 | Activation grants a configurable elevated permission set (up to full access) for a time-limited duration (default: 30 minutes). Implemented as a temporary role assignment (consistent with additive-only model), not a policy bypass. |
| FR-15.3 | Fully audited: distinct event on the bus with user, timestamp, duration, and reason. |
| FR-15.4 | Auto-expires after configured duration. Manual deactivation also supported. |
| FR-15.5 | Only explicitly designated break-glass-eligible users (system flag or dedicated role) can activate it. |
| FR-15.6 | Available via REST API, Karaf console, and an emergency UI action. |
| FR-15.7 | After expiration, permissions revert to normal without manual intervention. |

### FR-16: Delegation of Administration

| ID | Requirement |
|----|-------------|
| FR-16.1 | Non-admin users can be granted scoped admin rights: assign/revoke specific roles to/from a defined set of users. |
| FR-16.2 | Delegation is a tuple: `(delegator-role, assignable-roles, target-user-scope)` — e.g., "a `parent` can assign/revoke `child-alice` and `child-bob` to users in the `family` group." |
| FR-16.3 | A delegated admin can't assign roles granting more permissions than they have themselves (no privilege escalation). |
| FR-16.4 | Stored persistently, manageable via REST API and Karaf console. |
| FR-16.5 | UI provides a scoped admin interface for delegated users without exposing full admin functionality. |

### FR-17: Default Role Assignment

| ID | Requirement |
|----|-------------|
| FR-17.1 | Configurable default role auto-assigned to new users when no explicit role is specified. |
| FR-17.2 | Configured via PID-based system settings. Defaults to built-in `user` for backward compat. |
| FR-17.3 | With external IdP, users arriving without mapped roles get the default role (unless explicitly configured to deny unmapped users). |
| FR-17.4 | Default role assignment can be disabled entirely — users without explicit roles get nothing (deny-by-default). |

## 4. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | **Performance:** Permission checks add <5ms to REST API calls (cached evaluation). |
| NFR-2 | **Scale:** Handle 1000+ items with 50+ roles without degradation. |
| NFR-3 | **Backward compat:** Upgrading doesn't break anything. RBAC off = same behavior as today. |
| NFR-4 | **Simplicity:** Common cases (family with kids, shared apartment) configurable in <5 minutes via UI. |
| NFR-5 | **Maintainability:** RBAC logic decoupled from resource code via an authorization service interface. Endpoints call the service — they don't implement policy. |
| NFR-6 | **Testability:** Authorization service testable independently without REST infrastructure. |
| NFR-7 | **Storage:** JSON DB — same mechanism as everything else, supports backup/restore. |
| NFR-8 | **Standards:** OAuth2 implementation should pass conformance tests. Tokens and endpoints interoperable with standard OAuth2 clients and libraries out of the box. |
| NFR-9 | **Security:** Short-lived tokens (default: 1 hour). Refresh token rotation. PKCE required for public clients. |
| NFR-10 | **Interop:** Third-party tools (Grafana, Node-RED, Home Assistant) authenticate via standard OAuth2 flows without openHAB-specific hacks. |
| NFR-11 | **Role governance:** Tooling to detect unused roles (no users), redundant roles (identical perms), and overlapping roles (>90% overlap). Admin dashboard or report. Configurable soft limit on custom role count as a guardrail against role explosion. |
| NFR-12 | **Access review:** Periodic access review support. Admins can list all users with effective permissions and last-review timestamp. Optional notification when a user hasn't been reviewed within a configurable period (default: 90 days). |
| NFR-13 | **Extensibility (context conditions):** Permission model should accommodate future context conditions (network source, time-of-day, device type) without breaking changes. Initial implementation doesn't enforce them, but the data model must not preclude them. |
| NFR-14 | **Simulation:** Authorization service supports dry-run/what-if evaluation without persisting changes. Backs FR-12.2 and enables UI-based permission previews. |

    
