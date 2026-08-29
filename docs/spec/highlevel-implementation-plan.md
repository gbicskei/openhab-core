# RBAC for openHAB — High-Level Implementation Plan

## Guidelines

### Basic Expectations

- **Small, reviewable PRs.** Large monolithic changes won't get merged. Each PR should be a self-contained, reviewable unit with a clear description of what it does and what it doesn't.
- **No breakage.** Every PR must keep existing behavior intact. RBAC is opt-in. A user who never touches RBAC settings should notice zero difference.
- **Console first, REST later, UI last.** The consensus is that Karaf console commands are the safest way to expose new management capabilities. REST APIs come next (with proper security). UI is the final layer.
- **Start narrow.** Phase 1 focuses on Items, Pages, and Sitemaps only. Things, Rules, and Transformations are admin-only today — RBAC for them is deferred.
- **Build on PR #5753.** Nadahar's auth cleanup (removes JAAS, AuthenticationManager, AuthenticationHandler; makes JwtHelper public; moves passwords to char[]) should be the base.

### Technical Constraints

- Java 21, OSGi Declarative Services, JSON DB storage.
- `@RolesAllowed` stays as a coarse first gate. Fine-grained RBAC is a separate layer on top.
- The `AuthorizationService` interface lives in `org.openhab.core` (the API bundle) so any bundle can depend on it. The implementation lives in a separate bundle.
- Permission evaluation cached in a HashMap, cleared on registry changes (Items CRUD, role/permission changes). No new dependencies (no Caffeine) — same pattern as voice system permission caching.

---

## Phase -1: Regression Safety Net

**Goal:** Cover the existing auth behavior with tests *before* changing anything. This is the safety net that proves we haven't broken existing functionality as we build RBAC on top.

### PR -1.1: Test Coverage for Current Auth Behavior

**Bundles:** `org.openhab.core.io.rest.auth`, `org.openhab.core`, `org.openhab.core.io.rest.core`, `org.openhab.core.io.rest.sse`

- Test `AuthFilter`:
  - JWT bearer token authentication (valid, expired, malformed)
  - API token (`oh.*`) authentication (valid, invalid)
  - Basic Auth (when enabled, when disabled)
  - `implicitUserRole` behavior (true → anonymous gets `user` role; false → denied except from configured `trustedNetworks`)
  - `trustedNetworks` CIDR matching
  - `X-OPENHAB-TOKEN` header handling
- Test `RolesAllowedDynamicFeatureImpl`:
  - Endpoint with `@RolesAllowed({ Role.ADMIN })` — verify user role is rejected (401/403)
  - Endpoint with `@RolesAllowed({ Role.USER, Role.ADMIN })` — verify both roles accepted
  - Unauthenticated request to a secured endpoint → 401
- Test `UserRegistryImpl`:
  - User registration with roles
  - Password authentication (correct, incorrect)
  - API token creation, authentication, and revocation
  - Custom role strings accepted at registry level
- Test `ItemResource` access:
  - Authenticated user with `user` role sees all items
  - Authenticated user with `admin` role sees all items
  - Unauthenticated request with `implicitUserRole=true` sees all items
  - Unauthenticated request with `implicitUserRole=false` gets 401
- Test `UIResource` access:
  - User role can read all pages
  - User role cannot create/update/delete pages
  - Admin role can CRUD pages
- Test `SseResource` access:
  - User role can connect and receive events
  - Topic-based filtering works as expected
- Note: `EventWebSocket` also exists — existing WS filter tests should already cover it. Verify, don't duplicate.
- Test `TokenResource`:
  - Authorization code exchange (happy path)
  - PKCE validation (valid, invalid, missing)
  - Refresh token grant (valid, invalid)
  - Logout / session invalidation

**What this does NOT do:** No new features. Just tests proving current behavior. If any tests fail, we've found a bug in the existing code — fix it before proceeding.

---

## Phase 0: Foundation (non-breaking, no behavioral changes)

**Goal:** Lay the groundwork. Introduce the data model and registries. Nothing is enforced yet — RBAC is off.

### PR 0.1: Role & Permission Data Model + RoleRegistry

**Bundle:** `org.openhab.core`

- Add to core API:
  - `RoleDefinition` — name, description, `Set<Permission>`, builtIn flag
  - `Permission` record — `(ResourceType, Selector, Action)`
  - `ResourceType` enum — `ITEM, PAGE, SITEMAP` (start narrow; others added later)
  - `Action` — abstract per ResourceType. Examples: Items have `READ, COMMAND, EDIT`; Pages have `READ, EDIT, MANAGE` (or `READ, UPDATE, CREATE, DELETE`). Each ResourceType defines its own valid actions.
  - `Selector<T, E>` — generic interface with `boolean match(T type, E entity)`, implemented per ResourceType. Examples: Items use ById, ByGroup, ByTag, ByLocation; Pages use ById and can leverage existing `visibleTo` config. High flexibility without a one-size-fits-all model.
  - `RoleRegistry` interface extending `Registry<RoleDefinition, String>`
  - `RoleProvider` interface extending `Provider<RoleDefinition>`
- Add implementation:
  - `RoleRegistryImpl` — `AbstractRegistry` backed by JSON DB
  - `ManagedRoleProvider` — `DefaultAbstractManagedProvider` with storage name `"roles"`
- Pre-create built-in roles on first boot:
  - `administrator` — builtIn=true, no explicit permissions (short-circuits to allow-all)
  - `user` — builtIn=true, permissions: `(ITEM, All, COMMAND)`, `(PAGE, All, READ)`, `(SITEMAP, All, READ)` (matches current effective behavior)
- Tests: unit tests for RoleRegistry CRUD, permission hierarchy (`implies()`), selector matching

**What this does NOT do:** No enforcement, no REST API, no UI changes. Just the storage layer.

### PR 0.2: AuthorizationService Interface + No-Op Implementation

**Bundle:** `org.openhab.core` (interface), `org.openhab.core.auth.authorization` (implementation)

- Add to core API:
  - `AuthorizationService` interface:
    - `boolean isEnabled()`
    - `boolean hasPermission(Authentication auth, ResourceType type, String resourceId, Action action)`
    - `<T> List<T> filterAuthorized(Authentication auth, Collection<T> resources, ResourceType type, Action action, Function<T, String> idExtractor)`
  - `PermissionEvaluator` interface — pluggable per resource type, works with the type-specific Action and Selector implementations
- Add implementation:
  - `AuthorizationServiceImpl` — delegates to registered `PermissionEvaluator` instances per ResourceType
  - Default: `isEnabled()` returns `false` — all `hasPermission()` calls return `true`
  - Config PID `org.openhab.auth.rbac` with `enabled=false`
- No-op PermissionEvaluators registered for ITEM, PAGE, SITEMAP (stubs that always allow)
- Tests: unit tests for the service interface, verify no-op behavior
- **Next step: open a draft PR or GitHub issue with just the interfaces so technical details can be discussed at the code level.**

**What this does NOT do:** No actual permission checks. Just the service interface wired up and ready.

### PR 0.3: Custom Role Management via Karaf Console

**Bundle:** `org.openhab.core.io.console`

- New `openhab:roles` console command:
  - `list` — list all roles with their permissions
  - `add <name> [description]` — create a custom role
  - `remove <name>` — delete a custom role (blocks for built-in)
  - `addPermission <role> <resourceType> <selector> <action>` — add a permission to a role
  - `removePermission <role> <index>` — remove a permission by index
  - `show <role>` — show role details with all permissions
- Extend existing `openhab:users` command:
  - `addRole <username> <role>` — assign a role to a user
  - `removeRole <username> <role>` — remove a role from a user
- Tests: console command unit tests

**What this does NOT do:** No REST API, no UI, no enforcement. Just the ability to define roles and assign them.

---

## Phase 1: Core Enforcement (Items, Pages, Sitemaps)

**Goal:** When RBAC is toggled on, access control is enforced server-side for Items, Pages, and Sitemaps. Existing `@RolesAllowed` annotations stay untouched.

**Prerequisite:** Phase 0 merged. PR #5753 (Nadahar's auth cleanup PR) merged (or at least accounted for).

### PR 1.1: Item PermissionEvaluator + ItemResource Filtering

**Bundles:** `org.openhab.core.auth.authorization`, `org.openhab.core.io.rest.core`

- Implement `ItemPermissionEvaluator`:
  - Resolves `ByGroup` selectors via `ItemRegistry` group membership (transitive)
  - Resolves `ByLocation` selectors via semantic model tagging
  - Resolves `ByTag` selectors via `Item.getTags()`
  - Resolves `ById` and `All` directly
  - Caches results (Caffeine, invalidated on item/role registry changes)
- Modify `ItemResource`:
  - `getItems()`: call `authorizationService.filterAuthorized()` on the result set
  - `getItemByName()`: call `authorizationService.hasPermission()` — return 404 if denied
  - `postItemCommand()`: check `Action.COMMAND` — return 403 if denied
  - Item CRUD endpoints: check `Action.ADMIN` — return 403 if denied
  - All checks gated behind `authorizationService.isEnabled()` — no-op when RBAC is off
- Tests: unit tests for ItemPermissionEvaluator with various selector types, integration tests for filtered ItemResource responses

### PR 1.2: Page + Sitemap PermissionEvaluators + UIResource/SitemapResource Filtering

**Bundles:** `org.openhab.core.auth.authorization`, `org.openhab.core.io.rest.ui`, `org.openhab.core.io.rest.sitemap`

- Implement `PagePermissionEvaluator`:
  - Selectors: `ById` (page UID), `ByTag` (page tags), `All`
  - Pages reference items in widgets — a page the user can `read` may contain items they can't. The page itself is accessible; individual item states within it are filtered by the item evaluator (handled by the UI or a separate widget-rendering pass).
- Implement `SitemapPermissionEvaluator`:
  - Selectors: `ById` (sitemap name), `All`
- Modify `UIResource`:
  - `getComponents()`: filter by page permissions
  - `getComponent()`: check permission, 404 if denied
- Modify `SitemapResource`:
  - Filter sitemap list
  - Filter individual sitemap access
- Tests: unit + integration tests

### PR 1.3: SSE Event Filtering

**Bundles:** `org.openhab.core.io.rest.sse`, `org.openhab.core.io.rest.sitemap`

Two separate SSE systems exist in different bundles and need independent filtering:

**MainUI SSE** (`org.openhab.core.io.rest.sse` — `SseResource`):
- Capture the `Authentication` from `SecurityContext` at connection time
- Item state tracker (`/rest/events/states`): when a client POSTs an item list to track, reject with 403 if any items are unauthorized. Optionally support a permission-aware filter (configured after connect) that explicitly opts into receiving only permitted items — for clients designed to handle partial results. Other clients get a clear rejection by default.
- General event stream (`/rest/events`): filter emitted events — only send item events for items the user can read, page events for accessible pages

**Sitemap SSE** (`org.openhab.core.io.rest.sitemap` — `SitemapResource`):
- Capture the `Authentication` at subscription time (`POST /rest/sitemaps/events/subscribe`) and store it on the subscription
- Filter `SitemapWidgetEvent` delivery in `SitemapResource.onEvent()`: before broadcasting, check if the user can read the event's item. If not, suppress the event (or strip item data). This is Item-level filtering on widget-level events — access to a sitemap does not imply access to all items on it.
- The `WidgetsChangeListener` and subscription model remain unchanged — filtering happens at the delivery layer, not the listener layer. This keeps the change small and avoids breaking the shared-listener optimization.

Both paths gated behind `authorizationService.isEnabled()`

**Wildcard subscriptions require admin role.** Subscribing to all items/events via wildcard or broad topic filters is restricted to admin users. Non-admin users must subscribe to explicit item lists. This applies to both SSE and WebSocket. Avoids the edge case where permissions change after a wildcard subscription is active.

**WebSocket** follows the same RBAC rules as SSE. Explicit subscriptions are permission-checked; unauthorized filter messages are NACKed (connection stays open). Wildcards require admin.

**Voice control** is also an enforcement point — voice commands targeting items must be checked against the user's permissions. The voice system already has a permission caching pattern that can be extended.

- Tests: verify filtered vs. unfiltered event delivery for both MainUI and sitemap SSE paths. Verify wildcard rejection for non-admin users.

### PR 1.4: Guest Role + implicitUserRole Migration

**Bundle:** `org.openhab.core`

- Add a built-in `guest` role (builtIn=true, default permissions: empty = deny-all)
- When RBAC is enabled, replace `implicitUserRole` boolean behavior:
  - If `implicitUserRole` was `true`: map unauthenticated requests to the `guest` role
  - If `implicitUserRole` was `false`: unauthenticated requests have no role (denied)
- Admin can add permissions to the `guest` role via console (e.g., read a welcome page)
- Backward compat: when RBAC is off, `implicitUserRole` continues to work as today
- Tests: verify guest role behavior with RBAC on/off

---

## What Comes After (Not Planned in Detail)

These phases are scoped but not scheduled. Order depends on demand and contributor availability.

- **Phase 2: OAuth2 Standards Compliance** — align token endpoint with RFC 6749, add JWKS, discovery, introspection, revocation, client registration. Independent of RBAC enforcement.
- **Phase 3: External Auth Backends** — LDAP (Florian's branch as starting point), OIDC, reverse proxy trusted headers.
- **Phase 4: Extended Resource Types** — RBAC for Things, Rules, Transformations, Thing Actions.
- **Phase 5: Advanced Features** — Step-up auth (TOTP/master password), delegation, time-bound roles, break-glass, separation of duties.
- **Phase 6: UI** — Admin interface for role/permission management, permission tester, role governance dashboard.
