# habit-tracker-shared-libraries-auth

Shared JWT-verification client library for habit-tracker's microservices.

## Scope

Holds the **verify-only** subset of what `auth` used to do itself:
- `AccessTokenValidator` - parses and verifies an already-issued access
  token (signature + expiry), extracting a `JwtPrincipal` (email, first/last
  name) and its granted authorities from the claims.
- `JwtAuthenticationFilter` - a Spring Security `OncePerRequestFilter` that
  extracts the Bearer token, validates it, and sets the request's
  `Authentication`.
- `JwtAuthenticationException` - thrown on a missing/invalid/expired token.
- `AuthClientAutoConfiguration` - a Spring Boot auto-configuration that wires
  both beans automatically. A consuming service only needs to add this
  dependency and set `jwt.access-secret` - no manual `@Bean` definitions
  required. It still needs to insert `JwtAuthenticationFilter` into its own
  `SecurityFilterChain` (e.g. `.addFilterBefore(jwtAuthenticationFilter,
  UsernamePasswordAuthenticationFilter.class)`), since filter-chain assembly
  is inherently per-service.

Token **issuance** (login/register, refresh-token storage/revocation) stays
in the `auth` service itself - other services should only ever be able to
verify tokens, never mint them.

## Publishing

Publishes to this repo's own GitHub Packages Maven registry
(`com.habittracker:auth-client`) via the `Publish` workflow, which runs on
any pushed tag matching `v*` and authenticates with the default
`GITHUB_TOKEN` (no PAT needed - the workflow declares `packages: write`).

To cut a release: bump `version` in `build.gradle`, commit, tag that commit
`vX.Y.Z` matching the new version, and push the tag.
