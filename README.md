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

## Code style

Three tools, no overlap (wired in [`gradle/quality.gradle`](gradle/quality.gradle),
matching the `api` and `auth` services):

| Tool | Owns | Fix it with |
|---|---|---|
| **Spotless** (google-java-format, `aosp`) | all layout — 4-space indent, 100-column wrap, whitespace, import order | `./gradlew spotlessApply` |
| **Checkstyle** | semantic rules only — naming, declaration order, visibility, switch correctness | by hand |
| **Error Prone** | real defects at compile time — it runs inside `javac` | `./gradlew compileJava -PerrorproneFix=<Check1,Check2>` |

`./gradlew check` runs all three. **Never hand-format Java** — run `spotlessApply` and
let it decide. Don't add layout rules back to `config/checkstyle/checkstyle.xml`; they
will either be silently redundant or fight the formatter.

[`.githooks/pre-commit`](.githooks/pre-commit) runs `spotlessApply` over staged Java and
re-stages it. It is committed, but **`core.hooksPath` is local config and does not
survive a clone** — run this once per checkout or the hook silently never fires:

```sh
git config core.hooksPath .githooks
```

## Publishing

Publishes to this repo's own GitHub Packages Maven registry
(`com.habittracker:auth-client`) via the `Publish` workflow, which runs on
any pushed tag matching `v*` and authenticates with the default
`GITHUB_TOKEN` (no PAT needed - the workflow declares `packages: write`).

To cut a release: bump `version` in `build.gradle`, commit, tag that commit
`vX.Y.Z` matching the new version, and push the tag.
