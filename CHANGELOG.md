# Changelog

Every release of sitelabs-graph-security: a tag `v<version>`, and an entry here, newest first.
Versions follow [semantic versioning](https://semver.org/). Before 1.0, a minor release (0.1 to
0.2) may change the API, said so under **Changed** with what to do under **Upgrading**; a patch
release doesn't. The API: [the docs](https://sitelabs-com.github.io/sitelabs-graph-security/latest/overview/#versions).

## [Unreleased]

### Added

- The documentation site (`docs/`, published to GitHub Pages with mike: a site per release,
  `/0.2/`, `/0.3/` ..., and `/latest/`, which applications link to by the release they pin), a test
  workflow (`.github/workflows/ci.yml`, run by hand), and this changelog.

### Changed

- NOTICES.txt lists FastAPI and Starlette, pytest and Python.

## [0.2.0] - 2026-11-17

### Added

- `graph_security.web`, for FastAPI (the `fastapi` extra): `Security`, one per application, wired
  by hooks to its parts, request state, audit log and help texts. As dependencies: who the caller
  is, the permission, an admin login for admin permissions (an admin call with no key or token
  asks for one), the rate limit and work at once. `session_router()`: `GET`, `POST` and `DELETE
  /session`, and the sign-in at the identity provider (`/console/sso/...`).
- Tests with an application wired as the applications wire it.

### Upgrading

- An application that did these checks itself can replace them with `Security`
  ([In a FastAPI app](https://sitelabs-com.github.io/sitelabs-graph-security/0.2/fastapi/)). Nothing in 0.1.0 changed.

## [0.1.0] - 2026-11-17

### Added

- Security shared by the sitelabs graph servers, moved from sitelabs-graph-database and
  sitelabs-partitioned-graph, which each had a copy: API keys, roles and permissions (a `Catalogue`
  each application registers), the admin login, browser sessions, OAuth 2.0 / OpenID Connect access
  tokens, rate limits, internal TLS, the refusals and a settings dataclass, with their tests.

[Unreleased]: https://github.com/sitelabs-com/sitelabs-graph-security/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sitelabs-com/sitelabs-graph-security/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sitelabs-com/sitelabs-graph-security/releases/tag/v0.1.0
