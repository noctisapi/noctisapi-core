# Contributing to NoctisAPI Core

## Purpose

This document defines how to contribute to NoctisAPI Core in a way that is consistent, reviewable, and aligned with the project’s architecture and security goals.

NoctisAPI Core is a security-focused API honeypot platform. Contributions must prioritize determinism, observability, and realism of exposed endpoints.

---

## Scope of contributions

Valid contribution types:

- Bug fixes
- Performance improvements
- Documentation updates
- New modular endpoints aligned with the catalog system
- Improvements to detection, logging, or classification logic
- Refactoring that reduces complexity or removes legacy dependencies

Out of scope (will be rejected):

- Features that bypass the modular API architecture
- Hardcoded behavior not driven by configuration/catalog
- Non-deterministic logic without justification
- Cosmetic-only changes without functional value

---

## Architecture constraints

All contributions must respect the current architecture:

- `CatalogRegistry` defines the available endpoints
- `InstanceConfig` defines enabled behavior per deployment
- `EffectiveRuntimeConfig` is the resolved runtime configuration
- Execution must not depend on legacy path-based systems

Rules:

- No duplication between catalog and runtime
- No direct coupling between endpoints and transport layer
- All endpoint behavior must be derivable from configuration
- Avoid introducing new global state

---

## Endpoint contributions

When adding or modifying endpoints:

1. Define the endpoint in the catalog
2. Ensure it is configurable via `InstanceConfig`
3. Ensure runtime behavior is generated from `EffectiveRuntimeConfig`
4. Use `ResponseFactory` or equivalent standardized response mechanisms
5. Maintain consistency with existing endpoint patterns

Requirements:

- Deterministic responses for identical inputs (unless explicitly designed otherwise)
- Realistic API behavior (status codes, payloads, headers)
- Logging must capture interaction intent

---

## Security considerations

This project intentionally simulates vulnerable or exposed APIs.

Requirements:

- Do not introduce real vulnerabilities that affect the host system
- Do not include code that enables exploitation outside the honeypot context
- Ensure all behaviors are contained within the simulated environment
- Avoid external calls unless strictly necessary and controlled

If a contribution introduces risk:

- Document it explicitly
- Justify why it is required

---

## Coding standards

General:

- Keep functions small and deterministic
- Prefer explicit logic over implicit behavior
- Avoid unnecessary abstraction
- Remove dead or legacy code when modifying related areas

Naming:

- Use descriptive, unambiguous names
- Align with existing naming conventions

Error handling:

- Fail explicitly, not silently
- Avoid generic exceptions

---

## Performance requirements

- Avoid blocking operations in request paths
- Minimize cold-start overhead
- Ensure endpoints scale linearly under load
- Do not introduce unnecessary database or I/O operations

---

## Logging and observability

All relevant actions must be observable:

- Log incoming requests and derived classifications
- Preserve enough context for later analysis
- Avoid excessive noise or redundant logs

Logs must be:

- Structured
- Consistent across endpoints
- Useful for security analysis

---

## Pull request process

1. Fork the repository
2. Create a branch from `main`
3. Implement changes with clear scope
4. Ensure no unrelated changes are included
5. Open a pull request

PR requirements:

- Clear title and description
- Explanation of what was changed and why
- Reference to related issue (if applicable)
- No mixed concerns in a single PR

PRs may be rejected if:

- They violate architecture constraints
- They introduce unnecessary complexity
- They lack clear justification

---

## Review criteria

Maintainers will evaluate:

- Architectural alignment
- Code clarity
- Determinism and correctness
- Security impact
- Performance implications

---

## Testing

Minimum expectations:

- Changes must not break existing behavior
- New endpoints must be manually testable
- Edge cases must be considered

If automated tests exist in the modified area:

- They must pass
- They must be updated if behavior changes

---

## Documentation

Update documentation when:

- Adding new endpoints
- Changing configuration behavior
- Modifying core concepts

Documentation must reflect actual behavior, not intended behavior.

---

## Commit guidelines

- Use clear, concise commit messages
- One logical change per commit
- Avoid vague messages like "fix stuff"
