# Contributing to osctrl

Contributions are welcome across the Go services, React frontend, deployment assets, documentation, and tests.

## Before You Start

- Search existing issues and pull requests before opening a duplicate.
- Use the latest supported Go version from `go.mod` and Node.js 22 or newer for frontend work.
- Read [AGENTS.md](./AGENTS.md) for repository-specific workflows and [ARCHITECTURE.md](./ARCHITECTURE.md) before changing shared runtime behavior.
- Report vulnerabilities privately according to [SECURITY.md](./SECURITY.md), not in a public issue.

For substantial behavior or architecture changes, open an issue first so the approach and compatibility impact can be discussed.

## Development Workflow

Build the complete project:

```bash
make build
```

Run the Go test suite:

```bash
go test ./...
```

Validate frontend changes:

```bash
make frontend-test
```

When public REST behavior changes, regenerate and verify the API specification:

```bash
make openapi
make openapi-check
```

Release and package changes should also pass:

```bash
make release-check
make release-build
```

The local stack can be built and started with:

```bash
cp .env.example .env
make docker_dev_certs
make docker_dev_build
make docker_dev_up
```

Review the development credentials in `.env` before use. Never commit that file, generated certificates, tokens, or built artifacts.

## Pull Requests

Keep each pull request focused and include:

- The problem being solved
- The resulting behavior
- Security, compatibility, or operational impact
- Tests and validation performed
- Screenshots for visible frontend changes

Follow existing code patterns, format Go changes with `gofmt`, and add focused regression coverage for changed behavior. Generated OpenAPI files, sample configuration, package metadata, and documentation should remain synchronized with the implementation.

By contributing, you agree that your changes are provided under the repository's MIT license.
