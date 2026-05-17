# GitHub, GitLab and Gitea Support

This repository is prepared for the three common Git hosting platforms.

## GitHub

- Workflow: `.github/workflows/ci.yml`
- Runs tests and builds Linux, Windows and macOS binaries.
- Uses `--format json` and `--fail-on-invalid` cleanly in CI gates.

## GitLab

- Pipeline: `.gitlab-ci.yml`
- Runs tests and build jobs using a Go container image.
- Stores built binaries as artifacts.

## Gitea

- Workflow: `.gitea/workflows/ci.yml`
- Compatible with Gitea Actions runners that support standard checkout/setup-go style actions.

## Repository import checklist

After importing to a new host:

1. Update the module path in `go.mod` if you fork or move the repository.
2. Replace imports with your real module path if the module path changes.
3. Run `go mod tidy`.
4. Run `go test ./...`.
5. Build `./cmd/sslcertcheck`.
6. Configure branch protections and release permissions.
