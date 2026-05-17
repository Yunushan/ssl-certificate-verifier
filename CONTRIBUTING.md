# Contributing

Thank you for contributing to SSL Certificate Verifier.

## Development setup

```bash
go test ./...
go build -o bin/sslcertcheck ./cmd/sslcertcheck
./bin/sslcertcheck check example.com
```

## Contribution guidelines

- Keep the checker dependency-light and portable.
- Prefer standard-library features when possible.
- Add tests for parsing, TLS verification behavior and output changes.
- Keep CLI output stable enough for operators and JSON output stable enough for automation.
- Do not add telemetry or external callbacks.

## Pull request checklist

- [ ] `go test ./...` passes.
- [ ] New behavior is documented in `README.md` or `docs/`.
- [ ] Security-sensitive changes are explained clearly.
- [ ] JSON fields are kept backward compatible where practical.
