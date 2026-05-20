# Release Guide

## Local release build

```bash
./scripts/build.sh
```

On Windows PowerShell:

```powershell
./scripts/build.ps1
```

The Windows helper verifies that the required Go version is available before it runs tests or builds. If Go is missing, it prints install options and exits. To explicitly allow Go installation or update through `winget`, run:

```powershell
./scripts/build.ps1 -InstallGo
```

## Suggested release assets

- `sslcertcheck-windows-amd64.exe`
- `sslcertcheck-linux-amd64`
- `sslcertcheck-linux-arm64`
- `sslcertcheck-darwin-amd64`
- `sslcertcheck-darwin-arm64`
- `sslcertcheck-freebsd-amd64`
- `sslcertcheck-solaris-amd64`
- SHA-256 checksum file

## Versioning

Use semantic versioning:

- Patch: bug fixes and safe output additions.
- Minor: new checks or backward-compatible JSON fields.
- Major: breaking CLI or JSON schema changes.
