<div align="center">

# SSL Certificate Verifier

**Operator-first SSL/TLS certificate checker workspace for domains, IP addresses, HTTP/HTTPS URLs, non-standard ports, TLS version detection, root trust, intermediate and full-chain verification.**

![build](https://img.shields.io/badge/build-ready-brightgreen)
![release](https://img.shields.io/badge/release-v0.1.0-blue)
![license](https://img.shields.io/badge/license-MIT-blue)
![runtime](https://img.shields.io/badge/runtime-Go-orange)
![interfaces](https://img.shields.io/badge/interfaces-CLI%20%7C%20GUI-8A2BE2)
![targets](https://img.shields.io/badge/targets-domain%20%7C%20IP%20%7C%20HTTP%20%7C%20HTTPS-0E8A16)
![trust](https://img.shields.io/badge/trust-root%20%7C%20intermediate%20%7C%20chain-yellow)

[Quick Start](#quick-start) • [CLI](#cli-usage) • [GUI](#browser-gui) • [Target Syntax](#target-syntax) • [TLS Detection](#tls-version-detection) • [Chain Verification](#certificate-chain-verification) • [Feature Coverage](docs/FEATURE_COVERAGE.md) • [Private Sites](#private-sites-and-custom-cas) • [Platforms](#platform-support) • [GitHub/GitLab/Gitea](#github-gitlab-and-gitea) • [Security](#security-model) • [License](#license)

English • [Türkçe](README.tr.md)

</div>

---

A desktop, server and operator-friendly project for validating SSL/TLS endpoints before outages, releases, migrations, certificate rotations or compliance reviews. It can check public internet services, internal/private domains, IP-only appliances, load balancers, Kubernetes ingress endpoints, reverse proxies and services running on custom ports.

The project ships with a native CLI and a browser-based GUI. The GUI is intentionally served by the same binary, so it works on Windows, Windows Server, Linux, BSD, Solaris/illumos, macOS and mobile browsers without needing a heavyweight desktop framework.

## What it checks

- Domain names, IP addresses, `host:port`, `http://` and `https://` targets.
- HTTPS and raw TLS services on standard or non-standard ports.
- Plain HTTP reachability, with a clear warning that no certificate exists for plain HTTP.
- TLS handshake details: negotiated TLS version, cipher suite, ALPN and SNI.
- TLS version support probes for TLS 1.0, 1.1, 1.2 and 1.3.
- TLS 1.0-1.2 cipher suite inventory with weak, legacy, CBC, AEAD and forward-secrecy classification.
- Leaf certificate validity, expiry, not-before dates, SANs, IP SANs and fingerprint.
- Detailed certificate metadata including serial number, issuer/subject organization, validation-policy hints, key usage, EKU, public key hash, SHA-1/SHA-256 fingerprints, OCSP, CRL and CT/SCT signals.
- Root trust using the OS trust store, optionally extended with a private PEM CA bundle.
- Intermediate certificate presence and chain buildability.
- Hostname or IP identity verification, including IP SAN verification for IP targets.
- DNS A, AAAA, CNAME, PTR and CAA records that affect certificate issuance and installation diagnostics.
- HTTP/HTTPS response headers including HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy and redirect behavior.
- Local security findings for common certificate, protocol, cipher, header and installation problems.
- JSON output for automation, CI/CD, GitHub, GitLab, Gitea and monitoring scripts.

## Quick start

```bash
# Build the CLI and GUI binary
go build -o bin/sslcertcheck ./cmd/sslcertcheck

# Check a public domain
./bin/sslcertcheck check example.com

# Check a service on a custom HTTPS port
./bin/sslcertcheck check https://example.com:8443

# Check an internal IP using SNI and hostname verification
./bin/sslcertcheck check --servername app.internal.local --verify-name app.internal.local 10.10.0.25:443

# Use a private root CA bundle
./bin/sslcertcheck check --ca-file ./corp-root-ca.pem https://portal.internal:9443

# Start the browser GUI
./bin/sslcertcheck gui --open --listen 127.0.0.1:8088
```

## CLI usage

```text
sslcertcheck check [flags] <target> [target...]
sslcertcheck gui [flags]
sslcertcheck version
```

Useful flags:

```text
--format text|json        Output human-readable text or machine-readable JSON
--port 9443               Override the parsed/default port
--servername NAME         Send a specific SNI name during the TLS handshake
--verify-name NAME        Verify the certificate against a specific DNS name or IP
--timeout 10s             Network timeout
--tls-min 1.2             Minimum TLS version for the main handshake
--tls-max 1.3             Maximum TLS version for the main handshake
--ca-file FILE            Append a PEM CA bundle to the system trust store
--no-hostname             Verify only the chain, not the hostname
--skip-tls-probe          Skip TLS 1.0/1.1/1.2/1.3 version probing
--include-pem             Include PEM bodies in JSON output
--force-tls               Perform TLS even when the target uses http://
--skip-dns                Skip DNS A/AAAA/CNAME/CAA/PTR lookups
--skip-http               Skip HTTP/HTTPS response header checks
--skip-cipher-scan        Skip TLS 1.0-1.2 cipher suite inventory
--fail-on-invalid         Exit with code 2 when TLS verification fails
```

JSON output example:

```bash
sslcertcheck check --format json --fail-on-invalid example.com > report.json
```

## Browser GUI

The GUI is included in the same binary and exposes a local web interface plus a small JSON API.

```bash
sslcertcheck gui --open --listen 127.0.0.1:8088
```

For team or lab use, bind to a private interface and protect access with your network controls:

```bash
sslcertcheck gui --listen 10.0.0.15:8088
```

The default bind address is `127.0.0.1` to avoid accidentally exposing an internal network probing tool.

## Target syntax

| Input | Meaning |
|---|---|
| `example.com` | HTTPS/TLS check on port 443 |
| `example.com:8443` | HTTPS/TLS check on port 8443 |
| `192.168.1.10` | HTTPS/TLS check on IP port 443 |
| `10.0.0.5:9443` | HTTPS/TLS check on IP port 9443 |
| `https://portal.example.com:9443/path` | HTTPS/TLS check with URL path retained for display |
| `http://router.local:8080` | Plain HTTP reachability check; no certificate verification |
| `[2001:db8::10]:443` | IPv6 TLS check |

For IP endpoints hosting name-based certificates, provide SNI and verification identity:

```bash
sslcertcheck check --servername api.internal.example --verify-name api.internal.example 10.0.4.20:443
```

## TLS version detection

The checker performs a main TLS connection and, unless disabled, probes exact TLS versions independently:

```text
TLS 1.0  supported / not supported
TLS 1.1  supported / not supported
TLS 1.2  supported / not supported
TLS 1.3  supported / not supported
```

This helps detect legacy protocol exposure and verify that modern TLS is enabled. Use `--skip-tls-probe` for very slow or rate-limited endpoints.

Unless disabled with `--skip-cipher-scan`, the checker also probes TLS 1.0, 1.1 and 1.2 cipher suites and classifies accepted ciphers as modern, legacy or weak. TLS 1.3 cipher suites are reported through the negotiated/probed TLS connection because Go intentionally does not allow forcing individual TLS 1.3 cipher suites.

## Certificate chain verification

The verifier separates the major certificate checks so operators can quickly see what failed:

- **Chain verification**: can the leaf certificate build to a trusted root using the server-sent intermediates and the selected root store?
- **Hostname verification**: does the leaf certificate match the requested domain, verification name or IP SAN?
- **Root trust**: is the terminal root trusted by the OS trust store or by a custom CA bundle?
- **Intermediate detection**: did the server omit likely intermediate certificates?
- **Validity**: is the leaf expired or not yet valid?
- **Self-signed detection**: is the leaf self-signed?
- **Revocation and transparency hints**: does the certificate advertise OCSP/CRL endpoints, OCSP Must-Staple or SCTs?
- **Installation metadata**: issuer, subject, SANs, key usage, EKU, public key size/hash and fingerprints.

The TLS handshake intentionally collects peer certificates even when the certificate is invalid, then performs explicit verification. That means broken, expired, private or incomplete chains can still be inspected instead of failing silently.

## Local security findings

The `security` JSON section and text summary combine the evidence into a local score and grade. This grade is intentionally local and transparent; it is not a claim to reproduce Qualys SSL Labs' proprietary grading or multi-vantage public-internet scanner. Findings cover expired or mismatched certificates, chain/root trust failures, obsolete TLS versions, weak or legacy ciphers, missing HSTS/security headers, missing CAA records, BEAST/ROBOT preconditions that can be inferred locally, and unsupported low-level vulnerability probes such as Heartbleed, Ticketbleed and SSLv3 POODLE as explicit `not_tested` findings.

## Private sites and custom CAs

Private sites work when they are reachable from the machine running the checker. For private PKI, append your CA bundle:

```bash
sslcertcheck check --ca-file ./company-root-and-intermediates.pem https://intranet.local
```

The custom bundle is appended to the OS trust store. It does not replace system roots.

## Platform support

| Platform | CLI | GUI | Notes |
|---|---:|---:|---|
| Windows / Windows Server | ✅ | ✅ | Native `.exe`; GUI opens in the default browser |
| Linux | ✅ | ✅ | Static-friendly server/CLI binary |
| macOS | ✅ | ✅ | Native binary; `--open` uses the default browser |
| FreeBSD / OpenBSD / NetBSD | ✅ | ✅ | Browser GUI served by the binary |
| Solaris / illumos | ✅ | ✅ | Build with Go support for the target architecture |
| Android | ✅ | ✅ | CLI through terminal environments such as Termux; GUI through Android browser |
| iOS / iPadOS | Browser mode | ✅ | iOS normally does not allow arbitrary local CLI binaries; use the web GUI from a reachable checker host or embed the Go library in a signed app wrapper |

## Build from source

```bash
# Test
go test ./...

# Build current platform
go build -trimpath -ldflags="-s -w" -o dist/sslcertcheck ./cmd/sslcertcheck

# Examples for common targets
GOOS=windows GOARCH=amd64 go build -o dist/sslcertcheck-windows-amd64.exe ./cmd/sslcertcheck
GOOS=linux   GOARCH=amd64 go build -o dist/sslcertcheck-linux-amd64       ./cmd/sslcertcheck
GOOS=darwin  GOARCH=arm64 go build -o dist/sslcertcheck-darwin-arm64      ./cmd/sslcertcheck
GOOS=freebsd GOARCH=amd64 go build -o dist/sslcertcheck-freebsd-amd64     ./cmd/sslcertcheck
GOOS=android GOARCH=arm64 go build -o dist/sslcertcheck-android-arm64     ./cmd/sslcertcheck
```

For reproducible multi-platform release builds, see [`scripts/build.sh`](scripts/build.sh) and [`scripts/build.ps1`](scripts/build.ps1).

## Docker

```bash
docker build -t sslcertcheck:local .
docker run --rm sslcertcheck:local check example.com
docker run --rm -p 8088:8088 sslcertcheck:local gui --listen 0.0.0.0:8088
```

## GitHub, GitLab and Gitea

This repository includes platform-ready files:

- `.github/workflows/ci.yml` for GitHub Actions.
- `.gitlab-ci.yml` for GitLab CI.
- `.gitea/workflows/ci.yml` for Gitea Actions.
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `.gitignore` and release scripts.

The CLI is CI-friendly because `--format json` produces structured output and `--fail-on-invalid` returns a non-zero exit code for broken TLS targets.

Example CI gate:

```bash
sslcertcheck check --fail-on-invalid --format json https://production.example.com > tls-report.json
```

## Repository layout

```text
cmd/sslcertcheck/        CLI entry point
internal/checker/        TLS, certificate, chain and HTTP checking engine
internal/gui/            Browser GUI and JSON API
docs/                    Usage, platform, release and security notes
scripts/                 Cross-platform build helpers
.github/workflows/      GitHub Actions workflow
.gitea/workflows/       Gitea Actions workflow
.gitlab-ci.yml          GitLab CI workflow
```

## Security model

- No telemetry, analytics or external callback is built into the project.
- The checker opens outbound connections only to targets you provide.
- The GUI binds to `127.0.0.1` by default.
- Private CA files are read from the local machine running the checker.
- Results may contain internal hostnames, certificate subjects and fingerprints, so treat reports as operational evidence.

## License

MIT. See [`LICENSE`](LICENSE).
