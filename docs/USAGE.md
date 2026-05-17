# Usage Guide

## Basic checks

```bash
sslcertcheck check example.com
sslcertcheck check example.com:8443
sslcertcheck check https://example.com:9443/status
sslcertcheck check 192.168.1.10:443
```

## IP address with a name-based certificate

Many private services are reached by IP but present a certificate for a DNS name. Use `--servername` for SNI and `--verify-name` for identity verification.

```bash
sslcertcheck check \
  --servername api.internal.example \
  --verify-name api.internal.example \
  10.0.0.25:443
```

## Private CA bundle

```bash
sslcertcheck check --ca-file ./corp-ca.pem https://portal.internal.example
```

The bundle is appended to the system root store.

## JSON automation

```bash
sslcertcheck check --format json example.com > report.json
```

The top-level JSON fields are:

- `target`: normalized scheme, host, port, address, SNI and verify name.
- `tls`: handshake, negotiated TLS and TLS version probe results.
- `http`: plain HTTP reachability results when applicable.
- `verification`: hostname, root trust, chain and validity checks.
- `certificates`: certificates sent by the server.
- `warnings`: operational warnings.
- `errors`: connection or verification errors.

## CI gate

```bash
sslcertcheck check --fail-on-invalid --format json https://production.example.com > tls-report.json
```

Exit codes:

- `0`: command completed successfully.
- `1`: command usage, connection or runtime error.
- `2`: `--fail-on-invalid` was set and at least one TLS target failed verification.
