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
- `dns`: A, AAAA, CNAME, PTR and CAA lookup results.
- `tls`: handshake, negotiated TLS, OCSP staple/SCT data, TLS version probes and TLS 1.0-1.2 cipher inventory.
- `http`: HTTP/HTTPS reachability, redirects, response headers and security header checks.
- `verification`: hostname, root trust, chain and validity checks.
- `certificates`: certificates sent by the server, including issuer/subject fields, SANs, key usage, public key data, fingerprints, OCSP, CRL and CT/SCT hints.
- `security`: local score, local grade and pass/warn/fail/not-tested findings.
- `warnings`: operational warnings.
- `errors`: connection or verification errors.

## Advanced scan controls

The default check performs DNS, TLS version, cipher and HTTP/HTTPS header diagnostics. Disable slower or environment-sensitive checks when needed:

```bash
sslcertcheck check --skip-dns example.com
sslcertcheck check --skip-http example.com
sslcertcheck check --skip-cipher-scan example.com
sslcertcheck check --skip-tls-probe example.com
```

The local `security.local_grade` is a transparent local score, not a clone of SSL Labs' proprietary grade. Low-level vulnerability probes that cannot be performed safely with the Go standard TLS stack are included as `not_tested` findings instead of being silently omitted.

## CI gate

```bash
sslcertcheck check --fail-on-invalid --format json https://production.example.com > tls-report.json
```

Exit codes:

- `0`: command completed successfully.
- `1`: command usage, connection or runtime error.
- `2`: `--fail-on-invalid` was set and at least one TLS target failed verification.
