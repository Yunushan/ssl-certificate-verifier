# SSL Checker Feature Coverage

This project targets the combined public feature surface of common SSL checker tools while keeping the scanner local, transparent and dependency-light.

## Covered locally

- Host, URL, IP and custom port input.
- SNI and explicit hostname verification overrides.
- Certificate presence, subject, issuer, serial number, validity dates and days remaining.
- SAN DNS names, wildcard names, IP SANs, email SANs and URI SANs.
- Public key algorithm, key size, SPKI SHA-256, key usage and extended key usage.
- Signature algorithm, MD5/SHA-1/SHA-256 fingerprints and optional PEM output.
- OCSP, CRL, OCSP Must-Staple and certificate transparency SCT signals.
- Server-sent chain inspection, root trust, hostname match and verified chain candidates.
- TLS handshake details, ALPN and peer certificate count.
- TLS 1.0, 1.1, 1.2 and 1.3 protocol support probes.
- TLS 1.0-1.2 cipher inventory with weak, legacy, CBC, AEAD and forward-secrecy classification.
- DNS A, AAAA, CNAME, PTR and CAA records.
- HTTP/HTTPS response details, redirect behavior and common security headers.
- K3s and RKE2 presets for `/etc/rancher/...` kubeconfigs and `/var/lib/rancher/...` certificate directories.
- Kubernetes API server live TLS checks using kubeconfig CA file or inline CA data.
- Local security score, local grade and pass/warn/fail findings.

## Reported with explicit limits

- BEAST and ROBOT are reported from observable preconditions such as TLS 1.0 CBC support and static RSA key-exchange support.
- SSLv3 POODLE, Heartbleed and Ticketbleed require dedicated low-level probes that Go's standard TLS client does not expose safely. They appear as `not_tested` findings instead of being omitted or marked safe.
- TLS 1.3 cipher suites are reported through negotiated/probed connections. Individual TLS 1.3 cipher forcing is not exposed by Go.
- The local grade is not the Qualys SSL Labs grade. SSL Labs performs a public-internet, multi-endpoint assessment with its own scoring model.
