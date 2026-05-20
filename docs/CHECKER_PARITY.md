# External SSL Checker Parity Roadmap

This project aims to cover the combined public feature surface of common SSL/TLS checker tools while keeping the scanner local, transparent and operator-friendly.

## Target Checkers

- SSL Shopper SSL Checker
- Qualys SSL Labs SSL Server Test
- SSL.org SSL Certificate Checker
- SSLChecker.com SSL Certificate Checker
- Natro SSL Checker
- DigiCert SSL Installation Diagnostics Tool
- decoder.link SSL Checker
- GeoCerts SSL Installation Checker
- SSL.com SSL Certificate Checker
- MXToolBox HTTPS Lookup

## Definition Of 100% Parity

For this project, 100% parity means:

- Every publicly visible check category from the target tools has an equivalent local check, a better local check, or an explicit unsupported reason.
- Text and JSON reports expose enough evidence for an operator to understand the result without using a third-party website.
- Checks work for public targets, private DNS names, internal IPs and custom ports when reachable from the machine running the scanner.
- The tool does not silently claim safety for checks it cannot perform.

100% parity does not mean:

- Reproducing proprietary grading formulas exactly.
- Using private SSL Labs datasets, browser matrices or server-side scanner infrastructure.
- Providing paid hosted monitoring, email reminder delivery or third-party account features inside the local binary.

## Current Coverage

Implemented:

- Certificate installation, expiry, subject, issuer, serial number and fingerprints.
- SAN, wildcard SAN, IP SAN, email SAN and URI SAN display.
- Hostname verification, root trust and server-sent chain validation.
- Intermediate certificate inspection and verified chain candidates.
- TLS handshake details, negotiated protocol, cipher suite, SNI, ALPN and OCSP staple metadata.
- TLS 1.0, 1.1, 1.2 and 1.3 support probing.
- TLS 1.0-1.2 cipher inventory with weak, legacy, CBC, AEAD and forward-secrecy classification.
- DNS A, AAAA, CNAME, PTR and CAA lookups.
- HTTP/HTTPS reachability, redirect behavior and common security header checks.
- Plain HTTP detection and HTTPS redirect failure reporting.
- JSON output for automation and CI.
- K3s/RKE2 certificate and Kubernetes API TLS checks.

Partial:

- BEAST and ROBOT are inferred from observable preconditions.
- TLS 1.3 cipher information is reported from negotiated/probed connections, not individual TLS 1.3 cipher forcing.
- Local grading exists, but it is not an SSL Labs clone.
- OCSP, CRL, CT and SCT metadata is collected, but live revocation and CT log validation are not complete.

Missing:

- Full STARTTLS checks for SMTP, IMAP, POP3, LDAP, FTP and XMPP.
- Full low-level vulnerability probes for Heartbleed, Ticketbleed, DROWN, CRIME, POODLE variants, ROBOT and renegotiation issues.
- Browser/client simulation matrix.
- Public multi-vantage scanning across all DNS answers, CDN edges and IPv4/IPv6 paths.
- Live OCSP/CRL revocation verification.
- CT log lookup and SCT verification.
- Mixed-content crawling and insecure form submission detection.
- CSR decoder, certificate decoder, CSR/private-key/certificate matcher and CA matcher utilities.
- Expiry reminders, scheduled monitoring and alert delivery.
- MXToolBox-style HTTPS content/regex monitoring.
- Exact SSL Labs-compatible grade caps and category scores.

## Tool Parity Matrix

| Tool | Current parity | Main gaps |
|---|---:|---|
| SSL Shopper SSL Checker | High | Expiry reminder workflow |
| DigiCert SSL Installation Diagnostics | High | Common vulnerability probes, support-oriented remediation text |
| GeoCerts SSL Installation Checker | High | Hosted support workflow |
| SSL.com SSL Certificate Checker | High | Hosted health monitoring and account features |
| Natro SSL Checker | Medium-high | Expiry reminder workflow and commercial SSL metadata |
| SSLChecker.com SSL Certificate Checker | Medium-high | Email reminder, decoder/matcher side tools, insecure content checker |
| decoder.link SSL Checker | Medium | STARTTLS, OCSP checker, CT log tool, key/CA matcher, bulk checker |
| SSL.org SSL Certificate Checker | Medium | Full vulnerability scanner and deeper cipher/protocol detail |
| MXToolBox HTTPS Lookup | Medium | HTTPS content/regex monitoring, hosted monitor alerts |
| SSL Labs SSL Server Test | Medium | Browser simulation, revocation, CT, vulnerability probes, exact rating model, multi-endpoint public assessment |

## Implementation Roadmap

### Phase 1: Operator Root-Cause Coverage

- Detect insecure HTML form actions on HTTPS pages.
- Detect mixed active content such as scripts, stylesheets, iframes and forms loaded over HTTP.
- Improve remediation messages for IIS, Nginx, Apache and load balancers.
- Add `--summary-only` and `--explain` output modes for helpdesk-friendly diagnostics.

### Phase 2: Certificate And PKI Utilities

- Add certificate decoder for local PEM/DER files.
- Add CSR decoder.
- Add CSR/private-key/certificate matcher.
- Add CA/intermediate matcher.
- Add OCSP live status fetch.
- Add CRL fetch and revocation check.
- Add CT log lookup and SCT validation.

### Phase 3: STARTTLS And Service Coverage

- Add `starttls` command.
- Support SMTP, IMAP, POP3, LDAP, FTP and XMPP STARTTLS.
- Add service-specific default ports and protocol banners.
- Add JSON output compatible with the existing `check` result model.

### Phase 4: Low-Level TLS Vulnerability Probes

- Add dedicated low-level probe package outside Go's standard TLS client.
- Implement safe Heartbleed detection.
- Implement Ticketbleed detection.
- Implement DROWN precondition checks.
- Implement CRIME/BREACH-adjacent compression checks where remotely observable.
- Implement POODLE SSLv3 and POODLE TLS checks.
- Implement full ROBOT oracle checks with conservative rate limiting.
- Implement secure renegotiation and client-initiated renegotiation checks.

### Phase 5: SSL Labs-Style Assessment

- Add protocol, key-exchange and cipher-strength category scores.
- Add grade caps for common SSL Labs-style rules.
- Add browser/client simulation data as a versioned local dataset.
- Add per-IP endpoint scanning for all A/AAAA answers.
- Add optional public vantage support through self-hosted workers.

### Phase 6: Monitoring And Bulk Workflows

- Add bulk input files.
- Add watch mode for recurring local scans.
- Add expiry threshold alerts.
- Add webhook/email output integrations.
- Add content/regex checks for HTTPS pages.
- Add report history and diff output.

## Design Rule

When a target checker has a feature that cannot be implemented safely or locally, the report must say `not_tested` with a concrete reason. Silent omissions are not acceptable for the 100% parity goal.
