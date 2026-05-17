# Security Model

## Verification flow

1. Normalize the target.
2. Open a TCP connection.
3. Perform a TLS handshake with certificate verification disabled only for collection.
4. Extract the peer certificate chain.
5. Verify the leaf with Go's X.509 verifier against the system trust store plus any supplied custom CA bundle.
6. Verify hostname or IP identity unless explicitly disabled.
7. Probe exact TLS versions separately.
8. Return structured text or JSON results.

This design lets the tool inspect invalid, expired or incomplete certificates instead of aborting before a useful report can be produced.

## Trust store

By default, the system root store is used. `--ca-file` appends PEM certificates to the system roots; it does not replace them.

## GUI exposure

The GUI binds to `127.0.0.1` by default. Binding to `0.0.0.0` or a private network address makes the checker reachable by other users on that network. Protect it accordingly.

## Report sensitivity

Reports can include internal names, certificate subjects, SANs, serial numbers and fingerprints. Treat reports as operational/security evidence.
