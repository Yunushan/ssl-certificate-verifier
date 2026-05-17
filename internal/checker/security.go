package checker

import (
	"strings"
)

// AnalyzeSecurity builds a local, transparent risk summary from collected evidence.
func AnalyzeSecurity(r *Result) SecurityInfo {
	if r == nil {
		return SecurityInfo{}
	}
	findings := make([]SecurityFinding, 0, 24)
	add := func(id, title, severity, status, description string) {
		findings = append(findings, SecurityFinding{
			ID:          id,
			Title:       title,
			Severity:    severity,
			Status:      status,
			Description: description,
		})
	}

	if r.Protocol == "HTTP" && r.HTTP.Plaintext {
		add("plain_http", "Plain HTTP endpoint", "high", "fail", "The target was checked over plain HTTP, so no TLS certificate protects the connection.")
	}
	if r.TLS.Attempted && !r.TLS.Connected {
		add("tls_handshake", "TLS handshake failed", "critical", "fail", blankDash(r.TLS.Error))
	}
	if r.TLS.Connected {
		if r.TLS.Compression {
			add("tls_compression", "TLS compression enabled", "high", "fail", "TLS compression can expose CRIME-style attacks.")
		} else {
			add("tls_compression", "TLS compression disabled", "info", "pass", "TLS compression was not negotiated.")
		}
	}
	if r.Verification.Checked {
		if r.Verification.Verified {
			add("certificate_trust", "Certificate trusted", "info", "pass", "The leaf certificate built to a trusted root and matched the requested identity.")
		} else {
			add("certificate_trust", "Certificate trust problem", "critical", "fail", strings.Join(r.Verification.Errors, "; "))
		}
		if r.Verification.Expired {
			add("certificate_expired", "Certificate expired", "critical", "fail", "The leaf certificate is past its NotAfter date.")
		}
		if r.Verification.NotYetValid {
			add("certificate_not_yet_valid", "Certificate not yet valid", "high", "fail", "The leaf certificate NotBefore date is in the future.")
		}
		if r.Verification.SelfSignedLeaf {
			add("self_signed_leaf", "Self-signed leaf", "high", "fail", "The server presented a self-signed leaf certificate.")
		}
		if !r.Verification.HostnameVerified && r.Verification.HostnameChecked {
			add("hostname_mismatch", "Hostname mismatch", "critical", "fail", "The certificate does not match the requested verification name.")
		}
	}

	if len(r.Certificates) > 0 {
		leaf := r.Certificates[0]
		if leaf.DaysRemaining >= 0 && leaf.DaysRemaining <= 14 {
			add("expires_soon", "Certificate expires very soon", "high", "warn", "The leaf certificate expires within 14 days.")
		} else if leaf.DaysRemaining > 14 && leaf.DaysRemaining <= 30 {
			add("expires_soon", "Certificate expires soon", "medium", "warn", "The leaf certificate expires within 30 days.")
		}
		if strings.Contains(strings.ToUpper(leaf.SignatureAlgorithm), "SHA1") || strings.Contains(strings.ToUpper(leaf.SignatureAlgorithm), "MD5") {
			add("weak_signature", "Weak certificate signature", "high", "fail", "The leaf certificate uses a deprecated signature hash.")
		}
		if leaf.PublicKeyAlgorithm == "RSA" && leaf.PublicKeySize > 0 && leaf.PublicKeySize < 2048 {
			add("weak_key", "Weak RSA key", "high", "fail", "RSA server certificates should use at least 2048-bit keys.")
		}
		if len(leaf.OCSPServers) == 0 && len(leaf.CRLDistributionPoints) == 0 {
			add("revocation_info", "No revocation endpoints", "medium", "warn", "The leaf certificate does not advertise OCSP or CRL endpoints.")
		}
		if leaf.EmbeddedSCTCount == 0 && r.TLS.SCTCount == 0 {
			add("certificate_transparency", "No SCTs observed", "medium", "warn", "No embedded or handshake certificate transparency timestamps were observed.")
		}
	}

	if len(r.Warnings) > 0 {
		for _, warning := range r.Warnings {
			if strings.Contains(strings.ToLower(warning), "intermediate") || strings.Contains(strings.ToLower(warning), "chain order") {
				add("chain_installation", "Certificate chain installation warning", "medium", "warn", warning)
			}
		}
	}

	addProtocolFindings(r, add)
	addCipherFindings(r, add)
	addHTTPHeaderFindings(r, add)
	addDNSFindings(r, add)
	addVulnerabilityFindings(r, add)

	score := scoreFindings(findings)
	return SecurityInfo{
		LocalGrade: gradeScore(score, findings),
		Score:      score,
		Summary:    summaryForScore(score, findings),
		Findings:   findings,
	}
}

func addProtocolFindings(r *Result, add func(string, string, string, string, string)) {
	tls10 := tlsVersionSupported(r, "TLS 1.0")
	tls11 := tlsVersionSupported(r, "TLS 1.1")
	tls12 := tlsVersionSupported(r, "TLS 1.2")
	tls13 := tlsVersionSupported(r, "TLS 1.3")
	if tls10 {
		add("tls10", "TLS 1.0 enabled", "high", "fail", "TLS 1.0 is obsolete and exposes legacy protocol risk.")
	}
	if tls11 {
		add("tls11", "TLS 1.1 enabled", "medium", "fail", "TLS 1.1 is obsolete and should be disabled.")
	}
	if !tls12 && !tls13 && len(r.TLS.SupportedVersions) > 0 {
		add("modern_tls_missing", "Modern TLS missing", "critical", "fail", "Neither TLS 1.2 nor TLS 1.3 was accepted.")
	}
	if tls13 {
		add("tls13", "TLS 1.3 enabled", "info", "pass", "TLS 1.3 is supported.")
	} else if len(r.TLS.SupportedVersions) > 0 {
		add("tls13", "TLS 1.3 not enabled", "info", "info", "TLS 1.3 was not accepted; TLS 1.2 can still be acceptable when configured safely.")
	}
}

func addCipherFindings(r *Result, add func(string, string, string, string, string)) {
	if len(r.TLS.SupportedCiphers) == 0 {
		add("cipher_scan", "Cipher inventory not available", "info", "not_tested", "Cipher scan was skipped or no cipher probes were completed.")
		return
	}
	weak := 0
	legacy := 0
	noForwardSecrecy := 0
	for _, cipher := range r.TLS.SupportedCiphers {
		if !cipher.Supported {
			continue
		}
		if cipher.Insecure || cipher.RC4 || cipher.TripleDES {
			weak++
		}
		if cipher.Strength == "legacy" || cipher.CBC {
			legacy++
		}
		if !cipher.ForwardSecrecy {
			noForwardSecrecy++
		}
	}
	if weak > 0 {
		add("weak_ciphers", "Weak cipher suites enabled", "high", "fail", "The server accepted RC4, 3DES, or cipher suites marked insecure by Go.")
	} else {
		add("weak_ciphers", "No weak ciphers accepted", "info", "pass", "No RC4, 3DES, or Go-insecure cipher suites were accepted during the local scan.")
	}
	if legacy > 0 {
		add("legacy_ciphers", "Legacy cipher suites accepted", "medium", "warn", "The server accepted CBC or other legacy cipher suites.")
	}
	if noForwardSecrecy > 0 {
		add("forward_secrecy", "Cipher without forward secrecy", "medium", "warn", "At least one accepted cipher suite does not provide forward secrecy.")
	} else {
		add("forward_secrecy", "Forward secrecy", "info", "pass", "All accepted TLS 1.0-1.2 cipher suites in the local scan used ECDHE or DHE.")
	}
}

func addHTTPHeaderFindings(r *Result, add func(string, string, string, string, string)) {
	for _, check := range r.HTTP.SecurityHeaders {
		if check.Status == "pass" || check.Status == "info" {
			continue
		}
		id := "http_header_" + strings.ToLower(strings.ReplaceAll(check.Name, " ", "_"))
		add(id, check.Name+" missing", check.StatusSeverity(), check.Status, check.Description)
	}
}

func addDNSFindings(r *Result, add func(string, string, string, string, string)) {
	if !r.DNS.Attempted || r.Target.IsIP {
		return
	}
	if len(r.DNS.CAA) == 0 {
		add("caa_missing", "CAA record not found", "info", "info", "No CAA records were returned for the target host.")
	} else {
		add("caa_present", "CAA records present", "info", "pass", "CAA records restrict which certificate authorities may issue for the domain.")
	}
	if len(r.DNS.A) == 0 && len(r.DNS.AAAA) == 0 {
		add("dns_address_missing", "No DNS address records", "high", "fail", "No A or AAAA records were returned for the target host.")
	}
}

func addVulnerabilityFindings(r *Result, add func(string, string, string, string, string)) {
	tls10 := tlsVersionSupported(r, "TLS 1.0")
	cbcTLS10 := supportedCipherWhere(r, func(c TLSCipherSupport) bool {
		return c.Version == "TLS 1.0" && c.CBC
	})
	staticRSA := supportedCipherWhere(r, func(c TLSCipherSupport) bool {
		return strings.Contains(c.Name, "_RSA_") && !strings.Contains(c.Name, "_ECDHE_") && !strings.Contains(c.Name, "_DHE_")
	})

	if tls10 && cbcTLS10 {
		add("beast", "BEAST exposure", "medium", "warn", "TLS 1.0 with CBC suites was accepted. Modern clients mitigate BEAST, but disabling TLS 1.0 is recommended.")
	} else if len(r.TLS.SupportedVersions) > 0 {
		add("beast", "BEAST exposure", "info", "pass", "TLS 1.0 CBC exposure was not observed in the local probes.")
	}
	if staticRSA {
		add("robot", "ROBOT precondition present", "medium", "warn", "Static RSA key-exchange cipher suites were accepted. A full ROBOT oracle probe is not performed by this local standard-library scanner.")
	} else if len(r.TLS.SupportedCiphers) > 0 {
		add("robot", "ROBOT precondition absent", "info", "pass", "No static RSA key-exchange cipher suites were accepted in the local scan.")
	}
	add("poodle", "POODLE SSLv3 check", "info", "not_tested", "SSLv3 is not supported by Go's TLS client, so this scanner cannot negotiate SSLv3 to test POODLE directly.")
	add("heartbleed", "Heartbleed check", "info", "not_tested", "Heartbeat extension exploitation requires a dedicated low-level TLS probe and is not attempted by this scanner.")
	add("ticketbleed", "Ticketbleed check", "info", "not_tested", "Ticketbleed requires implementation-specific session-ticket probing and is not attempted by this scanner.")
}

func tlsVersionSupported(r *Result, version string) bool {
	for _, item := range r.TLS.SupportedVersions {
		if item.Version == version && item.Supported {
			return true
		}
	}
	return false
}

func supportedCipherWhere(r *Result, fn func(TLSCipherSupport) bool) bool {
	for _, cipher := range r.TLS.SupportedCiphers {
		if cipher.Supported && fn(cipher) {
			return true
		}
	}
	return false
}

func scoreFindings(findings []SecurityFinding) int {
	score := 100
	for _, finding := range findings {
		if finding.Status != "fail" && finding.Status != "warn" {
			continue
		}
		switch finding.Severity {
		case "critical":
			score -= 40
		case "high":
			score -= 25
		case "medium":
			score -= 10
		case "low":
			score -= 5
		}
	}
	if score < 0 {
		return 0
	}
	return score
}

func gradeScore(score int, findings []SecurityFinding) string {
	for _, finding := range findings {
		if finding.Status == "fail" && finding.Severity == "critical" {
			return "F"
		}
	}
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func summaryForScore(score int, findings []SecurityFinding) string {
	failures := 0
	warnings := 0
	for _, finding := range findings {
		if finding.Status == "fail" {
			failures++
		}
		if finding.Status == "warn" {
			warnings++
		}
	}
	if failures > 0 {
		return "Local scan found certificate, protocol, or configuration failures."
	}
	if warnings > 0 {
		return "Local scan found warnings; review before treating this endpoint as production ready."
	}
	if score >= 90 {
		return "Local scan did not find major certificate or TLS configuration issues."
	}
	return "Local scan completed."
}

func (h HTTPHeaderCheck) StatusSeverity() string {
	switch h.Status {
	case "fail":
		return "high"
	case "warn":
		return "medium"
	default:
		return "info"
	}
}
