package checker

import (
	"fmt"
	"strings"
	"time"
)

// RenderText produces a human-readable CLI report.
func RenderText(r *Result) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteByte('\n')
	}

	line("SSL Certificate Verifier report")
	line("%s", strings.Repeat("=", 32))
	line("Target:      %s://%s:%d%s", r.Target.Scheme, r.Target.Host, r.Target.Port, r.Target.Path)
	line("Address:     %s", r.Target.Address)
	line("Checked:     %s", r.CheckedAt.Format(time.RFC3339))
	line("Duration:    %d ms", r.DurationMillis)
	line("Protocol:    %s", r.Protocol)

	if r.DNS.Attempted {
		line("")
		line("DNS")
		line("---")
		line("Host:        %s", blankDash(r.DNS.Hostname))
		line("CNAME:       %s", blankDash(r.DNS.CNAME))
		if len(r.DNS.A) > 0 {
			line("A:           %s", joinLimit(r.DNS.A, 8))
		}
		if len(r.DNS.AAAA) > 0 {
			line("AAAA:        %s", joinLimit(r.DNS.AAAA, 8))
		}
		if len(r.DNS.PTR) > 0 {
			line("PTR:         %s", joinLimit(r.DNS.PTR, 8))
		}
		if len(r.DNS.CAA) > 0 {
			if r.DNS.CAAHost != "" && r.DNS.CAAHost != r.DNS.Hostname {
				line("CAA host:    %s", r.DNS.CAAHost)
			}
			for _, caa := range r.DNS.CAA {
				line("CAA:         %d %s %s", caa.Flag, caa.Tag, caa.Value)
			}
		} else if !r.Target.IsIP {
			line("CAA:         -")
		}
	}

	if r.TLS.Attempted {
		line("")
		line("TLS")
		line("---")
		line("Connected:   %s", yesNo(r.TLS.Connected))
		if r.TLS.SNI != "" {
			line("SNI:         %s", r.TLS.SNI)
		} else {
			line("SNI:         <none>")
		}
		if r.TLS.Connected {
			line("Version:     %s", r.TLS.NegotiatedVersion)
			line("Cipher:      %s", blankDash(r.TLS.CipherSuite))
			line("ALPN:        %s", blankDash(r.TLS.ALPN))
			line("Compression: %s", yesNo(r.TLS.Compression))
			line("OCSP staple: %s (%d bytes)", yesNo(r.TLS.OCSPStapled), r.TLS.OCSPResponseBytes)
			line("SCTs:        %d", r.TLS.SCTCount)
			line("Peer certs:  %d", r.TLS.PeerCertificateCount)
		} else if r.TLS.Error != "" {
			line("Error:       %s", r.TLS.Error)
		}
		if len(r.TLS.SupportedVersions) > 0 {
			line("")
			line("TLS version support")
			for _, v := range r.TLS.SupportedVersions {
				if v.Supported {
					line("  [ok]   %-7s  %s", v.Version, blankDash(v.CipherSuite))
				} else {
					line("  [fail] %-7s  %s", v.Version, blankDash(v.Error))
				}
			}
		}
		if len(r.TLS.SupportedCiphers) > 0 {
			line("")
			line("Accepted TLS 1.0-1.2 ciphers")
			count := 0
			for _, c := range r.TLS.SupportedCiphers {
				if !c.Supported {
					continue
				}
				flags := make([]string, 0, 4)
				if c.Insecure {
					flags = append(flags, "insecure")
				}
				if c.ForwardSecrecy {
					flags = append(flags, "fs")
				}
				if c.AEAD {
					flags = append(flags, "aead")
				}
				if c.CBC {
					flags = append(flags, "cbc")
				}
				line("  %-7s  %-42s  %s", c.Version, c.Name, strings.Join(flags, ","))
				count++
				if count >= 20 {
					line("  ... +%d more accepted ciphers", acceptedCipherCount(r.TLS.SupportedCiphers)-count)
					break
				}
			}
			if count == 0 {
				line("  -")
			}
		}
	}

	if r.HTTP.Attempted {
		line("")
		line("HTTP")
		line("----")
		line("URL:         %s", r.HTTP.URL)
		line("Reachable:   %s", yesNo(r.HTTP.Reachable))
		if r.HTTP.Reachable {
			line("Status:      %s", r.HTTP.Status)
			line("Server:      %s", blankDash(r.HTTP.Server))
			line("ContentType: %s", blankDash(r.HTTP.ContentType))
			line("Redirect:    %s", blankDash(r.HTTP.RedirectLocation))
			if len(r.HTTP.SecurityHeaders) > 0 {
				line("")
				line("HTTP security headers")
				for _, h := range r.HTTP.SecurityHeaders {
					line("  [%s] %s: %s", h.Status, h.Name, blankDash(h.Value))
				}
			}
		} else if r.HTTP.Error != "" {
			line("Error:       %s", r.HTTP.Error)
		}
	}

	if r.Verification.Checked {
		line("")
		line("Verification")
		line("------------")
		line("Overall:     %s", passFail(r.Verification.Verified))
		line("Chain:       %s", passFail(r.Verification.ChainVerified))
		line("Hostname:    %s", hostnameStatus(r.Verification))
		line("Root trust:  %s", passFail(r.Verification.RootTrusted))
		line("Complete:    %s", yesNo(r.Verification.ChainComplete))
		line("Expired:     %s", yesNo(r.Verification.Expired))
		line("Not before:  %s", yesNo(r.Verification.NotYetValid))
		line("Self-signed: %s", yesNo(r.Verification.SelfSignedLeaf))
		if r.Verification.UsesCustomCA {
			line("CA bundle:   system + custom")
		} else {
			line("CA bundle:   system")
		}
	}

	if len(r.Certificates) > 0 {
		line("")
		line("Server-sent certificates")
		line("------------------------")
		for _, c := range r.Certificates {
			line("[%d] %s  %s", c.Index, c.Role, blankDash(c.SubjectCommonName))
			line("    Subject:   %s", blankDash(c.Subject))
			line("    Issuer:    %s", blankDash(c.Issuer))
			line("    Validity:  %s -> %s (%s, %d days remaining)", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.Status, c.DaysRemaining)
			line("    Serial:    %s", blankDash(c.SerialNumberHex))
			line("    Validation: %s", blankDash(c.ValidationLevel))
			line("    Key:       %s %d", blankDash(c.PublicKeyAlgorithm), c.PublicKeySize)
			line("    Key SHA256:%s", blankDash(c.PublicKeySHA256))
			line("    Signature: %s", blankDash(c.SignatureAlgorithm))
			line("    SHA256:    %s", blankDash(c.FingerprintSHA256))
			line("    SHA1:      %s", blankDash(c.FingerprintSHA1))
			if len(c.DNSNames) > 0 {
				line("    DNS SANs:  %s", joinLimit(c.DNSNames, 8))
			}
			if len(c.IPAddresses) > 0 {
				line("    IP SANs:   %s", joinLimit(c.IPAddresses, 8))
			}
			if len(c.KeyUsage) > 0 {
				line("    Key usage: %s", strings.Join(c.KeyUsage, ", "))
			}
			if len(c.ExtKeyUsage) > 0 {
				line("    Ext usage: %s", strings.Join(c.ExtKeyUsage, ", "))
			}
			if len(c.CertificatePolicies) > 0 {
				line("    Policies:  %s", joinLimit(c.CertificatePolicies, 5))
			}
			if len(c.OCSPServers) > 0 {
				line("    OCSP:      %s", joinLimit(c.OCSPServers, 3))
			}
			if len(c.CRLDistributionPoints) > 0 {
				line("    CRL:       %s", joinLimit(c.CRLDistributionPoints, 3))
			}
		}
	}

	if len(r.Verification.VerifiedChains) > 0 {
		line("")
		line("Verified chain candidates")
		line("-------------------------")
		for _, chain := range r.Verification.VerifiedChains {
			parts := make([]string, 0, len(chain.Certificates))
			for _, cert := range chain.Certificates {
				name := cert.CommonName
				if name == "" {
					name = cert.Subject
				}
				parts = append(parts, name)
			}
			line("[%d] %s", chain.Chain, strings.Join(parts, " -> "))
		}
	}

	if len(r.Security.Findings) > 0 {
		line("")
		line("Local security summary")
		line("----------------------")
		line("Grade:       %s (%d/100)", blankDash(r.Security.LocalGrade), r.Security.Score)
		line("Summary:     %s", blankDash(r.Security.Summary))
		for _, finding := range r.Security.Findings {
			if finding.Status == "pass" {
				continue
			}
			line("  [%s/%s] %s: %s", finding.Status, finding.Severity, finding.Title, blankDash(finding.Description))
		}
	}

	if len(r.Warnings) > 0 {
		line("")
		line("Warnings")
		line("--------")
		for _, w := range r.Warnings {
			line("- %s", w)
		}
	}

	if len(r.Errors) > 0 || len(r.Verification.Errors) > 0 {
		line("")
		line("Errors")
		line("------")
		for _, e := range r.Errors {
			line("- %s", e)
		}
		for _, e := range r.Verification.Errors {
			line("- %s", e)
		}
	}

	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func passFail(v bool) string {
	if v {
		return "PASS"
	}
	return "FAIL"
}

func blankDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func hostnameStatus(v VerificationInfo) string {
	if !v.HostnameChecked {
		return "SKIPPED"
	}
	return passFail(v.HostnameVerified) + " (" + v.VerifyName + ")"
}

func joinLimit(values []string, limit int) string {
	if len(values) == 0 {
		return "-"
	}
	if limit <= 0 || len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:limit], ", ") + fmt.Sprintf(" ... +%d more", len(values)-limit)
}

func acceptedCipherCount(values []TLSCipherSupport) int {
	count := 0
	for _, value := range values {
		if value.Supported {
			count++
		}
	}
	return count
}
