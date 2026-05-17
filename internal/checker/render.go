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
			line("    Key:       %s %d", blankDash(c.PublicKeyAlgorithm), c.PublicKeySize)
			line("    Signature: %s", blankDash(c.SignatureAlgorithm))
			line("    SHA256:    %s", blankDash(c.FingerprintSHA256))
			if len(c.DNSNames) > 0 {
				line("    DNS SANs:  %s", joinLimit(c.DNSNames, 8))
			}
			if len(c.IPAddresses) > 0 {
				line("    IP SANs:   %s", joinLimit(c.IPAddresses, 8))
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
