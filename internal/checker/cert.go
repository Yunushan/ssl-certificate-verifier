package checker

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertificatesInfo converts x509 certificates into a JSON/text friendly report.
func CertificatesInfo(certs []*x509.Certificate, includePEM bool, now time.Time) []CertificateInfo {
	infos := make([]CertificateInfo, 0, len(certs))
	for i, cert := range certs {
		status := "valid"
		if now.Before(cert.NotBefore) {
			status = "not_yet_valid"
		} else if now.After(cert.NotAfter) {
			status = "expired"
		}

		isSelfSigned := IsSelfSigned(cert)
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		} else if isSelfSigned {
			role = "root"
		}

		pemText := ""
		if includePEM {
			pemText = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}

		infos = append(infos, CertificateInfo{
			Index:                  i,
			Role:                   role,
			Version:                cert.Version,
			Subject:                cert.Subject.String(),
			SubjectCommonName:      cert.Subject.CommonName,
			SubjectOrganization:    append([]string(nil), cert.Subject.Organization...),
			SubjectCountry:         append([]string(nil), cert.Subject.Country...),
			SubjectLocality:        append([]string(nil), cert.Subject.Locality...),
			Issuer:                 cert.Issuer.String(),
			IssuerCommonName:       cert.Issuer.CommonName,
			IssuerOrganization:     append([]string(nil), cert.Issuer.Organization...),
			IssuerCountry:          append([]string(nil), cert.Issuer.Country...),
			SerialNumber:           cert.SerialNumber.String(),
			SerialNumberHex:        strings.ToUpper(cert.SerialNumber.Text(16)),
			NotBefore:              cert.NotBefore,
			NotAfter:               cert.NotAfter,
			DaysRemaining:          int64(cert.NotAfter.Sub(now).Hours() / 24),
			Status:                 status,
			DNSNames:               append([]string(nil), cert.DNSNames...),
			WildcardDNSNames:       wildcardDNSNames(cert.DNSNames),
			IPAddresses:            ipStrings(cert.IPAddresses),
			EmailAddresses:         append([]string(nil), cert.EmailAddresses...),
			URIs:                   uriStrings(cert),
			IsCA:                   cert.IsCA,
			IsSelfSigned:           isSelfSigned,
			BasicConstraintsValid:  cert.BasicConstraintsValid,
			MaxPathLen:             cert.MaxPathLen,
			MaxPathLenZero:         cert.MaxPathLenZero,
			CertificatePolicies:    policyOIDs(cert),
			ValidationLevel:        validationLevel(cert),
			KeyUsage:               keyUsageNames(cert.KeyUsage),
			ExtKeyUsage:            extKeyUsageNames(cert.ExtKeyUsage),
			PublicKeyAlgorithm:     cert.PublicKeyAlgorithm.String(),
			PublicKeySize:          publicKeySize(cert.PublicKey),
			PublicKeySHA256:        publicKeySHA256(cert),
			SignatureAlgorithm:     cert.SignatureAlgorithm.String(),
			FingerprintMD5:         FingerprintMD5(cert.Raw),
			FingerprintSHA1:        FingerprintSHA1(cert.Raw),
			FingerprintSHA256:      FingerprintSHA256(cert.Raw),
			SubjectKeyID:           colonHex(cert.SubjectKeyId),
			AuthorityKeyID:         colonHex(cert.AuthorityKeyId),
			OCSPServers:            append([]string(nil), cert.OCSPServer...),
			OCSPMustStaple:         hasOCSPMustStaple(cert),
			IssuingCertificateURLs: append([]string(nil), cert.IssuingCertificateURL...),
			CRLDistributionPoints:  append([]string(nil), cert.CRLDistributionPoints...),
			EmbeddedSCTCount:       embeddedSCTCount(cert),
			PEM:                    pemText,
		})
	}
	return infos
}

// IsSelfSigned returns true when a certificate signs itself.
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// FingerprintSHA256 returns an uppercase, colon-separated SHA-256 fingerprint.
func FingerprintSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return colonHex(sum[:])
}

// FingerprintSHA1 returns an uppercase, colon-separated SHA-1 fingerprint.
func FingerprintSHA1(raw []byte) string {
	sum := sha1.Sum(raw)
	return colonHex(sum[:])
}

// FingerprintMD5 returns an uppercase, colon-separated MD5 fingerprint for compatibility reports.
func FingerprintMD5(raw []byte) string {
	sum := md5.Sum(raw)
	return colonHex(sum[:])
}

func colonHex(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	hexed := strings.ToUpper(hex.EncodeToString(raw))
	parts := make([]string, 0, len(hexed)/2)
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":")
}

func publicKeySize(pub any) int {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}

func publicKeySHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	raw, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	return FingerprintSHA256(raw)
}

func keyUsageNames(usage x509.KeyUsage) []string {
	checks := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	out := make([]string, 0, len(checks))
	for _, check := range checks {
		if usage&check.bit != 0 {
			out = append(out, check.name)
		}
	}
	return out
}

func extKeyUsageNames(usages []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(usages))
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "client_auth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "code_signing")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "email_protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			out = append(out, "ipsec_end_system")
		case x509.ExtKeyUsageIPSECTunnel:
			out = append(out, "ipsec_tunnel")
		case x509.ExtKeyUsageIPSECUser:
			out = append(out, "ipsec_user")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "time_stamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "ocsp_signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			out = append(out, "microsoft_server_gated_crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			out = append(out, "netscape_server_gated_crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			out = append(out, "microsoft_commercial_code_signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			out = append(out, "microsoft_kernel_code_signing")
		default:
			out = append(out, fmt.Sprintf("unknown_%d", usage))
		}
	}
	return out
}

func wildcardDNSNames(names []string) []string {
	out := make([]string, 0)
	for _, name := range names {
		if strings.HasPrefix(name, "*.") {
			out = append(out, name)
		}
	}
	return out
}

func policyOIDs(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.PolicyIdentifiers))
	for _, oid := range cert.PolicyIdentifiers {
		out = append(out, oid.String())
	}
	return out
}

func validationLevel(cert *x509.Certificate) string {
	policies := policyOIDs(cert)
	for _, policy := range policies {
		switch policy {
		case "2.23.140.1.1":
			return "ev"
		case "2.23.140.1.2.2":
			return "ov"
		case "2.23.140.1.2.1":
			return "dv"
		}
	}
	if len(cert.Subject.Organization) > 0 {
		return "organization_present"
	}
	return "domain_validated_or_unknown"
}

func hasOCSPMustStaple(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func embeddedSCTCount(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return countSCTList(ext.Value)
		}
	}
	return 0
}

func countSCTList(raw []byte) int {
	if len(raw) < 2 {
		return 0
	}
	total := int(raw[0])<<8 | int(raw[1])
	if total > len(raw)-2 {
		total = len(raw) - 2
	}
	count := 0
	offset := 2
	end := 2 + total
	for offset+2 <= end {
		size := int(raw[offset])<<8 | int(raw[offset+1])
		offset += 2
		if size < 0 || offset+size > end {
			break
		}
		count++
		offset += size
	}
	return count
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func uriStrings(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	return out
}

func compactCertName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.String()
}

func certLabel(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	cn := compactCertName(cert)
	if cn == "" {
		return fmt.Sprintf("serial=%s", cert.SerialNumber.String())
	}
	return cn
}
