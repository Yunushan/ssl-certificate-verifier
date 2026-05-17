package checker

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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
			Subject:                cert.Subject.String(),
			SubjectCommonName:      cert.Subject.CommonName,
			Issuer:                 cert.Issuer.String(),
			IssuerCommonName:       cert.Issuer.CommonName,
			SerialNumber:           cert.SerialNumber.String(),
			NotBefore:              cert.NotBefore,
			NotAfter:               cert.NotAfter,
			DaysRemaining:          int64(cert.NotAfter.Sub(now).Hours() / 24),
			Status:                 status,
			DNSNames:               append([]string(nil), cert.DNSNames...),
			IPAddresses:            ipStrings(cert.IPAddresses),
			EmailAddresses:         append([]string(nil), cert.EmailAddresses...),
			URIs:                   uriStrings(cert),
			IsCA:                   cert.IsCA,
			IsSelfSigned:           isSelfSigned,
			PublicKeyAlgorithm:     cert.PublicKeyAlgorithm.String(),
			PublicKeySize:          publicKeySize(cert.PublicKey),
			SignatureAlgorithm:     cert.SignatureAlgorithm.String(),
			FingerprintSHA256:      FingerprintSHA256(cert.Raw),
			SubjectKeyID:           colonHex(cert.SubjectKeyId),
			AuthorityKeyID:         colonHex(cert.AuthorityKeyId),
			OCSPServers:            append([]string(nil), cert.OCSPServer...),
			IssuingCertificateURLs: append([]string(nil), cert.IssuingCertificateURL...),
			CRLDistributionPoints:  append([]string(nil), cert.CRLDistributionPoints...),
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
