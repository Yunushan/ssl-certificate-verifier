package checker

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

func verifyPeerCertificates(certs []*x509.Certificate, target Target, opt Options, now time.Time) (VerificationInfo, []string) {
	info := VerificationInfo{
		Checked:         len(certs) > 0,
		UsesCustomCA:    opt.CAFile != "",
		VerifyName:      verifyName(target, opt),
		HostnameChecked: !opt.NoHostname,
	}
	var warnings []string
	if len(certs) == 0 {
		info.Errors = append(info.Errors, "no peer certificates were presented")
		return info, warnings
	}

	leaf := certs[0]
	info.Expired = now.After(leaf.NotAfter)
	info.NotYetValid = now.Before(leaf.NotBefore)
	info.SelfSignedLeaf = IsSelfSigned(leaf)

	roots, rootWarnings, rootErr := loadRoots(opt.CAFile)
	warnings = append(warnings, rootWarnings...)
	if rootErr != nil {
		info.Errors = append(info.Errors, fmt.Sprintf("roots: %v", rootErr))
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	baseOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	chainOnlyOpts := baseOpts
	chainOnlyChains, chainErr := leaf.Verify(chainOnlyOpts)
	info.ChainVerified = chainErr == nil
	info.RootTrusted = chainErr == nil
	info.ChainComplete = chainErr == nil
	if chainErr != nil {
		info.Errors = append(info.Errors, "chain: "+shortError(chainErr))
	}

	info.HostnameChecked = info.VerifyName != ""
	if info.HostnameChecked {
		hostErr := leaf.VerifyHostname(info.VerifyName)
		info.HostnameVerified = hostErr == nil
		if hostErr != nil {
			info.Errors = append(info.Errors, "hostname: "+shortError(hostErr))
		}
	} else {
		info.HostnameVerified = true
		if opt.NoHostname {
			warnings = append(warnings, "hostname verification was explicitly disabled")
		}
	}

	fullOpts := baseOpts
	if info.HostnameChecked {
		fullOpts.DNSName = info.VerifyName
	}
	fullChains, fullErr := leaf.Verify(fullOpts)
	info.Verified = fullErr == nil
	if fullErr != nil && !containsError(info.Errors, shortError(fullErr)) {
		info.Errors = append(info.Errors, "verification: "+shortError(fullErr))
	}

	if len(fullChains) > 0 {
		info.VerifiedChains = convertChains(fullChains)
	} else if len(chainOnlyChains) > 0 {
		info.VerifiedChains = convertChains(chainOnlyChains)
	}

	warnings = append(warnings, chainWarnings(certs, chainErr)...)
	return info, warnings
}

func loadRoots(caFile string) (*x509.CertPool, []string, error) {
	var warnings []string
	roots, err := x509.SystemCertPool()
	if err != nil {
		warnings = append(warnings, "system root store could not be loaded; only custom CA certificates will be used if provided")
		roots = x509.NewCertPool()
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile == "" {
		return roots, warnings, nil
	}

	data, readErr := os.ReadFile(caFile)
	if readErr != nil {
		return roots, warnings, readErr
	}
	if ok := roots.AppendCertsFromPEM(data); !ok {
		return roots, warnings, fmt.Errorf("no PEM certificates found in %s", caFile)
	}
	return roots, warnings, nil
}

func chainWarnings(certs []*x509.Certificate, chainErr error) []string {
	var warnings []string
	if len(certs) == 0 {
		return warnings
	}
	leaf := certs[0]
	if chainErr != nil && len(certs) == 1 && !IsSelfSigned(leaf) {
		warnings = append(warnings, "the server sent only the leaf certificate; an intermediate certificate may be missing")
	}
	for i, cert := range certs {
		if i > 0 && IsSelfSigned(cert) {
			warnings = append(warnings, fmt.Sprintf("server-sent certificate %d appears to be a root/self-signed certificate; servers normally send leaf plus intermediates, not the root", i))
		}
		if i < len(certs)-1 {
			if err := cert.CheckSignatureFrom(certs[i+1]); err != nil {
				warnings = append(warnings, fmt.Sprintf("server-sent chain order/signature issue between certificate %d (%s) and %d (%s): %s", i, certLabel(cert), i+1, certLabel(certs[i+1]), shortError(err)))
			}
		}
	}
	return warnings
}

func convertChains(chains [][]*x509.Certificate) []VerifiedChain {
	out := make([]VerifiedChain, 0, len(chains))
	for chainIdx, chain := range chains {
		vc := VerifiedChain{Chain: chainIdx, Certificates: make([]ChainCertificate, 0, len(chain))}
		for certIdx, cert := range chain {
			vc.Certificates = append(vc.Certificates, ChainCertificate{
				Subject:           cert.Subject.String(),
				Issuer:            cert.Issuer.String(),
				CommonName:        cert.Subject.CommonName,
				IsCA:              cert.IsCA,
				IsRoot:            certIdx == len(chain)-1,
				NotAfter:          cert.NotAfter,
				FingerprintSHA256: FingerprintSHA256(cert.Raw),
			})
		}
		out = append(out, vc)
	}
	return out
}

func containsError(existing []string, needle string) bool {
	for _, e := range existing {
		if e == needle || e == "verification: "+needle || e == "chain: "+needle || e == "hostname: "+needle {
			return true
		}
	}
	return false
}
