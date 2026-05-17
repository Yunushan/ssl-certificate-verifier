package checker

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KubernetesOptions controls K3s/RKE2 certificate checks.
type KubernetesOptions struct {
	Distro       string
	Kubeconfig   string
	CertDirs     []string
	Timeout      time.Duration
	IncludePEM   bool
	SkipLive     bool
	SkipCertScan bool
	CheckOptions Options
}

// KubernetesReport summarizes K3s/RKE2 API-server and local certificate checks.
type KubernetesReport struct {
	Distro        string                  `json:"distro"`
	Kubeconfig    string                  `json:"kubeconfig,omitempty"`
	APIServer     string                  `json:"api_server,omitempty"`
	CertDirs      []string                `json:"cert_dirs,omitempty"`
	APIServerCA   string                  `json:"api_server_ca,omitempty"`
	APIServerCheck *Result                `json:"api_server_check,omitempty"`
	Certificates  []KubernetesCertificate `json:"certificates,omitempty"`
	Warnings      []string                `json:"warnings,omitempty"`
	Errors        []string                `json:"errors,omitempty"`
}

// KubernetesCertificate reports one certificate discovered in a K3s/RKE2 path.
type KubernetesCertificate struct {
	Path        string          `json:"path"`
	Certificate CertificateInfo `json:"certificate"`
}

type kubernetesPreset struct {
	Distro     string
	Kubeconfig string
	CertDirs   []string
}

type kubeconfigInfo struct {
	Server   string
	CAFile   string
	CADataPEM []byte
}

// CheckKubernetes checks the Kubernetes API endpoint and local certificate files for K3s/RKE2.
func CheckKubernetes(ctx context.Context, opt KubernetesOptions) (*KubernetesReport, error) {
	preset, warnings := resolveKubernetesPreset(opt)
	report := &KubernetesReport{
		Distro:     preset.Distro,
		Kubeconfig: firstNonEmpty(opt.Kubeconfig, preset.Kubeconfig),
		CertDirs:   firstNonEmptySlice(opt.CertDirs, preset.CertDirs),
		Warnings:   warnings,
	}

	var kubeInfo kubeconfigInfo
	if report.Kubeconfig != "" {
		info, err := parseKubeconfig(report.Kubeconfig)
		if err != nil {
			report.Warnings = append(report.Warnings, "kubeconfig: "+shortError(err))
		} else {
			kubeInfo = info
			report.APIServer = info.Server
			report.APIServerCA = info.CAFile
		}
	}

	if !opt.SkipLive && report.APIServer != "" {
		checkOpt := opt.CheckOptions
		checkOpt.Timeout = normalizeTimeout(opt.Timeout)
		checkOpt.IncludePEM = opt.IncludePEM
		checkOpt.CAFile = kubeInfo.CAFile
		checkOpt.CABundlePEM = kubeInfo.CADataPEM
		result, err := Check(ctx, report.APIServer, checkOpt)
		if err != nil {
			report.Errors = append(report.Errors, "api-server: "+shortError(err))
		} else {
			report.APIServerCheck = result
		}
	}
	if !opt.SkipLive && report.APIServer == "" {
		report.Warnings = append(report.Warnings, "api-server: no server field found in kubeconfig")
	}

	if !opt.SkipCertScan {
		certs, scanWarnings := scanKubernetesCertDirs(report.CertDirs, opt.IncludePEM, time.Now().UTC())
		report.Certificates = certs
		report.Warnings = append(report.Warnings, scanWarnings...)
	}
	return report, nil
}

// RenderKubernetesText produces a human-readable K3s/RKE2 report.
func RenderKubernetesText(r *KubernetesReport) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteByte('\n')
	}

	line("Kubernetes certificate report")
	line("=============================")
	line("Distro:      %s", blankDash(r.Distro))
	line("Kubeconfig:  %s", blankDash(r.Kubeconfig))
	line("API server:  %s", blankDash(r.APIServer))
	if r.APIServerCA != "" {
		line("API CA file:  %s", r.APIServerCA)
	}
	if len(r.CertDirs) > 0 {
		line("Cert dirs:   %s", strings.Join(r.CertDirs, ", "))
	}

	if r.APIServerCheck != nil {
		line("")
		line("API server TLS")
		line("--------------")
		line("Connected:   %s", yesNo(r.APIServerCheck.TLS.Connected))
		if r.APIServerCheck.TLS.Connected {
			line("Version:     %s", blankDash(r.APIServerCheck.TLS.NegotiatedVersion))
			line("Cipher:      %s", blankDash(r.APIServerCheck.TLS.CipherSuite))
			line("Verified:    %s", passFail(r.APIServerCheck.Verification.Verified))
			line("Hostname:    %s", hostnameStatus(r.APIServerCheck.Verification))
			if len(r.APIServerCheck.Certificates) > 0 {
				leaf := r.APIServerCheck.Certificates[0]
				line("Leaf:        %s", blankDash(leaf.SubjectCommonName))
				line("Expires:     %s (%d days)", leaf.NotAfter.Format("2006-01-02"), leaf.DaysRemaining)
			}
		} else if r.APIServerCheck.TLS.Error != "" {
			line("Error:       %s", r.APIServerCheck.TLS.Error)
		}
	}

	if len(r.Certificates) > 0 {
		line("")
		line("Local certificates")
		line("------------------")
		for _, cert := range r.Certificates {
			c := cert.Certificate
			line("- %s", cert.Path)
			line("  Subject:   %s", blankDash(c.SubjectCommonName))
			line("  Issuer:    %s", blankDash(c.IssuerCommonName))
			line("  Role:      %s", blankDash(c.Role))
			line("  Status:    %s", c.Status)
			line("  Validity:  %s -> %s (%d days)", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.DaysRemaining)
			line("  SHA256:    %s", blankDash(c.FingerprintSHA256))
		}
	}

	if len(r.Warnings) > 0 {
		line("")
		line("Warnings")
		line("--------")
		for _, warning := range r.Warnings {
			line("- %s", warning)
		}
	}
	if len(r.Errors) > 0 {
		line("")
		line("Errors")
		line("------")
		for _, err := range r.Errors {
			line("- %s", err)
		}
	}
	return b.String()
}

func resolveKubernetesPreset(opt KubernetesOptions) (kubernetesPreset, []string) {
	presets := []kubernetesPreset{k3sPreset(), rke2Preset()}
	distro := strings.ToLower(strings.TrimSpace(opt.Distro))
	if distro == "" || distro == "auto" {
		if opt.Kubeconfig != "" || len(opt.CertDirs) > 0 {
			return kubernetesPreset{Distro: "custom"}, nil
		}
		for _, preset := range presets {
			if fileExists(preset.Kubeconfig) || anyDirExists(preset.CertDirs) {
				return preset, nil
			}
		}
		return k3sPreset(), []string{"auto discovery did not find K3s or RKE2 default paths; using K3s defaults"}
	}
	if distro == "custom" {
		return kubernetesPreset{Distro: "custom"}, nil
	}
	for _, preset := range presets {
		if distro == preset.Distro {
			return preset, nil
		}
	}
	return kubernetesPreset{Distro: distro}, []string{"unknown Kubernetes distro preset; use --kubeconfig and --cert-dir for custom paths"}
}

func k3sPreset() kubernetesPreset {
	return kubernetesPreset{
		Distro:     "k3s",
		Kubeconfig: "/etc/rancher/k3s/k3s.yaml",
		CertDirs: []string{
			"/var/lib/rancher/k3s/server/tls",
			"/var/lib/rancher/k3s/agent",
		},
	}
}

func rke2Preset() kubernetesPreset {
	return kubernetesPreset{
		Distro:     "rke2",
		Kubeconfig: "/etc/rancher/rke2/rke2.yaml",
		CertDirs: []string{
			"/var/lib/rancher/rke2/server/tls",
			"/var/lib/rancher/rke2/agent",
		},
	}
}

func parseKubeconfig(path string) (kubeconfigInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return kubeconfigInfo{}, err
	}
	baseDir := filepath.Dir(path)
	var info kubeconfigInfo
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "server:") && info.Server == "":
			info.Server = cleanYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "server:")))
		case strings.HasPrefix(trimmed, "certificate-authority:") && info.CAFile == "":
			caFile := cleanYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "certificate-authority:")))
			if caFile != "" && !filepath.IsAbs(caFile) {
				caFile = filepath.Join(baseDir, caFile)
			}
			info.CAFile = caFile
		case strings.HasPrefix(trimmed, "certificate-authority-data:") && len(info.CADataPEM) == 0:
			encoded := cleanYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "certificate-authority-data:")))
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return kubeconfigInfo{}, fmt.Errorf("decode certificate-authority-data: %w", err)
			}
			info.CADataPEM = decoded
		}
	}
	return info, nil
}

func cleanYAMLScalar(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
		return strings.Trim(value, "\"'")
	}
	if idx := strings.IndexByte(value, '#'); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	return strings.Trim(value, "\"'")
}

func scanKubernetesCertDirs(dirs []string, includePEM bool, now time.Time) ([]KubernetesCertificate, []string) {
	out := make([]KubernetesCertificate, 0)
	warnings := make([]string, 0)
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cert-dir %s: %s", dir, shortError(err)))
			continue
		}
		if !info.IsDir() {
			warnings = append(warnings, fmt.Sprintf("cert-dir %s: not a directory", dir))
			continue
		}
		err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %s", path, shortError(walkErr)))
				return nil
			}
			if entry.IsDir() || !isCertFile(path) {
				return nil
			}
			certs, err := readCertificates(path)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %s", path, shortError(err)))
				return nil
			}
			infos := CertificatesInfo(certs, includePEM, now)
			for _, info := range infos {
				out = append(out, KubernetesCertificate{Path: path, Certificate: info})
			}
			return nil
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cert-dir %s: %s", dir, shortError(err)))
		}
	}
	return out, warnings
}

func readCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0)
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("no certificate PEM or DER found")
	}
	return []*x509.Certificate{cert}, nil
}

func isCertFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".crt", ".cert", ".cer", ".pem":
		return true
	default:
		return false
	}
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func anyDirExists(paths []string) bool {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func firstNonEmpty(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func firstNonEmptySlice(primary, fallback []string) []string {
	if len(primary) > 0 {
		return append([]string(nil), primary...)
	}
	return append([]string(nil), fallback...)
}
