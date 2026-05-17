package checker

import "time"

// Options controls how a target is checked.
type Options struct {
	Port         int
	ServerName   string
	VerifyName   string
	Timeout      time.Duration
	TLSMin       string
	TLSMax       string
	CAFile       string
	NoHostname   bool
	IncludePEM   bool
	SkipTLSProbe bool
	ForceTLS     bool
}

// Target is the normalized destination derived from user input.
type Target struct {
	Input   string `json:"input"`
	Scheme  string `json:"scheme"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Path    string `json:"path"`
	Address string `json:"address"`
	IsIP    bool   `json:"is_ip"`
}

// TargetInfo is embedded in the public report.
type TargetInfo struct {
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Address    string `json:"address"`
	Path       string `json:"path"`
	IsIP       bool   `json:"is_ip"`
	ServerName string `json:"server_name"`
	VerifyName string `json:"verify_name"`
}

// Result is the top-level certificate and protocol report.
type Result struct {
	Input          string            `json:"input"`
	Target         TargetInfo        `json:"target"`
	CheckedAt      time.Time         `json:"checked_at"`
	DurationMillis int64             `json:"duration_ms"`
	Protocol       string            `json:"protocol"`
	TLS            TLSInfo           `json:"tls"`
	HTTP           HTTPInfo          `json:"http"`
	Verification   VerificationInfo  `json:"verification"`
	Certificates   []CertificateInfo `json:"certificates"`
	Warnings       []string          `json:"warnings"`
	Errors         []string          `json:"errors"`
}

// TLSInfo reports TLS connection and version support information.
type TLSInfo struct {
	Attempted            bool                `json:"attempted"`
	Connected            bool                `json:"connected"`
	NegotiatedVersion    string              `json:"negotiated_version"`
	CipherSuite          string              `json:"cipher_suite"`
	ALPN                 string              `json:"alpn"`
	SNI                  string              `json:"sni"`
	PeerCertificateCount int                 `json:"peer_certificate_count"`
	SupportedVersions    []TLSVersionSupport `json:"supported_versions"`
	Error                string              `json:"error"`
}

// TLSVersionSupport records the result of probing one exact TLS version.
type TLSVersionSupport struct {
	Version     string `json:"version"`
	Supported   bool   `json:"supported"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
}

// HTTPInfo reports plain HTTP reachability for http:// targets or fallbacks.
type HTTPInfo struct {
	Attempted        bool   `json:"attempted"`
	Reachable        bool   `json:"reachable"`
	URL              string `json:"url"`
	Status           string `json:"status,omitempty"`
	StatusCode       int    `json:"status_code,omitempty"`
	Server           string `json:"server,omitempty"`
	ContentType      string `json:"content_type,omitempty"`
	RedirectLocation string `json:"redirect_location,omitempty"`
	Plaintext        bool   `json:"plaintext"`
	Error            string `json:"error,omitempty"`
}

// VerificationInfo reports hostname, chain, root and validity verification.
type VerificationInfo struct {
	Checked          bool            `json:"checked"`
	Verified         bool            `json:"verified"`
	ChainVerified    bool            `json:"chain_verified"`
	HostnameChecked  bool            `json:"hostname_checked"`
	HostnameVerified bool            `json:"hostname_verified"`
	RootTrusted      bool            `json:"root_trusted"`
	ChainComplete    bool            `json:"chain_complete"`
	Expired          bool            `json:"expired"`
	NotYetValid      bool            `json:"not_yet_valid"`
	SelfSignedLeaf   bool            `json:"self_signed_leaf"`
	UsesCustomCA     bool            `json:"uses_custom_ca"`
	VerifyName       string          `json:"verify_name"`
	Errors           []string        `json:"errors"`
	VerifiedChains   []VerifiedChain `json:"verified_chains"`
}

// VerifiedChain is one chain built by the OS/custom CA verifier.
type VerifiedChain struct {
	Chain        int                `json:"chain"`
	Certificates []ChainCertificate `json:"certificates"`
}

// ChainCertificate is a compact certificate summary for verified chains.
type ChainCertificate struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	CommonName        string    `json:"common_name"`
	IsCA              bool      `json:"is_ca"`
	IsRoot            bool      `json:"is_root"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
}

// CertificateInfo is a detailed summary of a certificate sent by the peer.
type CertificateInfo struct {
	Index                  int       `json:"index"`
	Role                   string    `json:"role"`
	Subject                string    `json:"subject"`
	SubjectCommonName      string    `json:"subject_common_name"`
	Issuer                 string    `json:"issuer"`
	IssuerCommonName       string    `json:"issuer_common_name"`
	SerialNumber           string    `json:"serial_number"`
	NotBefore              time.Time `json:"not_before"`
	NotAfter               time.Time `json:"not_after"`
	DaysRemaining          int64     `json:"days_remaining"`
	Status                 string    `json:"status"`
	DNSNames               []string  `json:"dns_names"`
	IPAddresses            []string  `json:"ip_addresses"`
	EmailAddresses         []string  `json:"email_addresses"`
	URIs                   []string  `json:"uris"`
	IsCA                   bool      `json:"is_ca"`
	IsSelfSigned           bool      `json:"is_self_signed"`
	PublicKeyAlgorithm     string    `json:"public_key_algorithm"`
	PublicKeySize          int       `json:"public_key_size"`
	SignatureAlgorithm     string    `json:"signature_algorithm"`
	FingerprintSHA256      string    `json:"fingerprint_sha256"`
	SubjectKeyID           string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID         string    `json:"authority_key_id,omitempty"`
	OCSPServers            []string  `json:"ocsp_servers"`
	IssuingCertificateURLs []string  `json:"issuing_certificate_urls"`
	CRLDistributionPoints  []string  `json:"crl_distribution_points"`
	PEM                    string    `json:"pem,omitempty"`
}
