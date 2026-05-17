package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Check inspects the protocol, TLS handshake, certificates and trust chain for a target.
func Check(ctx context.Context, input string, opt Options) (*Result, error) {
	opt.Timeout = normalizeTimeout(opt.Timeout)
	minVersion, err := tlsVersionValue(opt.TLSMin)
	if err != nil {
		return nil, err
	}
	maxVersion, err := tlsVersionValue(opt.TLSMax)
	if err != nil {
		return nil, err
	}
	if minVersion != 0 && maxVersion != 0 && minVersion > maxVersion {
		return nil, fmt.Errorf("tls-min cannot be greater than tls-max")
	}

	target, err := ParseTarget(input, opt)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Input:     input,
		CheckedAt: time.Now().UTC(),
		Target: TargetInfo{
			Scheme:     target.Scheme,
			Host:       target.Host,
			Port:       target.Port,
			Address:    target.Address,
			Path:       target.Path,
			IsIP:       target.IsIP,
			ServerName: sniName(target, opt),
			VerifyName: verifyName(target, opt),
		},
	}

	start := time.Now()
	if !opt.SkipDNS {
		checkDNS(ctx, target, opt, result)
	}

	if target.Scheme == "http" && !opt.ForceTLS {
		result.Protocol = "HTTP"
		if !opt.SkipHTTP {
			checkHTTP(ctx, target, opt, result)
		}
		result.Warnings = append(result.Warnings, "plain HTTP does not provide a TLS certificate to verify; use https:// or --force-tls for TLS services")
		result.DurationMillis = time.Since(start).Milliseconds()
		result.Security = AnalyzeSecurity(result)
		return result, nil
	}

	result.Protocol = "TLS"
	checkTLS(ctx, target, opt, minVersion, maxVersion, result)
	if result.TLS.Connected && !opt.SkipHTTP {
		checkHTTP(ctx, target, opt, result)
	}
	if !result.TLS.Connected && target.Scheme == "https" {
		result.Errors = append(result.Errors, "HTTPS target did not complete a TLS handshake")
	}
	if !result.TLS.Connected && target.Scheme != "https" && !opt.ForceTLS {
		result.Warnings = append(result.Warnings, "TLS handshake failed; attempting a plain HTTP probe because no URL scheme was provided")
		fallback := target
		fallback.Scheme = "http"
		if !opt.SkipHTTP {
			checkHTTP(ctx, fallback, opt, result)
		}
	}
	result.DurationMillis = time.Since(start).Milliseconds()
	result.Security = AnalyzeSecurity(result)
	return result, nil
}

func checkTLS(ctx context.Context, target Target, opt Options, minVersion, maxVersion uint16, result *Result) {
	result.TLS.Attempted = true
	result.TLS.SNI = sniName(target, opt)

	conn, state, err := connectTLS(ctx, target, opt, minVersion, maxVersion)
	if err != nil {
		result.TLS.Error = shortError(err)
		result.Errors = append(result.Errors, "tls: "+shortError(err))
		return
	}
	defer conn.Close()

	result.TLS.Connected = true
	result.TLS.NegotiatedVersion = tlsVersionName(state.Version)
	result.TLS.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.TLS.ALPN = state.NegotiatedProtocol
	result.TLS.OCSPStapled = len(state.OCSPResponse) > 0
	result.TLS.OCSPResponseBytes = len(state.OCSPResponse)
	result.TLS.SCTCount = len(state.SignedCertificateTimestamps)
	result.TLS.PeerCertificateCount = len(state.PeerCertificates)
	result.Certificates = CertificatesInfo(state.PeerCertificates, opt.IncludePEM, result.CheckedAt)
	result.Verification, result.Warnings = verifyPeerCertificates(state.PeerCertificates, target, opt, result.CheckedAt)

	if !opt.SkipTLSProbe {
		result.TLS.SupportedVersions = probeTLSVersions(ctx, target, opt)
	}
	if !opt.SkipCiphers {
		result.TLS.SupportedCiphers = probeTLSCiphers(ctx, target, opt)
	}
}

func checkHTTP(ctx context.Context, target Target, opt Options, result *Result) {
	result.HTTP.Attempted = true
	result.HTTP.Plaintext = target.Scheme == "http"
	url := target.Scheme + "://" + target.Address + target.Path
	result.HTTP.URL = url

	transport := &http.Transport{}
	if target.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			ServerName:         sniName(target, opt),
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
	}
	client := &http.Client{
		Timeout:   normalizeTimeout(opt.Timeout),
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		result.HTTP.Error = shortError(err)
		result.Errors = append(result.Errors, "http: "+shortError(err))
		return
	}
	req.Header.Set("User-Agent", "sslcertcheck/0.1")
	if target.IsIP && sniName(target, opt) != "" {
		req.Host = sniName(target, opt)
	}
	resp, err := client.Do(req)
	if err != nil && ctx.Err() == nil {
		// Some servers reject HEAD. Try a GET request before reporting failure.
		reqGet, getReqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if getReqErr == nil {
			reqGet.Header.Set("User-Agent", "sslcertcheck/0.1")
			if target.IsIP && sniName(target, opt) != "" {
				reqGet.Host = sniName(target, opt)
			}
			resp, err = client.Do(reqGet)
		}
	}
	if err != nil {
		result.HTTP.Error = shortError(err)
		result.Errors = append(result.Errors, "http: "+shortError(err))
		return
	}
	defer resp.Body.Close()

	result.HTTP.Reachable = true
	result.HTTP.Status = resp.Status
	result.HTTP.StatusCode = resp.StatusCode
	result.HTTP.Server = resp.Header.Get("Server")
	result.HTTP.ContentType = resp.Header.Get("Content-Type")
	result.HTTP.RedirectLocation = resp.Header.Get("Location")
	result.HTTP.HTTPSRedirect = result.HTTP.Plaintext && strings.HasPrefix(strings.ToLower(result.HTTP.RedirectLocation), "https://")
	result.HTTP.Headers = cloneHeader(resp.Header)
	result.HTTP.SecurityHeaders = analyzeHTTPHeaders(resp.Header, result.HTTP.Plaintext, result.HTTP.StatusCode, result.HTTP.RedirectLocation)
}

// DefaultPort returns a string version of the default port for documentation and tests.
func DefaultPort(scheme string) string {
	if scheme == "http" {
		return strconv.Itoa(80)
	}
	return strconv.Itoa(443)
}
