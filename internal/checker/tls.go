package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

const defaultTimeout = 10 * time.Second

func tlsVersionValue(raw string) (uint16, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return 0, nil
	}
	s = strings.TrimPrefix(s, "tls")
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, " ")
	s = strings.ReplaceAll(s, "_", ".")
	s = strings.ReplaceAll(s, "-", ".")
	switch s {
	case "1", "1.0", "10":
		return tls.VersionTLS10, nil
	case "1.1", "11":
		return tls.VersionTLS11, nil
	case "1.2", "12":
		return tls.VersionTLS12, nil
	case "1.3", "13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q", raw)
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func normalizeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultTimeout
	}
	return timeout
}

func sniName(target Target, opt Options) string {
	if opt.ServerName != "" {
		return opt.ServerName
	}
	if target.IsIP {
		return ""
	}
	return target.Host
}

func verifyName(target Target, opt Options) string {
	if opt.NoHostname {
		return ""
	}
	if opt.VerifyName != "" {
		return opt.VerifyName
	}
	if opt.ServerName != "" {
		return opt.ServerName
	}
	return target.Host
}

func connectTLS(ctx context.Context, target Target, opt Options, minVersion, maxVersion uint16) (*tls.Conn, tls.ConnectionState, error) {
	timeout := normalizeTimeout(opt.Timeout)
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}

	cfg := &tls.Config{
		ServerName:         sniName(target, opt),
		InsecureSkipVerify: true, // We verify manually so invalid chains can still be inspected.
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	conn := tls.Client(rawConn, cfg)
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, tls.ConnectionState{}, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, conn.ConnectionState(), nil
}

func probeTLSVersions(ctx context.Context, target Target, opt Options) []TLSVersionSupport {
	versions := []struct {
		name  string
		value uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	}

	probeOpt := opt
	if probeOpt.Timeout <= 0 || probeOpt.Timeout > 4*time.Second {
		probeOpt.Timeout = 4 * time.Second
	}

	out := make([]TLSVersionSupport, 0, len(versions))
	for _, version := range versions {
		conn, state, err := connectTLS(ctx, target, probeOpt, version.value, version.value)
		if err != nil {
			out = append(out, TLSVersionSupport{
				Version:   version.name,
				Supported: false,
				Error:     shortError(err),
			})
			continue
		}
		_ = conn.Close()
		out = append(out, TLSVersionSupport{
			Version:     version.name,
			Supported:   true,
			CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		})
	}
	return out
}

func shortError(err error) string {
	if err == nil {
		return ""
	}
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 180 {
		return s[:177] + "..."
	}
	return s
}
