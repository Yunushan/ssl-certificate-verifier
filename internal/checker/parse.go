package checker

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseTarget accepts domain names, IP addresses, host:port pairs and http/https URLs.
func ParseTarget(input string, opt Options) (Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Target{}, fmt.Errorf("target is empty")
	}

	t := Target{Input: raw, Scheme: "https", Port: 443, Path: "/"}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("parse URL: %w", err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return Target{}, fmt.Errorf("unsupported scheme %q; use http or https", u.Scheme)
		}
		t.Scheme = scheme
		t.Host = strings.TrimSpace(u.Hostname())
		if t.Host == "" {
			return Target{}, fmt.Errorf("URL host is empty")
		}
		if p := u.Port(); p != "" {
			port, err := parsePort(p)
			if err != nil {
				return Target{}, err
			}
			t.Port = port
		} else if scheme == "http" {
			t.Port = 80
		}
		if u.EscapedPath() != "" {
			t.Path = u.EscapedPath()
		}
		if u.RawQuery != "" {
			t.Path += "?" + u.RawQuery
		}
	} else {
		host, port, hasPort, err := splitHostPortLoose(raw)
		if err != nil {
			return Target{}, err
		}
		t.Host = host
		if hasPort {
			t.Port = port
		}
	}

	if opt.Port > 0 {
		t.Port = opt.Port
	}
	if t.Host == "" {
		return Target{}, fmt.Errorf("host is empty")
	}
	t.Host = strings.Trim(t.Host, "[]")
	t.IsIP = net.ParseIP(t.Host) != nil
	t.Address = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	return t, nil
}

func splitHostPortLoose(raw string) (host string, port int, hasPort bool, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", 0, false, fmt.Errorf("target is empty")
	}

	// Standard host:port and [IPv6]:port forms.
	if h, p, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
		parsedPort, portErr := parsePort(p)
		if portErr != nil {
			return "", 0, false, portErr
		}
		return strings.Trim(h, "[]"), parsedPort, true, nil
	}

	// Bracketed IPv6 without port, e.g. [2001:db8::1].
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		inside := strings.Trim(trimmed, "[]")
		if net.ParseIP(inside) == nil {
			return "", 0, false, fmt.Errorf("invalid bracketed IP address %q", trimmed)
		}
		return inside, 0, false, nil
	}

	// Domain/IP with a single colon and numeric suffix, e.g. example.com:8443 or 10.0.0.4:9443.
	if strings.Count(trimmed, ":") == 1 {
		idx := strings.LastIndex(trimmed, ":")
		suffix := trimmed[idx+1:]
		if suffix != "" && allDigits(suffix) {
			parsedPort, portErr := parsePort(suffix)
			if portErr != nil {
				return "", 0, false, portErr
			}
			return trimmed[:idx], parsedPort, true, nil
		}
	}

	// Bare IPv6 must not be split on the final colon because it is ambiguous.
	return strings.Trim(trimmed, "[]"), 0, false, nil
}

func parsePort(raw string) (int, error) {
	p, err := strconv.Atoi(raw)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return p, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
