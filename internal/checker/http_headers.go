package checker

import (
	"net/http"
	"strings"
)

func cloneHeader(header http.Header) map[string][]string {
	out := make(map[string][]string, len(header))
	for key, values := range header {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func analyzeHTTPHeaders(header http.Header, plaintext bool, statusCode int, location string) []HTTPHeaderCheck {
	checks := make([]HTTPHeaderCheck, 0, 8)
	if plaintext {
		redirectsHTTPS := statusCode >= 300 && statusCode < 400 && strings.HasPrefix(strings.ToLower(location), "https://")
		checks = append(checks, HTTPHeaderCheck{
			Name:        "HTTPS redirect",
			Present:     redirectsHTTPS,
			Value:       location,
			Status:      headerStatus(redirectsHTTPS, "fail"),
			Description: "Plain HTTP should redirect to HTTPS.",
		})
		return checks
	}

	checks = append(checks,
		headerCheck(header, "Strict-Transport-Security", "warn", "Enforces HTTPS for repeat visitors and is required before HSTS preload."),
		headerCheck(header, "Content-Security-Policy", "warn", "Restricts where browsers can load active content from."),
		headerCheck(header, "X-Content-Type-Options", "warn", "Should normally be nosniff to block MIME sniffing."),
		frameProtectionCheck(header),
		headerCheck(header, "Referrer-Policy", "info", "Controls how much referrer data browsers send."),
		headerCheck(header, "Permissions-Policy", "info", "Restricts powerful browser features such as geolocation or camera."),
	)

	if server := header.Get("Server"); server != "" {
		checks = append(checks, HTTPHeaderCheck{
			Name:        "Server",
			Present:     true,
			Value:       server,
			Status:      "info",
			Description: "Server banner is visible; minimize version details when possible.",
		})
	}
	return checks
}

func headerCheck(header http.Header, name, missingStatus, description string) HTTPHeaderCheck {
	value := header.Get(name)
	present := strings.TrimSpace(value) != ""
	status := headerStatus(present, missingStatus)
	if strings.EqualFold(name, "X-Content-Type-Options") && present && !strings.EqualFold(strings.TrimSpace(value), "nosniff") {
		status = "warn"
	}
	return HTTPHeaderCheck{
		Name:        name,
		Present:     present,
		Value:       value,
		Status:      status,
		Description: description,
	}
}

func frameProtectionCheck(header http.Header) HTTPHeaderCheck {
	xfo := header.Get("X-Frame-Options")
	csp := header.Get("Content-Security-Policy")
	present := strings.TrimSpace(xfo) != "" || strings.Contains(strings.ToLower(csp), "frame-ancestors")
	value := xfo
	if strings.TrimSpace(value) == "" && strings.TrimSpace(csp) != "" {
		value = "Content-Security-Policy frame-ancestors"
	}
	return HTTPHeaderCheck{
		Name:        "Frame protection",
		Present:     present,
		Value:       value,
		Status:      headerStatus(present, "warn"),
		Description: "Prevents clickjacking with X-Frame-Options or CSP frame-ancestors.",
	}
}

func headerStatus(present bool, missingStatus string) string {
	if present {
		return "pass"
	}
	return missingStatus
}
