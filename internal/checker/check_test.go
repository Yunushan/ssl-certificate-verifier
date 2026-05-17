package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckHTTPSLocalServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result, err := Check(context.Background(), srv.URL, Options{Timeout: 3 * time.Second, SkipTLSProbe: true})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !result.TLS.Attempted || !result.TLS.Connected {
		t.Fatalf("expected TLS to connect, got %+v", result.TLS)
	}
	if len(result.Certificates) == 0 {
		t.Fatalf("expected at least one certificate")
	}
	if result.Verification.Verified {
		t.Fatalf("httptest certificate should not verify against system roots")
	}
}

func TestCheckHTTPPlainServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result, err := Check(context.Background(), srv.URL, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !result.HTTP.Attempted || !result.HTTP.Reachable {
		t.Fatalf("expected HTTP to be reachable, got %+v", result.HTTP)
	}
	if result.Verification.Checked {
		t.Fatalf("plain HTTP should not have certificate verification")
	}
}
