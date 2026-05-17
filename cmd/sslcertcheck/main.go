package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Yunushan/ssl-certificate-verifier/internal/checker"
	"github.com/Yunushan/ssl-certificate-verifier/internal/gui"
)

var version = "0.1.0"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]
	if strings.HasPrefix(cmd, "-") || !knownCommand(cmd) {
		cmd = "check"
		args = os.Args[1:]
	}

	var err error
	switch cmd {
	case "check":
		err = runCheck(args)
	case "gui":
		err = runGUI(args)
	case "version":
		fmt.Println("sslcertcheck", version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Println("error:", err)
		os.Exit(exitCode(err))
	}
}

func knownCommand(cmd string) bool {
	switch cmd {
	case "check", "gui", "version", "help", "--help", "-h":
		return true
	default:
		return false
	}
}

type invalidExit struct{}

func (invalidExit) Error() string { return "one or more TLS targets failed verification" }

func exitCode(err error) int {
	var invalid invalidExit
	if errors.As(err, &invalid) {
		return 2
	}
	return 1
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	opt := checker.Options{}
	format := fs.String("format", "text", "output format: text or json")
	fs.IntVar(&opt.Port, "port", 0, "override target port")
	fs.StringVar(&opt.ServerName, "servername", "", "SNI server name to send during TLS handshake")
	fs.StringVar(&opt.VerifyName, "verify-name", "", "hostname/IP to verify against the leaf certificate")
	fs.DurationVar(&opt.Timeout, "timeout", 10*time.Second, "network timeout, e.g. 5s or 30s")
	fs.StringVar(&opt.TLSMin, "tls-min", "", "minimum TLS version for the main handshake: 1.0, 1.1, 1.2, 1.3")
	fs.StringVar(&opt.TLSMax, "tls-max", "", "maximum TLS version for the main handshake: 1.0, 1.1, 1.2, 1.3")
	fs.StringVar(&opt.CAFile, "ca-file", "", "custom PEM CA bundle to append to the system trust store")
	fs.BoolVar(&opt.NoHostname, "no-hostname", false, "skip hostname verification and verify only the chain")
	fs.BoolVar(&opt.IncludePEM, "include-pem", false, "include PEM certificate bodies in JSON output")
	fs.BoolVar(&opt.SkipTLSProbe, "skip-tls-probe", false, "skip TLS 1.0-1.3 support detection")
	fs.BoolVar(&opt.SkipDNS, "skip-dns", false, "skip DNS A/AAAA/CNAME/CAA/PTR lookups")
	fs.BoolVar(&opt.SkipHTTP, "skip-http", false, "skip HTTP/HTTPS response header checks")
	fs.BoolVar(&opt.SkipCiphers, "skip-cipher-scan", false, "skip TLS 1.0-1.2 cipher suite inventory")
	fs.BoolVar(&opt.ForceTLS, "force-tls", false, "perform a TLS handshake even when the target uses http://")
	failOnInvalid := fs.Bool("fail-on-invalid", false, "exit with code 2 when a TLS certificate is not fully verified")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("target is required")
	}

	ctx := context.Background()
	results := make([]*checker.Result, 0, fs.NArg())
	anyInvalid := false
	for _, target := range fs.Args() {
		result, err := checker.Check(ctx, target, opt)
		if err != nil {
			return err
		}
		results = append(results, result)
		if result.TLS.Attempted && (!result.TLS.Connected || !result.Verification.Verified) {
			anyInvalid = true
		}
	}

	switch strings.ToLower(*format) {
	case "json":
		payload := any(results)
		if len(results) == 1 {
			payload = results[0]
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return err
		}
	case "text", "":
		for i, result := range results {
			if i > 0 {
				fmt.Println()
			}
			fmt.Print(checker.RenderText(result))
		}
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}

	if *failOnInvalid && anyInvalid {
		return invalidExit{}
	}
	return nil
}

func runGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8088", "address for the local web GUI")
	open := fs.Bool("open", false, "open the GUI in the default browser")
	timeout := fs.Duration("timeout", 10*time.Second, "default network timeout for GUI checks")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	server := gui.New(checker.Options{Timeout: *timeout})
	url := "http://" + *listen + "/"
	if *open {
		go func() {
			time.Sleep(300 * time.Millisecond)
			_ = openBrowser(url)
		}()
	}
	fmt.Printf("SSL Certificate Verifier GUI listening on %s\n", url)
	return http.ListenAndServe(*listen, server.Handler())
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "android":
		cmd = exec.Command("am", "start", "-a", "android.intent.action.VIEW", "-d", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

func usage() {
	fmt.Fprintf(os.Stderr, `SSL Certificate Verifier %s

Usage:
  sslcertcheck check [flags] <target> [target...]
  sslcertcheck gui [flags]
  sslcertcheck version

Targets:
  example.com
  example.com:8443
  192.168.1.20
  10.0.0.5:9443
  https://intranet.local:9443/health
  http://router.local:8080

Examples:
  sslcertcheck check example.com
  sslcertcheck check --format json --servername app.internal 10.0.0.5:443
  sslcertcheck check --ca-file ./private-root-ca.pem https://portal.internal:8443
  sslcertcheck check --tls-min 1.2 --fail-on-invalid example.com
  sslcertcheck gui --open --listen 127.0.0.1:8088

Use "sslcertcheck check -h" or "sslcertcheck gui -h" for command flags.
`, version)
}
