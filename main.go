package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func timedLog(message string) {
	fmt.Printf("%v - %s\n", time.Now(), message)
}

// options holds every flag, for every mode. Which of them are meaningful, and
// which are refused, depends on the mode.
type options struct {
	ListenAddress        string
	ListenPort           int
	PKCS11Path           string
	TokenSerial          string
	CertificateIndex     int
	PIN                  string
	PINFile              string
	DestinationURL       string
	NoPreserveHost       bool
	LogRequests          bool
	ListenTLS            bool
	ListenTLSCertificate string
	ListenTLSPrivateKey  string
}

// parseOptions decides the mode and reads the flags.
//
// The first argument names the mode when it is one of the known ones and is
// consumed; otherwise the mode is proxy and the whole list is flags, so every
// command line that worked before still works. A trailing list-certificates is
// honoured for the same reason.
func parseOptions(args []string, errorOutput io.Writer) (string, options, error) {
	mode := "proxy"
	if len(args) > 0 {
		switch args[0] {
		case "proxy", "sign", "list-certificates":
			mode, args = args[0], args[1:]
		default:
			if !strings.HasPrefix(args[0], "-") {
				return "", options{}, fmt.Errorf("unknown command %q", args[0])
			}
		}
	}

	opts := options{}
	flags := flag.NewFlagSet("pkcs11-web-proxy", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	flags.StringVar(&opts.ListenAddress, "listen-addr", "127.0.0.1", "Address to listen on")
	flags.IntVar(&opts.ListenPort, "listen-port", 8080, "Port to listen on")
	flags.StringVar(&opts.PKCS11Path, "pkcs11-path", "", "Path to the PKCS11 module. Use the card vendor-specific one, or run 'pkcs11-tool --help' and look for '--module' default value for a good one to use.")
	flags.StringVar(&opts.TokenSerial, "token-serial", "", "Serial number of the token. Run 'pkcs11-tool --list-token-slots' to find it.")
	flags.IntVar(&opts.CertificateIndex, "certificate-index", 0, "Index of the certificate to use. Run 'list-certificates' to find the index. By default, the first found certificate (index 0) will be used.")
	flags.StringVar(&opts.PIN, "pin", "", "PIN to access the card. Cannot be used with --pin-file.")
	flags.StringVar(&opts.PINFile, "pin-file", "", "File containing the PIN to access the card (will be deleted after read!). Cannot be used with --pin.")
	flags.StringVar(&opts.DestinationURL, "destination-url", "", "URL to forward requests to.")
	flags.BoolVar(&opts.NoPreserveHost, "no-preserve-host", false, "Do not preserve the host header in the request.")
	flags.BoolVar(&opts.LogRequests, "log-requests", false, "Log each request to stdout.")
	flags.BoolVar(&opts.ListenTLS, "listen-tls", false, "Listen on TLS instead of plain HTTP (useful if your upstream sets 'secure' cookies)")
	flags.StringVar(&opts.ListenTLSCertificate, "listen-tls-cert", "", "Path to the certificate or chain file for the TLS listener (required if --listen-tls is set)")
	flags.StringVar(&opts.ListenTLSPrivateKey, "listen-tls-key", "", "Path to the private key file for the TLS listener (required if --listen-tls is set)")
	flags.Usage = func() {
		fmt.Fprintf(errorOutput, "Usage: %s [proxy|sign|list-certificates] [options]\n", os.Args[0])
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return "", options{}, err
	}

	switch flags.NArg() {
	case 0:
	case 1:
		if flags.Arg(0) != "list-certificates" {
			return "", options{}, fmt.Errorf("unknown command %q", flags.Arg(0))
		}
		mode = "list-certificates"
	default:
		return "", options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	if opts.PIN != "" && opts.PINFile != "" {
		return "", options{}, fmt.Errorf("pin and pin-file cannot both be set")
	}

	// A flag that says "forward my card authentication somewhere" must not be
	// silently dropped in a mode that forwards nothing. Only flags actually
	// given on the command line count, so a default never trips this.
	if mode == "sign" {
		var refused []string
		flags.Visit(func(given *flag.Flag) {
			if given.Name == "destination-url" || given.Name == "no-preserve-host" {
				refused = append(refused, "-"+given.Name)
			}
		})
		if len(refused) > 0 {
			return "", options{}, fmt.Errorf("sign mode forwards nothing, so %s is not accepted", strings.Join(refused, " and "))
		}
	}

	return mode, opts, nil
}

// loggingHandler prints each request before serving it.
func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timedLog(fmt.Sprintf("Request: %s %s", r.Method, r.URL.String()))
		next.ServeHTTP(w, r)
	})
}

// listenAndServe runs the HTTP listener both modes share.
func listenAndServe(opts options, handler http.Handler) error {
	address := fmt.Sprintf("%s:%d", opts.ListenAddress, opts.ListenPort)
	if opts.ListenTLS {
		timedLog(fmt.Sprintf("Listening on %s over TLS", address))
		return http.ListenAndServeTLS(address, opts.ListenTLSCertificate, opts.ListenTLSPrivateKey, handler)
	}
	timedLog(fmt.Sprintf("Listening on %s", address))
	return http.ListenAndServe(address, handler)
}

// validateOptions checks what the chosen mode actually needs. Every mode needs
// the card; only proxy needs somewhere to forward to.
func validateOptions(mode string, opts options) error {
	if opts.PKCS11Path == "" {
		return fmt.Errorf("pkcs11-path is required")
	}
	if opts.TokenSerial == "" {
		return fmt.Errorf("token-serial is required")
	}
	if opts.PIN == "" && opts.PINFile == "" {
		return fmt.Errorf("either pin or pin-file is required")
	}
	if mode == "proxy" && opts.DestinationURL == "" {
		return fmt.Errorf("destination-url is required")
	}
	if opts.ListenTLS && (opts.ListenTLSCertificate == "" || opts.ListenTLSPrivateKey == "") {
		return fmt.Errorf("listen-tls-cert and listen-tls-key are required when listen-tls is set")
	}
	return nil
}

func run(args []string, output, errorOutput io.Writer) error {
	mode, opts, err := parseOptions(args, errorOutput)
	if err != nil {
		return err
	}
	if err := validateOptions(mode, opts); err != nil {
		return err
	}
	if opts.PINFile != "" {
		if opts.PIN, err = readPINFile(opts.PINFile); err != nil {
			return err
		}
	}

	switch mode {
	case "list-certificates":
		return runListCertificates(opts, output)
	case "sign":
		return runSign(opts)
	default:
		return runProxy(opts)
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
