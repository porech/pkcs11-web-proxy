package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

func timedLog(message string) {
	fmt.Printf("%v - %s\n", time.Now(), message)
}

func listCertificates(pkcs11path, tokenSerial *string, pinVal string) {
	config := crypto11.Config{
		Path:        *pkcs11path,
		TokenSerial: *tokenSerial,
		Pin:         pinVal,
	}

	context, err := crypto11.Configure(&config)
	if err != nil {
		log.Fatalln(err)
	}

	certificates, err := context.FindAllPairedCertificates()
	if err != nil {
		log.Fatalln(err)
	}

	index := 0
	for _, cert := range certificates {
		fmt.Printf("Certificate index %d: %v\n", index, cert.Leaf.Subject)
		index++
	}
}

func main() {
	listenAddress := flag.String("listen-addr", "127.0.0.1", "Address to listen on")
	listenPort := flag.Int("listen-port", 8080, "Port to listen on")
	pkcs11path := flag.String("pkcs11-path", "", "Path to the PKCS11 module. Use the card vendor-specific one, or run 'pkcs11-tool --help' and look for '--module' default value for a good one to use.")
	tokenSerial := flag.String("token-serial", "", "Serial number of the token. Run 'pkcs11-tool --list-token-slots' to find it.")
	certificateIndex := flag.Int("certificate-index", 0, fmt.Sprintf("Index of the certificate to use. Run '%s -token-serial ... [-pin/-pin-file] ... list-certificates' to find the index. By default, the first found certificate (index 0) will be used.", os.Args[0]))
	pin := flag.String("pin", "", "PIN to access the card. Cannot be used with --pin-file.")
	pinFile := flag.String("pin-file", "", "File containing the PIN to access the card (will be deleted after read!). Cannot be used with --pin.")
	destinationUrl := flag.String("destination-url", "", "URL to forward requests to.")
	noPreserveHost := flag.Bool("no-preserve-host", false, "Do not preserve the host header in the request.")
	logRequests := flag.Bool("log-requests", false, "Log each request to stdout.")
	listenTLS := flag.Bool("listen-tls", false, "Listen on TLS instead of plain HTTP (useful if your upstream sets 'secure' cookies")
	listenTLSCertificate := flag.String("listen-tls-cert", "", "Path to the certificate or chain file for the TLS listener (required if --listen-tls is set)")
	listenTLSPrivateKey := flag.String("listen-tls-key", "", "Path to the private key file for the TLS listener (required if --listen-tls is set)")
	flag.Parse()

	if *pkcs11path == "" {
		fmt.Println("pkcs11-path is required")
		flag.Usage()
		return
	}

	if *tokenSerial == "" {
		fmt.Println("token-serial is required")
		flag.Usage()
		return
	}

	if *pin == "" && *pinFile == "" {
		fmt.Println("Either pin or pin-file is required")
		flag.Usage()
		return
	}

	if *pin != "" && *pinFile != "" {
		fmt.Println("Both pin and pin-file are set. Please use only one")
		flag.Usage()
		return
	}

	pinVal := *pin

	if *pinFile != "" {
		pinBytes, err := os.ReadFile(*pinFile)
		if err != nil {
			log.Fatalf("Error reading pin file: %v", err)
		}
		pinVal = strings.TrimSpace(string(pinBytes))
		err = os.Remove(*pinFile)
		if err != nil {
			log.Fatalf("Error deleting pin file: %v", err)
		}
	}

	if flag.Arg(0) == "list-certificates" {
		listCertificates(pkcs11path, tokenSerial, pinVal)
		return
	}

	if *destinationUrl == "" {
		fmt.Println("destination-url is required")
		flag.Usage()
		return
	}

	if *listenTLS {
		if *listenTLSPrivateKey == "" || *listenTLSCertificate == "" {
			fmt.Println("listen-tls-private-key and listen-tls-certificate are required when listen-tls is set")
			flag.Usage()
			return
		}
	}

	timedLog("Reverse proxy is starting")
	config := crypto11.Config{
		Path:        *pkcs11path,
		TokenSerial: *tokenSerial,
		Pin:         pinVal,
	}

	context, err := crypto11.Configure(&config)
	if err != nil {
		log.Fatalln(err)
	}

	certificates, err := context.FindAllPairedCertificates()
	if err != nil {
		log.Fatalln(err)
	}

	if *certificateIndex >= len(certificates) {
		log.Fatalf("Certificate index %d is out of range. Run '%s -token-serial ... [-pin/-pin-file] ... list-certificates' to find the index.\n", *certificateIndex, os.Args[0])
		return
	}
	cert := certificates[*certificateIndex]
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:  []tls.Certificate{cert},
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}

	destUrl, err := url.Parse(*destinationUrl)
	proxy := httputil.NewSingleHostReverseProxy(destUrl)
	proxy.Transport = transport

	handler := func(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if !*noPreserveHost {
				r.Host = destUrl.Host
			}
			if *logRequests {
				timedLog(fmt.Sprintf("Request: %s %s", r.Method, r.URL.String()))
			}
			p.ServeHTTP(w, r)
		}
	}

	http.HandleFunc("/", handler(proxy))
	if *listenTLS {
		timedLog(fmt.Sprintf("Listening on %s:%d over TLS", *listenAddress, *listenPort))
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%s:%d", *listenAddress, *listenPort), *listenTLSCertificate, *listenTLSPrivateKey, nil))
	} else {
		timedLog(fmt.Sprintf("Listening on %s:%d", *listenAddress, *listenPort))
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *listenAddress, *listenPort), nil))
	}
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
