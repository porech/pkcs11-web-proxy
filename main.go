package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
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

func main() {
	listenAddress := flag.String("listen-addr", "127.0.0.1", "Address to listen on")
	listenPort := flag.Int("listen-port", 8080, "Port to listen on")
	pkcs11path := flag.String("pkcs11-path", "", "Path to the PKCS11 module. Use the card vendor-specific one, or run 'pkcs11-tool --help' and look for '--module' default value for a good one to use.")
	tokenSerial := flag.String("token-serial", "", "Serial number of the token. Run 'pkcs11-tool --list-token-slots' to find it.")
	pin := flag.String("pin", "", "PIN to access the card. Cannot be used with --pin-file.")
	pinFile := flag.String("pin-file", "", "File containing the PIN to access the card (will be deleted after read!). Cannot be used with --pin.")
	destinationUrl := flag.String("destination-url", "", "URL to forward requests to.")
	noPreserveHost := flag.Bool("no-preserve-host", false, "Do not preserve the host header in the request.")
	logRequests := flag.Bool("log-requests", false, "Log each request to stdout.")
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

	if *destinationUrl == "" {
		fmt.Println("destination-url is required")
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

	cert := certificates[0]
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:  []tls.Certificate{cert},
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}

	ipexUrl, err := url.Parse(*destinationUrl)
	proxy := httputil.NewSingleHostReverseProxy(ipexUrl)
	proxy.Transport = transport

	handler := func(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if !*noPreserveHost {
				r.Host = ipexUrl.Host
			}
			if *logRequests {
				timedLog(fmt.Sprintf("Request: %s %s", r.Method, r.URL.String()))
			}
			p.ServeHTTP(w, r)
		}
	}

	http.HandleFunc("/", handler(proxy))
	timedLog(fmt.Sprintf("Listening on %s:%d", *listenAddress, *listenPort))
	panic(http.ListenAndServe(fmt.Sprintf("%s:%d", *listenAddress, *listenPort), nil))
}
