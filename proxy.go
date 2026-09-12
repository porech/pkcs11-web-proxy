package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

// runProxy forwards everything upstream with TLS client authentication from the
// card. Every path is forwarded, including the signing API paths, which are not
// reserved here: proxy mode behaves exactly as it always has.
func runProxy(opts options) error {
	destinationURL, err := url.Parse(opts.DestinationURL)
	if err != nil {
		return fmt.Errorf("invalid destination URL: %w", err)
	}

	timedLog("Reverse proxy is starting")
	card, err := openCard(opts.PKCS11Path, opts.TokenSerial, opts.PIN)
	if err != nil {
		return err
	}
	defer card.Close()

	certificates, err := card.PairedCertificates()
	if err != nil {
		return err
	}
	certificate, err := selectCertificate(certificates, opts.CertificateIndex)
	if err != nil {
		return err
	}
	certificate, err = card.tlsCertificate(certificate)
	if err != nil {
		return fmt.Errorf("prepare the TLS client certificate: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(destinationURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:  []tls.Certificate{certificate},
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !opts.NoPreserveHost {
			r.Host = destinationURL.Host
		}
		proxy.ServeHTTP(w, r)
	})
	if opts.LogRequests {
		handler = loggingHandler(handler)
	}
	return listenAndServe(opts, handler)
}

// runListCertificates prints the certificates in the order that fixes their
// index.
func runListCertificates(opts options, output io.Writer) error {
	card, err := openCard(opts.PKCS11Path, opts.TokenSerial, opts.PIN)
	if err != nil {
		return err
	}
	defer card.Close()

	certificates, err := card.PairedCertificates()
	if err != nil {
		return err
	}
	for index, certificate := range certificates {
		fmt.Fprintf(output, "Certificate index %d: %v\n", index, certificate.Leaf.Subject)
	}
	return nil
}

// readPINFile reads the PIN and deletes the file, which is the whole point of
// passing one.
func readPINFile(path string) (string, error) {
	pinBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the PIN file: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("delete the PIN file: %w", err)
	}
	return strings.TrimSpace(string(pinBytes)), nil
}
