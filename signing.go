package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

// selectCertificate picks a certificate by index, which is the position it
// holds in the list shown by list-certificates.
func selectCertificate(certificates []tls.Certificate, index int) (tls.Certificate, error) {
	if index < 0 || index >= len(certificates) {
		return tls.Certificate{}, fmt.Errorf(
			"certificate index %d is out of range; run '%s list-certificates' to find the index",
			index, os.Args[0],
		)
	}
	return certificates[index], nil
}

// runSign serves the signing API and nothing else. There is no catch-all route:
// a path this API does not define is a 404, not a request sent somewhere.
func runSign(opts options) error {
	timedLog("Signing API is starting")
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
	signer, err := card.Signer(certificate)
	if err != nil {
		return err
	}
	// The RSA requirement is checked here, at startup, rather than once per
	// request: a card that cannot serve this API should not start serving it.
	handler, err := newSigningAPIHTTPHandler(certificate.Leaf, signer)
	if err != nil {
		return err
	}
	timedLog(fmt.Sprintf("Signing with certificate %d: %v", opts.CertificateIndex, certificate.Leaf.Subject))

	mux := http.NewServeMux()
	mux.Handle(signingAPINamespace, handler)
	mux.Handle(signingAPINamespace+"/", handler)
	mux.Handle("/", http.NotFoundHandler())
	if opts.LogRequests {
		return listenAndServe(opts, loggingHandler(mux))
	}
	return listenAndServe(opts, mux)
}
