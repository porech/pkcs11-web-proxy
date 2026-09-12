package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

const (
	signingAPINamespace      = "/api/v1/signing"
	signingAPIIdentityPath   = signingAPINamespace + "/identity"
	signingAPISignDigestPath = signingAPINamespace + "/sign-digest"

	// signRequestHeader is not authentication: anything that can reach the port
	// can set it. It exists because a cross-origin form post from a web page the
	// user happens to be visiting cannot set a custom header, and that is the
	// accident worth preventing.
	signRequestHeader = "X-PKCS11-Sign-Request"
	signRequestValue  = "1"
)

type signingAPIHTTPHandler struct {
	certificate *x509.Certificate
	signer      crypto.Signer
}

func newSigningAPIHTTPHandler(certificate *x509.Certificate, signer crypto.Signer) (*signingAPIHTTPHandler, error) {
	if certificate == nil {
		return nil, fmt.Errorf("the signing certificate is missing")
	}
	if _, isRSA := certificate.PublicKey.(*rsa.PublicKey); !isRSA {
		return nil, fmt.Errorf("signing requires an RSA certificate")
	}
	if signer == nil {
		return nil, fmt.Errorf("the signing key is missing")
	}
	return &signingAPIHTTPHandler{certificate: certificate, signer: signer}, nil
}

func (handler *signingAPIHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")

	switch request.URL.Path {
	case signingAPIIdentityPath:
		handler.identity(response, request)
	case signingAPISignDigestPath:
		handler.signDigest(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (handler *signingAPIHTTPHandler) identity(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fingerprint := sha256.Sum256(handler.certificate.Raw)
	publicKey := handler.certificate.PublicKey.(*rsa.PublicKey)
	body := struct {
		Version              int    `json:"version"`
		CertificateDERBase64 string `json:"certificate_der_base64"`
		CertificateSHA256    string `json:"certificate_sha256"`
		DigestAlgorithm      string `json:"digest_algorithm"`
		SignatureAlgorithm   string `json:"signature_algorithm"`
		SignatureLength      int    `json:"signature_length"`
	}{
		Version:              1,
		CertificateDERBase64: base64.StdEncoding.EncodeToString(handler.certificate.Raw),
		CertificateSHA256:    hex.EncodeToString(fingerprint[:]),
		DigestAlgorithm:      "SHA-256",
		SignatureAlgorithm:   "RSASSA-PKCS1-v1_5",
		SignatureLength:      publicKey.Size(),
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(body); err != nil {
		log.Printf("encode signing identity: %v", err)
	}
}

func (handler *signingAPIHTTPHandler) signDigest(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if request.Header.Get(signRequestHeader) != signRequestValue {
		http.Error(response, "missing "+signRequestHeader+" header", http.StatusForbidden)
		return
	}

	// One byte more than a digest is read, so a body that is too long is
	// rejected rather than silently truncated to something signable.
	digest, err := io.ReadAll(io.LimitReader(request.Body, int64(crypto.SHA256.Size()+1)))
	if err != nil {
		http.Error(response, "cannot read the digest", http.StatusBadRequest)
		return
	}
	if len(digest) != crypto.SHA256.Size() {
		http.Error(response, fmt.Sprintf("the SHA-256 digest must be exactly %d bytes", crypto.SHA256.Size()), http.StatusBadRequest)
		return
	}

	signature, err := handler.signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Printf("sign a SHA-256 digest: %v", err)
		http.Error(response, "signing failed", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("X-Digest-Algorithm", "SHA-256")
	response.Header().Set("X-Signature-Algorithm", "RSASSA-PKCS1-v1_5")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(signature)
}
