package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestSigningIdentity(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	der, key := newTestCertificateDER(t, "signer")
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func TestSigningAPIIdentityExposesTheActiveCertificate(t *testing.T) {
	certificate, key := newTestSigningIdentity(t)
	handler, err := newSigningAPIHTTPHandler(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, signingAPIIdentityPath, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", response.Code, response.Body.String())
	}
	var body struct {
		Version              int    `json:"version"`
		CertificateDERBase64 string `json:"certificate_der_base64"`
		CertificateSHA256    string `json:"certificate_sha256"`
		DigestAlgorithm      string `json:"digest_algorithm"`
		SignatureAlgorithm   string `json:"signature_algorithm"`
		SignatureLength      int    `json:"signature_length"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(body.CertificateDERBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, certificate.Raw) {
		t.Fatal("identity returned a certificate other than the active one")
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	if body.Version != 1 || body.CertificateSHA256 != hex.EncodeToString(fingerprint[:]) ||
		body.DigestAlgorithm != "SHA-256" || body.SignatureAlgorithm != "RSASSA-PKCS1-v1_5" ||
		body.SignatureLength != key.Size() {
		t.Fatalf("unexpected identity metadata: %#v", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the identity response is cacheable")
	}
}

func TestSigningAPIReturnsAVerifiableSignatureWithoutHashingAgain(t *testing.T) {
	certificate, key := newTestSigningIdentity(t)
	handler, err := newSigningAPIHTTPHandler(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("the data the caller is signing"))
	request := httptest.NewRequest(http.MethodPost, signingAPISignDigestPath, bytes.NewReader(digest[:]))
	request.Header.Set(signRequestHeader, signRequestValue)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", response.Code, response.Body.String())
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], response.Body.Bytes()); err != nil {
		t.Fatalf("the response is not a PKCS#1 v1.5 signature of the supplied digest: %v", err)
	}
	doubleDigest := sha256.Sum256(digest[:])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, doubleDigest[:], response.Body.Bytes()); err == nil {
		t.Fatal("the signature verifies against a double-hashed digest")
	}
}

func TestSigningAPIRefusesInvalidRequestsBeforeSigning(t *testing.T) {
	certificate, key := newTestSigningIdentity(t)
	tests := []struct {
		name       string
		path       string
		method     string
		digest     []byte
		withHeader bool
		wantStatus int
	}{
		{name: "missing header", path: signingAPISignDigestPath, method: http.MethodPost, digest: make([]byte, 32), wantStatus: http.StatusForbidden},
		{name: "short digest", path: signingAPISignDigestPath, method: http.MethodPost, digest: make([]byte, 31), withHeader: true, wantStatus: http.StatusBadRequest},
		{name: "long digest", path: signingAPISignDigestPath, method: http.MethodPost, digest: make([]byte, 33), withHeader: true, wantStatus: http.StatusBadRequest},
		{name: "wrong method on sign-digest", path: signingAPISignDigestPath, method: http.MethodGet, withHeader: true, wantStatus: http.StatusMethodNotAllowed},
		{name: "wrong method on identity", path: signingAPIIdentityPath, method: http.MethodPost, wantStatus: http.StatusMethodNotAllowed},
		{name: "unknown path", path: signingAPINamespace + "/unknown", method: http.MethodGet, wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := newSigningAPIHTTPHandler(certificate, key)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, test.path, bytes.NewReader(test.digest))
			if test.withHeader {
				request.Header.Set(signRequestHeader, signRequestValue)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestSigningAPIRefusesANonRSACertificate(t *testing.T) {
	certificate, key := newTestSigningIdentity(t)
	certificate.PublicKey = struct{}{}
	if _, err := newSigningAPIHTTPHandler(certificate, key); err == nil {
		t.Fatal("a non-RSA certificate was accepted")
	}
	if _, err := newSigningAPIHTTPHandler(nil, key); err == nil {
		t.Fatal("a missing certificate was accepted")
	}
}
