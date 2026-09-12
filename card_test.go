package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"testing"
)

func TestDigestInfoPrefixCoversTheSchemesATLSHandshakeMayAsk(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want []byte
	}{
		{crypto.SHA256, sha256DigestInfoPrefix},
		{crypto.SHA384, sha384DigestInfoPrefix},
		{crypto.SHA512, sha512DigestInfoPrefix},
	}
	for _, test := range tests {
		got, err := digestInfoPrefix(test.hash)
		if err != nil {
			t.Fatalf("%v: %v", test.hash, err)
		}
		if !bytes.Equal(got, test.want) {
			t.Fatalf("%v: prefix = %x, want %x", test.hash, got, test.want)
		}
	}
}

func TestDigestInfoPrefixRefusesWhatTheCardCannotDo(t *testing.T) {
	if _, err := digestInfoPrefix(&rsa.PSSOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("RSA-PSS was accepted")
	}
	if _, err := digestInfoPrefix(crypto.SHA1); err == nil {
		t.Fatal("SHA-1 was accepted")
	}
	if _, err := digestInfoPrefix(nil); err == nil {
		t.Fatal("a missing hash function was accepted")
	}
}
