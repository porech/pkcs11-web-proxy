package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
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

// fakeModule stands in for a PKCS#11 module so the card layer can be tested
// without a card. The calls slice is what makes the order of operations
// assertable.
type fakeModule struct {
	slots      []uint
	tokens     map[uint]pkcs11.TokenInfo
	tokenError map[uint]error

	calls   []string
	signed  []byte
	logins  []uint
	signErr error

	objects    map[pkcs11.ObjectHandle]map[string][]byte
	findResult [][]pkcs11.ObjectHandle
	findIndex  int
}

func (m *fakeModule) GetSlotList(bool) ([]uint, error) { return m.slots, nil }

func (m *fakeModule) GetTokenInfo(slot uint) (pkcs11.TokenInfo, error) {
	if err, failing := m.tokenError[slot]; failing {
		return pkcs11.TokenInfo{}, err
	}
	return m.tokens[slot], nil
}

func (m *fakeModule) OpenSession(uint, uint) (pkcs11.SessionHandle, error) { return 1, nil }
func (m *fakeModule) CloseSession(pkcs11.SessionHandle) error              { return nil }
func (m *fakeModule) Logout(pkcs11.SessionHandle) error                    { return nil }
func (m *fakeModule) Destroy()                                             {}

func (m *fakeModule) Login(_ pkcs11.SessionHandle, userType uint, _ string) error {
	m.calls = append(m.calls, "Login")
	m.logins = append(m.logins, userType)
	return nil
}

func (m *fakeModule) SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	m.calls = append(m.calls, "SignInit")
	return nil
}

func (m *fakeModule) Sign(_ pkcs11.SessionHandle, message []byte) ([]byte, error) {
	m.calls = append(m.calls, "Sign")
	m.signed = append([]byte{}, message...)
	if m.signErr != nil {
		return nil, m.signErr
	}
	return []byte("signature"), nil
}

func (m *fakeModule) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error { return nil }
func (m *fakeModule) FindObjectsFinal(pkcs11.SessionHandle) error                     { return nil }

func (m *fakeModule) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	if m.findIndex >= len(m.findResult) {
		return nil, false, nil
	}
	result := m.findResult[m.findIndex]
	m.findIndex++
	return result, false, nil
}

func (m *fakeModule) GetAttributeValue(_ pkcs11.SessionHandle, object pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	attributes, known := m.objects[object]
	if !known {
		return nil, fmt.Errorf("no such object")
	}
	var out []*pkcs11.Attribute
	for _, wanted := range template {
		value, present := attributes[attributeName(wanted.Type)]
		if !present {
			return nil, fmt.Errorf("attribute not available")
		}
		out = append(out, &pkcs11.Attribute{Type: wanted.Type, Value: value})
	}
	return out, nil
}

// attributeName keeps the fake readable: tests describe objects by attribute
// name rather than by numeric type.
func attributeName(attributeType uint) string {
	switch attributeType {
	case pkcs11.CKA_ID:
		return "id"
	case pkcs11.CKA_VALUE:
		return "value"
	case pkcs11.CKA_ALWAYS_AUTHENTICATE:
		return "always"
	default:
		return "unknown"
	}
}

func TestFindSlotBySerialIgnoresPaddingAndUnreadableSlots(t *testing.T) {
	module := &fakeModule{
		slots:      []uint{0, 1, 2},
		tokens:     map[uint]pkcs11.TokenInfo{1: {SerialNumber: "other"}, 2: {SerialNumber: "7430010024925855  "}},
		tokenError: map[uint]error{0: fmt.Errorf("reader is mute")},
	}

	slot, err := findSlotBySerial(module, "7430010024925855")
	if err != nil {
		t.Fatal(err)
	}
	if slot != 2 {
		t.Fatalf("slot = %d, want 2", slot)
	}
}

func TestFindSlotBySerialReportsAnAbsentToken(t *testing.T) {
	module := &fakeModule{slots: []uint{0}, tokens: map[uint]pkcs11.TokenInfo{0: {SerialNumber: "other"}}}
	if _, err := findSlotBySerial(module, "7430010024925855"); err == nil {
		t.Fatal("an absent token was accepted")
	}
}
