package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// DigestInfo prefixes (RFC 8017). Signing happens with CKM_RSA_PKCS over the
// DigestInfo, which is exactly what an RSA crypto.Signer does: the caller hands
// over a digest, and the prefix declares which function produced it.
//
// There are three because a TLS 1.2 handshake may ask for any of the three
// PKCS#1 v1.5 schemes. Signing a SHA-384 digest under the SHA-256 prefix
// produces a signature the server rejects without saying why, which is the kind
// of mistake that is only found in production.
var (
	sha256DigestInfoPrefix = []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	}
	sha384DigestInfoPrefix = []byte{
		0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
	}
	sha512DigestInfoPrefix = []byte{
		0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
	}
)

// digestInfoPrefix says how to sign what is being asked, or why we cannot.
//
// The error names the scheme: if the other end ever moves to TLS 1.3 the
// signature becomes PSS, and that should be readable in the log rather than
// guessed from a handshake that fails.
func digestInfoPrefix(opts crypto.SignerOpts) ([]byte, error) {
	if pss, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return nil, fmt.Errorf(
			"this card signs PKCS#1 v1.5 only, and RSA-PSS was requested (hash %v)", pss.Hash,
		)
	}
	if opts == nil {
		return nil, fmt.Errorf("signing needs a declared hash function")
	}
	switch opts.HashFunc() {
	case crypto.SHA256:
		return sha256DigestInfoPrefix, nil
	case crypto.SHA384:
		return sha384DigestInfoPrefix, nil
	case crypto.SHA512:
		return sha512DigestInfoPrefix, nil
	default:
		return nil, fmt.Errorf("unsupported hash function for PKCS#1 v1.5: %v", opts.HashFunc())
	}
}

// tokenModule is the slice of a PKCS#11 module this program uses. *pkcs11.Ctx
// satisfies it as it is; declaring it is what lets the card layer be tested
// without a card.
type tokenModule interface {
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error)
	CloseSession(sh pkcs11.SessionHandle) error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error
	Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error)
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	Destroy()
}

// findSlotBySerial locates the token by serial number. A slot that will not
// answer is not an empty slot: the search carries on, because the card may be
// in another reader, but the failure is reported if no slot holds the token.
func findSlotBySerial(module tokenModule, serial string) (uint, error) {
	slots, err := module.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("list PKCS#11 slots: %w", err)
	}
	var unreadable error
	for _, slot := range slots {
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			unreadable = err
			continue
		}
		if strings.TrimSpace(info.SerialNumber) == serial {
			return slot, nil
		}
	}
	if unreadable != nil {
		return 0, fmt.Errorf("no token with serial %q, and a slot could not be read: %w", serial, unreadable)
	}
	return 0, fmt.Errorf("no token with serial %q is present", serial)
}

// findObjects runs a PKCS#11 object search to exhaustion.
func findObjects(module tokenModule, session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := module.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("PKCS#11 find init: %w", err)
	}
	defer func() { _ = module.FindObjectsFinal(session) }()

	var all []pkcs11.ObjectHandle
	for {
		handles, _, err := module.FindObjects(session, 64)
		if err != nil {
			return nil, fmt.Errorf("PKCS#11 find: %w", err)
		}
		if len(handles) == 0 {
			return all, nil
		}
		all = append(all, handles...)
	}
}
