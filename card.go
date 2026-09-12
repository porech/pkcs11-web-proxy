package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync"

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

// pairedCertificates lists the certificates on the card that have a usable
// private key, in the order that fixes their index.
//
// The order is a contract. It walks private keys in the order the module
// returns them and reaches the certificate from the key, never the reverse,
// because that is the order -certificate-index has always meant. Two skip
// rules apply, and both must stay: a key with no CKA_ID cannot be paired, and
// a key whose CKA_ID matches no certificate has nothing to present.
//
// An attribute that cannot be read is treated as absent rather than fatal:
// tokens differ in what they expose, and one unreadable object should not make
// the whole card unusable.
func pairedCertificates(module tokenModule, session pkcs11.SessionHandle) ([]tls.Certificate, error) {
	keys, err := findObjects(module, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	if err != nil {
		return nil, err
	}

	var certificates []tls.Certificate
	for _, key := range keys {
		attributes, err := module.GetAttributeValue(session, key, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil || len(attributes[0].Value) == 0 {
			continue
		}
		identifier := attributes[0].Value

		handles, err := findObjects(module, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_ID, identifier),
		})
		if err != nil {
			return nil, err
		}
		if len(handles) == 0 {
			continue
		}

		values, err := module.GetAttributeValue(session, handles[0], []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if err != nil {
			continue
		}
		der := values[0].Value
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		certificates = append(certificates, tls.Certificate{
			Leaf:        leaf,
			Certificate: [][]byte{der},
		})
	}
	return certificates, nil
}

// certificateIdentifier finds the CKA_ID of the card object holding these
// certificate bytes. The identifier is what ties a certificate to its key.
func certificateIdentifier(module tokenModule, session pkcs11.SessionHandle, der []byte) ([]byte, error) {
	handles, err := findObjects(module, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, der),
	})
	if err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, fmt.Errorf("the certificate is not on the card")
	}
	attributes, err := module.GetAttributeValue(session, handles[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("read the certificate identifier: %w", err)
	}
	return attributes[0].Value, nil
}

// findSigningKey returns the private key for an identifier, and whether that
// key demands the PIN again for every signature.
//
// CKA_ALWAYS_AUTHENTICATE is what distinguishes a non-repudiation key from an
// authentication key: PKCS#11 requires a C_Login(CKU_CONTEXT_SPECIFIC) between
// C_SignInit and C_Sign for such a key, and Italian smart cards impose it on
// the qualified signing key.
//
// A token that does not expose the attribute is taken not to need it, which is
// the common case and not an error.
func findSigningKey(module tokenModule, session pkcs11.SessionHandle, identifier []byte) (pkcs11.ObjectHandle, bool, error) {
	handles, err := findObjects(module, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, identifier),
	})
	if err != nil {
		return 0, false, err
	}
	if len(handles) == 0 {
		return 0, false, fmt.Errorf("no private key matches the certificate")
	}
	attributes, err := module.GetAttributeValue(session, handles[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, nil),
	})
	if err != nil {
		return handles[0], false, nil
	}
	return handles[0], len(attributes[0].Value) == 1 && attributes[0].Value[0] == 1, nil
}

// *pkcs11.Ctx must remain usable as the module: this fails to compile the
// moment the interface and the library drift apart.
var _ tokenModule = (*pkcs11.Ctx)(nil)

// card owns the PKCS#11 module, the session, and the PIN for the life of the
// process. It opens once at startup: if the card goes away, operations fail
// with the error the module gives, and nothing tries to recover.
type card struct {
	module  tokenModule
	session pkcs11.SessionHandle
	pin     string
	mutex   sync.Mutex
}

// openCard loads the module, finds the token, and logs in.
func openCard(modulePath, tokenSerial, pin string) (*card, error) {
	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, fmt.Errorf("cannot load the PKCS#11 module %q", modulePath)
	}
	if err := module.Initialize(); err != nil {
		module.Destroy()
		return nil, fmt.Errorf("initialize the PKCS#11 module %q: %w", modulePath, err)
	}

	slot, err := findSlotBySerial(module, tokenSerial)
	if err != nil {
		_ = module.Finalize()
		module.Destroy()
		return nil, err
	}
	session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		_ = module.Finalize()
		module.Destroy()
		return nil, fmt.Errorf("open a session on token %q: %w", tokenSerial, err)
	}
	if err := module.Login(session, pkcs11.CKU_USER, pin); err != nil {
		_ = module.CloseSession(session)
		_ = module.Finalize()
		module.Destroy()
		return nil, fmt.Errorf("log in to token %q: %w", tokenSerial, err)
	}
	return &card{module: module, session: session, pin: pin}, nil
}

func (c *card) Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.module == nil {
		return
	}
	_ = c.module.Logout(c.session)
	_ = c.module.CloseSession(c.session)
	c.module.Destroy()
	c.module = nil
}

func (c *card) PairedCertificates() ([]tls.Certificate, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return pairedCertificates(c.module, c.session)
}

// cardSigner presents the key of one certificate as a crypto.Signer. It holds
// nothing of the card: it asks the card.
type cardSigner struct {
	card               *card
	key                pkcs11.ObjectHandle
	alwaysAuthenticate bool
	public             crypto.PublicKey
}

func (s *cardSigner) Public() crypto.PublicKey { return s.public }

func (s *cardSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	prefix, err := digestInfoPrefix(opts)
	if err != nil {
		return nil, err
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf(
			"the digest is %d bytes but %v produces %d",
			len(digest), opts.HashFunc(), opts.HashFunc().Size(),
		)
	}
	return s.card.sign(s, append(append([]byte{}, prefix...), digest...))
}

// sign performs one signature. The order below is prescribed by PKCS#11 and
// inverting it fails on cards that enforce it, which is why the login sits
// between the init and the signature rather than before both.
//
// The mutex is not decoration: two signatures interleaving on one session would
// step on each other's security state.
func (c *card) sign(signer *cardSigner, message []byte) ([]byte, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := c.module.SignInit(c.session, mechanism, signer.key); err != nil {
		return nil, fmt.Errorf("PKCS#11 sign init: %w", err)
	}
	if signer.alwaysAuthenticate {
		if err := c.module.Login(c.session, pkcs11.CKU_CONTEXT_SPECIFIC, c.pin); err != nil {
			return nil, fmt.Errorf("PKCS#11 context-specific login: %w", err)
		}
	}
	signature, err := c.module.Sign(c.session, message)
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 sign: %w", err)
	}
	return signature, nil
}

// Signer binds a certificate from this card to its key.
func (c *card) Signer(certificate tls.Certificate) (*cardSigner, error) {
	if certificate.Leaf == nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("the certificate carries no usable bytes")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()

	identifier, err := certificateIdentifier(c.module, c.session, certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, alwaysAuthenticate, err := findSigningKey(c.module, c.session, identifier)
	if err != nil {
		return nil, err
	}
	return &cardSigner{
		card:               c,
		key:                key,
		alwaysAuthenticate: alwaysAuthenticate,
		public:             certificate.Leaf.PublicKey,
	}, nil
}

// tlsCertificate ties a card certificate to its key and declares which
// signature schemes we can perform.
//
// Declaring them matters: without it Go may pick RSA-PSS and discover
// mid-handshake that we cannot do it.
func (c *card) tlsCertificate(certificate tls.Certificate) (tls.Certificate, error) {
	signer, err := c.Signer(certificate)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate.PrivateKey = signer
	certificate.SupportedSignatureAlgorithms = []tls.SignatureScheme{
		tls.PKCS1WithSHA256,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA512,
	}
	return certificate, nil
}
