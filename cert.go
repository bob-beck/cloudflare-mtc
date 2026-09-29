package mtc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var tagRelativeOID = cbasn1.Tag(13)

// MarshalTrustAnchorIDName returns the DER Name that identifies the MTC CA
// (or cosigner) id: a single RDN with a single id-rdna-trustAnchorID
// attribute whose value is a RELATIVE-OID.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 5.1.
func MarshalTrustAnchorIDName(id TrustAnchorID) []byte {
	b := cryptobyte.NewBuilder(nil)
	addTrustAnchorIDName(b, id)
	return b.BytesOrPanic()
}

func addTrustAnchorIDName(b *cryptobyte.Builder, id TrustAnchorID) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(OIDRDNATrustAnchorID)
				attr.AddASN1(tagRelativeOID, func(val *cryptobyte.Builder) {
					val.AddBytes(id)
				})
			})
		})
	})
}

// ParseTrustAnchorIDName parses a DER Name of the form produced by
// MarshalTrustAnchorIDName and returns the trust anchor ID.
func ParseTrustAnchorIDName(der []byte) (TrustAnchorID, error) {
	s := cryptobyte.String(der)
	var dn, rdn, attr cryptobyte.String
	var oid asn1.ObjectIdentifier
	var val cryptobyte.String
	if !s.ReadASN1(&dn, cbasn1.SEQUENCE) || !s.Empty() ||
		!dn.ReadASN1(&rdn, cbasn1.SET) || !dn.Empty() ||
		!rdn.ReadASN1(&attr, cbasn1.SEQUENCE) || !rdn.Empty() ||
		!attr.ReadASN1ObjectIdentifier(&oid) ||
		!attr.ReadASN1(&val, tagRelativeOID) || !attr.Empty() {
		return nil, errors.New("name is not a single trust anchor ID attribute")
	}
	if !oid.Equal(OIDRDNATrustAnchorID) {
		return nil, errors.New("name is not a trust anchor ID")
	}
	id := TrustAnchorID(append([]byte(nil), val...))
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id, nil
}

func addX509Time(b *cryptobyte.Builder, t time.Time) {
	t = t.UTC().Truncate(time.Second)
	if y := t.Year(); 1950 <= y && y <= 2049 {
		b.AddASN1UTCTime(t)
	} else {
		b.AddASN1GeneralizedTime(t)
	}
}

func addValidity(b *cryptobyte.Builder, notBefore, notAfter time.Time) {
	b.AddASN1(cbasn1.SEQUENCE, func(v *cryptobyte.Builder) {
		addX509Time(v, notBefore)
		addX509Time(v, notAfter)
	})
}

// A Template holds the parts of a certificate that the subscriber chooses.
type Template struct {
	// Subject is the DER Name of the subject. An empty Subject is the
	// empty Name.
	Subject []byte

	// SPKI is the DER SubjectPublicKeyInfo.
	SPKI []byte

	NotBefore, NotAfter time.Time

	// Rest is the DER of the TBSCertificate fields after the
	// subjectPublicKeyInfo: optional unique identifiers and the [3]
	// extensions, exactly as they appear in the TBSCertificate.
	Rest []byte
}

// dummyKey signs throwaway certificates in NewTemplateFromX509; only the
// encodings of the subject and extensions are kept.
var dummyKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// NewTemplateFromX509 returns a Template with the subject and extensions
// that crypto/x509 produces for tmpl (DNSNames, IPAddresses, KeyUsage,
// ExtKeyUsage, BasicConstraints and so on), and the given public key.
// tmpl.NotBefore and tmpl.NotAfter are copied.
func NewTemplateFromX509(tmpl *x509.Certificate, pub crypto.PublicKey) (*Template, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	t := *tmpl
	if t.SerialNumber == nil {
		t.SerialNumber = big.NewInt(1)
	}
	// A parent without a SubjectKeyId keeps crypto/x509 from adding an
	// AuthorityKeyIdentifier.
	parent := &x509.Certificate{Subject: pkix.Name{CommonName: "unused"}}
	der, err := x509.CreateCertificate(rand.Reader, &t, parent, dummyKey.Public(), dummyKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return nil, err
	}
	return &Template{
		Subject:   tbs.Subject,
		SPKI:      spki,
		NotBefore: tmpl.NotBefore,
		NotAfter:  tmpl.NotAfter,
		Rest:      tbs.Rest,
	}, nil
}

// extensionsDroppedFromX509 are extensions of an existing certificate that
// refer to its issuer or its signature, and so are not carried over by
// NewTemplateFromCertificate.
var extensionsDroppedFromX509 = []asn1.ObjectIdentifier{
	{2, 5, 29, 35},                     // authorityKeyIdentifier
	{2, 5, 29, 31},                     // cRLDistributionPoints
	{1, 3, 6, 1, 5, 5, 7, 1, 1},        // authorityInfoAccess
	{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, // SCT list
	{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, // CT poison
}

// NewTemplateFromCertificate returns a Template with the subject, public key,
// validity and extensions of an existing certificate, leaving out extensions
// that describe its issuer or its signature.
func NewTemplateFromCertificate(cert *x509.Certificate) (*Template, error) {
	var exts []pkix.Extension
	for _, e := range cert.Extensions {
		drop := false
		for _, oid := range extensionsDroppedFromX509 {
			if e.Id.Equal(oid) {
				drop = true
			}
		}
		if !drop {
			exts = append(exts, e)
		}
	}
	t := &Template{
		Subject:   cert.RawSubject,
		SPKI:      cert.RawSubjectPublicKeyInfo,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
	if len(exts) > 0 {
		der, err := asn1.Marshal(exts)
		if err != nil {
			return nil, err
		}
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(e *cryptobyte.Builder) {
			e.AddBytes(der)
		})
		t.Rest = b.BytesOrPanic()
	}
	return t, nil
}

// Serial returns the serial number of index in log logNumber, logNumber <<
// 48 | index.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.2.
func Serial(logNumber uint16, index uint64) uint64 {
	return uint64(logNumber)<<48 | index
}

// MarshalTBSCertificate returns the TBSCertificate of the MTC certificate for
// tmpl issued by caID with the given serial number.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.2.
func (tmpl *Template) MarshalTBSCertificate(caID TrustAnchorID, serial uint64) ([]byte, error) {
	if tmpl.NotAfter.Before(tmpl.NotBefore) {
		return nil, errors.New("certificate notAfter is before notBefore")
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
			v.AddASN1Uint64(2) // v3
		})
		tbs.AddASN1Uint64(serial)
		tbs.AddBytes(mtcProofAlgorithmIdentifier)
		addTrustAnchorIDName(tbs, caID)
		addValidity(tbs, tmpl.NotBefore, tmpl.NotAfter)
		if len(tmpl.Subject) == 0 {
			tbs.AddASN1(cbasn1.SEQUENCE, func(*cryptobyte.Builder) {})
		} else {
			tbs.AddBytes(tmpl.Subject)
		}
		tbs.AddBytes(tmpl.SPKI)
		tbs.AddBytes(tmpl.Rest)
	})
	der, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	// Round-trip through the parser to reject malformed template fields.
	if _, err := ParseTBSCertificate(der); err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	return der, nil
}

// MarshalCertificate assembles an MTC certificate from its TBSCertificate and
// MTCProof: the signatureAlgorithm is id-alg-mtcProof and the signatureValue
// holds the serialized MTCProof.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.2.
func MarshalCertificate(tbs []byte, proof *MTCProof) ([]byte, error) {
	p, err := proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddBytes(tbs)
		cert.AddBytes(mtcProofAlgorithmIdentifier)
		cert.AddASN1BitString(p)
	})
	return b.Bytes()
}

// A CAParams describes an MTC CA for its CA certificate.
type CAParams struct {
	ID TrustAnchorID

	// Key is the CA cosigner's public key.
	Key crypto.PublicKey

	// MinSerial and MaxSerial bound the serial numbers the CA issues; both
	// are at least 2^48.
	MinSerial, MaxSerial uint64

	NotBefore, NotAfter time.Time

	// PrefixURL, if set, is the c2sp.org/mtc-tlog CA prefix URL, carried in
	// a non-critical extension.
	PrefixURL string
}

func addUnsignedAlgorithmIdentifier(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
		alg.AddASN1ObjectIdentifier(OIDAlgUnsigned)
	})
}

// addUnsignedIssuerName adds the placeholder issuer Name of an RFC 9925
// unsigned certificate.
func addUnsignedIssuerName(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(OIDRDNAUnsigned)
				attr.AddASN1(cbasn1.UTF8String, func(*cryptobyte.Builder) {})
			})
		})
	})
}

func addExtension(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, critical bool, value func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
		ext.AddASN1ObjectIdentifier(oid)
		if critical {
			ext.AddASN1Boolean(true)
		}
		ext.AddASN1(cbasn1.OCTET_STRING, value)
	})
}

// marshalUnsignedCertificate returns an RFC 9925 unsigned certificate whose
// subject is the trust anchor ID name of id.
func marshalUnsignedCertificate(id TrustAnchorID, key crypto.PublicKey, notBefore, notAfter time.Time, exts func(*cryptobyte.Builder)) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
			tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
				v.AddASN1Uint64(2)
			})
			tbs.AddASN1Uint64(1)
			addUnsignedAlgorithmIdentifier(tbs)
			addUnsignedIssuerName(tbs)
			addValidity(tbs, notBefore, notAfter)
			addTrustAnchorIDName(tbs, id)
			tbs.AddBytes(spki)
			if exts != nil {
				tbs.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(e *cryptobyte.Builder) {
					e.AddASN1(cbasn1.SEQUENCE, exts)
				})
			}
		})
		addUnsignedAlgorithmIdentifier(cert)
		cert.AddASN1BitString(nil)
	})
	return b.Bytes()
}

// MarshalCACertificate returns the CA certificate for p: an RFC 9925 unsigned
// certificate whose subject is the CA ID, whose key is the CA cosigner key,
// and which carries the critical id-pe-mtcCertificationAuthority-SHA256
// extension.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 5.5.
func MarshalCACertificate(p *CAParams) ([]byte, error) {
	if p.MinSerial < 1<<48 || p.MaxSerial < p.MinSerial {
		return nil, errors.New("CA serial range must satisfy 2^48 <= min <= max")
	}
	if err := p.ID.Validate(); err != nil {
		return nil, err
	}
	sigAlg, err := signatureAlgorithmOID(p.Key)
	if err != nil {
		return nil, err
	}
	return marshalUnsignedCertificate(p.ID, p.Key, p.NotBefore, p.NotAfter, func(exts *cryptobyte.Builder) {
		// keyUsage: keyCertSign.
		addExtension(exts, oidKeyUsage, true, func(v *cryptobyte.Builder) {
			// Bit 5 set; two unused trailing bits.
			v.AddASN1(cbasn1.BIT_STRING, func(bs *cryptobyte.Builder) {
				bs.AddBytes([]byte{0x02, 0x04})
			})
		})
		// basicConstraints: cA TRUE.
		addExtension(exts, oidBasicConstraints, true, func(v *cryptobyte.Builder) {
			v.AddASN1(cbasn1.SEQUENCE, func(bc *cryptobyte.Builder) {
				bc.AddASN1Boolean(true)
			})
		})
		// subjectKeyIdentifier: the binary CA ID.
		addExtension(exts, oidSubjectKeyID, false, func(v *cryptobyte.Builder) {
			v.AddASN1OctetString(p.ID)
		})
		addExtension(exts, OIDMTCCertificationAuthoritySHA256, true, func(v *cryptobyte.Builder) {
			v.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
				seq.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
					alg.AddASN1ObjectIdentifier(sigAlg)
				})
				seq.AddASN1Uint64(p.MinSerial)
				seq.AddASN1Uint64(p.MaxSerial)
			})
		})
		if p.PrefixURL != "" {
			addExtension(exts, OIDMTCTlogPrefixURL, false, func(v *cryptobyte.Builder) {
				v.AddASN1(cbasn1.IA5String, func(s *cryptobyte.Builder) {
					s.AddBytes([]byte(p.PrefixURL))
				})
			})
		}
	})
}

// MarshalCosignerCertificate returns a certificate representing an
// additional cosigner: the CA certificate's unsigned shape, with the
// cosigner ID as subject and the cosigner key, and no extensions. The draft
// does not define this; it is the form OpenSSL's
// OSSL_MTC_COSIGNER_parse_certificates() reads.
func MarshalCosignerCertificate(c *CosignerPublic, notBefore, notAfter time.Time) ([]byte, error) {
	return marshalUnsignedCertificate(c.ID, c.Key, notBefore, notAfter, nil)
}

func signatureAlgorithmOID(key crypto.PublicKey) (asn1.ObjectIdentifier, error) {
	if k, ok := key.(*mldsa.PublicKey); ok && k.Parameters() == mldsa.MLDSA44() {
		return OIDMLDSA44, nil
	}
	return nil, errors.New("CA cosigner key is not ML-DSA-44")
}
