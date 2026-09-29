package mtc

import (
	"encoding/asn1"
)

// Object identifiers used by Merkle Tree Certificates.
//
// The drafts leave the final OIDs as TBD. These are the early experimentation
// OIDs from draft-ietf-plants-merkle-tree-certs-06, Sections 5.1, 5.5 and 6.2,
// which are also what OpenSSL's MTC implementation accepts.
var (
	// OIDMTCProof is id-alg-mtcProof (Section 6.2).
	OIDMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}

	// OIDRDNATrustAnchorID is id-rdna-trustAnchorID (Section 5.1). Its
	// value is a RELATIVE-OID.
	OIDRDNATrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 3}

	// OIDMTCCertificationAuthoritySHA256 is
	// id-pe-mtcCertificationAuthority-SHA256 (Section 5.5).
	OIDMTCCertificationAuthoritySHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 4}

	// OIDMTCTlogPrefixURL is id-mtcTlogPrefixURL from c2sp.org/mtc-tlog: a
	// non-critical CA certificate extension holding the CA prefix URL as an
	// IA5String.
	OIDMTCTlogPrefixURL = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 1}

	// OIDAlgUnsigned is id-alg-unsigned (RFC 9925).
	OIDAlgUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}

	// OIDRDNAUnsigned is id-rdna-unsigned (RFC 9925).
	OIDRDNAUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 1}

	// OIDMLDSA44 is id-ml-dsa-44 (RFC 9881).
	OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// oidDER returns the DER encoding of an OBJECT IDENTIFIER, including tag and
// length.
func oidDER(oid asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return b
}

// mtcProofAlgorithmIdentifier is the DER AlgorithmIdentifier for
// id-alg-mtcProof, with absent parameters (Section 6.2).
var mtcProofAlgorithmIdentifier = func() []byte {
	o := oidDER(OIDMTCProof)
	return append([]byte{0x30, byte(len(o))}, o...)
}()
