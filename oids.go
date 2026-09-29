package mtc

import (
	"encoding/asn1"
)

// Object identifiers used by Merkle Tree Certificates.
//
// OIDMTCProof, OIDRDNATrustAnchorID and OIDMTCCertificationAuthoritySHA256
// are the early experimentation OIDs of
// draft-ietf-plants-merkle-tree-certs-06, Sections 5.1, 5.5 and 6.2, and are
// what this package issues and accepts, as does OpenSSL's MTC
// implementation. The OIDs IANA assigned for the same purposes are the
// ...IANA variables; they are recognised by DescribeOID only.
var (
	// OIDMTCProof is id-alg-mtcProof (Section 6.2).
	OIDMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}

	// OIDRDNATrustAnchorID is id-rdna-trustAnchorID (Section 5.1). Its
	// value is a RELATIVE-OID.
	OIDRDNATrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 3}

	// OIDMTCCertificationAuthoritySHA256 is
	// id-pe-mtcCertificationAuthority-SHA256 (Section 5.5).
	OIDMTCCertificationAuthoritySHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 4}

	// OIDMTCProofIANA is the IANA-assigned id-alg-mtcProof,
	// 1.3.6.1.5.5.7.6.67.
	OIDMTCProofIANA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 67}

	// OIDRDNATrustAnchorIDIANA is the IANA-assigned id-rdna-trustAnchorID,
	// 1.3.6.1.5.5.7.25.3.
	OIDRDNATrustAnchorIDIANA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}

	// OIDMTCCertificationAuthoritySHA256IANA is the IANA-assigned
	// id-pe-mtcCertificationAuthority-SHA256, 1.3.6.1.5.5.7.1.38.
	OIDMTCCertificationAuthoritySHA256IANA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 38}

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

// oidNames names the OIDs DescribeOID knows.
var oidNames = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{OIDMTCProof, "id-alg-mtcProof (draft experimental)"},
	{OIDRDNATrustAnchorID, "id-rdna-trustAnchorID (draft experimental)"},
	{OIDMTCCertificationAuthoritySHA256, "id-pe-mtcCertificationAuthority-SHA256 (draft experimental)"},
	{OIDMTCProofIANA, "id-alg-mtcProof (IANA)"},
	{OIDRDNATrustAnchorIDIANA, "id-rdna-trustAnchorID (IANA)"},
	{OIDMTCCertificationAuthoritySHA256IANA, "id-pe-mtcCertificationAuthority-SHA256 (IANA)"},
	{OIDMTCTlogPrefixURL, "id-mtcTlogPrefixURL"},
	{OIDAlgUnsigned, "id-alg-unsigned"},
	{OIDRDNAUnsigned, "id-rdna-unsigned"},
	{OIDMLDSA44, "id-ml-dsa-44"},
	{oidKeyUsage, "keyUsage"},
	{oidBasicConstraints, "basicConstraints"},
	{oidSubjectKeyID, "subjectKeyIdentifier"},
	{asn1.ObjectIdentifier{2, 5, 29, 17}, "subjectAltName"},
	{asn1.ObjectIdentifier{2, 5, 29, 37}, "extKeyUsage"},
	{asn1.ObjectIdentifier{2, 5, 29, 35}, "authorityKeyIdentifier"},
}

// DescribeOID returns the dotted form of oid followed by its name, if it is
// one of the OIDs above, such as
// "1.3.6.1.4.1.44363.47.0 id-alg-mtcProof (draft experimental)".
func DescribeOID(oid asn1.ObjectIdentifier) string {
	for _, n := range oidNames {
		if n.oid.Equal(oid) {
			return oid.String() + " " + n.name
		}
	}
	return oid.String()
}
