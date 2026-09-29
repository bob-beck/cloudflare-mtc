package mtc

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/mod/sumdb/tlog"
)

// A TrustedCA is an MTC CA as configured at a relying party.
type TrustedCA struct {
	ID TrustAnchorID

	// Cosigner is the CA cosigner.
	Cosigner *CosignerPublic

	// MinSerial and MaxSerial bound the serial numbers the relying party
	// accepts from this CA.
	MinSerial, MaxSerial uint64

	// PrefixURL is the c2sp.org/mtc-tlog CA prefix URL, if the CA
	// certificate carries one.
	PrefixURL string
}

// ParseCACertificate parses an MTC CA certificate: its subject is the CA ID,
// its key the CA cosigner key, and its critical
// id-pe-mtcCertificationAuthority-SHA256 extension holds the serial range.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 5.5.
func ParseCACertificate(der []byte) (*TrustedCA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	id, err := ParseTrustAnchorIDName(cert.RawSubject)
	if err != nil {
		return nil, fmt.Errorf("CA certificate subject: %w", err)
	}
	cosigner, err := NewCosignerPublic(id, cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("CA certificate key: %w", err)
	}
	ca := &TrustedCA{ID: id, Cosigner: cosigner}
	found := false
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(OIDMTCCertificationAuthoritySHA256):
			if !ext.Critical {
				return nil, errors.New("MTC CA extension is not critical")
			}
			v := cryptobyte.String(ext.Value)
			var seq, alg cryptobyte.String
			if !v.ReadASN1(&seq, cbasn1.SEQUENCE) || !v.Empty() ||
				!seq.ReadASN1(&alg, cbasn1.SEQUENCE) ||
				!seq.ReadASN1Integer(&ca.MinSerial) ||
				!seq.ReadASN1Integer(&ca.MaxSerial) || !seq.Empty() {
				return nil, errors.New("malformed MTC CA extension")
			}
			if ca.MinSerial < 1<<48 || ca.MaxSerial < ca.MinSerial {
				return nil, errors.New("invalid serial range in MTC CA extension")
			}
			found = true
		case ext.Id.Equal(OIDMTCTlogPrefixURL):
			v := cryptobyte.String(ext.Value)
			var s cryptobyte.String
			if !v.ReadASN1(&s, cbasn1.IA5String) || !v.Empty() {
				return nil, errors.New("malformed mtc-tlog prefix URL extension")
			}
			ca.PrefixURL = string(s)
		}
	}
	if !found {
		return nil, errors.New("certificate has no MTC CA extension")
	}
	return ca, nil
}

// ParseCosignerCertificate parses a certificate of the form written by
// MarshalCosignerCertificate.
func ParseCosignerCertificate(der []byte) (*CosignerPublic, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDMTCCertificationAuthoritySHA256) {
			return nil, errors.New("certificate is a CA certificate, not a cosigner certificate")
		}
	}
	id, err := ParseTrustAnchorIDName(cert.RawSubject)
	if err != nil {
		return nil, err
	}
	return NewCosignerPublic(id, cert.PublicKey)
}

// A TrustedSubtree is a subtree hash a relying party has obtained out of
// band, typically a landmark subtree.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 7.4.
type TrustedSubtree struct {
	CAID      TrustAnchorID
	LogNumber uint16
	Subtree
	Hash tlog.Hash
}

// A RevokedRange is a revoked range [Start, End) of serial numbers.
type RevokedRange struct {
	CAID       TrustAnchorID
	Start, End uint64
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	CAs             []*TrustedCA
	Cosigners       []*CosignerPublic
	TrustedSubtrees []TrustedSubtree
	Revoked         []RevokedRange

	// Quorum is the number of valid signatures from Cosigners, in addition
	// to the CA cosigner's, that a certificate needs when it does not match
	// a trusted subtree.
	Quorum int

	// CurrentTime is the time at which the validity period is checked. If
	// zero, the current time is used.
	CurrentTime time.Time
}

// VerifyResult describes a verified certificate.
type VerifyResult struct {
	CA        *TrustedCA
	LogNumber uint16
	Index     uint64
	Proof     *MTCProof
	Subtree   Subtree
	// TrustedSubtree reports whether the certificate matched a trusted
	// subtree; otherwise it was accepted on its signatures.
	TrustedSubtree bool
	// Cosigners are the IDs of the cosigners whose valid signatures were
	// counted.
	Cosigners []TrustAnchorID
}

// Verify checks the MTCProof of an MTC certificate and its validity period.
// It does not check anything else, such as names or key usage.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 7.2.
func Verify(der []byte, opts *VerifyOptions) (*VerifyResult, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return nil, err
	}

	// Step 1: both signature algorithms are id-alg-mtcProof with absent
	// parameters.
	outerAlg, sigValue, err := certificateSignature(der)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(outerAlg, mtcProofAlgorithmIdentifier) ||
		!bytes.Equal(tbs.Signature, mtcProofAlgorithmIdentifier) {
		return nil, errors.New("signature algorithm is not id-alg-mtcProof")
	}

	// Step 2: parse the MTCProof.
	var proof MTCProof
	if err := proof.UnmarshalBinary(sigValue); err != nil {
		return nil, err
	}

	// Steps 3-6: serial number, revocation, log ID.
	serial, err := tbs.SerialUint64()
	if err != nil {
		return nil, err
	}
	caID, err := ParseTrustAnchorIDName(tbs.Issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	var ca *TrustedCA
	for _, c := range opts.CAs {
		if c.ID.Equal(caID) {
			ca = c
		}
	}
	if ca == nil {
		return nil, fmt.Errorf("unknown MTC CA %s", caID)
	}
	if serial < ca.MinSerial || serial > ca.MaxSerial {
		return nil, errors.New("serial number is outside the CA's range")
	}
	for _, r := range opts.Revoked {
		if r.CAID.Equal(caID) && r.Start <= serial && serial < r.End {
			return nil, errors.New("certificate is revoked")
		}
	}
	index := serial & MaxLogEntries
	logNumber := uint16(serial >> 48)
	if logNumber == 0 {
		return nil, errors.New("log number is zero")
	}
	logID := LogID(caID, logNumber)

	// Steps 7-10: rebuild the log entry and evaluate the inclusion proof.
	entry, err := tbs.LogEntry(proof.Extensions)
	if err != nil {
		return nil, err
	}
	if proof.Start > index || index >= proof.End {
		return nil, errors.New("serial number is outside the proof's subtree")
	}
	subtreeHash, err := evaluateInclusionProof(proof.InclusionProof, proof.Start, proof.End, index, EntryHash(entry))
	if err != nil {
		return nil, err
	}

	res := &VerifyResult{
		CA:        ca,
		LogNumber: logNumber,
		Index:     index,
		Proof:     &proof,
		Subtree:   Subtree{proof.Start, proof.End},
	}

	// Step 11: a trusted subtree.
	matched := false
	for _, ts := range opts.TrustedSubtrees {
		if ts.CAID.Equal(caID) && ts.LogNumber == logNumber &&
			ts.Start == proof.Start && ts.End == proof.End {
			if ts.Hash != subtreeHash {
				return nil, errors.New("subtree hash does not match the trusted subtree")
			}
			matched = true
			res.TrustedSubtree = true
		}
	}

	// Step 12: cosignatures. The CA cosigner is always required.
	if !matched {
		caSigned := false
		others := 0
		for _, sig := range proof.Signatures {
			var c *CosignerPublic
			if sig.CosignerID.Equal(caID) {
				c = ca.Cosigner
			} else {
				for _, o := range opts.Cosigners {
					if o.ID.Equal(sig.CosignerID) {
						c = o
					}
				}
			}
			if c == nil || !c.VerifySubtree(logID, proof.Start, proof.End, subtreeHash, sig.Signature) {
				continue
			}
			res.Cosigners = append(res.Cosigners, c.ID)
			if c == ca.Cosigner {
				caSigned = true
			} else {
				others++
			}
		}
		if !caSigned {
			return nil, errors.New("no valid CA cosignature")
		}
		if others < opts.Quorum {
			return nil, fmt.Errorf("%d valid cosignatures, need %d", others, opts.Quorum)
		}
	}

	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("certificate is not valid at the current time")
	}
	return res, nil
}

// certificateSignature returns the DER signatureAlgorithm and the
// signatureValue bytes of a certificate, requiring a whole number of octets.
func certificateSignature(der []byte) (alg, value []byte, err error) {
	s := cryptobyte.String(der)
	var cert, tbs, algS cryptobyte.String
	var bits cryptobyte.String
	if !s.ReadASN1(&cert, cbasn1.SEQUENCE) || !s.Empty() ||
		!cert.ReadASN1Element(&tbs, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&algS, cbasn1.SEQUENCE) ||
		!cert.ReadASN1(&bits, cbasn1.BIT_STRING) || !cert.Empty() {
		return nil, nil, errors.New("malformed certificate")
	}
	if len(bits) == 0 || bits[0] != 0 {
		return nil, nil, errors.New("signatureValue is not a whole number of octets")
	}
	return algS, bits[1:], nil
}

// evaluateInclusionProof runs a subtree inclusion proof and returns the
// implied subtree hash.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 4.3.2.
func evaluateInclusionProof(proof []tlog.Hash, start, end, index uint64, entryHash tlog.Hash) (tlog.Hash, error) {
	if !torchwood.ValidSubtree(int64(start), int64(end)) || start == end {
		return tlog.Hash{}, errors.New("invalid subtree in MTCProof")
	}
	fn := index - start
	sn := end - start - 1
	r := entryHash
	for _, p := range proof {
		if sn == 0 {
			return tlog.Hash{}, errors.New("inclusion proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			r = tlog.NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = tlog.NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return tlog.Hash{}, errors.New("inclusion proof is too short")
	}
	return r, nil
}
