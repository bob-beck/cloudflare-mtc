package mtc

import (
	"errors"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

// A SubtreeSignature is a cosignature in an MTCProof.
type SubtreeSignature struct {
	CosignerID TrustAnchorID
	Signature  []byte
}

// An MTCProof is the signatureValue of a Merkle Tree Certificate.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.2.
type MTCProof struct {
	// Extensions is the contents of the MTCLogEntryExtension vector, equal
	// to the log entry's extensions.
	Extensions     []byte
	Start, End     uint64
	InclusionProof []tlog.Hash
	// Signatures are sorted by CompareCosignerIDs, without duplicates.
	// A landmark-relative certificate has none.
	Signatures []SubtreeSignature
}

// MarshalBinary serializes p. It sorts the signatures and rejects duplicate
// cosigner IDs.
func (p *MTCProof) MarshalBinary() ([]byte, error) {
	if p.Start > MaxLogEntries || p.End > MaxLogEntries {
		return nil, errors.New("subtree bounds exceed 48 bits")
	}
	sigs := slices.Clone(p.Signatures)
	slices.SortFunc(sigs, func(a, b SubtreeSignature) int {
		return CompareCosignerIDs(a.CosignerID, b.CosignerID)
	})
	for i := 1; i < len(sigs); i++ {
		if CompareCosignerIDs(sigs[i-1].CosignerID, sigs[i].CosignerID) == 0 {
			return nil, errors.New("duplicate cosigner ID in MTCProof")
		}
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(ext *cryptobyte.Builder) {
		ext.AddBytes(p.Extensions)
	})
	b.AddUint48(p.Start)
	b.AddUint48(p.End)
	b.AddUint16LengthPrefixed(func(proof *cryptobyte.Builder) {
		for _, h := range p.InclusionProof {
			proof.AddBytes(h[:])
		}
	})
	b.AddUint24LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, s := range sigs {
			if len(s.CosignerID) == 0 || len(s.CosignerID) > 255 {
				list.SetError(errors.New("invalid cosigner ID length"))
				return
			}
			list.AddUint8LengthPrefixed(func(id *cryptobyte.Builder) {
				id.AddBytes(s.CosignerID)
			})
			list.AddUint16LengthPrefixed(func(sig *cryptobyte.Builder) {
				sig.AddBytes(s.Signature)
			})
		}
	})
	return b.Bytes()
}

// UnmarshalBinary parses a serialized MTCProof strictly: no trailing data,
// a whole number of hashes in the inclusion proof, and signatures in strictly
// increasing cosigner ID order.
func (p *MTCProof) UnmarshalBinary(data []byte) error {
	*p = MTCProof{}
	s := cryptobyte.String(data)
	var ext, proof, sigs cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ext) ||
		!s.ReadUint48(&p.Start) ||
		!s.ReadUint48(&p.End) ||
		!s.ReadUint16LengthPrefixed(&proof) ||
		!s.ReadUint24LengthPrefixed(&sigs) ||
		!s.Empty() {
		return errors.New("malformed MTCProof")
	}
	if err := checkEntryExtensions(ext); err != nil {
		return err
	}
	p.Extensions = ext
	if len(proof)%tlog.HashSize != 0 {
		return errors.New("MTCProof inclusion proof is not a whole number of hashes")
	}
	for len(proof) > 0 {
		var h tlog.Hash
		copy(h[:], proof)
		p.InclusionProof = append(p.InclusionProof, h)
		proof = proof[tlog.HashSize:]
	}
	for !sigs.Empty() {
		var id, sig cryptobyte.String
		if !sigs.ReadUint8LengthPrefixed(&id) || len(id) == 0 ||
			!sigs.ReadUint16LengthPrefixed(&sig) {
			return errors.New("malformed SubtreeSignature")
		}
		if n := len(p.Signatures); n > 0 &&
			CompareCosignerIDs(p.Signatures[n-1].CosignerID, TrustAnchorID(id)) >= 0 {
			return errors.New("MTCProof signatures are not in increasing cosigner ID order")
		}
		p.Signatures = append(p.Signatures, SubtreeSignature{
			CosignerID: TrustAnchorID(id),
			Signature:  sig,
		})
	}
	return nil
}
