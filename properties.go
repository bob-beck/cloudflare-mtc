package mtc

import (
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Certificate property types.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 7.
const (
	PropertyTrustAnchorID          = 0
	PropertyTrustAnchorGroups      = 1
	PropertyTrustAnchorNegotiation = 2
)

// PEMTypeCertificateProperties is the PEM label of a serialized
// CertificatePropertyList.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 7.4.
const PEMTypeCertificateProperties = "CERTIFICATE PROPERTIES"

// A CertificatePropertyList holds the certificate properties of a
// certification path.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 7.
type CertificatePropertyList struct {
	// TrustAnchorID is the trust_anchor_id property, if non-empty.
	TrustAnchorID TrustAnchorID

	// TrustAnchorGroups is the trust_anchor_groups property, if non-empty.
	TrustAnchorGroups []TrustAnchorIDPattern

	// TrustAnchorNegotiation is the trust_anchor_negotiation property.
	TrustAnchorNegotiation bool
}

// MarshalBinary returns the serialized CertificatePropertyList.
func (l *CertificatePropertyList) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(props *cryptobyte.Builder) {
		if len(l.TrustAnchorID) != 0 {
			props.AddUint16(PropertyTrustAnchorID)
			props.AddUint16LengthPrefixed(func(data *cryptobyte.Builder) {
				data.AddBytes(l.TrustAnchorID)
			})
		}
		if len(l.TrustAnchorGroups) != 0 {
			props.AddUint16(PropertyTrustAnchorGroups)
			props.AddUint16LengthPrefixed(func(data *cryptobyte.Builder) {
				data.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
					for _, p := range l.TrustAnchorGroups {
						pb, err := p.MarshalBinary()
						if err != nil {
							list.SetError(err)
							return
						}
						list.AddUint8LengthPrefixed(func(pattern *cryptobyte.Builder) {
							pattern.AddBytes(pb)
						})
					}
				})
			})
		}
		if l.TrustAnchorNegotiation {
			props.AddUint16(PropertyTrustAnchorNegotiation)
			props.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {})
		}
	})
	return b.Bytes()
}

// UnmarshalBinary parses a serialized CertificatePropertyList. Properties
// must be sorted by type without duplicates; unknown types are ignored.
func (l *CertificatePropertyList) UnmarshalBinary(data []byte) error {
	*l = CertificatePropertyList{}
	s := cryptobyte.String(data)
	var props cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&props) || !s.Empty() {
		return errors.New("malformed certificate property list")
	}
	first := true
	var last uint16
	for !props.Empty() {
		var typ uint16
		var value cryptobyte.String
		if !props.ReadUint16(&typ) || !props.ReadUint16LengthPrefixed(&value) {
			return errors.New("malformed certificate property")
		}
		if !first && typ <= last {
			return errors.New("certificate properties are not sorted or contain duplicates")
		}
		first, last = false, typ
		switch typ {
		case PropertyTrustAnchorID:
			id := TrustAnchorID(append([]byte(nil), value...))
			if err := id.Validate(); err != nil {
				return fmt.Errorf("trust_anchor_id property: %w", err)
			}
			l.TrustAnchorID = id
		case PropertyTrustAnchorGroups:
			var list cryptobyte.String
			if !value.ReadUint16LengthPrefixed(&list) || !value.Empty() || list.Empty() {
				return errors.New("malformed trust_anchor_groups property")
			}
			for !list.Empty() {
				var pb cryptobyte.String
				if !list.ReadUint8LengthPrefixed(&pb) {
					return errors.New("malformed trust_anchor_groups property")
				}
				var p TrustAnchorIDPattern
				if err := p.UnmarshalBinary(pb); err != nil {
					return fmt.Errorf("trust_anchor_groups property: %w", err)
				}
				l.TrustAnchorGroups = append(l.TrustAnchorGroups, p)
			}
		case PropertyTrustAnchorNegotiation:
			if !value.Empty() {
				return errors.New("trust_anchor_negotiation property is not empty")
			}
			l.TrustAnchorNegotiation = true
		}
	}
	return nil
}

// EncodePEMChainWithProperties returns a certification path in the
// application/pem-certificate-chain-with-properties format: a CERTIFICATE
// PROPERTIES block followed by each certificate, end-entity first, without
// the trust anchor.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 7.4.
func EncodePEMChainWithProperties(props *CertificatePropertyList, chain ...[]byte) ([]byte, error) {
	pb, err := props.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificateProperties, Bytes: pb})
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out, nil
}

// StandaloneProperties returns the certificate properties of a standalone
// certificate issued by the CA caID: the CA's trust anchor ID and the group
// caID.2.{0-}.{0-}.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 8.2.1.
func StandaloneProperties(caID TrustAnchorID) (*CertificatePropertyList, error) {
	group, err := ExactPattern(caID,
		PatternRange{Min: 2, Max: 2},
		PatternRange{Min: 0, Infinite: true},
		PatternRange{Min: 0, Infinite: true})
	if err != nil {
		return nil, err
	}
	return &CertificatePropertyList{
		TrustAnchorID:     caID,
		TrustAnchorGroups: []TrustAnchorIDPattern{group},
	}, nil
}

// LandmarkProperties returns the certificate properties of a
// landmark-relative certificate for landmark L of log N: the landmark's
// trust anchor ID, the group caID.2.N.{L-}, and trust_anchor_negotiation.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 8.2.1.
func LandmarkProperties(caID TrustAnchorID, logNumber uint16, landmark uint64) (*CertificatePropertyList, error) {
	group, err := ExactPattern(caID,
		PatternRange{Min: 2, Max: 2},
		PatternRange{Min: uint64(logNumber), Max: uint64(logNumber)},
		PatternRange{Min: landmark, Infinite: true})
	if err != nil {
		return nil, err
	}
	return &CertificatePropertyList{
		TrustAnchorID:          LandmarkID(caID, logNumber, landmark),
		TrustAnchorGroups:      []TrustAnchorIDPattern{group},
		TrustAnchorNegotiation: true,
	}, nil
}
