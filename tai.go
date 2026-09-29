package mtc

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// A TrustAnchorID is a trust anchor identifier in its binary representation:
// the contents octets of a RELATIVE-OID relative to 1.3.6.1.4.1, i.e. the
// base-128 encoding of each component, concatenated.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 4.
type TrustAnchorID []byte

// ParseTrustAnchorID parses the ASCII representation of a trust anchor ID,
// such as "32473.1".
func ParseTrustAnchorID(s string) (TrustAnchorID, error) {
	if s == "" {
		return nil, errors.New("empty trust anchor ID")
	}
	var id TrustAnchorID
	for _, part := range strings.Split(s, ".") {
		v, err := parseComponent(part)
		if err != nil {
			return nil, fmt.Errorf("trust anchor ID %q: %w", s, err)
		}
		id = appendBase128(id, v)
	}
	if len(id) > 255 {
		return nil, fmt.Errorf("trust anchor ID %q is longer than 255 bytes", s)
	}
	return id, nil
}

// MustParseTrustAnchorID is like ParseTrustAnchorID but panics on error.
func MustParseTrustAnchorID(s string) TrustAnchorID {
	id, err := ParseTrustAnchorID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// parseComponent parses a decimal component with no sign and no leading
// zeros.
func parseComponent(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("invalid component %q", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid component %q", s)
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid component %q", s)
	}
	return v, nil
}

// appendBase128 appends the minimal base-128 encoding of v (X.690, Section
// 8.20.2) to b.
func appendBase128(b []byte, v uint64) []byte {
	var tmp [10]byte
	i := len(tmp) - 1
	tmp[i] = byte(v & 0x7f)
	for v >>= 7; v != 0; v >>= 7 {
		i--
		tmp[i] = byte(v&0x7f) | 0x80
	}
	return append(b, tmp[i:]...)
}

// readBase128 reads one minimal base-128 value from b.
func readBase128(b []byte) (v uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, nil, errors.New("truncated base-128 value")
	}
	if b[0] == 0x80 {
		return 0, nil, errors.New("non-minimal base-128 value")
	}
	for i, c := range b {
		if v > math.MaxUint64>>7 {
			return 0, nil, errors.New("base-128 value overflows 64 bits")
		}
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("truncated base-128 value")
}

// Components returns the components of id.
func (id TrustAnchorID) Components() ([]uint64, error) {
	if len(id) == 0 {
		return nil, errors.New("empty trust anchor ID")
	}
	var out []uint64
	rest := []byte(id)
	for len(rest) > 0 {
		var v uint64
		var err error
		v, rest, err = readBase128(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// String returns the ASCII representation of id, such as "32473.1".
func (id TrustAnchorID) String() string {
	comps, err := id.Components()
	if err != nil {
		return fmt.Sprintf("<invalid trust anchor ID %x>", []byte(id))
	}
	parts := make([]string, len(comps))
	for i, c := range comps {
		parts[i] = strconv.FormatUint(c, 10)
	}
	return strings.Join(parts, ".")
}

// Validate checks that id is a well-formed binary trust anchor ID.
func (id TrustAnchorID) Validate() error {
	if len(id) > 255 {
		return errors.New("trust anchor ID is longer than 255 bytes")
	}
	_, err := id.Components()
	return err
}

// Child returns id with the given components appended.
func (id TrustAnchorID) Child(components ...uint64) TrustAnchorID {
	out := append(TrustAnchorID(nil), id...)
	for _, c := range components {
		out = appendBase128(out, c)
	}
	return out
}

// Equal reports whether id and other are the same trust anchor ID.
func (id TrustAnchorID) Equal(other TrustAnchorID) bool {
	return bytes.Equal(id, other)
}

// OriginString returns the representation of id used as a checkpoint origin
// and cosigner name: "oid/1.3.6.1.4.1." followed by the ASCII
// representation.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 5.3.1, and
// c2sp.org/mtc-tlog.
func (id TrustAnchorID) OriginString() string {
	return "oid/1.3.6.1.4.1." + id.String()
}

// CompareCosignerIDs orders trust anchor IDs as required for MTCProof
// signatures: shorter first, then lexicographically.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.2.
func CompareCosignerIDs(a, b TrustAnchorID) int {
	return cmp.Or(cmp.Compare(len(a), len(b)), bytes.Compare(a, b))
}

// LogID returns the log ID {caID logs(0) N} of log number logNumber.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 5.2.
func LogID(caID TrustAnchorID, logNumber uint16) TrustAnchorID {
	return caID.Child(0, uint64(logNumber))
}

// LandmarkID returns the trust anchor ID {caID landmarks(1) N L} of landmark
// L of log N.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 8.2.
func LandmarkID(caID TrustAnchorID, logNumber uint16, landmark uint64) TrustAnchorID {
	return caID.Child(1, uint64(logNumber), landmark)
}

// LandmarkGroupID returns the trust anchor ID {caID landmarkGroups(2) N L}
// that a relying party sends when its latest trusted landmark of log N is L.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 8.2.1.
func LandmarkGroupID(caID TrustAnchorID, logNumber uint16, landmark uint64) TrustAnchorID {
	return caID.Child(2, uint64(logNumber), landmark)
}

// A PatternRange is one component of a TrustAnchorIDPattern: the inclusive
// range [Min, Max], where Infinite means there is no upper bound.
type PatternRange struct {
	Min, Max uint64
	Infinite bool
}

// A TrustAnchorIDPattern matches trust anchor IDs with the same number of
// components, each within the corresponding range.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 5.3.1.
type TrustAnchorIDPattern []PatternRange

// ParseTrustAnchorIDPattern parses the text form of a pattern, in which each
// dot-separated component is "v", "{min-max}" or "{min-}". For example
// "32473.1.2.{0-}.{0-}".
func ParseTrustAnchorIDPattern(s string) (TrustAnchorIDPattern, error) {
	if s == "" {
		return nil, errors.New("empty trust anchor ID pattern")
	}
	var p TrustAnchorIDPattern
	for _, part := range strings.Split(s, ".") {
		inner, ok := strings.CutPrefix(part, "{")
		if !ok {
			v, err := parseComponent(part)
			if err != nil {
				return nil, fmt.Errorf("pattern %q: %w", s, err)
			}
			p = append(p, PatternRange{Min: v, Max: v})
			continue
		}
		inner, ok = strings.CutSuffix(inner, "}")
		lo, hi, ok2 := strings.Cut(inner, "-")
		if !ok || !ok2 {
			return nil, fmt.Errorf("pattern %q: invalid component %q", s, part)
		}
		minV, err := parseComponent(lo)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", s, err)
		}
		if hi == "" {
			p = append(p, PatternRange{Min: minV, Infinite: true})
			continue
		}
		maxV, err := parseComponent(hi)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", s, err)
		}
		if maxV < minV {
			return nil, fmt.Errorf("pattern %q: empty range %q", s, part)
		}
		p = append(p, PatternRange{Min: minV, Max: maxV})
	}
	return p, nil
}

// String returns the text form of p.
func (p TrustAnchorIDPattern) String() string {
	parts := make([]string, len(p))
	for i, r := range p {
		switch {
		case r.Infinite:
			parts[i] = fmt.Sprintf("{%d-}", r.Min)
		case r.Min == r.Max:
			parts[i] = strconv.FormatUint(r.Min, 10)
		default:
			parts[i] = fmt.Sprintf("{%d-%d}", r.Min, r.Max)
		}
	}
	return strings.Join(parts, ".")
}

// MarshalBinary returns the binary form of p: for each component, the
// base-128 minimum followed by the base-128 maximum, with the single byte
// 0x80 standing for an infinite maximum.
//
// See draft-ietf-tls-trust-anchor-ids-05, Section 5.3.1.
func (p TrustAnchorIDPattern) MarshalBinary() ([]byte, error) {
	var b []byte
	for _, r := range p {
		b = appendBase128(b, r.Min)
		if r.Infinite {
			b = append(b, 0x80)
		} else {
			b = appendBase128(b, r.Max)
		}
	}
	if len(b) > 255 {
		return nil, errors.New("trust anchor ID pattern is longer than 255 bytes")
	}
	return b, nil
}

// UnmarshalBinary parses the binary form of a pattern.
func (p *TrustAnchorIDPattern) UnmarshalBinary(b []byte) error {
	var out TrustAnchorIDPattern
	for len(b) > 0 {
		var r PatternRange
		var err error
		if b[0] == 0x80 {
			return errors.New("pattern minimum cannot be infinite")
		}
		r.Min, b, err = readBase128(b)
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return errors.New("truncated pattern")
		}
		if b[0] == 0x80 {
			r.Infinite = true
			b = b[1:]
		} else {
			r.Max, b, err = readBase128(b)
			if err != nil {
				return err
			}
		}
		out = append(out, r)
	}
	*p = out
	return nil
}

// Contains reports whether id matches p.
func (p TrustAnchorIDPattern) Contains(id TrustAnchorID) bool {
	comps, err := id.Components()
	if err != nil || len(comps) != len(p) {
		return false
	}
	for i, c := range comps {
		if c < p[i].Min || (!p[i].Infinite && c > p[i].Max) {
			return false
		}
	}
	return true
}

// ExactPattern returns the pattern that matches exactly id, with further
// components appended.
func ExactPattern(id TrustAnchorID, more ...PatternRange) (TrustAnchorIDPattern, error) {
	comps, err := id.Components()
	if err != nil {
		return nil, err
	}
	var p TrustAnchorIDPattern
	for _, c := range comps {
		p = append(p, PatternRange{Min: c, Max: c})
	}
	return append(p, more...), nil
}
