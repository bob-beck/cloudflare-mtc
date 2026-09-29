package mtc

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
)

// A Landmark is an agreed-upon tree size of an issuance log.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.4.1.
type Landmark struct {
	// Number is the landmark number. Landmark 0 has tree size 0 and is never
	// active.
	Number uint64

	// TreeSize is the tree size of the landmark; tree sizes strictly
	// increase with the landmark number.
	TreeSize uint64

	// Expiry is the time, in POSIX seconds, after which the landmark is no
	// longer active. It is at least the notAfter of every entry below
	// TreeSize.
	Expiry int64
}

// Active reports whether l is active at time now.
func (l *Landmark) Active(now time.Time) bool {
	return l.Number != 0 && now.Unix() <= l.Expiry
}

// A Subtree is a subtree [Start, End) of an issuance log.
type Subtree struct {
	Start, End uint64
}

// Empty reports whether s contains no entries.
func (s Subtree) Empty() bool { return s.Start == s.End }

// Contains reports whether index is in s.
func (s Subtree) Contains(index uint64) bool {
	return s.Start <= index && index < s.End
}

// FindSubtrees returns the two subtrees that cover [start, end), per
// draft-ietf-plants-merkle-tree-certs-06, Section 4.5.1. The second may be
// empty.
func FindSubtrees(start, end uint64) (Subtree, Subtree, error) {
	leftStart, mid, err := torchwood.CoverInterval(int64(start), int64(end))
	if err != nil {
		return Subtree{}, Subtree{}, err
	}
	return Subtree{uint64(leftStart), uint64(mid)}, Subtree{uint64(mid), end}, nil
}

// LandmarkSubtrees returns the two subtrees of landmark l, given the tree size
// of the previous landmark.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.4.2.
func LandmarkSubtrees(prevTreeSize, treeSize uint64) (Subtree, Subtree, error) {
	if prevTreeSize > treeSize {
		return Subtree{}, Subtree{}, errors.New("landmark tree sizes decrease")
	}
	return FindSubtrees(prevTreeSize, treeSize)
}

// MarshalLandmarks returns the published form of a landmark sequence: the
// latest landmark number, then one line per landmark, newest first, with its
// tree size and expiry, down to and including the first landmark that has
// expired at time now. landmarks is ordered oldest first and must start at
// landmark 0.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.4.3.
func MarshalLandmarks(landmarks []Landmark, now time.Time) ([]byte, error) {
	if err := checkLandmarkSequence(landmarks); err != nil {
		return nil, err
	}
	latest := landmarks[len(landmarks)-1]
	var b bytes.Buffer
	fmt.Fprintf(&b, "%d\n", latest.Number)
	for i := len(landmarks) - 1; i >= 0; i-- {
		l := landmarks[i]
		fmt.Fprintf(&b, "%d %d\n", l.TreeSize, l.Expiry)
		if !l.Active(now) {
			break
		}
	}
	return b.Bytes(), nil
}

func checkLandmarkSequence(landmarks []Landmark) error {
	if len(landmarks) == 0 || landmarks[0] != (Landmark{}) {
		return errors.New("landmark sequence must start with landmark 0")
	}
	for i := 1; i < len(landmarks); i++ {
		prev, l := landmarks[i-1], landmarks[i]
		if l.Number != prev.Number+1 {
			return errors.New("landmark numbers are not consecutive")
		}
		if l.TreeSize <= prev.TreeSize {
			return errors.New("landmark tree sizes do not strictly increase")
		}
		if l.Expiry < prev.Expiry {
			return errors.New("landmark expiries decrease")
		}
		if l.TreeSize > MaxLogEntries {
			return errors.New("landmark tree size exceeds the maximum log size")
		}
	}
	return nil
}

// ParseLandmarks parses the published form of a landmark sequence. It
// returns the landmarks it lists, newest first, including the final expired
// one. It checks that tree sizes strictly decrease and expiries do not
// increase, and that the list ends in a landmark that has expired at time
// now or in landmark 0.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 6.4.3.
func ParseLandmarks(data []byte, now time.Time) ([]Landmark, error) {
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("landmarks: missing final newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	latest, err := parseDecimal(lines[0])
	if err != nil || latest > MaxLogEntries {
		return nil, fmt.Errorf("landmarks: invalid latest landmark %q", lines[0])
	}
	var out []Landmark
	for i, line := range lines[1:] {
		if uint64(i) > latest {
			return nil, errors.New("landmarks: more lines than landmarks")
		}
		sizeText, expiryText, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("landmarks: malformed line %q", line)
		}
		size, err1 := parseDecimal(sizeText)
		expiry, err2 := parseDecimal(expiryText)
		if err1 != nil || err2 != nil || size > MaxLogEntries || expiry > 1<<63-1 {
			return nil, fmt.Errorf("landmarks: malformed line %q", line)
		}
		l := Landmark{Number: latest - uint64(i), TreeSize: size, Expiry: int64(expiry)}
		if n := len(out); n > 0 {
			if l.TreeSize >= out[n-1].TreeSize {
				return nil, errors.New("landmarks: tree sizes do not strictly decrease")
			}
			if l.Expiry > out[n-1].Expiry {
				return nil, errors.New("landmarks: expiries increase")
			}
		}
		out = append(out, l)
		if !l.Active(now) {
			if i != len(lines)-2 {
				return nil, errors.New("landmarks: lines after the expired landmark")
			}
			return out, nil
		}
	}
	return nil, errors.New("landmarks: no expired landmark")
}

func parseDecimal(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number %q", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}
