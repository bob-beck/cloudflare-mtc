package mtc

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// A Cosigner is an MTC cosigner holding its private key: a CA cosigner, a
// mirror, or a witness.
//
// Cosigners use ML-DSA-44 and the subtree/v1 cosigned message, which is both
// the MTC signature format (draft-ietf-plants-merkle-tree-certs-06, Section
// 5.3.1) and the ML-DSA-44 cosignature of c2sp.org/tlog-cosignature, as
// c2sp.org/mtc-tlog requires.
type Cosigner struct {
	ID     TrustAnchorID
	Key    *mldsa.PrivateKey
	signer *torchwood.CosignatureSigner
}

// NewCosigner returns a Cosigner with the given ID and ML-DSA-44 key.
func NewCosigner(id TrustAnchorID, key *mldsa.PrivateKey) (*Cosigner, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if key.PublicKey().Parameters() != mldsa.MLDSA44() {
		return nil, errors.New("cosigner key is not ML-DSA-44")
	}
	s, err := torchwood.NewCosignatureSigner(id.OriginString(), key)
	if err != nil {
		return nil, err
	}
	return &Cosigner{ID: id, Key: key, signer: s}, nil
}

// NoteSigner returns the cosigner as a note.Signer, which produces
// timestamped checkpoint cosignatures.
func (c *Cosigner) NoteSigner() *torchwood.CosignatureSigner {
	return c.signer
}

// Public returns the public half of c.
func (c *Cosigner) Public() *CosignerPublic {
	v := c.signer.Verifier()
	return &CosignerPublic{ID: c.ID, Key: c.Key.PublicKey(), verifier: v}
}

// SignSubtree returns the raw ML-DSA-44 signature over the subtree/v1
// cosigned message for subtree [start, end) of log logID, with timestamp
// zero, as it goes in an MTCProof SubtreeSignature.
func (c *Cosigner) SignSubtree(logID TrustAnchorID, start, end uint64, hash tlog.Hash) ([]byte, error) {
	line, err := c.signer.SignSubtree(logID.OriginString(), int64(start), int64(end), hash)
	if err != nil {
		return nil, err
	}
	return RawSubtreeSignature(string(line), c.ID)
}

// RawSubtreeSignature extracts the raw signature from a note signature line
// "— <name> base64(key hash || timestamp || signature)\n" as returned by a
// tlog-witness sign-subtree call. The timestamp must be zero and the name
// must be the cosigner name of id.
func RawSubtreeSignature(line string, id TrustAnchorID) ([]byte, error) {
	line, ok := strings.CutSuffix(line, "\n")
	if !ok {
		return nil, errors.New("signature line does not end in a newline")
	}
	line, ok = strings.CutPrefix(line, "— ")
	if !ok {
		return nil, errors.New("malformed signature line")
	}
	name, b64, _ := strings.Cut(line, " ")
	if name != id.OriginString() {
		return nil, fmt.Errorf("signature line is from %q, not %q", name, id.OriginString())
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sig) != 4+8+mldsa.MLDSA44SignatureSize {
		return nil, errors.New("malformed subtree signature")
	}
	if binary.BigEndian.Uint64(sig[4:]) != 0 {
		return nil, errors.New("subtree signature has a nonzero timestamp")
	}
	return sig[12:], nil
}

// A CosignerPublic is a cosigner's ID and public key.
type CosignerPublic struct {
	ID       TrustAnchorID
	Key      *mldsa.PublicKey
	verifier *torchwood.CosignatureVerifier
}

// NewCosignerPublic returns the public cosigner with the given ID and key.
func NewCosignerPublic(id TrustAnchorID, key crypto.PublicKey) (*CosignerPublic, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	k, ok := key.(*mldsa.PublicKey)
	if !ok || k.Parameters() != mldsa.MLDSA44() {
		return nil, errors.New("cosigner key is not ML-DSA-44")
	}
	v, err := torchwood.NewCosignatureVerifierFromKey(id.OriginString(), k)
	if err != nil {
		return nil, err
	}
	return &CosignerPublic{ID: id, Key: k, verifier: v}, nil
}

// NoteVerifier returns the cosigner as a note.Verifier for checkpoint
// cosignatures.
func (c *CosignerPublic) NoteVerifier() *torchwood.CosignatureVerifier {
	return c.verifier
}

// VerifySubtree reports whether sig is a valid raw signature by c over
// subtree [start, end) of log logID with the given hash, timestamp zero.
func (c *CosignerPublic) VerifySubtree(logID TrustAnchorID, start, end uint64, hash tlog.Hash, sig []byte) bool {
	if len(sig) != mldsa.MLDSA44SignatureSize {
		return false
	}
	raw := make([]byte, 0, 12+len(sig))
	raw = binary.BigEndian.AppendUint32(raw, c.verifier.KeyHash())
	raw = binary.BigEndian.AppendUint64(raw, 0)
	raw = append(raw, sig...)
	line := "— " + c.ID.OriginString() + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
	return c.verifier.VerifySubtree(logID.OriginString(), int64(start), int64(end), hash, []byte(line))
}

// GenerateCosignerKey returns a new random ML-DSA-44 key.
func GenerateCosignerKey() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA44())
}

// MarshalPrivateKeyPEM encodes an ML-DSA private key as a PKCS#8 PEM block.
func MarshalPrivateKeyPEM(key *mldsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM parses a PKCS#8 PEM ML-DSA-44 private key.
func ParsePrivateKeyPEM(data []byte) (*mldsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := key.(*mldsa.PrivateKey)
	if !ok || k.PublicKey().Parameters() != mldsa.MLDSA44() {
		return nil, errors.New("private key is not ML-DSA-44")
	}
	return k, nil
}

// LoadPrivateKeyFile reads a PKCS#8 PEM ML-DSA-44 private key from a file.
func LoadPrivateKeyFile(path string) (*mldsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}
