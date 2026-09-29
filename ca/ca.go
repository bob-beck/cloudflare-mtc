// Package ca implements a Merkle Tree Certificate CA following
// draft-ietf-plants-merkle-tree-certs-06, serving its issuance log as a tiled
// transparency log per c2sp.org/mtc-tlog.
package ca

import (
	"crypto/mldsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/internal/tlogstore"
	"github.com/nightlyone/lockfile"
	"golang.org/x/mod/sumdb/tlog"
)

// Config is the CA configuration, stored as config.json in the CA directory.
type Config struct {
	// ID is the CA ID in ASCII form, e.g. "32473.1".
	ID string `json:"id"`

	// LogNumber is the current issuance log.
	LogNumber uint16 `json:"log_number"`

	// PrefixURL is the c2sp.org/mtc-tlog CA prefix URL. The log is served
	// at <PrefixURL>/<log number>.
	PrefixURL string `json:"prefix_url,omitempty"`

	// MaxLifetime bounds the validity period of issued certificates, and
	// sets how long landmarks stay active.
	MaxLifetime Duration `json:"max_lifetime"`

	// LandmarkInterval is time_between_landmarks
	// (draft-ietf-plants-merkle-tree-certs-06, Section 6.4.2).
	LandmarkInterval Duration `json:"landmark_interval"`

	// MinSerial and MaxSerial are written in the CA certificate.
	MinSerial uint64 `json:"min_serial"`
	MaxSerial uint64 `json:"max_serial"`

	// Mirrors are c2sp.org/tlog-mirror mirrors that the CA pushes its log
	// to and whose subtree cosignatures go in standalone certificates.
	Mirrors []MirrorConfig `json:"mirrors,omitempty"`
}

// MirrorConfig configures a mirror the CA uploads to.
type MirrorConfig struct {
	// SubmissionPrefix is the mirror's submission prefix URL.
	SubmissionPrefix string `json:"submission_prefix"`

	// CosignerCert is the path, relative to the CA directory, of the
	// mirror's cosigner certificate (see mtc.MarshalCosignerCertificate).
	CosignerCert string `json:"cosigner_cert"`

	// Required makes issuance fail if the mirror does not cosign.
	Required bool `json:"required,omitempty"`
}

// Duration is a time.Duration that marshals as a string such as "168h".
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// A CA is an open CA directory.
type CA struct {
	dir      string
	config   Config
	id       mtc.TrustAnchorID
	cosigner *mtc.Cosigner
	store    *tlogstore.Store
	lock     lockfile.Lockfile
	mirrors  []*mirrorClient
}

// NewOpts are the options for New.
type NewOpts struct {
	ID               string
	LogNumber        uint16
	PrefixURL        string
	MaxLifetime      time.Duration
	LandmarkInterval time.Duration
}

// New creates a CA in dir, which must not exist yet: a fresh ML-DSA-44 CA
// cosigner key, the configuration, and the CA certificate.
func New(dir string, opts NewOpts) (*CA, error) {
	id, err := mtc.ParseTrustAnchorID(opts.ID)
	if err != nil {
		return nil, err
	}
	if opts.LogNumber == 0 {
		opts.LogNumber = 1
	}
	if opts.MaxLifetime == 0 {
		opts.MaxLifetime = 7 * 24 * time.Hour
	}
	if opts.LandmarkInterval == 0 {
		opts.LandmarkInterval = time.Hour
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	key, err := mtc.GenerateCosignerKey()
	if err != nil {
		return nil, err
	}
	keyPEM, err := mtc.MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), keyPEM, 0o400); err != nil {
		return nil, err
	}
	cfg := Config{
		ID:               id.String(),
		LogNumber:        opts.LogNumber,
		PrefixURL:        strings.TrimSuffix(opts.PrefixURL, "/"),
		MaxLifetime:      Duration{opts.MaxLifetime},
		LandmarkInterval: Duration{opts.LandmarkInterval},
		MinSerial:        mtc.Serial(opts.LogNumber, 0),
		MaxSerial:        1<<64 - 1,
	}
	if err := writeJSON(filepath.Join(dir, "config.json"), &cfg); err != nil {
		return nil, err
	}
	for _, d := range []string{"queue", "state", "certs", "www"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	ca, err := Open(dir)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert, err := ca.caCertificate(now, now.AddDate(10, 0, 0))
	if err != nil {
		ca.Close()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca-cert.pem"), cert, 0o644); err != nil {
		ca.Close()
		return nil, err
	}
	if err := tlogstore.WriteFile(filepath.Join(dir, "www", "ca-cert.pem"), cert); err != nil {
		ca.Close()
		return nil, err
	}
	return ca, nil
}

// Open opens the CA in dir and takes its lock.
func Open(dir string) (*CA, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	ca := &CA{dir: abs}
	data, err := os.ReadFile(filepath.Join(abs, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &ca.config); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	ca.id, err = mtc.ParseTrustAnchorID(ca.config.ID)
	if err != nil {
		return nil, err
	}
	if ca.config.LogNumber == 0 {
		return nil, errors.New("config.json: log_number must be at least 1")
	}
	ca.lock, err = lockfile.New(filepath.Join(abs, "lock"))
	if err != nil {
		return nil, err
	}
	if err := ca.lock.TryLock(); err != nil {
		return nil, fmt.Errorf("locking %s: %w", abs, err)
	}
	ok := false
	defer func() {
		if !ok {
			ca.lock.Unlock()
		}
	}()
	keyPath := filepath.Join(abs, "ca-key.pem")
	if fi, err := os.Stat(keyPath); err != nil {
		return nil, err
	} else if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by group or others", keyPath)
	}
	key, err := mtc.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	ca.cosigner, err = mtc.NewCosigner(ca.id, key)
	if err != nil {
		return nil, err
	}
	ca.store, err = tlogstore.Open(ca.logDir())
	if err != nil {
		return nil, err
	}
	for _, m := range ca.config.Mirrors {
		mm, err := ca.newMirror(m)
		if err != nil {
			return nil, err
		}
		ca.mirrors = append(ca.mirrors, mm)
	}
	ok = true
	return ca, nil
}

// Close releases the CA lock.
func (ca *CA) Close() error { return ca.lock.Unlock() }

// ID returns the CA ID.
func (ca *CA) ID() mtc.TrustAnchorID { return ca.id }

// Config returns the CA configuration.
func (ca *CA) Config() Config { return ca.config }

// Dir returns the CA directory.
func (ca *CA) Dir() string { return ca.dir }

// LogID returns the log ID of the current log.
func (ca *CA) LogID() mtc.TrustAnchorID { return mtc.LogID(ca.id, ca.config.LogNumber) }

// Cosigner returns the public CA cosigner.
func (ca *CA) Cosigner() *mtc.CosignerPublic { return ca.cosigner.Public() }

// WWWDir is the directory served at the CA prefix URL.
func (ca *CA) WWWDir() string { return filepath.Join(ca.dir, "www") }

func (ca *CA) logDir() string {
	return filepath.Join(ca.dir, "www", strconv.Itoa(int(ca.config.LogNumber)))
}

func (ca *CA) stateDir() string {
	return filepath.Join(ca.dir, "state", strconv.Itoa(int(ca.config.LogNumber)))
}

// CertDir is the directory holding the issued certificates of the current
// log: <index>.pem for standalone certificates, and
// <index>-landmark-<L>.pem for landmark-relative ones.
func (ca *CA) CertDir() string {
	return filepath.Join(ca.dir, "certs", strconv.Itoa(int(ca.config.LogNumber)))
}

func (ca *CA) caCertificate(notBefore, notAfter time.Time) ([]byte, error) {
	der, err := mtc.MarshalCACertificate(&mtc.CAParams{
		ID:        ca.id,
		Key:       ca.cosigner.Key.PublicKey(),
		MinSerial: ca.config.MinSerial,
		MaxSerial: ca.config.MaxSerial,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PrefixURL: ca.config.PrefixURL,
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CACertificatePEM returns the CA certificate written when the CA was
// created.
func (ca *CA) CACertificatePEM() ([]byte, error) {
	return os.ReadFile(filepath.Join(ca.dir, "ca-cert.pem"))
}

// Request is a queued certificate request.
type Request struct {
	Subject []byte `json:"subject,omitempty"`
	SPKI    []byte `json:"spki"`
	Rest    []byte `json:"rest,omitempty"`

	// Lifetime, if nonzero, shortens the validity period below the CA's
	// MaxLifetime.
	Lifetime Duration `json:"lifetime,omitempty"`
}

// RequestFromTemplate returns a Request for tmpl. The validity period of
// tmpl is not used; if it is set, its length becomes the requested
// lifetime.
func RequestFromTemplate(tmpl *mtc.Template) *Request {
	r := &Request{Subject: tmpl.Subject, SPKI: tmpl.SPKI, Rest: tmpl.Rest}
	if !tmpl.NotBefore.IsZero() && tmpl.NotAfter.After(tmpl.NotBefore) {
		r.Lifetime = Duration{tmpl.NotAfter.Sub(tmpl.NotBefore)}
	}
	return r
}

// Queue adds a request to the issuance queue and returns its queue ID.
func (ca *CA) Queue(r *Request) (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(rnd[:]))
	if err := writeJSON(filepath.Join(ca.dir, "queue", name+".json"), r); err != nil {
		return "", err
	}
	return name, nil
}

// QueueLen returns the number of queued requests.
func (ca *CA) QueueLen() (int, error) {
	names, err := ca.queued()
	return len(names), err
}

func (ca *CA) queued() ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(ca.dir, "queue"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// IssuedCert describes a certificate written by Issue.
type IssuedCert struct {
	QueueID  string
	Index    uint64
	Path     string
	Landmark uint64 // zero for standalone certificates
}

// IssueResult describes an issuance run.
type IssueResult struct {
	OldSize, NewSize uint64
	Subtrees         []mtc.Subtree
	Certs            []IssuedCert
	NewLandmarks     []mtc.Landmark
	Warnings         []string
}

// Issue logs all queued requests, signs a checkpoint and the covering
// subtrees, obtains mirror cosignatures, writes standalone certificates, and
// allocates landmarks and writes landmark-relative certificates when due.
//
// See draft-ietf-plants-merkle-tree-certs-06, Sections 6.3 and 6.4.
func (ca *CA) Issue(now time.Time) (*IssueResult, error) {
	now = now.UTC().Truncate(time.Second)
	res := &IssueResult{}
	names, err := ca.queued()
	if err != nil {
		return nil, err
	}
	oldSize, err := ca.store.Size()
	if err != nil {
		return nil, err
	}
	res.OldSize, res.NewSize = uint64(oldSize), uint64(oldSize)
	if err := os.MkdirAll(ca.CertDir(), 0o755); err != nil {
		return nil, err
	}

	if len(names) > 0 {
		if err := ca.issueQueued(now, names, res); err != nil {
			return nil, err
		}
	}
	if err := ca.updateLandmarks(now, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (ca *CA) issueQueued(now time.Time, names []string, res *IssueResult) error {
	oldSize := res.OldSize
	if oldSize+uint64(len(names)) > mtc.MaxLogEntries {
		return errors.New("the current log is full; move to the next log number")
	}
	var entries [][]byte
	var tbss [][]byte
	for i, name := range names {
		var r Request
		data, err := os.ReadFile(filepath.Join(ca.dir, "queue", name))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("queue/%s: %w", name, err)
		}
		lifetime := ca.config.MaxLifetime.Duration
		if r.Lifetime.Duration > 0 && r.Lifetime.Duration < lifetime {
			lifetime = r.Lifetime.Duration
		}
		tmpl := &mtc.Template{
			Subject:   r.Subject,
			SPKI:      r.SPKI,
			Rest:      r.Rest,
			NotBefore: now,
			NotAfter:  now.Add(lifetime),
		}
		index := oldSize + uint64(i)
		tbs, err := tmpl.MarshalTBSCertificate(ca.id, mtc.Serial(ca.config.LogNumber, index))
		if err != nil {
			return fmt.Errorf("queue/%s: %w", name, err)
		}
		parsed, err := mtc.ParseTBSCertificate(tbs)
		if err != nil {
			return err
		}
		entry, err := parsed.LogEntry(nil)
		if err != nil {
			return fmt.Errorf("queue/%s: %w", name, err)
		}
		entries = append(entries, entry)
		tbss = append(tbss, tbs)
	}

	// Keep the TBSCertificates: landmark-relative certificates are built
	// from them later.
	for i, tbs := range tbss {
		index := oldSize + uint64(i)
		if err := tlogstore.WriteFile(filepath.Join(ca.CertDir(), fmt.Sprintf("%d.tbs", index)), tbs); err != nil {
			return err
		}
	}

	tree, err := ca.store.Append(entries)
	if err != nil {
		return err
	}
	newSize := uint64(tree.N)
	res.NewSize = newSize
	hr := ca.store.HashReader(tree.N)

	checkpoint, err := ca.store.WriteCheckpoint(ca.LogID().OriginString(), tree, ca.cosigner.NoteSigner())
	if err != nil {
		return err
	}

	// Cosign the two subtrees covering the new entries.
	left, right, err := mtc.FindSubtrees(oldSize, newSize)
	if err != nil {
		return err
	}
	type signedSubtree struct {
		mtc.Subtree
		hash tlog.Hash
		sigs []mtc.SubtreeSignature
	}
	var subtrees []*signedSubtree
	for _, st := range []mtc.Subtree{left, right} {
		if st.Empty() {
			continue
		}
		h, err := torchwood.SubtreeHash(int64(st.Start), int64(st.End), hr)
		if err != nil {
			return err
		}
		sig, err := ca.cosigner.SignSubtree(ca.LogID(), st.Start, st.End, h)
		if err != nil {
			return err
		}
		subtrees = append(subtrees, &signedSubtree{
			Subtree: st,
			hash:    h,
			sigs:    []mtc.SubtreeSignature{{CosignerID: ca.id, Signature: sig}},
		})
		res.Subtrees = append(res.Subtrees, st)
	}

	// Push to mirrors and collect their subtree cosignatures.
	for _, m := range ca.mirrors {
		mirrorCheckpoint, err := m.upload(ca.LogID().OriginString(), checkpoint, tree, hr, ca.store.ReadEntries)
		if err == nil {
			for _, st := range subtrees {
				var sig []byte
				sig, err = m.signSubtree(ca.LogID(), mirrorCheckpoint, tree, st.Subtree, st.hash, hr)
				if err != nil {
					break
				}
				st.sigs = append(st.sigs, mtc.SubtreeSignature{CosignerID: m.cosigner.ID, Signature: sig})
			}
		}
		if err != nil {
			if m.config.Required {
				return fmt.Errorf("mirror %s: %w", m.config.SubmissionPrefix, err)
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("mirror %s: %v", m.config.SubmissionPrefix, err))
			// Drop any partial set of this mirror's signatures.
			for _, st := range subtrees {
				st.sigs = dropCosigner(st.sigs, m.cosigner.ID)
			}
		}
	}

	props, err := mtc.StandaloneProperties(ca.id)
	if err != nil {
		return err
	}
	for i, tbs := range tbss {
		index := oldSize + uint64(i)
		var st *signedSubtree
		for _, s := range subtrees {
			if s.Contains(index) {
				st = s
			}
		}
		proof, err := torchwood.ProveRecordInSubtree(int64(st.Start), int64(st.End), int64(index), hr)
		if err != nil {
			return err
		}
		cert, err := mtc.MarshalCertificate(tbs, &mtc.MTCProof{
			Start:          st.Start,
			End:            st.End,
			InclusionProof: proof,
			Signatures:     st.sigs,
		})
		if err != nil {
			return err
		}
		out, err := mtc.EncodePEMChainWithProperties(props, cert)
		if err != nil {
			return err
		}
		path := filepath.Join(ca.CertDir(), fmt.Sprintf("%d.pem", index))
		if err := tlogstore.WriteFile(path, out); err != nil {
			return err
		}
		qid := strings.TrimSuffix(names[i], ".json")
		if err := writeJSON(filepath.Join(ca.CertDir(), fmt.Sprintf("%d.json", index)), map[string]any{"queue_id": qid}); err != nil {
			return err
		}
		res.Certs = append(res.Certs, IssuedCert{QueueID: qid, Index: index, Path: path})
	}

	for _, name := range names {
		if err := os.Remove(filepath.Join(ca.dir, "queue", name)); err != nil {
			return err
		}
	}
	return nil
}

func dropCosigner(sigs []mtc.SubtreeSignature, id mtc.TrustAnchorID) []mtc.SubtreeSignature {
	var out []mtc.SubtreeSignature
	for _, s := range sigs {
		if !s.CosignerID.Equal(id) {
			out = append(out, s)
		}
	}
	return out
}

// landmarkState is the stored landmark sequence of a log.
type landmarkState struct {
	Landmarks []mtc.Landmark `json:"landmarks"`
	// LastAllocation is when the latest landmark was allocated, in POSIX
	// seconds.
	LastAllocation int64 `json:"last_allocation"`
}

func (ca *CA) loadLandmarks() (*landmarkState, error) {
	var st landmarkState
	data, err := os.ReadFile(filepath.Join(ca.stateDir(), "landmarks.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &landmarkState{Landmarks: []mtc.Landmark{{}}}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("landmarks.json: %w", err)
	}
	return &st, nil
}

// Landmarks returns the landmark sequence of the current log, oldest first,
// starting with landmark 0.
func (ca *CA) Landmarks() ([]mtc.Landmark, error) {
	st, err := ca.loadLandmarks()
	if err != nil {
		return nil, err
	}
	return st.Landmarks, nil
}

// updateLandmarks allocates a landmark if one is due, writes the
// landmark-relative certificates for it, and publishes the active landmarks.
//
// See draft-ietf-plants-merkle-tree-certs-06, Sections 6.4.2 to 6.4.4.
func (ca *CA) updateLandmarks(now time.Time, res *IssueResult) error {
	if err := os.MkdirAll(ca.stateDir(), 0o755); err != nil {
		return err
	}
	st, err := ca.loadLandmarks()
	if err != nil {
		return err
	}
	last := st.Landmarks[len(st.Landmarks)-1]
	size := res.NewSize
	due := len(st.Landmarks) == 1 ||
		now.Sub(time.Unix(st.LastAllocation, 0)) >= ca.config.LandmarkInterval.Duration
	if due && size > last.TreeSize {
		l := mtc.Landmark{
			Number:   last.Number + 1,
			TreeSize: size,
			Expiry:   now.Add(ca.config.MaxLifetime.Duration).Unix(),
		}
		if l.Expiry < last.Expiry {
			l.Expiry = last.Expiry
		}
		st.Landmarks = append(st.Landmarks, l)
		st.LastAllocation = now.Unix()
		if err := ca.writeLandmarkCerts(last.TreeSize, l, res); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(ca.stateDir(), "landmarks.json"), st); err != nil {
			return err
		}
		res.NewLandmarks = append(res.NewLandmarks, l)
	}
	data, err := mtc.MarshalLandmarks(st.Landmarks, now)
	if err != nil {
		return err
	}
	return tlogstore.WriteFile(filepath.Join(ca.logDir(), "landmarks"), data)
}

// writeLandmarkCerts writes the landmark-relative certificates of the entries
// [prevSize, l.TreeSize).
func (ca *CA) writeLandmarkCerts(prevSize uint64, l mtc.Landmark, res *IssueResult) error {
	left, right, err := mtc.LandmarkSubtrees(prevSize, l.TreeSize)
	if err != nil {
		return err
	}
	hr := ca.store.HashReader(int64(l.TreeSize))
	props, err := mtc.LandmarkProperties(ca.id, ca.config.LogNumber, l.Number)
	if err != nil {
		return err
	}
	for index := prevSize; index < l.TreeSize; index++ {
		tbs, err := os.ReadFile(filepath.Join(ca.CertDir(), fmt.Sprintf("%d.tbs", index)))
		if errors.Is(err, os.ErrNotExist) {
			continue // a null entry
		}
		if err != nil {
			return err
		}
		st := left
		if !st.Contains(index) {
			st = right
		}
		proof, err := torchwood.ProveRecordInSubtree(int64(st.Start), int64(st.End), int64(index), hr)
		if err != nil {
			return err
		}
		cert, err := mtc.MarshalCertificate(tbs, &mtc.MTCProof{
			Start:          st.Start,
			End:            st.End,
			InclusionProof: proof,
		})
		if err != nil {
			return err
		}
		out, err := mtc.EncodePEMChainWithProperties(props, cert)
		if err != nil {
			return err
		}
		path := filepath.Join(ca.CertDir(), fmt.Sprintf("%d-landmark-%d.pem", index, l.Number))
		if err := tlogstore.WriteFile(path, out); err != nil {
			return err
		}
		res.Certs = append(res.Certs, IssuedCert{Index: index, Path: path, Landmark: l.Number})
	}
	return nil
}

// TrustedSubtree is a landmark subtree with its hash, as a relying party
// holds it once it has validated the landmark.
type TrustedSubtree struct {
	Landmark uint64
	mtc.Subtree
	Hash tlog.Hash
}

// ActiveLandmarkSubtrees returns the non-empty subtrees of the landmarks
// active at now, newest first, with hashes computed from the CA's own log.
// A relying party gets these from the log and checks them against cosigned
// checkpoints (draft-ietf-plants-merkle-tree-certs-06, Section 7.4); this is
// the CA's view, for testing.
func (ca *CA) ActiveLandmarkSubtrees(now time.Time) ([]TrustedSubtree, error) {
	ls, err := ca.Landmarks()
	if err != nil {
		return nil, err
	}
	size, err := ca.store.Size()
	if err != nil {
		return nil, err
	}
	hr := ca.store.HashReader(size)
	var out []TrustedSubtree
	for i := len(ls) - 1; i >= 1; i-- {
		if !ls[i].Active(now) {
			break
		}
		left, right, err := mtc.LandmarkSubtrees(ls[i-1].TreeSize, ls[i].TreeSize)
		if err != nil {
			return nil, err
		}
		for _, st := range []mtc.Subtree{left, right} {
			if st.Empty() {
				continue
			}
			h, err := torchwood.SubtreeHash(int64(st.Start), int64(st.End), hr)
			if err != nil {
				return nil, err
			}
			out = append(out, TrustedSubtree{Landmark: ls[i].Number, Subtree: st, Hash: h})
		}
	}
	return out, nil
}

// Checkpoint returns the latest signed checkpoint, or nil.
func (ca *CA) Checkpoint() ([]byte, error) { return ca.store.Checkpoint() }

// Size returns the size of the current log.
func (ca *CA) Size() (uint64, error) {
	n, err := ca.store.Size()
	return uint64(n), err
}

// Entry returns entry index of the current log.
func (ca *CA) Entry(index uint64) ([]byte, error) {
	es, err := ca.store.ReadEntries(int64(index), int64(index)+1)
	if err != nil {
		return nil, err
	}
	return es[0], nil
}

// AddMirror adds a mirror to the configuration. The cosigner certificate
// is copied into the CA directory.
func (ca *CA) AddMirror(submissionPrefix string, cosignerCertPEM []byte, required bool) error {
	block, _ := pem.Decode(cosignerCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("no CERTIFICATE PEM block in the mirror cosigner certificate")
	}
	c, err := mtc.ParseCosignerCertificate(block.Bytes)
	if err != nil {
		return err
	}
	rel := filepath.Join("mirrors", c.ID.String()+".pem")
	if err := tlogstore.WriteFile(filepath.Join(ca.dir, rel), cosignerCertPEM); err != nil {
		return err
	}
	mc := MirrorConfig{
		SubmissionPrefix: strings.TrimSuffix(submissionPrefix, "/"),
		CosignerCert:     rel,
		Required:         required,
	}
	m, err := ca.newMirror(mc)
	if err != nil {
		return err
	}
	ca.config.Mirrors = append(ca.config.Mirrors, mc)
	ca.mirrors = append(ca.mirrors, m)
	return writeJSON(filepath.Join(ca.dir, "config.json"), &ca.config)
}

// CosignerCertificatesPEM returns the cosigner certificates of the
// configured mirrors, concatenated.
func (ca *CA) CosignerCertificatesPEM() ([]byte, error) {
	var out []byte
	for _, m := range ca.config.Mirrors {
		data, err := os.ReadFile(filepath.Join(ca.dir, m.CosignerCert))
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
	}
	return out, nil
}

// CAKey returns the CA cosigner's private key.
func (ca *CA) CAKey() *mldsa.PrivateKey { return ca.cosigner.Key }

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return tlogstore.WriteFile(path, append(data, '\n'))
}
