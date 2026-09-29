// Package mirror implements a c2sp.org/tlog-mirror mirror for MTC issuance
// logs: it keeps a verified copy of each log, serves it as a tiled
// transparency log, and cosigns checkpoints and subtrees with an ML-DSA-44
// MTC cosigner key, as c2sp.org/mtc-tlog requires.
package mirror

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/torchwood"
	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/internal/tlogstore"
	"github.com/nightlyone/lockfile"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Config is the mirror configuration, stored as config.json.
type Config struct {
	// ID is the mirror's cosigner ID in ASCII form. Its cosigner name is
	// oid/1.3.6.1.4.1.<ID>.
	ID string `json:"id"`

	// Logs are the origin logs the mirror accepts.
	Logs []LogConfig `json:"logs"`
}

// LogConfig configures an origin log.
type LogConfig struct {
	// CACert is the path, relative to the mirror directory, of the MTC CA
	// certificate. The log's checkpoints must be signed by its CA
	// cosigner.
	CACert string `json:"ca_cert"`

	// LogNumber is the issuance log number. Following c2sp.org/mtc-tlog,
	// the mirror also accepts the next few log numbers of the CA.
	LogNumber uint16 `json:"log_number"`
}

// acceptNextLogs is how many log numbers past the configured one the
// mirror accepts (c2sp.org/mtc-tlog, Cosigners).
const acceptNextLogs = 4

// A Mirror is an open mirror directory.
type Mirror struct {
	dir      string
	config   Config
	cosigner *mtc.Cosigner
	lock     lockfile.Lockfile

	mu   sync.Mutex
	logs map[string]*originLog // by origin
}

type originLog struct {
	origin   string
	verifier note.Verifier // the CA cosigner
	store    *tlogstore.Store
	dir      string // per-log state directory
}

// New creates a mirror in dir with a fresh ML-DSA-44 key.
func New(dir, id string) (*Mirror, error) {
	tid, err := mtc.ParseTrustAnchorID(id)
	if err != nil {
		return nil, err
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
	if err := os.WriteFile(filepath.Join(dir, "mirror-key.pem"), keyPEM, 0o400); err != nil {
		return nil, err
	}
	cfg := Config{ID: tid.String()}
	if err := writeJSON(filepath.Join(dir, "config.json"), &cfg); err != nil {
		return nil, err
	}
	m, err := Open(dir)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	der, err := mtc.MarshalCosignerCertificate(m.cosigner.Public(), now, now.AddDate(10, 0, 0))
	if err != nil {
		m.Close()
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "cosigner-cert.pem"), certPEM, 0o644); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

// Open opens the mirror in dir and takes its lock.
func Open(dir string) (*Mirror, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	m := &Mirror{dir: abs, logs: map[string]*originLog{}}
	data, err := os.ReadFile(filepath.Join(abs, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &m.config); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	id, err := mtc.ParseTrustAnchorID(m.config.ID)
	if err != nil {
		return nil, err
	}
	m.lock, err = lockfile.New(filepath.Join(abs, "lock"))
	if err != nil {
		return nil, err
	}
	if err := m.lock.TryLock(); err != nil {
		return nil, fmt.Errorf("locking %s: %w", abs, err)
	}
	ok := false
	defer func() {
		if !ok {
			m.lock.Unlock()
		}
	}()
	key, err := mtc.LoadPrivateKeyFile(filepath.Join(abs, "mirror-key.pem"))
	if err != nil {
		return nil, err
	}
	m.cosigner, err = mtc.NewCosigner(id, key)
	if err != nil {
		return nil, err
	}
	for _, lc := range m.config.Logs {
		if err := m.openLogs(lc); err != nil {
			return nil, err
		}
	}
	ok = true
	return m, nil
}

func (m *Mirror) openLogs(lc LogConfig) error {
	data, err := os.ReadFile(filepath.Join(m.dir, lc.CACert))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("%s: no CERTIFICATE PEM block", lc.CACert)
	}
	ca, err := mtc.ParseCACertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %w", lc.CACert, err)
	}
	for n := uint32(lc.LogNumber); n <= uint32(lc.LogNumber)+acceptNextLogs && n <= 0xffff; n++ {
		origin := mtc.LogID(ca.ID, uint16(n)).OriginString()
		dir := filepath.Join(m.dir, "logs", OriginHash(origin))
		store, err := tlogstore.Open(filepath.Join(dir, "www"))
		if err != nil {
			return err
		}
		m.logs[origin] = &originLog{
			origin:   origin,
			verifier: ca.Cosigner.NoteVerifier(),
			store:    store,
			dir:      dir,
		}
	}
	return nil
}

// Close releases the mirror lock.
func (m *Mirror) Close() error { return m.lock.Unlock() }

// Cosigner returns the mirror's public cosigner.
func (m *Mirror) Cosigner() *mtc.CosignerPublic { return m.cosigner.Public() }

// CosignerCertificatePEM returns the mirror's cosigner certificate.
func (m *Mirror) CosignerCertificatePEM() ([]byte, error) {
	return os.ReadFile(filepath.Join(m.dir, "cosigner-cert.pem"))
}

// AddLog adds an MTC CA's issuance log, starting at logNumber, to the
// configuration. The CA certificate is copied into the mirror directory.
func (m *Mirror) AddLog(caCertPEM []byte, logNumber uint16) error {
	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("no CERTIFICATE PEM block in the CA certificate")
	}
	ca, err := mtc.ParseCACertificate(block.Bytes)
	if err != nil {
		return err
	}
	if logNumber == 0 {
		logNumber = 1
	}
	rel := filepath.Join("cas", ca.ID.String()+".pem")
	if err := tlogstore.WriteFile(filepath.Join(m.dir, rel), caCertPEM); err != nil {
		return err
	}
	lc := LogConfig{CACert: rel, LogNumber: logNumber}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.openLogs(lc); err != nil {
		return err
	}
	m.config.Logs = append(m.config.Logs, lc)
	return writeJSON(filepath.Join(m.dir, "config.json"), &m.config)
}

// OriginHash is the lowercase hex SHA-256 of an origin, used in the
// monitoring URL of a mirrored log.
func OriginHash(origin string) string {
	h := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(h[:])
}

// Handler returns the HTTP handler for the mirror: add-checkpoint,
// add-entries and sign-subtree under the submission prefix, and each
// mirrored log under <monitoring prefix>/<origin hash>/. Both prefixes are
// the root of the handler.
func (m *Mirror) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", m.handleAddCheckpoint)
	mux.HandleFunc("POST /add-entries", m.handleAddEntries)
	mux.HandleFunc("POST /sign-subtree", m.handleSignSubtree)
	mux.HandleFunc("GET /{hash}/{path...}", m.handleRead)
	return mux
}

func httpError(w http.ResponseWriter, code int, format string, args ...any) {
	http.Error(w, fmt.Sprintf(format, args...), code)
}

// pendingCheckpoint returns the log's pending checkpoint, verified, or nil.
func (l *originLog) pendingCheckpoint() (*torchwood.Checkpoint, []byte, error) {
	data, err := os.ReadFile(filepath.Join(l.dir, "pending"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	c, err := l.verify(data)
	if err != nil {
		return nil, nil, fmt.Errorf("stored pending checkpoint: %w", err)
	}
	return c, data, nil
}

func (l *originLog) verify(signed []byte) (*torchwood.Checkpoint, error) {
	n, err := note.Open(signed, note.VerifierList(l.verifier))
	if err != nil {
		return nil, err
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}
	if c.Origin != l.origin {
		return nil, errors.New("checkpoint origin mismatch")
	}
	return &c, nil
}

// mirrorCheckpoint returns the size of the mirror checkpoint.
func (l *originLog) mirrorCheckpointSize() (int64, error) {
	data, err := l.store.Checkpoint()
	if err != nil || data == nil {
		return 0, err
	}
	n, err := note.Open(data, note.VerifierList(l.verifier))
	if err != nil {
		return 0, err
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return 0, err
	}
	return c.N, nil
}

func checkpointOrigin(signed []byte) string {
	origin, _, _ := strings.Cut(string(signed), "\n")
	return origin
}

// handleAddCheckpoint implements add-checkpoint, which updates the pending
// checkpoint without cosigning it (c2sp.org/tlog-mirror).
func (m *Mirror) handleAddCheckpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "reading body: %v", err)
		return
	}
	header, signed, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		httpError(w, http.StatusBadRequest, "malformed request")
		return
	}
	lines := strings.Split(string(header), "\n")
	oldText, ok := strings.CutPrefix(lines[0], "old ")
	old, err := strconv.ParseInt(oldText, 10, 64)
	if !ok || err != nil || old < 0 || oldText != strconv.FormatInt(old, 10) {
		httpError(w, http.StatusBadRequest, "malformed old size line")
		return
	}
	var proof tlog.TreeProof
	for _, line := range lines[1:] {
		h, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(h) != tlog.HashSize {
			httpError(w, http.StatusBadRequest, "malformed consistency proof line")
			return
		}
		proof = append(proof, tlog.Hash(h))
	}
	if len(proof) > 63 {
		httpError(w, http.StatusBadRequest, "consistency proof too long")
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.logs[checkpointOrigin(signed)]
	if !ok {
		httpError(w, http.StatusNotFound, "unknown log")
		return
	}
	c, err := l.verify(signed)
	if err != nil {
		httpError(w, http.StatusForbidden, "checkpoint verification: %v", err)
		return
	}
	if old > c.N {
		httpError(w, http.StatusBadRequest, "old size is larger than the checkpoint size")
		return
	}
	pending, _, err := l.pendingCheckpoint()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	var pendingSize int64
	if pending != nil {
		pendingSize = pending.N
	}
	if old != pendingSize {
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", pendingSize)
		return
	}
	if c.N == 0 && c.Hash != tlog.Hash(sha256.Sum256(nil)) {
		httpError(w, http.StatusUnprocessableEntity, "empty tree with a non-empty hash")
		return
	}
	switch {
	case old == 0:
		if len(proof) != 0 {
			httpError(w, http.StatusUnprocessableEntity, "non-empty proof from size zero")
			return
		}
	case old == c.N:
		if pending.Hash != c.Hash {
			httpError(w, http.StatusUnprocessableEntity, "root hash mismatch at the same size")
			return
		}
	default:
		if err := tlog.CheckTree(proof, c.N, c.Hash, old, pending.Hash); err != nil {
			httpError(w, http.StatusUnprocessableEntity, "consistency proof: %v", err)
			return
		}
	}
	if err := tlogstore.WriteFile(filepath.Join(l.dir, "pending"), signed); err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (m *Mirror) writeMirrorInfo(w http.ResponseWriter, code int, pendingSize, next int64) {
	w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
	w.WriteHeader(code)
	fmt.Fprintf(w, "%d\n%d\n\n", pendingSize, next)
}

// handleAddEntries implements add-entries (c2sp.org/tlog-mirror). Each
// authenticated entry package is committed to the log copy at once; the
// mirror checkpoint moves to the pending checkpoint once all entries are in.
func (m *Mirror) handleAddEntries(w http.ResponseWriter, r *http.Request) {
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			httpError(w, http.StatusBadRequest, "gzip: %v", err)
			return
		}
		body = gz
	}
	w.Header().Set("Accept-Encoding", "gzip")
	br := bufio.NewReader(body)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		httpError(w, http.StatusBadRequest, "malformed request")
		return
	}
	origin := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	var fixed [18]byte
	if _, err := io.ReadFull(br, origin); err != nil {
		httpError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if _, err := io.ReadFull(br, fixed[:]); err != nil {
		httpError(w, http.StatusBadRequest, "malformed request")
		return
	}
	uploadStart := int64(binary.BigEndian.Uint64(fixed[0:]))
	uploadEnd := int64(binary.BigEndian.Uint64(fixed[8:]))
	ticket := make([]byte, binary.BigEndian.Uint16(fixed[16:]))
	if _, err := io.ReadFull(br, ticket); err != nil {
		httpError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if uploadStart < 0 || uploadEnd < 0 || uploadStart > uploadEnd {
		httpError(w, http.StatusBadRequest, "invalid upload interval")
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.logs[string(origin)]
	if !ok {
		httpError(w, http.StatusNotFound, "unknown log")
		return
	}
	pending, pendingSigned, err := l.pendingCheckpoint()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if pending == nil {
		httpError(w, http.StatusUnprocessableEntity, "no pending checkpoint")
		return
	}
	mirrorSize, err := l.mirrorCheckpointSize()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	next, err := l.store.Size()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if uploadEnd != pending.N || uploadEnd < mirrorSize || uploadStart > next {
		m.writeMirrorInfo(w, http.StatusConflict, pending.N, next)
		return
	}

	// Process the canonical sequence of entry packages.
	const tw = torchwood.TileWidth
	committed := false
	if uploadStart < uploadEnd {
		roundedStart := uploadStart / tw * tw
		for base := roundedStart; base < uploadEnd; base += tw {
			pkgStart := max(uploadStart, base)
			pkgEnd := min(uploadEnd, base+tw)
			entries, proof, err := readPackage(br, pkgEnd-pkgStart)
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			if err != nil {
				httpError(w, http.StatusBadRequest, "%v", err)
				return
			}
			next, err = l.store.Size()
			if err != nil {
				httpError(w, http.StatusInternalServerError, "%v", err)
				return
			}
			if next >= pkgEnd {
				committed = true
				continue // already have these entries
			}
			if next < pkgStart {
				break
			}
			newEntries := entries[next-pkgStart:]
			overlay := torchwood.NewHashReaderOverlay(next, l.store.HashReader(next))
			for _, e := range newEntries {
				if err := overlay.AppendRecordHash(tlog.RecordHash(e)); err != nil {
					httpError(w, http.StatusInternalServerError, "%v", err)
					return
				}
			}
			sh, err := torchwood.SubtreeHash(base, pkgEnd, overlay)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "%v", err)
				return
			}
			if err := torchwood.CheckSubtree(proof, pending.N, pending.Hash, base, pkgEnd, sh); err != nil {
				httpError(w, http.StatusUnprocessableEntity, "entry package [%d, %d): %v", pkgStart, pkgEnd, err)
				return
			}
			if _, err := l.store.Append(newEntries); err != nil {
				httpError(w, http.StatusInternalServerError, "%v", err)
				return
			}
			committed = true
		}
	}
	next, err = l.store.Size()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if next < uploadEnd {
		if !committed {
			httpError(w, http.StatusBadRequest, "no entry package received")
			return
		}
		m.writeMirrorInfo(w, http.StatusAccepted, pending.N, next)
		return
	}

	// All entries are in: check the tree and move the mirror checkpoint.
	tree, err := l.store.Tree()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if tree.N != pending.N || tree.Hash != pending.Hash {
		httpError(w, http.StatusInternalServerError, "stored log does not match the pending checkpoint")
		return
	}
	n, err := note.Open(pendingSigned, note.VerifierList(l.verifier))
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if mirrorSize > uploadEnd {
		m.writeMirrorInfo(w, http.StatusConflict, pending.N, next)
		return
	}
	logSigs := n.Sigs
	signed, err := note.Sign(&note.Note{Text: n.Text, Sigs: logSigs}, m.cosigner.NoteSigner())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if err := l.store.StoreCheckpoint(signed); err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(ownSignatureLines(signed, m.cosigner.ID.OriginString()))
}

// readPackage reads one entry package with count entries.
func readPackage(r *bufio.Reader, count int64) ([][]byte, torchwood.SubtreeProof, error) {
	var entries [][]byte
	for i := int64(0); i < count; i++ {
		var lb [2]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			if i == 0 && err == io.EOF {
				return nil, nil, io.EOF
			}
			return nil, nil, io.ErrUnexpectedEOF
		}
		e := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(r, e); err != nil {
			return nil, nil, io.ErrUnexpectedEOF
		}
		entries = append(entries, e)
	}
	n, err := r.ReadByte()
	if err != nil {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if n > 63 {
		return nil, nil, errors.New("too many proof hashes")
	}
	proof := make(torchwood.SubtreeProof, n)
	for i := range proof {
		if _, err := io.ReadFull(r, proof[i][:]); err != nil {
			return nil, nil, io.ErrUnexpectedEOF
		}
	}
	return entries, proof, nil
}

// ownSignatureLines returns the signature lines of a signed note by name.
func ownSignatureLines(signed []byte, name string) []byte {
	var out []byte
	_, sigs, _ := bytes.Cut(signed, []byte("\n\n"))
	for _, line := range bytes.SplitAfter(sigs, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("— "+name+" ")) {
			out = append(out, line...)
		}
	}
	return out
}

// handleSignSubtree implements sign-subtree (c2sp.org/tlog-witness): given a
// checkpoint the mirror has cosigned and a subtree consistency proof, it
// returns a subtree cosignature.
func (m *Mirror) handleSignSubtree(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "reading body: %v", err)
		return
	}
	header, signed, ok := bytes.Cut(body, []byte("\n\n"))
	lines := strings.Split(string(header), "\n")
	if !ok || len(lines) < 2 {
		httpError(w, http.StatusBadRequest, "malformed request")
		return
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 3 || fields[0] != "subtree" {
		httpError(w, http.StatusBadRequest, "malformed subtree line")
		return
	}
	start, err1 := strconv.ParseInt(fields[1], 10, 64)
	end, err2 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil || lines[0] != fmt.Sprintf("subtree %d %d", start, end) {
		httpError(w, http.StatusBadRequest, "malformed subtree line")
		return
	}
	hb, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(hb) != tlog.HashSize {
		httpError(w, http.StatusBadRequest, "malformed subtree hash")
		return
	}
	hash := tlog.Hash(hb)
	var proof torchwood.SubtreeProof
	for _, line := range lines[2:] {
		h, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(h) != tlog.HashSize {
			httpError(w, http.StatusBadRequest, "malformed consistency proof line")
			return
		}
		proof = append(proof, tlog.Hash(h))
	}
	if len(proof) > 63 {
		httpError(w, http.StatusBadRequest, "consistency proof too long")
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	origin := checkpointOrigin(signed)
	if _, ok := m.logs[origin]; !ok {
		httpError(w, http.StatusNotFound, "unknown log")
		return
	}
	n, err := note.Open(signed, note.VerifierList(m.cosigner.Public().NoteVerifier()))
	if err != nil {
		httpError(w, http.StatusForbidden, "checkpoint is not cosigned by this mirror: %v", err)
		return
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil || c.Origin != origin {
		httpError(w, http.StatusBadRequest, "malformed checkpoint")
		return
	}
	if !torchwood.ValidSubtree(start, end) || end > c.N {
		httpError(w, http.StatusBadRequest, "invalid subtree")
		return
	}
	if err := torchwood.CheckSubtree(proof, c.N, c.Hash, start, end, hash); err != nil {
		httpError(w, http.StatusUnprocessableEntity, "subtree consistency proof: %v", err)
		return
	}
	line, err := m.cosigner.NoteSigner().SignSubtree(origin, start, end, hash)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(line)
}

// handleRead serves a mirrored log's tiles and mirror checkpoint.
func (m *Mirror) handleRead(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	path := r.PathValue("path")
	m.mu.Lock()
	var l *originLog
	for _, ol := range m.logs {
		if OriginHash(ol.origin) == hash {
			l = ol
		}
	}
	m.mu.Unlock()
	if l == nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case path == "checkpoint":
		data, err := l.store.Checkpoint()
		if err != nil || data == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	case strings.HasPrefix(path, "tile/"):
		if _, err := torchwood.ParseTilePath(path); err != nil {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join(l.store.Dir(), filepath.FromSlash(path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return tlogstore.WriteFile(path, append(data, '\n'))
}
