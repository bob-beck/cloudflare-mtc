package ca

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/bob-beck/cloudflare-mtc"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// A mirrorClient is the client side of the c2sp.org/tlog-mirror protocol, used by
// the CA to upload its log and obtain subtree cosignatures.
type mirrorClient struct {
	config   MirrorConfig
	cosigner *mtc.CosignerPublic
	client   *http.Client
	// statePath holds the last tree size the mirror is known to hold.
	statePath string
}

func (ca *CA) newMirror(mc MirrorConfig) (*mirrorClient, error) {
	data, err := os.ReadFile(filepath.Join(ca.dir, mc.CosignerCert))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", mc.CosignerCert)
	}
	c, err := mtc.ParseCosignerCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mc.CosignerCert, err)
	}
	return &mirrorClient{
		config:    mc,
		cosigner:  c,
		client:    &http.Client{Timeout: 60 * time.Second},
		statePath: filepath.Join(ca.dir, "state", "mirror-"+c.ID.String()),
	}, nil
}

func (m *mirrorClient) knownSize() int64 {
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (m *mirrorClient) setKnownSize(n int64) {
	_ = os.WriteFile(m.statePath, []byte(strconv.FormatInt(n, 10)+"\n"), 0o644)
}

func (m *mirrorClient) post(path, contentType string, body []byte, gz bool) (int, []byte, error) {
	var rd io.Reader = bytes.NewReader(body)
	if gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(body)
		w.Close()
		rd = &buf
	}
	req, err := http.NewRequest("POST", m.config.SubmissionPrefix+"/"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}

// addCheckpoint sends the add-checkpoint request, updating the mirror's
// pending checkpoint. It returns the old size that the mirror accepted.
func (m *mirrorClient) addCheckpoint(checkpoint []byte, tree tlog.Tree, hr tlog.HashReader) error {
	old := m.knownSize()
	for attempt := 0; attempt < 2; attempt++ {
		if old > tree.N {
			old = 0
		}
		var body bytes.Buffer
		fmt.Fprintf(&body, "old %d\n", old)
		if old > 0 && old < tree.N {
			proof, err := tlog.ProveTree(tree.N, old, hr)
			if err != nil {
				return err
			}
			for _, h := range proof {
				fmt.Fprintf(&body, "%s\n", base64.StdEncoding.EncodeToString(h[:]))
			}
		}
		body.WriteString("\n")
		body.Write(checkpoint)
		code, resp, err := m.post("add-checkpoint", "text/plain", body.Bytes(), false)
		if err != nil {
			return err
		}
		switch code {
		case http.StatusOK:
			return nil
		case http.StatusConflict:
			n, err := strconv.ParseInt(strings.TrimSpace(string(resp)), 10, 64)
			if err != nil {
				return fmt.Errorf("add-checkpoint: malformed 409 response %q", resp)
			}
			old = n
			m.setKnownSize(n)
			continue
		default:
			return fmt.Errorf("add-checkpoint: HTTP %d: %s", code, bytes.TrimSpace(resp))
		}
	}
	return errors.New("add-checkpoint: mirror state keeps changing")
}

// mirrorInfo is the text/x.tlog.mirror-info response body.
type mirrorInfo struct {
	pendingSize, nextEntry int64
	ticket                 []byte
}

func parseMirrorInfo(data []byte) (*mirrorInfo, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return nil, fmt.Errorf("malformed mirror-info %q", data)
	}
	var mi mirrorInfo
	var err error
	if mi.pendingSize, err = strconv.ParseInt(lines[0], 10, 64); err != nil {
		return nil, fmt.Errorf("malformed mirror-info %q", data)
	}
	if mi.nextEntry, err = strconv.ParseInt(lines[1], 10, 64); err != nil {
		return nil, fmt.Errorf("malformed mirror-info %q", data)
	}
	if mi.ticket, err = base64.StdEncoding.DecodeString(lines[2]); err != nil {
		return nil, fmt.Errorf("malformed mirror-info %q", data)
	}
	return &mi, nil
}

// maxPackagesPerRequest is the c2sp.org/tlog-mirror recommended limit.
const maxPackagesPerRequest = 32

// addEntries uploads entries [start, tree.N) and returns the mirror's
// cosignature lines on the checkpoint.
func (m *mirrorClient) addEntries(origin string, start int64, tree tlog.Tree, ticket []byte, hr tlog.HashReader, readEntries func(start, end int64) ([][]byte, error)) ([]byte, error) {
	for attempt := 0; attempt < 1000; attempt++ {
		if start > tree.N {
			start = tree.N
		}
		body, err := buildAddEntries(origin, start, tree.N, ticket, hr, readEntries)
		if err != nil {
			return nil, err
		}
		code, resp, err := m.post("add-entries", "application/octet-stream", body, true)
		if err != nil {
			return nil, err
		}
		switch code {
		case http.StatusOK:
			return resp, nil
		case http.StatusAccepted, http.StatusConflict:
			mi, err := parseMirrorInfo(resp)
			if err != nil {
				return nil, err
			}
			if code == http.StatusConflict && mi.pendingSize != tree.N {
				return nil, fmt.Errorf("add-entries: mirror pending checkpoint is %d, not %d", mi.pendingSize, tree.N)
			}
			start, ticket = mi.nextEntry, mi.ticket
		default:
			return nil, fmt.Errorf("add-entries: HTTP %d: %s", code, bytes.TrimSpace(resp))
		}
	}
	return nil, errors.New("add-entries: too many rounds")
}

// buildAddEntries builds an add-entries request body for [start, end) with
// at most maxPackagesPerRequest entry packages.
func buildAddEntries(origin string, start, end int64, ticket []byte, hr tlog.HashReader, readEntries func(start, end int64) ([][]byte, error)) ([]byte, error) {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(origin)))
	b = append(b, origin...)
	b = binary.BigEndian.AppendUint64(b, uint64(start))
	b = binary.BigEndian.AppendUint64(b, uint64(end))
	b = binary.BigEndian.AppendUint16(b, uint16(len(ticket)))
	b = append(b, ticket...)
	if start == end {
		return b, nil
	}
	const w = torchwood.TileWidth
	roundedStart := start / w * w
	for i := int64(0); i < maxPackagesPerRequest; i++ {
		pkgBase := roundedStart + i*w
		if pkgBase >= end {
			break
		}
		pkgStart := max(start, pkgBase)
		pkgEnd := min(end, pkgBase+w)
		entries, err := readEntries(pkgStart, pkgEnd)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
			b = append(b, e...)
		}
		proof, err := torchwood.ProveSubtree(end, pkgBase, pkgEnd, hr)
		if err != nil {
			return nil, err
		}
		if len(proof) > 63 {
			return nil, errors.New("subtree consistency proof too long")
		}
		b = append(b, byte(len(proof)))
		for _, h := range proof {
			b = append(b, h[:]...)
		}
	}
	return b, nil
}

// upload brings the mirror up to the CA's checkpoint and returns the
// checkpoint carrying only the mirror's cosignature, for sign-subtree.
func (m *mirrorClient) upload(origin string, checkpoint []byte, tree tlog.Tree, hr tlog.HashReader, readEntries func(start, end int64) ([][]byte, error)) ([]byte, error) {
	if err := m.addCheckpoint(checkpoint, tree, hr); err != nil {
		return nil, err
	}
	sigLines, err := m.addEntries(origin, m.knownSize(), tree, nil, hr, readEntries)
	if err != nil {
		return nil, err
	}
	m.setKnownSize(tree.N)
	return m.mirrorCheckpoint(checkpoint, sigLines)
}

// signSubtree requests a subtree cosignature from the mirror with a
// checkpoint the mirror has cosigned, and returns the raw signature.
func (m *mirrorClient) signSubtree(logID mtc.TrustAnchorID, mirrorCheckpoint []byte, tree tlog.Tree, st mtc.Subtree, hash tlog.Hash, hr tlog.HashReader) ([]byte, error) {
	proof, err := torchwood.ProveSubtree(tree.N, int64(st.Start), int64(st.End), hr)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "subtree %d %d\n", st.Start, st.End)
	fmt.Fprintf(&body, "%s\n", base64.StdEncoding.EncodeToString(hash[:]))
	for _, h := range proof {
		fmt.Fprintf(&body, "%s\n", base64.StdEncoding.EncodeToString(h[:]))
	}
	body.WriteString("\n")
	body.Write(mirrorCheckpoint)
	code, resp, err := m.post("sign-subtree", "text/plain", body.Bytes(), false)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("sign-subtree: HTTP %d: %s", code, bytes.TrimSpace(resp))
	}
	sc := bufio.NewScanner(bytes.NewReader(resp))
	sc.Buffer(nil, 1<<16)
	for sc.Scan() {
		sig, err := mtc.RawSubtreeSignature(sc.Text()+"\n", m.cosigner.ID)
		if err != nil {
			continue
		}
		if !m.cosigner.VerifySubtree(logID, st.Start, st.End, hash, sig) {
			return nil, errors.New("sign-subtree: invalid cosignature from the mirror")
		}
		return sig, nil
	}
	return nil, errors.New("sign-subtree: no cosignature from the mirror in the response")
}

// mirrorCheckpoint adds the mirror's cosignature lines to checkpoint, checks
// them, and returns the checkpoint with only the mirror's signatures.
func (m *mirrorClient) mirrorCheckpoint(checkpoint, sigLines []byte) ([]byte, error) {
	signed := append(append([]byte(nil), checkpoint...), sigLines...)
	n, err := note.Open(signed, note.VerifierList(m.cosigner.NoteVerifier()))
	if err != nil {
		return nil, fmt.Errorf("mirror cosignature: %w", err)
	}
	return note.Sign(&note.Note{Text: n.Text, Sigs: n.Sigs})
}
