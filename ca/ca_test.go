package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/torchwood"
	"github.com/bob-beck/cloudflare-mtc"
	"github.com/bob-beck/cloudflare-mtc/mirror"
	"golang.org/x/mod/sumdb/note"
)

func readCert(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			t.Fatalf("%s: no certificate", path)
		}
		if b.Type == "CERTIFICATE" {
			return b.Bytes
		}
	}
}

func queue(t *testing.T, a *CA, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl, err := mtc.NewTemplateFromX509(&x509.Certificate{
			DNSNames:    []string{fmt.Sprintf("host%d.example", i)},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, k.Public())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Queue(RequestFromTemplate(tmpl)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIssueWithMirror(t *testing.T) {
	dir := t.TempDir()
	a, err := New(filepath.Join(dir, "ca"), NewOpts{
		ID:               "32473.1",
		LogNumber:        2,
		MaxLifetime:      24 * time.Hour,
		LandmarkInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	m, err := mirror.New(filepath.Join(dir, "mirror"), "32473.2")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	caPEM, err := a.CACertificatePEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddLog(caPEM, 2); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	mirrorCertPEM, err := m.CosignerCertificatePEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddMirror(srv.URL, mirrorCertPEM, true); err != nil {
		t.Fatal(err)
	}

	caCert, err := mtc.ParseCACertificate(readCert(t, filepath.Join(a.Dir(), "ca-cert.pem")))
	if err != nil {
		t.Fatal(err)
	}
	opts := &mtc.VerifyOptions{
		CAs:       []*mtc.TrustedCA{caCert},
		Cosigners: []*mtc.CosignerPublic{m.Cosigner()},
		Quorum:    1,
	}

	now := time.Now()
	sizes := []int{3, 300, 1, 0, 257}
	for round, n := range sizes {
		queue(t, a, n)
		now = now.Add(2 * time.Hour) // a landmark is due every round
		res, err := a.Issue(now)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		opts.CurrentTime = now
		standalone := 0
		for _, c := range res.Certs {
			if c.Landmark != 0 {
				continue
			}
			standalone++
			vr, err := mtc.Verify(readCert(t, c.Path), opts)
			if err != nil {
				t.Fatalf("round %d: %s: %v", round, c.Path, err)
			}
			if vr.Index != c.Index || len(vr.Cosigners) != 2 {
				t.Errorf("round %d: %s: %+v", round, c.Path, vr)
			}
		}
		if standalone != n {
			t.Errorf("round %d: %d standalone certificates, want %d", round, standalone, n)
		}

		// Landmark-relative certificates verify against the landmark
		// subtrees, and not without them.
		active, err := a.ActiveLandmarkSubtrees(now)
		if err != nil {
			t.Fatal(err)
		}
		lopts := &mtc.VerifyOptions{CAs: opts.CAs, CurrentTime: now}
		for _, st := range active {
			lopts.TrustedSubtrees = append(lopts.TrustedSubtrees, mtc.TrustedSubtree{
				CAID: a.ID(), LogNumber: 2, Subtree: st.Subtree, Hash: st.Hash,
			})
		}
		for _, c := range res.Certs {
			if c.Landmark == 0 {
				continue
			}
			der := readCert(t, c.Path)
			if _, err := mtc.Verify(der, lopts); err != nil {
				t.Fatalf("round %d: %s: %v", round, c.Path, err)
			}
			if _, err := mtc.Verify(der, opts); err == nil {
				t.Errorf("round %d: %s verified without trusted subtrees", round, c.Path)
			}
		}

		// The published landmarks parse.
		data, err := os.ReadFile(filepath.Join(a.WWWDir(), "2", "landmarks"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mtc.ParseLandmarks(data, now); err != nil {
			t.Errorf("round %d: landmarks %q: %v", round, data, err)
		}
	}

	// The CA's tiles authenticate against its checkpoint with an
	// independent tlog-tiles client, and the mirror holds the same tree.
	total := 0
	for _, n := range sizes {
		total += n
	}
	checkpoint, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	policy := torchwood.ThresholdPolicy(2,
		torchwood.OriginPolicy("oid/1.3.6.1.4.1.32473.1.0.2"),
		torchwood.SingleVerifierPolicy(a.Cosigner().NoteVerifier()))
	c, _, err := torchwood.VerifyCheckpoint(checkpoint, policy)
	if err != nil {
		t.Fatal(err)
	}
	if c.N != int64(total) || c.Origin != "oid/1.3.6.1.4.1.32473.1.0.2" {
		t.Fatalf("checkpoint %+v", c)
	}
	tfs, err := torchwood.NewTileFS(os.DirFS(filepath.Join(a.WWWDir(), "2")))
	if err != nil {
		t.Fatal(err)
	}
	client, err := torchwood.NewClient(tfs)
	if err != nil {
		t.Fatal(err)
	}
	count := int64(0)
	for i, e := range client.AllEntries(context.Background(), c.Tree, 0) {
		want, err := a.Entry(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(e, want) {
			t.Fatalf("entry %d differs", i)
		}
		count++
	}
	if err := client.Err(); err != nil {
		t.Fatal(err)
	}
	if count != c.N {
		t.Errorf("read %d entries, want %d", count, c.N)
	}

	mc, err := mirrorCheckpoint(srv.URL, "oid/1.3.6.1.4.1.32473.1.0.2")
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(mc, note.VerifierList(a.Cosigner().NoteVerifier(), m.Cosigner().NoteVerifier()))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Sigs) != 2 {
		t.Errorf("mirror checkpoint has %d verified signatures", len(n.Sigs))
	}
	mcp, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil || mcp.Tree != c.Tree {
		t.Errorf("mirror checkpoint %+v, CA %+v", mcp, c)
	}
}

func mirrorCheckpoint(base, origin string) ([]byte, error) {
	tf, err := torchwood.NewTileFetcher(base + "/" + mirror.OriginHash(origin))
	if err != nil {
		return nil, err
	}
	return tf.ReadEndpoint(context.Background(), "checkpoint")
}
