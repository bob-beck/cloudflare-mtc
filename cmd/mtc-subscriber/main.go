// Command mtc-subscriber keeps TLS servers supplied with Merkle Tree
// Certificates from an mtc CA. It takes the place of the server's ACME
// client and the CA's ACME server (draft-ietf-plants-merkle-tree-certs-06,
// Section 9), speaking the CA's own HTTP interface instead.
//
// For each configured server it requests a new certificate on an interval,
// collects the standalone certificate and, once the next landmark has been
// allocated, the landmark-relative one, and rewrites the server's chain file
// with every certificate that has not yet expired, in the format OpenSSL's
// s_server -tai_chains reads.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bob-beck/cloudflare-mtc"
)

type server struct {
	name     string
	dns      []string
	keyType  string
	interval time.Duration
}

type serverFlags []server

func (s *serverFlags) String() string { return fmt.Sprint(len(*s)) }

// Set parses name:dns[,dns...]:keytype:interval.
func (s *serverFlags) Set(spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 4 {
		return fmt.Errorf("server %q: want name:dns[,dns...]:keytype:interval", spec)
	}
	interval, err := time.ParseDuration(parts[3])
	if err != nil {
		return fmt.Errorf("server %q: %v", spec, err)
	}
	switch parts[2] {
	case "p256", "mldsa44":
	default:
		return fmt.Errorf("server %q: unknown key type %q", spec, parts[2])
	}
	*s = append(*s, server{name: parts[0], dns: strings.Split(parts[1], ","), keyType: parts[2], interval: interval})
	return nil
}

// order is one certificate request and what has come back for it.
type order struct {
	QueueID    string    `json:"queue_id"`
	Requested  time.Time `json:"requested"`
	LogNumber  uint16    `json:"log_number,omitempty"`
	Index      uint64    `json:"index,omitempty"`
	Issued     bool      `json:"issued,omitempty"`
	Standalone string    `json:"standalone,omitempty"`
	Landmark   string    `json:"landmark,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
}

type state struct {
	LastRequest time.Time `json:"last_request"`
	Orders      []*order  `json:"orders"`
}

type subscriber struct {
	caURL  string
	out    string
	client *http.Client
}

func main() {
	var servers serverFlags
	caURL := flag.String("ca-url", "http://localhost:8080", "CA prefix URL")
	out := flag.String("out", "servers", "output directory; each server gets a subdirectory")
	tick := flag.Duration("tick", 5*time.Second, "how often to poll the CA")
	once := flag.Bool("once", false, "run one pass and exit")
	flag.Var(&servers, "server", "server to keep certified, as name:dns[,dns...]:keytype:interval (repeatable)")
	flag.Parse()
	if len(servers) == 0 {
		log.Fatal("no -server given")
	}
	s := &subscriber{caURL: strings.TrimSuffix(*caURL, "/"), out: *out, client: &http.Client{Timeout: 30 * time.Second}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		for i := range servers {
			if err := s.pass(ctx, &servers[i], time.Now()); err != nil {
				log.Printf("%s: %v", servers[i].name, err)
			}
		}
		if *once {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*tick):
		}
	}
}

// pass does one round for srv: request if due, collect what the CA has
// finished, rewrite the chain file.
func (s *subscriber) pass(ctx context.Context, srv *server, now time.Time) error {
	dir := filepath.Join(s.out, srv.name)
	if err := os.MkdirAll(filepath.Join(dir, "certs"), 0o755); err != nil {
		return err
	}
	pubPEM, keyPEM, err := loadOrGenerateKey(filepath.Join(dir, "key.pem"), srv.keyType)
	if err != nil {
		return err
	}
	var st state
	if data, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("state.json: %w", err)
		}
	}
	if now.Sub(st.LastRequest) >= srv.interval {
		qid, err := s.request(ctx, srv, pubPEM)
		if err != nil {
			return err
		}
		st.Orders = append(st.Orders, &order{QueueID: qid, Requested: now})
		st.LastRequest = now
		log.Printf("%s: requested %s", srv.name, qid)
	}
	var keep []*order
	for _, o := range st.Orders {
		if err := s.collect(ctx, srv, dir, o); err != nil {
			log.Printf("%s: %s: %v", srv.name, o.QueueID, err)
		}
		if !o.NotAfter.IsZero() && o.NotAfter.Before(now) {
			continue
		}
		keep = append(keep, o)
	}
	st.Orders = keep
	if err := writeChains(filepath.Join(dir, "chains.pem"), st.Orders, keyPEM); err != nil {
		return err
	}
	data, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "state.json"), data)
}

func (s *subscriber) request(ctx context.Context, srv *server, pubPEM []byte) (string, error) {
	q := url.Values{"dns": srv.dns}
	req, err := http.NewRequestWithContext(ctx, "POST", s.caURL+"/queue?"+q.Encode(), bytes.NewReader(pubPEM))
	if err != nil {
		return "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST /queue: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	var r struct {
		QueueID string `json:"queue_id"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.QueueID == "" {
		return "", fmt.Errorf("POST /queue: bad response %q", body)
	}
	return r.QueueID, nil
}

// collect fetches whatever the CA has produced for o that has not been
// fetched yet. A 202 means not yet.
func (s *subscriber) collect(ctx context.Context, srv *server, dir string, o *order) error {
	if !o.Issued {
		body, status, err := s.get(ctx, s.caURL+"/queue?id="+url.QueryEscape(o.QueueID))
		if err != nil {
			return err
		}
		if status == http.StatusAccepted {
			return nil
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /queue?id=%s: %d", o.QueueID, status)
		}
		var issued struct {
			LogNumber uint16 `json:"log_number"`
			Index     uint64 `json:"index"`
		}
		if err := json.Unmarshal(body, &issued); err != nil {
			return err
		}
		o.LogNumber, o.Index, o.Issued = issued.LogNumber, issued.Index, true
	}
	base := fmt.Sprintf("%s/%d/cert/%d", s.caURL, o.LogNumber, o.Index)
	if o.Standalone == "" {
		body, status, err := s.get(ctx, base)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET %s: %d", base, status)
		}
		notAfter, err := chainNotAfter(body)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "certs", fmt.Sprintf("%d.pem", o.Index))
		if err := writeFile(path, body); err != nil {
			return err
		}
		o.Standalone, o.NotAfter = path, notAfter
		log.Printf("%s: %s: standalone certificate %d, expires %s", srv.name, o.QueueID, o.Index, notAfter.Format(time.RFC3339))
	}
	if o.Landmark == "" {
		body, status, err := s.get(ctx, base+"/landmark")
		if err != nil {
			return err
		}
		if status == http.StatusAccepted {
			return nil
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET %s/landmark: %d", base, status)
		}
		path := filepath.Join(dir, "certs", fmt.Sprintf("%d-landmark.pem", o.Index))
		if err := writeFile(path, body); err != nil {
			return err
		}
		o.Landmark = path
		log.Printf("%s: %s: landmark-relative certificate %d", srv.name, o.QueueID, o.Index)
	}
	return nil
}

func (s *subscriber) get(ctx context.Context, u string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, err
}

// chainNotAfter returns the end-entity certificate's notAfter from a
// pem-certificate-chain-with-properties document.
func chainNotAfter(data []byte) (time.Time, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return time.Time{}, errors.New("no CERTIFICATE in the chain")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return cert.NotAfter, nil
	}
}

// writeChains writes the s_server -tai_chains file: each certificate's
// pem-certificate-chain-with-properties document followed by the private
// key, landmark-relative certificates first, newest first within each kind.
func writeChains(path string, orders []*order, keyPEM []byte) error {
	sorted := append([]*order(nil), orders...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Index > sorted[j].Index })
	var b bytes.Buffer
	for _, pick := range []func(*order) string{
		func(o *order) string { return o.Landmark },
		func(o *order) string { return o.Standalone },
	} {
		for _, o := range sorted {
			p := pick(o)
			if p == "" {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			b.Write(data)
			b.Write(keyPEM)
		}
	}
	return writeFile(path, b.Bytes())
}

// loadOrGenerateKey returns the server's public key as a PEM PUBLIC KEY and
// its private key as a PEM PRIVATE KEY, generating the key if path does not
// exist.
func loadOrGenerateKey(path, keyType string) (pubPEM, keyPEM []byte, err error) {
	keyPEM, err = os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		var signer crypto.Signer
		switch keyType {
		case "p256":
			signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "mldsa44":
			signer, err = mtc.GenerateCosignerKey()
		}
		if err != nil {
			return nil, nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(signer)
		if err != nil {
			return nil, nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("%s: not a PEM PRIVATE KEY", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("%s: key does not sign", path)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), keyPEM, nil
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
