package ca

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/torchwood"
	"github.com/bob-beck/cloudflare-mtc"
)

// Handler returns an HTTP handler that serves the CA at the root of its
// prefix URL:
//
//	GET  /ca-cert.pem                    the CA certificate
//	GET  /<log>/checkpoint               the latest checkpoint
//	GET  /<log>/tile/...                 tlog-tiles hash tiles and entry bundles
//	GET  /<log>/landmarks                the active landmarks (text/plain)
//	GET  /<log>/cert/<index>             the standalone certificate, as
//	                                     application/pem-certificate-chain-with-properties
//	GET  /<log>/cert/<index>/landmark    the landmark-relative certificate, or 202
//	POST /queue                          queue a request; the body is a PEM
//	                                     CERTIFICATE (used as a template) or
//	                                     PUBLIC KEY plus ?dns=... names
//
// The layout under /<log>/ follows c2sp.org/mtc-tlog.
func (ca *CA) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca-cert.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		http.ServeFile(w, r, filepath.Join(ca.WWWDir(), "ca-cert.pem"))
	})
	mux.HandleFunc("GET /{log}/checkpoint", ca.logFile("checkpoint", "text/plain; charset=utf-8", "no-store"))
	mux.HandleFunc("GET /{log}/landmarks", ca.logFile("landmarks", "text/plain; charset=utf-8", "no-store"))
	mux.HandleFunc("GET /{log}/tile/{path...}", ca.handleTile)
	mux.HandleFunc("GET /{log}/cert/{index}", ca.handleCert(false))
	mux.HandleFunc("GET /{log}/cert/{index}/landmark", ca.handleCert(true))
	mux.HandleFunc("POST /queue", ca.handleQueue)
	return mux
}

func (ca *CA) logNumber(r *http.Request) (string, bool) {
	log := r.PathValue("log")
	return log, log == strconv.Itoa(int(ca.config.LogNumber))
}

func (ca *CA) logFile(name, contentType, cacheControl string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ca.logNumber(r); !ok {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join(ca.logDir(), name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", cacheControl)
		w.Write(data)
	}
}

func (ca *CA) handleTile(w http.ResponseWriter, r *http.Request) {
	if _, ok := ca.logNumber(r); !ok {
		http.NotFound(w, r)
		return
	}
	path := "tile/" + r.PathValue("path")
	if _, err := torchwood.ParseTilePath(path); err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(filepath.Join(ca.logDir(), filepath.FromSlash(path)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}

func (ca *CA) handleCert(landmark bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ca.logNumber(r); !ok {
			http.NotFound(w, r)
			return
		}
		index, err := strconv.ParseUint(r.PathValue("index"), 10, 48)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var path string
		if landmark {
			matches, _ := filepath.Glob(filepath.Join(ca.CertDir(), fmt.Sprintf("%d-landmark-*.pem", index)))
			if len(matches) == 0 {
				if _, err := os.Stat(filepath.Join(ca.CertDir(), fmt.Sprintf("%d.pem", index))); err != nil {
					http.NotFound(w, r)
					return
				}
				// Section 9: not ready yet.
				w.Header().Set("Retry-After", strconv.Itoa(int(ca.config.LandmarkInterval.Seconds())))
				w.WriteHeader(http.StatusAccepted)
				return
			}
			path = matches[0]
		} else {
			path = filepath.Join(ca.CertDir(), fmt.Sprintf("%d.pem", index))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain-with-properties")
		w.Write(data)
	}
}

func (ca *CA) handleQueue(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode(body)
	if block == nil {
		http.Error(w, "expected a PEM CERTIFICATE or PUBLIC KEY", http.StatusBadRequest)
		return
	}
	var tmpl *mtc.Template
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			tmpl, err = mtc.NewTemplateFromCertificate(cert)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			tmpl, err = mtc.NewTemplateFromX509(&x509.Certificate{
				DNSNames:    r.URL.Query()["dns"],
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}, pub)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "expected a PEM CERTIFICATE or PUBLIC KEY", http.StatusBadRequest)
		return
	}
	id, err := ca.Queue(RequestFromTemplate(tmpl))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"queue_id": strings.TrimSpace(id)})
}
