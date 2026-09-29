// Command mtc runs a Merkle Tree Certificate CA and mirror, and verifies
// certificates, following draft-ietf-plants-merkle-tree-certs-06 and
// draft-ietf-tls-trust-anchor-ids-05.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bob-beck/cloudflare-mtc"
	"github.com/bob-beck/cloudflare-mtc/ca"
	"github.com/bob-beck/cloudflare-mtc/mirror"
	"github.com/urfave/cli/v2"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

func main() {
	app := &cli.App{
		Name:  "mtc",
		Usage: "Merkle Tree Certificates (draft-ietf-plants-merkle-tree-certs-06)",
		Commands: []*cli.Command{
			caCommand(),
			mirrorCommand(),
			verifyCommand(),
			inspectCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "mtc: %v\n", err)
		os.Exit(1)
	}
}

var caPathFlag = &cli.StringFlag{
	Name:    "ca-path",
	Aliases: []string{"p"},
	Usage:   "CA directory",
	Value:   ".",
}

func openCA(c *cli.Context) (*ca.CA, error) {
	return ca.Open(c.String("ca-path"))
}

func parseNow(c *cli.Context) (time.Time, error) {
	s := c.String("now")
	if s == "" {
		return time.Now(), nil
	}
	return time.Parse(time.RFC3339, s)
}

var nowFlag = &cli.StringFlag{
	Name:  "now",
	Usage: "act as if the current time is `RFC3339`, for testing",
}

func caCommand() *cli.Command {
	return &cli.Command{
		Name:  "ca",
		Usage: "manage an MTC CA",
		Flags: []cli.Flag{caPathFlag},
		Subcommands: []*cli.Command{
			{
				Name:      "new",
				Usage:     "create a CA",
				ArgsUsage: "<CA ID, e.g. 32473.1>",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "log", Usage: "issuance log number", Value: 1},
					&cli.StringFlag{Name: "prefix-url", Usage: "c2sp.org/mtc-tlog CA prefix `URL`"},
					&cli.DurationFlag{Name: "max-lifetime", Usage: "maximum certificate lifetime", Value: 7 * 24 * time.Hour},
					&cli.DurationFlag{Name: "landmark-interval", Usage: "time between landmarks", Value: time.Hour},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return errors.New("expected a CA ID")
					}
					if c.Uint("log") == 0 || c.Uint("log") > 0xffff {
						return errors.New("--log must be between 1 and 65535")
					}
					a, err := ca.New(c.String("ca-path"), ca.NewOpts{
						ID:               c.Args().First(),
						LogNumber:        uint16(c.Uint("log")),
						PrefixURL:        c.String("prefix-url"),
						MaxLifetime:      c.Duration("max-lifetime"),
						LandmarkInterval: c.Duration("landmark-interval"),
					})
					if err != nil {
						return err
					}
					defer a.Close()
					fmt.Printf("created CA %s; certificate in %s\n", a.ID(), filepath.Join(a.Dir(), "ca-cert.pem"))
					return nil
				},
			},
			{
				Name:  "queue",
				Usage: "queue a certificate request",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "dns", Aliases: []string{"d"}, Usage: "DNS name"},
					&cli.StringSliceFlag{Name: "ip", Usage: "IP address"},
					&cli.StringFlag{Name: "cn", Usage: "subject common name"},
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Usage: "`PEM` file with the subscriber's public key, private key or certificate"},
					&cli.StringFlag{Name: "generate-key", Usage: "generate a key of `TYPE` (p256, mldsa44) and write it to --key"},
					&cli.StringFlag{Name: "from-x509", Aliases: []string{"x"}, Usage: "copy subject, key and extensions from an X.509 certificate `PEM`"},
					&cli.BoolFlag{Name: "client", Usage: "client authentication instead of server authentication"},
					&cli.DurationFlag{Name: "lifetime", Usage: "requested lifetime (at most the CA's maximum)"},
				},
				Action: caQueue,
			},
			{
				Name:   "show-queue",
				Usage:  "show the number of queued requests",
				Action: caShowQueue,
			},
			{
				Name:   "issue",
				Usage:  "issue queued requests and allocate landmarks",
				Flags:  []cli.Flag{nowFlag},
				Action: caIssue,
			},
			{
				Name:  "serve",
				Usage: "serve the CA and issue periodically",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "listen", Value: "localhost:8080", Usage: "listen `address`"},
					&cli.DurationFlag{Name: "issue-every", Value: 10 * time.Second, Usage: "issuance interval, 0 to not issue"},
				},
				Action: caServe,
			},
			{
				Name:      "add-mirror",
				Usage:     "push the log to a c2sp.org/tlog-mirror mirror and use its cosignatures",
				ArgsUsage: "<submission prefix URL> <mirror cosigner certificate PEM>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "required", Usage: "fail issuance if the mirror does not cosign"},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() != 2 {
						return errors.New("expected a submission prefix and a cosigner certificate")
					}
					data, err := os.ReadFile(c.Args().Get(1))
					if err != nil {
						return err
					}
					a, err := openCA(c)
					if err != nil {
						return err
					}
					defer a.Close()
					return a.AddMirror(c.Args().Get(0), data, c.Bool("required"))
				},
			},
			{
				Name:  "export-openssl",
				Usage: "write files for OpenSSL's s_client/s_server MTC options",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "out", Aliases: []string{"o"}, Value: "openssl", Usage: "output `directory`"},
					nowFlag,
				},
				Action: caExportOpenSSL,
			},
		},
	}
}

// loadKeyMaterial reads a PEM file with a public key, private key or
// certificate and returns the public key.
func loadKeyMaterial(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: no public key, private key or certificate", path)
		}
		switch block.Type {
		case "PUBLIC KEY":
			return x509.ParsePKIXPublicKey(block.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("%s: unsupported private key", path)
			}
			return s.Public(), nil
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return k.Public(), nil
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			return cert.PublicKey, nil
		}
	}
}

func generateKey(typ, path string) (crypto.PublicKey, error) {
	var signer crypto.Signer
	var err error
	switch typ {
	case "p256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "mldsa44":
		signer, err = mtc.GenerateCosignerKey()
	default:
		return nil, fmt.Errorf("unknown key type %q", typ)
	}
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

func caQueue(c *cli.Context) error {
	var tmpl *mtc.Template
	if path := c.String("from-x509"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var block *pem.Block
		for {
			block, data = pem.Decode(data)
			if block == nil || block.Type == "CERTIFICATE" {
				break
			}
		}
		if block == nil {
			return fmt.Errorf("%s: no CERTIFICATE", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		tmpl, err = mtc.NewTemplateFromCertificate(cert)
		if err != nil {
			return err
		}
	} else {
		keyPath := c.String("key")
		if keyPath == "" {
			return errors.New("--key or --from-x509 is required")
		}
		var pub crypto.PublicKey
		var err error
		if typ := c.String("generate-key"); typ != "" {
			pub, err = generateKey(typ, keyPath)
		} else {
			pub, err = loadKeyMaterial(keyPath)
		}
		if err != nil {
			return err
		}
		x := &x509.Certificate{
			DNSNames:    c.StringSlice("dns"),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		x.Subject.CommonName = c.String("cn")
		if c.Bool("client") {
			x.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		for _, s := range c.StringSlice("ip") {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("invalid IP address %q", s)
			}
			x.IPAddresses = append(x.IPAddresses, ip)
		}
		if len(x.DNSNames) == 0 && len(x.IPAddresses) == 0 && x.Subject.CommonName == "" {
			return errors.New("give at least one of --dns, --ip or --cn")
		}
		tmpl, err = mtc.NewTemplateFromX509(x, pub)
		if err != nil {
			return err
		}
	}
	r := ca.RequestFromTemplate(tmpl)
	if d := c.Duration("lifetime"); d > 0 {
		r.Lifetime = ca.Duration{Duration: d}
	}
	a, err := openCA(c)
	if err != nil {
		return err
	}
	defer a.Close()
	id, err := a.Queue(r)
	if err != nil {
		return err
	}
	fmt.Printf("queued %s\n", id)
	return nil
}

func caShowQueue(c *cli.Context) error {
	a, err := openCA(c)
	if err != nil {
		return err
	}
	defer a.Close()
	n, err := a.QueueLen()
	if err != nil {
		return err
	}
	fmt.Printf("%d queued requests\n", n)
	return nil
}

func printIssueResult(res *ca.IssueResult) {
	if res.NewSize != res.OldSize {
		fmt.Printf("log grew from %d to %d entries; subtrees", res.OldSize, res.NewSize)
		for _, st := range res.Subtrees {
			fmt.Printf(" [%d, %d)", st.Start, st.End)
		}
		fmt.Println()
	}
	for _, l := range res.NewLandmarks {
		fmt.Printf("landmark %d at tree size %d, expires %s\n", l.Number, l.TreeSize, time.Unix(l.Expiry, 0).UTC().Format(time.RFC3339))
	}
	for _, cert := range res.Certs {
		if cert.Landmark != 0 {
			fmt.Printf("  %d: landmark %d certificate %s\n", cert.Index, cert.Landmark, cert.Path)
		} else {
			fmt.Printf("  %d: standalone certificate %s (%s)\n", cert.Index, cert.Path, cert.QueueID)
		}
	}
	for _, w := range res.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
}

func caIssue(c *cli.Context) error {
	now, err := parseNow(c)
	if err != nil {
		return err
	}
	a, err := openCA(c)
	if err != nil {
		return err
	}
	defer a.Close()
	res, err := a.Issue(now)
	if err != nil {
		return err
	}
	printIssueResult(res)
	return nil
}

func serveUntilSignal(ctx context.Context, g *errgroup.Group, srv *http.Server) {
	g.Go(func() error {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	g.Go(func() error {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	})
}

func caServe(c *cli.Context) error {
	a, err := openCA(c)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, ctx := errgroup.WithContext(ctx)
	srv := &http.Server{
		Addr:         c.String("listen"),
		Handler:      a.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	serveUntilSignal(ctx, g, srv)
	if every := c.Duration("issue-every"); every > 0 {
		g.Go(func() error {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-t.C:
					res, err := a.Issue(time.Now())
					if err != nil {
						log.Printf("issue: %v", err)
						continue
					}
					printIssueResult(res)
				}
			}
		})
	}
	log.Printf("serving CA %s on %s", a.ID(), c.String("listen"))
	return g.Wait()
}

func caExportOpenSSL(c *cli.Context) error {
	now, err := parseNow(c)
	if err != nil {
		return err
	}
	a, err := openCA(c)
	if err != nil {
		return err
	}
	defer a.Close()
	out := c.String("out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	caPEM, err := a.CACertificatePEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "ca-cert.pem"), caPEM, 0o644); err != nil {
		return err
	}
	cosigners, err := a.CosignerCertificatesPEM()
	if err != nil {
		return err
	}
	if len(cosigners) > 0 {
		if err := os.WriteFile(filepath.Join(out, "cosigners.pem"), cosigners, 0o644); err != nil {
			return err
		}
	}
	ls, err := a.Landmarks()
	if err != nil {
		return err
	}
	landmarks, err := mtc.MarshalLandmarks(ls, now)
	if err != nil {
		return err
	}
	logNumber := a.Config().LogNumber
	lpath := filepath.Join(out, fmt.Sprintf("landmarks-%d.txt", logNumber))
	if err := os.WriteFile(lpath, landmarks, 0o644); err != nil {
		return err
	}
	subtrees, err := a.ActiveLandmarkSubtrees(now)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# active landmark subtrees of %s log %d, from the CA's own log\n", a.ID(), logNumber)
	for _, st := range subtrees {
		fmt.Fprintf(&b, "%s %d %d %d %s\n", a.ID(), logNumber, st.Start, st.End, base64.StdEncoding.EncodeToString(st.Hash[:]))
	}
	spath := filepath.Join(out, fmt.Sprintf("subtrees-%d.txt", logNumber))
	if err := os.WriteFile(spath, b.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", out)
	fmt.Printf("client options: -mtc_cas %s -mtc_landmarks %s:%d:%s -mtc_subtrees %s",
		filepath.Join(out, "ca-cert.pem"), a.ID(), logNumber, lpath, spath)
	if len(cosigners) > 0 {
		fmt.Printf(" -mtc_cosigners %s", filepath.Join(out, "cosigners.pem"))
	}
	fmt.Println()
	return nil
}

func mirrorCommand() *cli.Command {
	pathFlag := &cli.StringFlag{Name: "mirror-path", Aliases: []string{"p"}, Usage: "mirror directory", Value: "."}
	open := func(c *cli.Context) (*mirror.Mirror, error) { return mirror.Open(c.String("mirror-path")) }
	return &cli.Command{
		Name:  "mirror",
		Usage: "run a c2sp.org/tlog-mirror mirror for MTC issuance logs",
		Flags: []cli.Flag{pathFlag},
		Subcommands: []*cli.Command{
			{
				Name:      "new",
				Usage:     "create a mirror",
				ArgsUsage: "<cosigner ID, e.g. 32473.2>",
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return errors.New("expected a cosigner ID")
					}
					m, err := mirror.New(c.String("mirror-path"), c.Args().First())
					if err != nil {
						return err
					}
					defer m.Close()
					fmt.Printf("created mirror %s; cosigner certificate in %s\n", m.Cosigner().ID,
						filepath.Join(c.String("mirror-path"), "cosigner-cert.pem"))
					return nil
				},
			},
			{
				Name:      "add-log",
				Usage:     "accept an MTC CA's issuance logs",
				ArgsUsage: "<CA certificate PEM>",
				Flags:     []cli.Flag{&cli.UintFlag{Name: "log", Value: 1, Usage: "first log number"}},
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return errors.New("expected a CA certificate")
					}
					data, err := os.ReadFile(c.Args().First())
					if err != nil {
						return err
					}
					m, err := open(c)
					if err != nil {
						return err
					}
					defer m.Close()
					return m.AddLog(data, uint16(c.Uint("log")))
				},
			},
			{
				Name:  "serve",
				Usage: "serve the mirror",
				Flags: []cli.Flag{&cli.StringFlag{Name: "listen", Value: "localhost:8081", Usage: "listen `address`"}},
				Action: func(c *cli.Context) error {
					m, err := open(c)
					if err != nil {
						return err
					}
					defer m.Close()
					ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
					defer stop()
					g, ctx := errgroup.WithContext(ctx)
					srv := &http.Server{Addr: c.String("listen"), Handler: m.Handler(), ReadTimeout: 5 * time.Minute}
					serveUntilSignal(ctx, g, srv)
					log.Printf("serving mirror %s on %s", m.Cosigner().ID, c.String("listen"))
					return g.Wait()
				},
			},
		},
	}
}

// readPEMCertificates returns the DER of every CERTIFICATE block in a file,
// with the CERTIFICATE PROPERTIES block preceding the first, if any.
func readPEMCertificates(path string) (certs [][]byte, props []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certs = append(certs, block.Bytes)
		case mtc.PEMTypeCertificateProperties:
			if props == nil && len(certs) == 0 {
				props = block.Bytes
			}
		}
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("%s: no certificates", path)
	}
	return certs, props, nil
}

func verifyCommand() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		Usage:     "verify an MTC certificate's proof and validity period",
		ArgsUsage: "<certificate PEM>...",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "ca-cert", Usage: "MTC CA certificate `PEM` (repeatable)", Required: true},
			&cli.StringSliceFlag{Name: "cosigner-cert", Usage: "cosigner certificate `PEM` (repeatable)"},
			&cli.IntFlag{Name: "quorum", Usage: "required cosignatures besides the CA's"},
			&cli.StringSliceFlag{Name: "subtrees", Usage: "trusted subtree `file` in OpenSSL -mtc_subtrees format"},
			nowFlag,
		},
		Action: func(c *cli.Context) error {
			now, err := parseNow(c)
			if err != nil {
				return err
			}
			opts := &mtc.VerifyOptions{Quorum: c.Int("quorum"), CurrentTime: now}
			for _, p := range c.StringSlice("ca-cert") {
				ders, _, err := readPEMCertificates(p)
				if err != nil {
					return err
				}
				for _, der := range ders {
					ca, err := mtc.ParseCACertificate(der)
					if err != nil {
						return fmt.Errorf("%s: %w", p, err)
					}
					opts.CAs = append(opts.CAs, ca)
				}
			}
			for _, p := range c.StringSlice("cosigner-cert") {
				ders, _, err := readPEMCertificates(p)
				if err != nil {
					return err
				}
				for _, der := range ders {
					cs, err := mtc.ParseCosignerCertificate(der)
					if err != nil {
						return fmt.Errorf("%s: %w", p, err)
					}
					opts.Cosigners = append(opts.Cosigners, cs)
				}
			}
			for _, p := range c.StringSlice("subtrees") {
				sts, err := readSubtreeFile(p)
				if err != nil {
					return err
				}
				opts.TrustedSubtrees = append(opts.TrustedSubtrees, sts...)
			}
			if c.NArg() == 0 {
				return errors.New("no certificates to verify")
			}
			failed := false
			for _, p := range c.Args().Slice() {
				ders, _, err := readPEMCertificates(p)
				if err != nil {
					return err
				}
				res, err := mtc.Verify(ders[0], opts)
				if err != nil {
					fmt.Printf("%s: FAIL: %v\n", p, err)
					failed = true
					continue
				}
				how := "cosignatures"
				if res.TrustedSubtree {
					how = "trusted subtree"
				}
				fmt.Printf("%s: OK: CA %s log %d index %d, subtree [%d, %d), by %s",
					p, res.CA.ID, res.LogNumber, res.Index, res.Subtree.Start, res.Subtree.End, how)
				if len(res.Cosigners) > 0 {
					var ids []string
					for _, id := range res.Cosigners {
						ids = append(ids, id.String())
					}
					fmt.Printf(" (%s)", strings.Join(ids, ", "))
				}
				fmt.Println()
			}
			if failed {
				return errors.New("verification failed")
			}
			return nil
		},
	}
}

// readSubtreeFile reads trusted subtrees in the format of OpenSSL's
// -mtc_subtrees option: "<CA ID> <log> <start> <end> <base64 hash>" per line.
func readSubtreeFile(path string) ([]mtc.TrustedSubtree, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []mtc.TrustedSubtree
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var idText, hashText string
		var logNumber uint16
		var st mtc.TrustedSubtree
		if _, err := fmt.Sscanf(line, "%s %d %d %d %s", &idText, &logNumber, &st.Start, &st.End, &hashText); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, i+1, err)
		}
		id, err := mtc.ParseTrustAnchorID(idText)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, i+1, err)
		}
		h, err := base64.StdEncoding.DecodeString(hashText)
		if err != nil || len(h) != tlog.HashSize {
			return nil, fmt.Errorf("%s:%d: malformed hash", path, i+1)
		}
		st.CAID, st.LogNumber, st.Hash = id, logNumber, tlog.Hash(h)
		out = append(out, st)
	}
	return out, nil
}

func inspectCommand() *cli.Command {
	return &cli.Command{
		Name:  "inspect",
		Usage: "print MTC structures",
		Subcommands: []*cli.Command{
			{
				Name:      "cert",
				Usage:     "print an MTC certificate's proof and properties",
				ArgsUsage: "<certificate PEM>",
				Action: func(c *cli.Context) error {
					ders, props, err := readPEMCertificates(c.Args().First())
					if err != nil {
						return err
					}
					return inspectCert(ders[0], props)
				},
			},
			{
				Name:      "landmarks",
				Usage:     "print a landmarks file with its subtrees",
				ArgsUsage: "<landmarks file>",
				Flags:     []cli.Flag{nowFlag},
				Action: func(c *cli.Context) error {
					now, err := parseNow(c)
					if err != nil {
						return err
					}
					data, err := os.ReadFile(c.Args().First())
					if err != nil {
						return err
					}
					ls, err := mtc.ParseLandmarks(data, now)
					if err != nil {
						return err
					}
					for i, l := range ls {
						fmt.Printf("landmark %d: tree size %d, expiry %s", l.Number, l.TreeSize, time.Unix(l.Expiry, 0).UTC().Format(time.RFC3339))
						if i+1 < len(ls) {
							left, right, err := mtc.LandmarkSubtrees(ls[i+1].TreeSize, l.TreeSize)
							if err == nil {
								fmt.Printf(", subtrees [%d, %d) [%d, %d)", left.Start, left.End, right.Start, right.End)
							}
						} else {
							fmt.Printf(" (expired; bounds the landmark above)")
						}
						fmt.Println()
					}
					return nil
				},
			},
		},
	}
}

func inspectCert(der, props []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	tbs, err := mtc.ParseTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return err
	}
	serial, err := tbs.SerialUint64()
	if err != nil {
		return err
	}
	issuer, err := mtc.ParseTrustAnchorIDName(tbs.Issuer)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	fmt.Printf("issuer      %s\n", issuer)
	fmt.Printf("serial      %#x (log %d, index %d)\n", serial, serial>>48, serial&mtc.MaxLogEntries)
	fmt.Printf("subject     %s\n", cert.Subject)
	fmt.Printf("dns names   %s\n", strings.Join(cert.DNSNames, ", "))
	fmt.Printf("validity    %s to %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	var proof mtc.MTCProof
	if err := proof.UnmarshalBinary(cert.Signature); err != nil {
		return fmt.Errorf("MTCProof: %w", err)
	}
	fmt.Printf("subtree     [%d, %d)\n", proof.Start, proof.End)
	fmt.Printf("proof       %d hashes\n", len(proof.InclusionProof))
	if len(proof.Signatures) == 0 {
		fmt.Printf("signatures  none (landmark-relative)\n")
	}
	for _, s := range proof.Signatures {
		fmt.Printf("signature   %s, %d bytes\n", s.CosignerID, len(s.Signature))
	}
	if props != nil {
		var l mtc.CertificatePropertyList
		if err := l.UnmarshalBinary(props); err != nil {
			return fmt.Errorf("certificate properties: %w", err)
		}
		if len(l.TrustAnchorID) > 0 {
			fmt.Printf("trust anchor id  %s\n", l.TrustAnchorID)
		}
		for _, g := range l.TrustAnchorGroups {
			fmt.Printf("trust anchor group  %s\n", g)
		}
		if l.TrustAnchorNegotiation {
			fmt.Printf("trust anchor negotiation\n")
		}
	}
	return nil
}
