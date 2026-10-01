Merkle Tree Certificates for TLS
================================

A Hacked up Go implementation of Merkle Tree Certificates (MTC), following

- [draft-ietf-plants-merkle-tree-certs-06](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/06/)
- [draft-ietf-tls-trust-anchor-ids-05](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/05/)

and the C2SP specifications the draft defers to for serving and
cosigning logs:
[mtc-tlog](https://c2sp.org/mtc-tlog),
[tlog-tiles](https://c2sp.org/tlog-tiles),
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint),
[tlog-cosignature](https://c2sp.org/tlog-cosignature),
[tlog-witness](https://c2sp.org/tlog-witness) and
[tlog-mirror](https://c2sp.org/tlog-mirror).

It contains a CA, a mirror, and a verifier. The certificates it issues are
accepted by OpenSSL's MTC implementation (`s_client` / `s_server` with
`-mtc_cas`, `-mtc_landmarks`, `-mtc_subtrees`, `-mtc_cosigners` and
`-tai_chains`). There is no ACME support.

The draft leaves the final OIDs and the `trust_anchors` codepoint to IANA;
this code uses the early experimentation OIDs of -06
(`1.3.6.1.4.1.44363.47.0`, `.47.3` and `.47.4`), as OpenSSL does. IANA has
since assigned `id-alg-mtcProof` (`1.3.6.1.5.5.7.6.67`),
`id-rdna-trustAnchorID` (`1.3.6.1.5.5.7.25.3`) and
`id-pe-mtcCertificationAuthority-SHA256` (`1.3.6.1.5.5.7.1.38`); the CA
issues with the experimental OIDs, and parsing and verification accept
either set (OpenSSL accepts only the experimental ones for now).

Don't use this, it's my giant hack of the cloudflare MTC just for testing.
Run Away.

Overview
--------

An MTC CA appends every certificate it issues, as an `MTCLogEntry`, to an
append-only **issuance log**, a Merkle tree. A certificate is an ordinary
X.509 certificate whose `signatureValue` holds an **MTCProof** instead of a
signature: an inclusion proof into a **subtree** `[start, end)` of the log,
and, for a *standalone* certificate, signatures over that subtree by
**cosigners** (the CA itself, and mirrors or witnesses).

Every so often the CA allocates a **landmark**, a tree size that relying
parties learn out of band. A relying party that knows the landmark's
subtree hashes can accept *landmark-relative* certificates, which carry no
signatures at all.

The CA is identified by a [trust anchor ID](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/05/)
such as `32473.1` (a relative OID under `1.3.6.1.4.1`; get your own arc as
a [private enterprise number](https://www.iana.org/assignments/enterprise-numbers/)).
Log `N` of CA `32473.1` has log ID `32473.1.0.N`, and landmark `L` of that
log has trust anchor ID `32473.1.1.N.L`.

All cosigners, including the CA cosigner, use ML-DSA-44, as
[mtc-tlog](https://c2sp.org/mtc-tlog) requires.

Installing
----------

Go 1.27 or later is required (for `crypto/mldsa`).

```
$ go install github.com/bob-beck/cloudflare-mtc/cmd/mtc@latest
```

Creating a CA
-------------

```
$ mtc ca -p ca new --log 1 --max-lifetime 168h --landmark-interval 1h \
    --prefix-url http://localhost:8080 32473.1
```

This creates the directory `ca` with

- `ca-key.pem` -- the CA cosigner's ML-DSA-44 key (mode 0400);
- `ca-cert.pem` -- the CA certificate: an RFC 9925 unsigned certificate
  whose subject is the CA ID, whose key is the CA cosigner key, and which
  carries the critical `id-pe-mtcCertificationAuthority-SHA256` extension
  with the serial number range (Section 5.5), and, with `--prefix-url`, the
  mtc-tlog prefix URL extension;
- `config.json` -- the configuration;
- `queue/`, `state/`, `certs/` and `www/`.

`www/` is what is served at the CA prefix URL. Log `N` lives in `www/N/`
in the tlog-tiles layout: `checkpoint`, `tile/...` and `tile/entries/...`,
plus `landmarks`.

Requesting certificates
-----------------------

Requests are queued and issued in batches. Queue a request for a key you
have, or let `mtc` generate one:

```
$ mtc ca -p ca queue --key server-key.pem --generate-key p256 --dns a.example
$ mtc ca -p ca queue --key other.pem --dns b.example --ip 192.0.2.1 --lifetime 24h
$ mtc ca -p ca queue --from-x509 existing-cert.pem
```

`--key` takes a PEM public key, private key or certificate. `--client` makes
a client certificate. `--from-x509` copies the subject, key, validity length
and extensions of an existing certificate, leaving out those that describe
its issuer (AKI, CRL distribution points, AIA, SCTs).

`mtc ca -p ca show-queue` prints the number of queued requests.

Issuing
-------

```
$ mtc ca -p ca issue
```

An issuance run (Section 6.3)

1. appends the queued entries to the log and writes the new tiles;
2. signs a checkpoint with the CA cosigner (a tlog-cosignature ML-DSA-44
   note signature);
3. covers the new entries with two subtrees (Section 4.5) and signs them
   with the CA cosigner;
4. uploads the log to each configured mirror and obtains the mirrors'
   subtree cosignatures (see below);
5. writes each standalone certificate to `certs/N/<index>.pem`;
6. allocates a landmark if `--landmark-interval` has passed since the last
   one (Section 6.4.2), writes the landmark-relative certificates of the
   entries it covers to `certs/N/<index>-landmark-<L>.pem`, and publishes
   the active landmarks in `www/N/landmarks` (Section 6.4.3).

Certificates are written in the
`application/pem-certificate-chain-with-properties` format of TAI -05,
Section 7.4: a `CERTIFICATE PROPERTIES` block followed by the certificate.
Standalone certificates carry the trust anchor ID of the CA and the group
`caID.2.{0-}.{0-}`; landmark-relative ones carry the landmark's trust
anchor ID, the group `caID.2.N.{L-}` and `trust_anchor_negotiation`
(Section 8.2.1).

`--now` sets the time used, for testing.

Inspect a certificate:

```
$ mtc inspect cert ca/certs/1/0.pem
$ mtc inspect landmarks ca/www/1/landmarks
```

Serving the CA
--------------

```
$ mtc ca -p ca serve --listen localhost:8080 --issue-every 10s
```

This serves, at the root of the listen address:

- `/ca-cert.pem`
- `/<log>/checkpoint`, `/<log>/tile/...` -- the log as tlog-tiles;
- `/<log>/landmarks` -- the active landmarks;
- `/<log>/cert/<index>` -- the standalone certificate;
- `/<log>/cert/<index>/landmark` -- the landmark-relative certificate, or
  `202 Accepted` with `Retry-After` while there is none yet (Section 9);
- `POST /queue` -- queue a request: a PEM certificate to use as a template,
  or a PEM public key with `?dns=` names.

and issues every `--issue-every`.

Mirrors
-------

A mirror (tlog-mirror) keeps a verified copy of the CA's log, serves it,
and cosigns checkpoints and subtrees with its own ML-DSA-44 key, so that
relying parties can require a quorum of cosigners besides the CA.

```
$ mtc mirror -p mirror new 32473.2
$ mtc mirror -p mirror add-log --log 1 ca/ca-cert.pem
$ mtc mirror -p mirror serve --listen localhost:8081 &
$ mtc ca -p ca add-mirror --required http://localhost:8081 mirror/cosigner-cert.pem
```

`mirror new` writes `mirror/cosigner-cert.pem`, a certificate for the
mirror's cosigner ID and key in the form OpenSSL's `-mtc_cosigners` reads.
The mirror accepts the configured log number and the next few, as
mtc-tlog asks.

From then on, each issuance run pushes the log to the mirror with
tlog-mirror's `add-checkpoint` and `add-entries`, and asks for the subtree
cosignatures with tlog-witness's `sign-subtree`. The mirror serves each log
at `/<hex SHA-256 of the log origin>/`, with a checkpoint carrying both the
CA's and the mirror's signatures.

The tlog machinery (checkpoints, note signatures, cosignatures, tiles,
subtree hashes and proofs) is [torchwood](https://pkg.go.dev/filippo.io/torchwood)
and [golang.org/x/mod/sumdb](https://pkg.go.dev/golang.org/x/mod/sumdb).

Verifying
---------

```
$ mtc verify --ca-cert ca/ca-cert.pem ca/certs/1/0.pem
$ mtc verify --ca-cert ca/ca-cert.pem --cosigner-cert mirror/cosigner-cert.pem --quorum 1 ca/certs/1/0.pem
$ mtc verify --ca-cert ca/ca-cert.pem --subtrees subtrees-1.txt ca/certs/1/0-landmark-1.pem
```

This checks the MTCProof as in Section 7.2 and the validity period, and
nothing else (no name or key usage checks). A standalone certificate needs
a valid CA cosignature plus `--quorum` valid signatures from the
`--cosigner-cert` cosigners. A certificate whose subtree is in `--subtrees`
is checked against that hash instead.

Using the certificates with OpenSSL
-----------------------------------

`mtc ca export-openssl` writes what OpenSSL's MTC options take:

```
$ mtc ca -p ca export-openssl -o ossl
```

- `ossl/ca-cert.pem` for `-mtc_cas`;
- `ossl/cosigners.pem` (mirror cosigner certificates) for `-mtc_cosigners`;
- `ossl/landmarks-N.txt` for `-mtc_landmarks <CA ID>:N:ossl/landmarks-N.txt`;
- `ossl/subtrees-N.txt` for `-mtc_subtrees`.

The subtree hashes come from the CA's own log. A real relying party gets
landmark subtrees from the log and checks them against a cosigned
checkpoint with subtree consistency proofs (Section 7.4).

A server with a standalone and a landmark-relative certificate for the
same key, and a client that trusts the CA:

```
$ cat ca/certs/1/0-landmark-1.pem server-key.pem > chains.pem
$ cat ca/certs/1/0.pem server-key.pem >> chains.pem
$ openssl s_server -tls1_3 -cert fallback.pem -key fallback-key.pem \
    -tai_chains chains.pem
$ openssl s_client -tls1_3 -no-CAfile -no-CApath -no-CAstore \
    -mtc_cas ossl/ca-cert.pem \
    -mtc_landmarks 32473.1:1:ossl/landmarks-1.txt \
    -mtc_subtrees ossl/subtrees-1.txt
```

With the landmark subtrees loaded the client advertises the landmark group
and gets the landmark-relative certificate; without them it gets the
standalone one.

Code layout
-----------

- `github.com/bob-beck/cloudflare-mtc` -- the formats: trust anchor IDs and patterns,
  certificate property lists, `MTCLogEntry`, `MTCProof`, certificate and CA
  certificate construction, landmarks, cosigners, and verification.
- `ca` -- the CA.
- `mirror` -- the tlog-mirror mirror.
- `internal/tlogstore` -- a tlog-tiles log on the local filesystem.
- `cmd/mtc` -- the command line tool.

`testdata/openssl` holds certificates generated by the draft's reference
tool, taken from OpenSSL's tests; the unit tests verify them.
