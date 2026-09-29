package mtc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTrustAnchorID(t *testing.T) {
	for _, tc := range []struct {
		text string
		hex  string
	}{
		{"32473.1", "81fd5901"},
		{"32473.100.1.8.42", "81fd596401082a"},
		{"0", "00"},
		{"18446744073709551615", "81ffffffffffffffff7f"},
	} {
		id, err := ParseTrustAnchorID(tc.text)
		if err != nil {
			t.Fatalf("%s: %v", tc.text, err)
		}
		if got := hex.EncodeToString(id); got != tc.hex {
			t.Errorf("%s: got %s, want %s", tc.text, got, tc.hex)
		}
		if id.String() != tc.text {
			t.Errorf("%s: round trip gives %s", tc.text, id)
		}
	}
	for _, bad := range []string{"", "1.", ".1", "01", "1..2", "-1", "1.a", "18446744073709551616"} {
		if _, err := ParseTrustAnchorID(bad); err == nil {
			t.Errorf("%q: parsed", bad)
		}
	}
	if err := TrustAnchorID(mustHex(t, "8001")).Validate(); err == nil {
		t.Error("non-minimal ID accepted")
	}
	if err := TrustAnchorID(mustHex(t, "81")).Validate(); err == nil {
		t.Error("truncated ID accepted")
	}
	if got := MustParseTrustAnchorID("32473.1").OriginString(); got != "oid/1.3.6.1.4.1.32473.1" {
		t.Errorf("origin string %q", got)
	}
	if got := LogID(MustParseTrustAnchorID("32473.2"), 42).OriginString(); got != "oid/1.3.6.1.4.1.32473.2.0.42" {
		t.Errorf("log origin %q", got)
	}
}

func TestPatterns(t *testing.T) {
	// draft-ietf-tls-trust-anchor-ids-05, Section 5.3.1.
	p, err := ParseTrustAnchorIDPattern("32473.{123-456}.{789-}")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if want := "81fd5981fd597b834886158 0"; hex.EncodeToString(b) != strings.ReplaceAll(want, " ", "") {
		t.Errorf("got %x", b)
	}
	var q TrustAnchorIDPattern
	if err := q.UnmarshalBinary(b); err != nil || q.String() != "32473.{123-456}.{789-}" {
		t.Errorf("round trip: %v %s", err, q)
	}
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"32473.123.789", true},
		{"32473.456.100000", true},
		{"32473.122.789", false},
		{"32473.457.789", false},
		{"32473.200.788", false},
		{"32473.200", false},
		{"32473.200.800.1", false},
	} {
		if got := p.Contains(MustParseTrustAnchorID(tc.id)); got != tc.want {
			t.Errorf("%s: got %v", tc.id, got)
		}
	}
	for _, bad := range []string{"8042", "81fd59", "81"} {
		var r TrustAnchorIDPattern
		if err := r.UnmarshalBinary(mustHex(t, bad)); err == nil {
			t.Errorf("%s: parsed", bad)
		}
	}
}

func TestCertificateProperties(t *testing.T) {
	// draft-ietf-tls-trust-anchor-ids-05, Section 7.4.
	example, _ := base64.StdEncoding.DecodeString("ACoAAAAEgf1ZAQABABoAGAmRC5ELAgJkgUgNgf1Zgf1ZAwMqgGSBSAACAAA=")
	var l CertificatePropertyList
	if err := l.UnmarshalBinary(example); err != nil {
		t.Fatal(err)
	}
	if l.TrustAnchorID.String() != "32473.1" || !l.TrustAnchorNegotiation || len(l.TrustAnchorGroups) != 2 ||
		l.TrustAnchorGroups[0].String() != "2187.2.{100-200}" ||
		l.TrustAnchorGroups[1].String() != "32473.3.{42-}.{100-200}" {
		t.Fatalf("parsed %+v", l)
	}
	out, err := l.MarshalBinary()
	if err != nil || !bytes.Equal(out, example) {
		t.Errorf("round trip: %v %x", err, out)
	}

	// The property lists of OpenSSL's test/mtc/mtc-server.pem and
	// mtc-landmark-1.pem.
	caID := MustParseTrustAnchorID("32473.1")
	sp, _ := StandaloneProperties(caID)
	b, _ := sp.MarshalBinary()
	if want := "001d0000000481fd590100010011000f0e81fd5981fd590101020200800080"; hex.EncodeToString(b) != want {
		t.Errorf("standalone properties %x", b)
	}
	lp, _ := LandmarkProperties(caID, 2, 1)
	b, _ = lp.MarshalBinary()
	if want := "00240000000781fd590101020100010011000f0e81fd5981fd59010102020202018000020000"; hex.EncodeToString(b) != want {
		t.Errorf("landmark properties %x", b)
	}

	for _, bad := range []string{
		"0008 0001 0000 0000 0000", // unsorted
		"0008 0000 0000 0000 0000", // duplicate
		"0004 0002 0001",           // truncated
		"0005 0002 0001 00",        // non-empty negotiation
	} {
		if err := l.UnmarshalBinary(mustHex(t, bad)); err == nil {
			t.Errorf("%s: parsed", bad)
		}
	}
}

func TestFindSubtrees(t *testing.T) {
	for _, tc := range []struct {
		start, end uint64
		l, r       Subtree
	}{
		{5, 13, Subtree{4, 8}, Subtree{8, 13}},
		{37, 41, Subtree{36, 40}, Subtree{40, 41}},
		{0, 1, Subtree{0, 1}, Subtree{1, 1}},
		{3, 3, Subtree{3, 3}, Subtree{3, 3}},
		{0, 8, Subtree{0, 4}, Subtree{4, 8}},
		{0xfffffffffffe, 0xffffffffffff, Subtree{0xfffffffffffe, 0xffffffffffff}, Subtree{0xffffffffffff, 0xffffffffffff}},
	} {
		l, r, err := FindSubtrees(tc.start, tc.end)
		if err != nil || l != tc.l || r != tc.r {
			t.Errorf("[%d, %d): got %v %v %v", tc.start, tc.end, l, r, err)
		}
	}
}

func TestLandmarks(t *testing.T) {
	now := time.Unix(1735689600, 0)
	data, err := os.ReadFile("testdata/openssl/mtc-landmark-10-w2-landmarks.txt")
	if err != nil {
		t.Fatal(err)
	}
	ls, err := ParseLandmarks(data, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 3 || ls[0].Number != 10 || ls[0].TreeSize != 41 || ls[2].Number != 8 || ls[2].TreeSize != 33 {
		t.Fatalf("parsed %+v", ls)
	}
	seq := []Landmark{{}, {1, 5, 100}, {2, 9, 200}, {3, 13, 300}}
	out, err := MarshalLandmarks(seq, time.Unix(150, 0))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "3\n13 300\n9 200\n5 100\n" {
		t.Errorf("marshaled %q", out)
	}
	out, _ = MarshalLandmarks(seq[:2], time.Unix(50, 0))
	if string(out) != "1\n5 100\n0 0\n" {
		t.Errorf("marshaled %q", out)
	}
	if _, err := ParseLandmarks(out, time.Unix(50, 0)); err != nil {
		t.Errorf("parsing %q: %v", out, err)
	}
	for _, bad := range []string{
		"1\n5 100\n",           // no expired landmark
		"1\n5 100\n0 0\n0 0\n", // too many lines
		"2\n5 100\n9 90\n",     // sizes increase
		"1\n5  100\n0 0\n",     // extra space
		"1\n5 100\n0 0",        // no final newline
		"01\n5 100\n0 0\n",     // leading zero
	} {
		if _, err := ParseLandmarks([]byte(bad), time.Unix(50, 0)); err == nil {
			t.Errorf("%q: parsed", bad)
		}
	}
}

func TestProofRoundTrip(t *testing.T) {
	p := &MTCProof{
		Start: 8, End: 13,
		InclusionProof: []tlog.Hash{{1}, {2}},
		Signatures: []SubtreeSignature{
			{CosignerID: MustParseTrustAnchorID("32473.10"), Signature: []byte("b")},
			{CosignerID: MustParseTrustAnchorID("32473.1"), Signature: []byte("a")},
		},
	}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var q MTCProof
	if err := q.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if q.Start != 8 || q.End != 13 || len(q.InclusionProof) != 2 ||
		q.Signatures[0].CosignerID.String() != "32473.1" {
		t.Errorf("round trip %+v", q)
	}
	if err := q.UnmarshalBinary(append(b, 0)); err == nil {
		t.Error("trailing byte accepted")
	}
	if err := q.UnmarshalBinary(b[:len(b)-1]); err == nil {
		t.Error("truncated proof accepted")
	}
	p.Signatures[1].CosignerID = p.Signatures[0].CosignerID
	if _, err := p.MarshalBinary(); err == nil {
		t.Error("duplicate cosigner accepted")
	}
}

func readPEM(t *testing.T, path string) (der, props []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			t.Fatalf("%s: no certificate", path)
		}
		switch block.Type {
		case PEMTypeCertificateProperties:
			props = block.Bytes
		case "CERTIFICATE":
			return block.Bytes, props
		}
	}
}

// TestVerifyOpenSSLFixtures verifies certificates generated by the draft's
// demo tool, as used by OpenSSL's tests.
func TestVerifyOpenSSLFixtures(t *testing.T) {
	now := time.Unix(1735689600, 0)
	caDER, _ := readPEM(t, "testdata/openssl/mtc-ca-cert.pem")
	ca, err := ParseCACertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	if ca.ID.String() != "32473.1" || ca.MinSerial != 1<<48 || ca.MaxSerial != 1<<64-1 {
		t.Fatalf("CA %s [%d, %d]", ca.ID, ca.MinSerial, ca.MaxSerial)
	}
	opts := &VerifyOptions{CAs: []*TrustedCA{ca}, CurrentTime: now}

	der, props := readPEM(t, "testdata/openssl/mtc-server.pem")
	res, err := Verify(der, opts)
	if err != nil {
		t.Fatalf("mtc-server.pem: %v", err)
	}
	if res.LogNumber != 2 || res.TrustedSubtree {
		t.Errorf("mtc-server.pem: %+v", res)
	}
	var l CertificatePropertyList
	if err := l.UnmarshalBinary(props); err != nil || l.TrustAnchorID.String() != "32473.1" {
		t.Errorf("mtc-server.pem properties: %v %+v", err, l)
	}
	opts.Quorum = 1
	if _, err := Verify(der, opts); err == nil {
		t.Error("mtc-server.pem: quorum 1 met with only the CA cosignature")
	}
	opts.Quorum = 0

	// Landmark-relative: needs the trusted subtree.
	der, _ = readPEM(t, "testdata/openssl/mtc-landmark-10.pem")
	if _, err := Verify(der, opts); err == nil {
		t.Error("mtc-landmark-10.pem verified without trusted subtrees")
	}
	subtrees, err := os.ReadFile("testdata/openssl/mtc-landmark-10-w2-subtrees.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(subtrees)), "\n") {
		f := strings.Fields(line)
		h, _ := base64.StdEncoding.DecodeString(f[4])
		var st TrustedSubtree
		st.CAID = MustParseTrustAnchorID(f[0])
		st.LogNumber = 2
		st.Start, st.End = parseUint(t, f[2]), parseUint(t, f[3])
		copy(st.Hash[:], h)
		opts.TrustedSubtrees = append(opts.TrustedSubtrees, st)
	}
	res, err = Verify(der, opts)
	if err != nil {
		t.Fatalf("mtc-landmark-10.pem: %v", err)
	}
	if !res.TrustedSubtree || res.Subtree != (Subtree{36, 40}) || res.Index != 37 {
		t.Errorf("mtc-landmark-10.pem: %+v", res)
	}
	// Landmark 5 is not among the trusted subtrees.
	der, _ = readPEM(t, "testdata/openssl/mtc-landmark-5.pem")
	if _, err := Verify(der, opts); err == nil {
		t.Error("mtc-landmark-5.pem verified")
	}
}

func parseUint(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := parseDecimal(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestCAReadsOwnFormats checks that the CA and cosigner certificates this
// package writes parse back, including the fields OpenSSL checks.
func TestCAReadsOwnFormats(t *testing.T) {
	key, err := GenerateCosignerKey()
	if err != nil {
		t.Fatal(err)
	}
	id := MustParseTrustAnchorID("32473.99")
	now := time.Now()
	der, err := MarshalCACertificate(&CAParams{
		ID: id, Key: key.PublicKey(),
		MinSerial: Serial(1, 0), MaxSerial: 1<<64 - 1,
		NotBefore: now, NotAfter: now.Add(time.Hour),
		PrefixURL: "https://ca.example/mtc",
	})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCACertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.ID.Equal(id) || ca.PrefixURL != "https://ca.example/mtc" || ca.MinSerial != 1<<48 {
		t.Errorf("parsed %+v", ca)
	}
	c, err := NewCosigner(MustParseTrustAnchorID("32473.98"), key)
	if err != nil {
		t.Fatal(err)
	}
	der, err = MarshalCosignerCertificate(c.Public(), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := ParseCosignerCertificate(der)
	if err != nil || cp.ID.String() != "32473.98" {
		t.Errorf("cosigner certificate: %v", err)
	}
	logID := LogID(id, 1)
	h := tlog.Hash{7}
	sig, err := c.SignSubtree(logID, 4, 8, h)
	if err != nil {
		t.Fatal(err)
	}
	if !cp.VerifySubtree(logID, 4, 8, h, sig) {
		t.Error("subtree signature does not verify")
	}
	if cp.VerifySubtree(logID, 4, 8, tlog.Hash{8}, sig) {
		t.Error("subtree signature verifies for another hash")
	}
}
