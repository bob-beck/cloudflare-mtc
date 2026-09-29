package mtc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/mod/sumdb/tlog"
)

// MTCLogEntryType values.
//
// See draft-ietf-plants-merkle-tree-certs-06, Section 5.2.1.
const (
	EntryTypeNull    = 0
	EntryTypeTBSCert = 1

	maxLogEntrySize = 0xffff

	// MaxLogEntries is the maximum number of entries in a log, 2^48-1.
	MaxLogEntries = uint64(1)<<48 - 1
)

// MarshalNullEntry returns an MTCLogEntry of type null_entry with no
// extensions.
func MarshalNullEntry() []byte {
	return []byte{0, 0, 0, EntryTypeNull}
}

// A TBSCertificate is a parsed TBSCertificate, holding each field as its
// complete DER encoding (tag, length and contents).
type TBSCertificate struct {
	Raw          []byte
	Version      []byte // empty if absent (v1)
	SerialNumber []byte
	Signature    []byte
	Issuer       []byte
	Validity     []byte
	Subject      []byte
	SPKI         []byte
	SPKIAlg      []byte // SubjectPublicKeyInfo.algorithm
	// Rest is everything after the SubjectPublicKeyInfo: issuerUniqueID,
	// subjectUniqueID and extensions, as they appear in the TBSCertificate.
	Rest []byte
}

// ParseTBSCertificate splits a DER TBSCertificate into its fields. It checks
// the structure but not the contents of each field.
func ParseTBSCertificate(der []byte) (*TBSCertificate, error) {
	input := cryptobyte.String(der)
	var tbs cryptobyte.String
	var outerTag cbasn1.Tag
	if !input.ReadAnyASN1Element(&tbs, &outerTag) || outerTag != cbasn1.SEQUENCE || !input.Empty() {
		return nil, errors.New("malformed TBSCertificate")
	}
	t := &TBSCertificate{Raw: der}
	var outer cryptobyte.String = tbs
	if !outer.ReadASN1(&tbs, cbasn1.SEQUENCE) || !outer.Empty() {
		return nil, errors.New("malformed TBSCertificate")
	}
	versionTag := cbasn1.Tag(0).Constructed().ContextSpecific()
	if tbs.PeekASN1Tag(versionTag) {
		var v cryptobyte.String
		if !tbs.ReadASN1Element(&v, versionTag) {
			return nil, errors.New("malformed TBSCertificate version")
		}
		t.Version = v
	}
	fields := []struct {
		out *[]byte
		tag cbasn1.Tag
	}{
		{&t.SerialNumber, cbasn1.INTEGER},
		{&t.Signature, cbasn1.SEQUENCE},
		{&t.Issuer, cbasn1.SEQUENCE},
		{&t.Validity, cbasn1.SEQUENCE},
		{&t.Subject, cbasn1.SEQUENCE},
		{&t.SPKI, cbasn1.SEQUENCE},
	}
	for _, f := range fields {
		var v cryptobyte.String
		if !tbs.ReadASN1Element(&v, f.tag) {
			return nil, errors.New("malformed TBSCertificate")
		}
		*f.out = v
	}
	spki := cryptobyte.String(t.SPKI)
	var spkiInner, alg cryptobyte.String
	if !spki.ReadASN1(&spkiInner, cbasn1.SEQUENCE) ||
		!spkiInner.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
		return nil, errors.New("malformed SubjectPublicKeyInfo")
	}
	t.SPKIAlg = alg
	t.Rest = tbs
	return t, nil
}

// SerialUint64 returns the serial number of an MTC certificate as a uint64.
func (t *TBSCertificate) SerialUint64() (uint64, error) {
	s := cryptobyte.String(t.SerialNumber)
	var serial uint64
	if !s.ReadASN1Integer(&serial) || !s.Empty() {
		return 0, errors.New("serial number is not a non-negative 64-bit integer")
	}
	return serial, nil
}

// LogEntry returns the MTCLogEntry of type tbs_cert_entry that corresponds to
// t, with the given entry extensions (the serialized
// MTCLogEntryExtension vector contents, usually empty).
//
// The TBSCertificateLogEntry holds the fields of the TBSCertificate except
// serialNumber and signature, with subjectPublicKeyInfo replaced by its
// algorithm and the hash of its DER encoding. The entry carries its contents
// octets only, without the outer SEQUENCE header.
//
// See draft-ietf-plants-merkle-tree-certs-06, Sections 5.2.1 and 7.2.
func (t *TBSCertificate) LogEntry(extensions []byte) ([]byte, error) {
	spkiHash := sha256.Sum256(t.SPKI)
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(ext *cryptobyte.Builder) {
		ext.AddBytes(extensions)
	})
	b.AddUint16(EntryTypeTBSCert)
	b.AddBytes(t.Version)
	b.AddBytes(t.Issuer)
	b.AddBytes(t.Validity)
	b.AddBytes(t.Subject)
	b.AddBytes(t.SPKIAlg)
	b.AddASN1OctetString(spkiHash[:])
	b.AddBytes(t.Rest)
	entry, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if len(entry) > maxLogEntrySize {
		return nil, fmt.Errorf("log entry is %d bytes, more than the maximum %d", len(entry), maxLogEntrySize)
	}
	return entry, nil
}

// EntryHash returns the Merkle tree leaf hash of a serialized MTCLogEntry,
// SHA-256(0x00 || entry).
func EntryHash(entry []byte) tlog.Hash {
	return tlog.RecordHash(entry)
}

// ParsedLogEntry is a parsed MTCLogEntry.
type ParsedLogEntry struct {
	Extensions []byte // contents of the extensions vector
	Type       uint16
	Data       []byte // tbs_cert_entry_data, for type tbs_cert_entry
}

// ParseLogEntry parses a serialized MTCLogEntry.
func ParseLogEntry(entry []byte) (*ParsedLogEntry, error) {
	s := cryptobyte.String(entry)
	var ext cryptobyte.String
	var e ParsedLogEntry
	if !s.ReadUint16LengthPrefixed(&ext) || !s.ReadUint16(&e.Type) {
		return nil, errors.New("malformed MTCLogEntry")
	}
	if err := checkEntryExtensions(ext); err != nil {
		return nil, err
	}
	e.Extensions = ext
	switch e.Type {
	case EntryTypeNull:
		if !s.Empty() {
			return nil, errors.New("null_entry has trailing data")
		}
	case EntryTypeTBSCert:
		e.Data = s
	default:
		return nil, fmt.Errorf("unknown MTCLogEntryType %d", e.Type)
	}
	return &e, nil
}

// checkEntryExtensions checks that an MTCLogEntryExtension vector is well
// formed and sorted by extension_type without duplicates.
func checkEntryExtensions(ext []byte) error {
	s := cryptobyte.String(ext)
	first := true
	var last uint16
	for !s.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !s.ReadUint16(&typ) || !s.ReadUint16LengthPrefixed(&data) {
			return errors.New("malformed MTCLogEntryExtension")
		}
		if !first && typ <= last {
			return errors.New("MTCLogEntryExtensions are not sorted or contain duplicates")
		}
		first, last = false, typ
	}
	return nil
}

// SameTBSFields reports whether two parsed TBSCertificates agree on every
// field that enters the log entry.
func SameTBSFields(a, b *TBSCertificate) bool {
	return bytes.Equal(a.Version, b.Version) &&
		bytes.Equal(a.Issuer, b.Issuer) &&
		bytes.Equal(a.Validity, b.Validity) &&
		bytes.Equal(a.Subject, b.Subject) &&
		bytes.Equal(a.SPKI, b.SPKI) &&
		bytes.Equal(a.Rest, b.Rest)
}
