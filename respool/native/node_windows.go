//go:build windows

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Exit node
//
// The node never listens. It dials out to the gateway and keeps one tunnel
// open, so it works behind NAT, survives most firewalls, and looks like an
// ordinary outbound HTTPS connection.
// ---------------------------------------------------------------------------

var (
	poolMu      sync.Mutex
	poolCancel  chan struct{}
	poolRunning bool
)

func poolStop() {
	poolMu.Lock()
	defer poolMu.Unlock()
	if poolRunning {
		close(poolCancel)
		poolRunning = false
	}
}

func poolStart(s Settings) {
	if s.Gateway == "" {
		sendEvent("error", map[string]interface{}{"message": "gateway address required (host:port)"})
		return
	}
	if s.Token == "" {
		sendEvent("error", map[string]interface{}{"message": "shared token required"})
		return
	}

	poolMu.Lock()
	if poolRunning {
		poolMu.Unlock()
		sendEvent("error", map[string]interface{}{"message": "node already running"})
		return
	}
	poolCancel = make(chan struct{})
	poolRunning = true
	stop := poolCancel
	poolMu.Unlock()

	minBackoff := s.MinBackoffMs
	if minBackoff <= 0 {
		minBackoff = 2000
	}
	maxBackoff := s.MaxBackoffMs
	if maxBackoff <= 0 {
		maxBackoff = 60000
	}

	sendEvent("status", map[string]interface{}{
		"state": "connecting", "detail": "dialing gateway " + s.Gateway,
	})

	go func() {
		backoff := minBackoff
		for {
			select {
			case <-stop:
				return
			default:
			}

			err := runNode(s, stop)
			stats.setConnected(false)
			if err != nil {
				sendEvent("status", map[string]interface{}{
					"state": "retrying",
					"detail": fmt.Sprintf("tunnel closed: %v — retry in %dms", err, backoff),
				})
			}

			select {
			case <-stop:
				return
			case <-time.After(time.Duration(backoff) * time.Millisecond):
			}

			// Exponential backoff with a cap, so a gateway outage does not
			// turn every node into a reconnect storm.
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}

// runNode holds one tunnel connection for its lifetime.
func runNode(s Settings, stop chan struct{}) error {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if s.UseTLS {
		host, _, _ := net.SplitHostPort(s.Gateway)
		conn, err = tls.DialWithDialer(dialer, "tcp", s.Gateway, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.Dial("tcp", s.Gateway)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	// Handshake: identity + token.
	hostname, _ := os.Hostname()
	hello := map[string]interface{}{
		"token": s.Token,
		"label": s.Label,
		"host":  hostname,
		"os":    runtime.GOOS,
		"arch":  runtime.GOARCH,
	}
	hb, _ := json.Marshal(hello)
	if err := writeFrame(conn, frame{Type: frameHello, Payload: hb}); err != nil {
		return err
	}

	f, err := readFrame(conn)
	if err != nil {
		return err
	}
	if f.Type == frameError {
		return fmt.Errorf("gateway rejected: %s", string(f.Payload))
	}
	if f.Type != frameReady {
		return fmt.Errorf("unexpected handshake reply 0x%02x", f.Type)
	}

	stats.setConnected(true)
	sendEvent("status", map[string]interface{}{
		"state": "connected", "detail": "tunnel established, node serving",
	})

	// Close the connection when asked to stop.
	go func() {
		<-stop
		_ = conn.Close()
	}()

	streams := newStreamTable(s.MaxStreams)

	// Keepalive so idle tunnels are not reaped by NAT.
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = writeFrame(conn, frame{Type: framePing})
				sum := poolStats()
				sb, _ := json.Marshal(sum)
				_ = writeFrame(conn, frame{Type: frameStats, Payload: sb})
			}
		}
	}()

	for {
		f, err := readFrame(conn)
		if err != nil {
			streams.closeAll()
			return err
		}

		switch f.Type {
		case frameOpen:
			if streams.full() {
				_ = writeFrame(conn, frame{
					Type: frameError, StreamID: f.StreamID,
					Payload: []byte("stream limit reached"),
				})
				continue
			}
			go handleOpen(conn, streams, f)
		case frameData:
			streams.writeTo(f.StreamID, f.Payload)
		case frameClose:
			streams.close(f.StreamID)
		case framePing:
			_ = writeFrame(conn, frame{Type: framePong, StreamID: f.StreamID})
		case framePong:
			// keepalive acknowledged
		case frameError:
			streams.close(f.StreamID)
		}
	}
}

// handleOpen dials the requested target and pumps bytes both ways.
func handleOpen(conn net.Conn, streams *streamTable, f frame) {
	target := strings.TrimSpace(string(f.Payload))
	if target == "" {
		_ = writeFrame(conn, frame{Type: frameError, StreamID: f.StreamID, Payload: []byte("empty target")})
		return
	}
	// Only allow host:port — never a URL scheme.
	if strings.Contains(target, "://") {
		_ = writeFrame(conn, frame{Type: frameError, StreamID: f.StreamID, Payload: []byte("expected host:port")})
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	out, err := net.DialTimeout("tcp", target, 12*time.Second)
	if err != nil {
		_ = writeFrame(conn, frame{
			Type: frameError, StreamID: f.StreamID,
			Payload: []byte("dial " + target + ": " + err.Error()),
		})
		return
	}

	stats.openStream()
	id := f.StreamID
	streams.add(id, out)

	var wg sync.WaitGroup
	wg.Add(2)

	// target -> tunnel
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				stats.addUp(n)
				if werr := writeFrame(conn, frame{Type: frameData, StreamID: id, Payload: buf[:n]}); werr != nil {
					return
				}
			}
			if err != nil {
				break
			}
		}
		_ = writeFrame(conn, frame{Type: frameClose, StreamID: id})
	}()

	// tunnel -> target is driven by the main read loop writing into the
	// stream's pipe (see streamTable.writeTo).

	wg.Wait()
	streams.close(id)
	stats.closeStream()
}

// ---------------------------------------------------------------------------
// stream table
// ---------------------------------------------------------------------------

type streamTable struct {
	mu      sync.Mutex
	conns   map[uint32]net.Conn
	max     int
}

func newStreamTable(max int) *streamTable {
	if max <= 0 {
		max = 64
	}
	return &streamTable{conns: map[uint32]net.Conn{}, max: max}
}

func (t *streamTable) add(id uint32, c net.Conn) {
	t.mu.Lock()
	t.conns[id] = c
	t.mu.Unlock()
}

func (t *streamTable) writeTo(id uint32, data []byte) {
	t.mu.Lock()
	c := t.conns[id]
	t.mu.Unlock()
	if c == nil {
		return
	}
	if _, err := c.Write(data); err != nil {
		t.close(id)
		return
	}
	stats.addDown(len(data))
}

func (t *streamTable) close(id uint32) {
	t.mu.Lock()
	c := t.conns[id]
	delete(t.conns, id)
	t.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (t *streamTable) closeAll() {
	t.mu.Lock()
	conns := t.conns
	t.conns = map[uint32]net.Conn{}
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (t *streamTable) full() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns) >= t.max
}

var (
	_ = io.Copy
	_ = strconv.Itoa
)
