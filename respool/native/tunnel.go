package main

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Tunnel framing.
//
// One long-lived TCP (or TLS) connection carries many logical streams. Each
// frame is a fixed 9-byte header plus an optional payload:
//
//	[1 byte type][4 bytes stream id][4 bytes length][length bytes payload]
//
// Stream ids are assigned by the gateway (even) and the node (odd) so the two
// sides never collide without a negotiation round-trip.
// ---------------------------------------------------------------------------

const (
	frameOpen  = 0x01 // gateway -> node: open a TCP connection to payload host:port
	frameData  = 0x02 // either direction: stream bytes
	frameClose = 0x03 // either direction: close the stream
	framePing  = 0x04 // keepalive
	framePong  = 0x05
	frameHello = 0x06 // node -> gateway: identity handshake
	frameReady = 0x07 // gateway -> node: accepted
	frameError = 0x08 // gateway -> node: rejected / stream failed
	frameStats = 0x09 // node -> gateway: bandwidth accounting
)

const frameHeaderLen = 9

// maxPayload bounds a single frame so a hostile peer cannot force a huge alloc.
const maxPayload = 64 * 1024

type frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

func writeFrame(w io.Writer, f frame) error {
	hdr := make([]byte, frameHeaderLen)
	hdr[0] = f.Type
	binary.BigEndian.PutUint32(hdr[1:5], f.StreamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(f.Payload)))

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > maxPayload {
		return frame{}, errors.New("frame too large")
	}
	f := frame{
		Type:     hdr[0],
		StreamID: binary.BigEndian.Uint32(hdr[1:5]),
	}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// Node side: dial the gateway, then service OPEN requests by dialing targets
// and pumping bytes back over the tunnel.
// ---------------------------------------------------------------------------

type nodeStats struct {
	mu          sync.Mutex
	Streams     int   `json:"streams"`
	TotalOpened int64 `json:"totalOpened"`
	BytesUp     int64 `json:"bytesUp"`
	BytesDown   int64 `json:"bytesDown"`
	Connected   bool  `json:"connected"`
	Since       int64 `json:"since"`
}

var stats nodeStats

func poolStats() map[string]interface{} {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	return map[string]interface{}{
		"streams":     stats.Streams,
		"totalOpened": stats.TotalOpened,
		"bytesUp":     stats.BytesUp,
		"bytesDown":   stats.BytesDown,
		"connected":   stats.Connected,
		"since":       stats.Since,
	}
}

func (s *nodeStats) addUp(n int) {
	s.mu.Lock()
	s.BytesUp += int64(n)
	s.mu.Unlock()
}

func (s *nodeStats) addDown(n int) {
	s.mu.Lock()
	s.BytesDown += int64(n)
	s.mu.Unlock()
}

func (s *nodeStats) openStream() {
	s.mu.Lock()
	s.Streams++
	s.TotalOpened++
	s.mu.Unlock()
}

func (s *nodeStats) closeStream() {
	s.mu.Lock()
	if s.Streams > 0 {
		s.Streams--
	}
	s.mu.Unlock()
}

func (s *nodeStats) setConnected(v bool) {
	s.mu.Lock()
	s.Connected = v
	if v {
		s.Since = time.Now().UnixMilli()
	}
	s.mu.Unlock()
}
