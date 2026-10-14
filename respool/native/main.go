package main

import (
	"encoding/json"
	"sync"
)

var (
	sendMu sync.Mutex
	sendFn func(event string, payload []byte)
	host   map[string]interface{}
)

func setSend(fn func(event string, payload []byte)) {
	sendMu.Lock()
	sendFn = fn
	sendMu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	sendMu.Lock()
	fn := sendFn
	sendMu.Unlock()
	if fn == nil {
		return
	}
	var raw []byte
	switch v := payload.(type) {
	case []byte:
		raw = v
	case nil:
		raw = nil
	default:
		raw, _ = json.Marshal(v)
	}
	fn(event, raw)
}

func handleInit(hostJSON []byte) error {
	if len(hostJSON) > 0 {
		_ = json.Unmarshal(hostJSON, &host)
	}
	sendEvent("status", map[string]interface{}{"state": "loaded"})
	return nil
}

func handleUnload() {
	poolStop()
	sendEvent("status", map[string]interface{}{"state": "unloaded"})
}

// Settings mirror what the operator configures in the panel.
type Settings struct {
	// Gateway host:port the node dials out to.
	Gateway string `json:"gateway"`
	// Shared secret; the gateway rejects nodes without it.
	Token string `json:"token"`
	// Advertised identity, filled in by the node on connect.
	Label string `json:"label"`
	// Cap on concurrent relayed streams.
	MaxStreams int `json:"maxStreams"`
	// Per-second bandwidth ceiling (KB), 0 = unlimited.
	BandwidthKB int `json:"bandwidthKb"`
	// Reconnect backoff bounds.
	MinBackoffMs int `json:"minBackoffMs"`
	MaxBackoffMs int `json:"maxBackoffMs"`
	// TLS for the tunnel.
	UseTLS bool `json:"useTls"`
}

func handleEvent(event string, payload []byte) error {
	preflight()
	var s Settings
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &s)
	}

	switch event {
	case "ping":
		sendEvent("pong", nil)
	case "start":
		go poolStart(s)
	case "stop":
		poolStop()
		sendEvent("status", map[string]interface{}{"state": "idle", "detail": "node stopped"})
	case "stats":
		sendEvent("stats", poolStats())
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
