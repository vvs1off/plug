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

var (
	stopMu  sync.Mutex
	stopped = true
	stopCh  = make(chan struct{})
)

func resetStop() chan struct{} {
	stopMu.Lock()
	defer stopMu.Unlock()
	stopCh = make(chan struct{})
	stopped = false
	return stopCh
}

func isStopped() bool {
	stopMu.Lock()
	defer stopMu.Unlock()
	return stopped
}

func doStop() {
	stopMu.Lock()
	defer stopMu.Unlock()
	if !stopped {
		stopped = true
		close(stopCh)
	}
}

func handleUnload() {
	doStop()
	restoreAll()
	sendEvent("status", map[string]interface{}{"state": "unloaded"})
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

type Settings struct {
	// Spoofing
	Targets     []string `json:"targets"`     // victim IPs
	Gateway     string   `json:"gateway"`     // router IP to impersonate
	Interface   string   `json:"iface"`       // e.g. "Ethernet" or an index
	// DNS
	DNSSpoof    map[string]string `json:"dnsSpoof"` // domain -> fake IP
	DNSUpstream string            `json:"dnsUpstream"`
	// Responder
	CaptureNTLM bool   `json:"captureNTLM"`
	RelayTarget string `json:"relayTarget"` // host to relay captured hashes to
	// Relay
	EnableRelay bool `json:"enableRelay"`
}

func handleEvent(event string, payload []byte) error {
	preflight()
	switch event {
	case "ping":
		sendEvent("pong", nil)
	case "ifaces":
		go listInterfaces()
	case "start":
		var s Settings
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &s)
		}
		go startMitm(s)
	case "stop":
		doStop()
		restoreAll()
		sendEvent("status", map[string]interface{}{"state": "idle", "detail": "stopped, ARP restored"})
	case "discover":
		go discoverLAN()
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
