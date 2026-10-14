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
	sendEvent("status", map[string]interface{}{"state": "unloaded"})
}

type Settings struct {
	Domain   string `json:"domain"`
	DC       string `json:"dc"`
	BaseDN   string `json:"baseDn"`
	User     string `json:"user"`
	Password string `json:"password"`
	// Use the current machine's logon session rather than explicit creds.
	UseCurrent bool `json:"useCurrent"`
	// Enumeration scope
	MaxObjects int `json:"maxObjects"`
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
	case "discover":
		go discoverDomain(s)
	case "enumerate":
		go enumerate(s)
	case "kerberoast":
		go kerberoast(s)
	case "asrep":
		go asrepRoast(s)
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
