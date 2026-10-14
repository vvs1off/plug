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
	// Targets to check; empty = use the ARP table.
	Targets []string `json:"targets"`
	// Credential pairs to try against cameras/hubs.
	Users     []string `json:"users"`
	Passwords []string `json:"passwords"`
	// Snapshot capture
	CaptureSnapshot bool `json:"captureSnapshot"`
	// Max devices to process in one run.
	MaxDevices int `json:"maxDevices"`
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
	case "scan":
		go scanIoT(s)
	case "snapshot":
		go snapshotIoT(s)
	case "tv_command":
		go tvCommand(s, payload)
	case "hub_dump":
		go hubDump(s)
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
