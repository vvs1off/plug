//go:build !windows

package main

func stopAllProxies() {}

func genLookalikes(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "aitm is Windows-only in this build"})
}

func startProxy(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "aitm is Windows-only in this build"})
}

func setupDNSRedirect(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "aitm is Windows-only in this build"})
}

func deployPortal(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "aitm is Windows-only in this build"})
}

func buildOAuthURL(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "aitm is Windows-only in this build"})
}

func listTemplates() {
	sendEvent("error", map[string]interface{}{"message": "aitm is Windows-only in this build"})
}
