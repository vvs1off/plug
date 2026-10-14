//go:build !windows

package main

func privRecon() {
	sendEvent("error", map[string]interface{}{"message": "privsec is Windows-only in this build"})
}

func listTokens() {
	sendEvent("error", map[string]interface{}{"message": "privsec is Windows-only in this build"})
}

func escalate(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "privsec is Windows-only in this build"})
}

func stealToken(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "privsec is Windows-only in this build"})
}

func uacBypass(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "privsec is Windows-only in this build"})
}

func checkUAC() {
	sendEvent("error", map[string]interface{}{"message": "privsec is Windows-only in this build"})
}
