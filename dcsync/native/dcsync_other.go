//go:build !windows

package main

func recon(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "dcsync is Windows-only in this build"})
}

func dcsync(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "dcsync is Windows-only in this build"})
}

func extractKerberoast(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "dcsync is Windows-only in this build"})
}

func extractAsrep(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "dcsync is Windows-only in this build"})
}

func forgeGolden(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "dcsync is Windows-only in this build"})
}

func machineDomain() string { return "" }
