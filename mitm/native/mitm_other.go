//go:build !windows

package main

func startMitm(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "MITM is Windows-only in this build"})
}

func restoreAll() {}

func discoverLAN() {
	sendEvent("error", map[string]interface{}{"message": "MITM is Windows-only in this build"})
}

func listInterfaces() {
	sendEvent("error", map[string]interface{}{"message": "MITM is Windows-only in this build"})
}
