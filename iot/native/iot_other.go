//go:build !windows

package main

func scanIoT(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "iot scanning is Windows-only in this build"})
}

func snapshotIoT(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "iot scanning is Windows-only in this build"})
}

func tvCommand(s Settings, payload []byte) {
	sendEvent("error", map[string]interface{}{"message": "iot scanning is Windows-only in this build"})
}

func hubDump(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "iot scanning is Windows-only in this build"})
}
