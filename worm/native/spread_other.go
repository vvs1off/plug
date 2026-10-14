//go:build !windows

package main

func discover() {
	sendEvent("error", map[string]interface{}{"message": "lateral spread is Windows-only"})
}

func spread(payload []byte) {
	sendEvent("error", map[string]interface{}{"message": "lateral spread is Windows-only"})
}
