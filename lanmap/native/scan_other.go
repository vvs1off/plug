//go:build !windows

package main

func scanNetwork() {
	sendEvent("error", map[string]interface{}{"message": "lan scanning is Windows-only in this build"})
}
