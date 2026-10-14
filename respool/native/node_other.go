//go:build !windows

package main

func poolStart(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "proxy node is Windows-only in this build"})
}

func poolStop() {}

func poolStats() map[string]interface{} { return map[string]interface{}{} }
