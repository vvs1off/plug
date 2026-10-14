//go:build !windows

package main

func discoverDomain(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "AD enumeration is Windows-only in this build"})
}

func enumerate(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "AD enumeration is Windows-only in this build"})
}

func kerberoast(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "AD enumeration is Windows-only in this build"})
}

func asrepRoast(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "AD enumeration is Windows-only in this build"})
}
