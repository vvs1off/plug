//go:build !windows

package main

func defenseRecon() {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func patchAMSI() {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func patchETW() {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func unhookNtdll() {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func harden(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func wipeLogs(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func timestomp(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func killAV() {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}

func disableDefender() {
	sendEvent("error", map[string]interface{}{"message": "evasion is Windows-only in this build"})
}
