//go:build !windows

package main

func dumpHives(payload []byte) {
	sendEvent("error", map[string]interface{}{"message": "credential dumping is Windows-only"})
}

func dumpLsass(payload []byte) {
	sendEvent("error", map[string]interface{}{"message": "credential dumping is Windows-only"})
}

func checkPriv() {
	sendEvent("priv", map[string]interface{}{"admin": false, "note": "non-windows host"})
}
