//go:build !windows

package main

func detectRouter(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func attackRouter(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func dumpRouterARP(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func setDNS(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func upnpMap(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func upnpList(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func rebootRouter(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}

func factoryReset(s Settings) {
	sendEvent("error", map[string]interface{}{"message": "router takeover is Windows-only in this build"})
}
