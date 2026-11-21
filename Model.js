// Pure data logic for the WireGuard plugin: no Qt, so Node tests can load it.
// Everything parsed here comes from bin/wg-status, which reads sysfs, `ip`,
// `nmcli`, and (optionally) a redacted `wg show all dump`. Treat all of it as
// untrusted text: bound lengths and never hand it to a shell.

var MAX_LINES = 4000
var MAX_FIELD = 512
var MAX_PEERS = 256
var STALE_HANDSHAKE_SEC = 180

function formatter(fmt) {
  return typeof fmt === "function" ? fmt : function(v, d) { return d === undefined ? String(v) : Number(v).toFixed(d) }
}

function clip(value) {
  var s = String(value === undefined || value === null ? "" : value)
  return s.length > MAX_FIELD ? s.substring(0, MAX_FIELD) : s
}

function toNumber(value) {
  var n = Number(value)
  return isFinite(n) && n >= 0 ? n : 0
}

// nmcli -t output: fields separated by ':', literal ':' and '\' escaped.
function splitTerse(line) {
  var out = []
  var cur = ""
  var s = String(line || "")
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i)
    if (c === "\\" && i + 1 < s.length) {
      cur += s.charAt(i + 1)
      i++
    } else if (c === ":") {
      out.push(cur)
      cur = ""
    } else {
      cur += c
    }
  }
  out.push(cur)
  return out
}

function unescapeNm(value) {
  return String(value || "").replace(/\\(.)/g, "$1")
}

function splitList(value, sep) {
  var parts = String(value || "").split(sep)
  var out = []
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim()
    if (p !== "") out.push(clip(p))
  }
  return out
}

function isKey(value) {
  return /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(String(value || ""))
}

// `nmcli -g wireguard.peers`: "<key> allowed-ips=a;b endpoint=h\:p persistent-keepalive=25, <key> ..."
// `nmcli -g` escapes colons, so IPv6 addresses arrive as "fd00\\:\\:53".
function nmList(value) {
  return splitList(String(value || "").replace(/\\:/g, ":"), ",")
}

function parseNmPeers(value) {
  var text = String(value || "").trim()
  if (text === "") return []
  var chunks = text.split(/,\s*(?=[A-Za-z0-9+/]{43}=)/)
  var peers = []
  for (var i = 0; i < chunks.length && peers.length < MAX_PEERS; i++) {
    var tokens = chunks[i].trim().split(/\s+/)
    if (!isKey(tokens[0])) continue
    var peer = { publicKey: tokens[0], endpoint: "", allowedIps: [], keepalive: 0, handshake: 0, rx: 0, tx: 0, live: false }
    for (var t = 1; t < tokens.length; t++) {
      var eq = tokens[t].indexOf("=")
      if (eq <= 0) continue
      var k = tokens[t].substring(0, eq)
      var v = unescapeNm(tokens[t].substring(eq + 1))
      if (k === "allowed-ips") peer.allowedIps = splitList(v, ";")
      else if (k === "endpoint") peer.endpoint = clip(v)
      else if (k === "persistent-keepalive") peer.keepalive = toNumber(v)
    }
    peers.push(peer)
  }
  return peers
}

function emptySnapshot() {
  return { ifaces: {}, conns: [], nm: {}, dump: {}, stats: "", resolved: {}, domains: {}, globalDns: false, dnsFix: false, dnsFixForeign: false, hookVersion: 0, full: false }
}

function parseSnapshot(raw) {
  var snap = emptySnapshot()
  var lines = String(raw || "").split("\n")
  if (lines.length > MAX_LINES) lines = lines.slice(0, MAX_LINES)
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i]
    if (line === "") continue
    var f = line.split("\t")
    var tag = f[0]
    if (tag === "I" && f.length >= 6) {
      var name = clip(f[1])
      if (name === "") continue
      snap.ifaces[name] = { rx: toNumber(f[2]), tx: toNumber(f[3]), mtu: toNumber(f[4]), addresses: splitList(f[5], ",") }
    } else if (tag === "C") {
      snap.full = true
      var c = splitTerse(f.slice(1).join("\t"))
      if (c.length < 7 || c[2] !== "wireguard") continue
      snap.conns.push({
        name: clip(c[0]),
        uuid: clip(c[1]),
        device: clip(c[3]),
        state: clip(c[4]),
        filename: clip(c[5]),
        autoconnect: c[6] === "yes"
      })
    } else if (tag === "N" && f.length >= 3) {
      var uuid = clip(f[1])
      if (!snap.nm[uuid]) snap.nm[uuid] = {}
      snap.nm[uuid][clip(f[2])] = f.length > 3 ? f.slice(3).join("\t") : ""
    } else if (tag === "D") {
      parseDumpLine(snap.dump, f.slice(1))
    } else if (tag === "R" && f.length >= 2) {
      snap.resolved[clip(f[1])] = splitList(f.length > 2 ? f[2] : "", /\s+/)
    } else if (tag === "Q" && f.length >= 2) {
      snap.domains[clip(f[1])] = splitList(f.length > 2 ? f[2] : "", /\s+/)
    } else if (tag === "G" && f.length >= 3) {
      snap.globalDns = f[1] === "yes"
      snap.dnsFix = f[2] === "yes"
      // Someone else's script at the hook's path: leave it alone, offer nothing.
      snap.dnsFixForeign = f[2] === "foreign"
      snap.hookVersion = snap.dnsFix ? Math.max(1, toNumber(f[3])) : 0
    } else if (tag === "S") {
      snap.full = true
      snap.stats = f[1] === "ok" || f[1] === "fail" || f[1] === "absent" ? f[1] : ""
    }
  }
  return snap
}

// wg show all dump: interface lines have 5 fields, peer lines 9.
function parseDumpLine(dump, f) {
  if (f.length === 5) {
    var name = clip(f[0])
    dump[name] = dump[name] || { peers: [] }
    dump[name].publicKey = isKey(f[2]) ? f[2] : ""
    dump[name].listenPort = toNumber(f[3])
  } else if (f.length === 9) {
    var iface = clip(f[0])
    dump[iface] = dump[iface] || { peers: [] }
    if (dump[iface].peers.length >= MAX_PEERS || !isKey(f[1])) return
    dump[iface].peers.push({
      publicKey: f[1],
      endpoint: f[3] === "(none)" ? "" : clip(f[3]),
      allowedIps: f[4] === "(none)" ? [] : splitList(f[4], ","),
      handshake: toNumber(f[5]),
      rx: toNumber(f[6]),
      tx: toNumber(f[7]),
      keepalive: f[8] === "off" ? 0 : toNumber(f[8]),
      live: true
    })
  }
}

// Fast polls only carry interface counters; keep the rest from the last full one.
function mergeSnapshot(previous, next) {
  if (next.full) return next
  var prev = previous || emptySnapshot()
  return {
    ifaces: next.ifaces, conns: prev.conns, nm: prev.nm, dump: prev.dump, stats: prev.stats,
    resolved: prev.resolved, domains: prev.domains || {}, globalDns: prev.globalDns, dnsFix: prev.dnsFix,
    dnsFixForeign: prev.dnsFixForeign === true, hookVersion: prev.hookVersion || 0, full: false
  }
}

function contains(list, value) {
  if (!(list instanceof Array)) return false
  for (var i = 0; i < list.length; i++) if (String(list[i]) === value) return true
  return false
}

function mergePeers(configured, live) {
  if (!live || live.length === 0) return configured
  var byKey = {}
  var out = []
  for (var i = 0; i < live.length; i++) {
    byKey[live[i].publicKey] = true
    out.push(live[i])
  }
  // Keep configured peers the kernel does not list (should not happen, but a
  // half-applied profile is better shown than hidden).
  for (var j = 0; j < configured.length; j++) if (!byKey[configured[j].publicKey]) out.push(configured[j])
  return out
}

// One row per tunnel the user can see. Kinds:
//   nm       saved NetworkManager profile: toggled with nmcli, no root
//   wgquick  /etc/wireguard/<name>.conf listed in settings: toggled via pkexec
//   external a live WireGuard interface something else owns: read-only
function buildTunnels(snap, options) {
  var opts = options || {}
  var exclude = opts.excludeInterfaces || []
  var wgQuick = opts.wgQuickConfigs || []
  var tunnels = []
  var claimed = {}

  for (var i = 0; i < snap.conns.length; i++) {
    var c = snap.conns[i]
    var volatile = c.filename === "" || c.filename.indexOf("/run/") === 0
    if (volatile) continue
    var device = c.device || c.name
    if (contains(exclude, device) || contains(exclude, c.name)) {
      if (c.device) claimed[c.device] = true
      continue
    }
    var nm = snap.nm[c.uuid] || {}
    var activated = c.state === "activated"
    var iface = activated && c.device ? snap.ifaces[c.device] : null
    var live = snap.dump[c.device] || null
    if (c.device) claimed[c.device] = true
    tunnels.push({
      id: "nm:" + c.uuid,
      kind: "nm",
      name: c.name,
      uuid: c.uuid,
      device: c.device,
      state: c.state || "",
      active: activated,
      busy: c.state === "activating" || c.state === "deactivating",
      autoconnect: c.autoconnect,
      addresses: iface && iface.addresses.length > 0 ? iface.addresses : nmList(nm["ipv4.addresses"]).concat(nmList(nm["ipv6.addresses"])),
      dns: nmList(nm["ipv4.dns"]).concat(nmList(nm["ipv6.dns"])),
      dnsInUse: activated && c.device && snap.resolved[c.device] ? snap.resolved[c.device] : [],
      dnsDomainsInUse: activated && c.device && snap.domains[c.device] ? snap.domains[c.device] : [],
      dnsPriority: dnsPriority(nm["ipv4.dns-priority"], nm["ipv6.dns-priority"]),
      dnsSearch: nmList(nm["ipv4.dns-search"]).concat(nmList(nm["ipv6.dns-search"])),
      neverDefault: { v4: nm["ipv4.never-default"] === "yes", v6: nm["ipv6.never-default"] === "yes" },
      // An address family NetworkManager has switched off takes no DNS or routes.
      familyOff: { v4: nm["ipv4.method"] === "disabled", v6: nm["ipv6.method"] === "disabled" || nm["ipv6.method"] === "ignore" },
      routeSpecs: nmList(nm["ipv4.routes"]).concat(nmList(nm["ipv6.routes"])),
      routes: routePrefixes(nmList(nm["ipv4.routes"]).concat(nmList(nm["ipv6.routes"]))),
      listenPort: live && live.listenPort ? live.listenPort : toNumber(nm["wireguard.listen-port"]),
      publicKey: live ? live.publicKey || "" : "",
      mtu: iface ? iface.mtu : 0,
      rx: iface ? iface.rx : 0,
      tx: iface ? iface.tx : 0,
      peers: mergePeers(parseNmPeers(nm["wireguard.peers"]), live ? live.peers : null)
    })
  }

  var names = Object.keys(snap.ifaces).sort()
  for (var n = 0; n < names.length; n++) {
    var name = names[n]
    if (claimed[name] || contains(exclude, name)) continue
    var ifc = snap.ifaces[name]
    var dumped = snap.dump[name] || null
    tunnels.push({
      id: "if:" + name,
      kind: contains(wgQuick, name) ? "wgquick" : "external",
      name: name,
      uuid: "",
      device: name,
      state: "activated",
      active: true,
      busy: false,
      autoconnect: false,
      addresses: ifc.addresses,
      dns: [],
      dnsInUse: snap.resolved[name] || [],
      dnsDomainsInUse: snap.domains[name] || [],
      dnsPriority: 0,
      dnsSearch: [],
      neverDefault: { v4: false, v6: false },
      familyOff: { v4: false, v6: false },
      routeSpecs: [],
      routes: [],
      listenPort: dumped ? dumped.listenPort || 0 : 0,
      publicKey: dumped ? dumped.publicKey || "" : "",
      mtu: ifc.mtu,
      rx: ifc.rx,
      tx: ifc.tx,
      peers: dumped ? dumped.peers : []
    })
    claimed[name] = true
  }

  for (var q = 0; q < wgQuick.length; q++) {
    var cfg = String(wgQuick[q] || "")
    if (!isInterfaceName(cfg) || claimed[cfg] || contains(exclude, cfg)) continue
    tunnels.push({
      id: "if:" + cfg, kind: "wgquick", name: cfg, uuid: "", device: "", state: "", active: false, busy: false,
      autoconnect: false, addresses: [], dns: [], dnsInUse: [], dnsDomainsInUse: [], dnsPriority: 0, dnsSearch: [], neverDefault: { v4: false, v6: false }, familyOff: { v4: false, v6: false }, routeSpecs: [], routes: [], listenPort: 0, publicKey: "", mtu: 0, rx: 0, tx: 0, peers: []
    })
  }

  return tunnels
}

// "ok": the tunnel's own DNS servers are what resolved uses on its link.
// "missing": it has DNS servers configured but none of them are in use.
// "none": nothing to check (inactive, or no DNS configured).
function dnsState(tunnel) {
  if (!tunnel || !tunnel.active || !tunnel.dns || tunnel.dns.length === 0) return "none"
  var inUse = tunnel.dnsInUse || []
  for (var i = 0; i < tunnel.dns.length; i++) if (inUse.indexOf(tunnel.dns[i]) !== -1) return "ok"
  return "missing"
}

// The DNS hook (bin/tunnel-dns-dispatcher) version this plugin ships.
var DNS_HOOK_VERSION = 2
// What "Use for all lookups" sets ipv4/ipv6.dns-priority to. Negative is
// NetworkManager's "only this connection's DNS" (see nm-settings dns-priority).
var PREFERRED_DNS_PRIORITY = -50

// Effective priority, NetworkManager style: 0 is "default" (50 for VPNs); the
// better of v4 and v6 counts.
function dnsPriority(v4, v6) {
  var best = null
  var values = [v4, v6]
  for (var i = 0; i < values.length; i++) {
    var n = parseInt(String(values[i] === undefined ? "" : values[i]).trim(), 10)
    if (!isFinite(n) || n === 0) continue
    if (best === null || n < best) best = n
  }
  return best === null ? 50 : best
}

// Has the profile its own "~corp.example" routing domains (split DNS)?
function hasRoutingDomains(tunnel) {
  var list = (tunnel && tunnel.dnsSearch) || []
  for (var i = 0; i < list.length; i++) {
    var d = String(list[i] || "")
    if (d.charAt(0) === "~" && d !== "~" && d !== "~.") return true
  }
  return false
}

// How systemd-resolved is using a connected tunnel's DNS right now:
//   "all"      every lookup without a more specific match (it has "~.")
//   "domains"  only its own routing/search domains
//   "none"     not connected, or no DNS of its own
function dnsRole(tunnel) {
  if (!tunnel || !tunnel.active || !tunnel.dnsInUse || tunnel.dnsInUse.length === 0) return "none"
  return (tunnel.dnsDomainsInUse || []).indexOf("~.") !== -1 ? "all" : "domains"
}

// Connected tunnels that all take every lookup: systemd-resolved asks each
// of them in parallel and goes with whichever answers first.
function dnsCatchAll(tunnels) {
  return (tunnels || []).filter(function(t) { return dnsRole(t) === "all" })
}

// The NetworkManager tunnel marked "use for all lookups" (lowest negative
// priority), or null for automatic.
function preferredDnsTunnel(tunnels) {
  var best = null
  for (var i = 0; i < (tunnels || []).length; i++) {
    var t = tunnels[i]
    if (t.kind !== "nm" || !(t.dnsPriority < 0)) continue
    if (!best || t.dnsPriority < best.dnsPriority) best = t
  }
  return best
}

// Tunnels the DNS choice can point at: NetworkManager profiles with DNS that
// aren't split DNS (a "~corp.example" profile only ever answers its domains).
function dnsChoices(tunnels) {
  return (tunnels || []).filter(function(t) {
    return t.kind === "nm" && t.dns && t.dns.length > 0 && !hasRoutingDomains(t)
  })
}

// nmcli commands that make `chosen` (or nobody, for automatic) the preferred
// DNS tunnel, then reapply connected ones so the change takes effect now.
function preferDnsCommands(tunnels, chosen) {
  var cmds = []
  var reapply = []
  var list = dnsChoices(tunnels)
  for (var i = 0; i < list.length; i++) {
    var t = list[i]
    var want = chosen && t.id === chosen.id
    var value
    if (want && t.dnsPriority !== PREFERRED_DNS_PRIORITY) value = String(PREFERRED_DNS_PRIORITY)
    else if (!want && t.dnsPriority < 0) value = "0"
    else continue
    cmds.push(["nmcli", "connection", "modify", "uuid", t.uuid, "ipv4.dns-priority", value, "ipv6.dns-priority", value])
    if (t.active && isInterfaceName(t.device)) reapply.push(t.device)
  }
  for (var r = 0; r < reapply.length; r++) cmds.push(["nmcli", "device", "reapply", reapply[r]])
  return cmds
}

// ---- addresses, DNS servers and routes typed into the panel ----------

function parseIPv4(text) {
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(text || ""))
  if (!m) return null
  var out = []
  for (var i = 1; i <= 4; i++) {
    if (m[i].length > 1 && m[i].charAt(0) === "0") return null
    var n = parseInt(m[i], 10)
    if (n > 255) return null
    out.push(n)
  }
  return out
}

// Eight 16-bit groups, or null. Embedded dotted IPv4 is not accepted.
function parseIPv6(text) {
  var s = String(text || "").toLowerCase()
  if (!/^[0-9a-f:]{2,39}$/.test(s)) return null
  var halves = s.split("::")
  if (halves.length > 2) return null
  function groups(part) {
    if (part === "") return []
    var g = part.split(":")
    var out = []
    for (var i = 0; i < g.length; i++) {
      if (!/^[0-9a-f]{1,4}$/.test(g[i])) return null
      out.push(parseInt(g[i], 16))
    }
    return out
  }
  var head = groups(halves[0])
  if (!head) return null
  if (halves.length === 1) return head.length === 8 ? head : null
  var tail = groups(halves[1])
  if (!tail) return null
  var fill = 8 - head.length - tail.length
  if (fill < 1) return null
  var zeros = []
  for (var z = 0; z < fill; z++) zeros.push(0)
  return head.concat(zeros, tail)
}

// { family, bits: [0/1 x 32|128], prefix } for "addr" or "addr/prefix".
function parseCidr(text) {
  var s = String(text || "").trim()
  var slash = s.indexOf("/")
  var addr = slash === -1 ? s : s.substring(0, slash)
  var v4 = parseIPv4(addr)
  var v6 = v4 ? null : parseIPv6(addr)
  if (!v4 && !v6) return null
  var width = v4 ? 8 : 16
  var max = v4 ? 32 : 128
  var prefix = max
  if (slash !== -1) {
    var p = s.substring(slash + 1)
    if (!/^\d{1,3}$/.test(p)) return null
    prefix = parseInt(p, 10)
    if (prefix > max) return null
  }
  var bits = []
  var parts = v4 || v6
  for (var i = 0; i < parts.length; i++) for (var b = width - 1; b >= 0; b--) bits.push((parts[i] >> b) & 1)
  return { family: v4 ? "v4" : "v6", bits: bits, prefix: prefix }
}

function cidrContains(net, addr) {
  if (!net || !addr || net.family !== addr.family) return false
  for (var i = 0; i < net.prefix; i++) if (net.bits[i] !== addr.bits[i]) return false
  return true
}

// The network a CIDR names, written back out: "10.73.12.9/24" -> "10.73.12.0/24".
function cidrText(c) {
  var bits = c.bits.slice()
  for (var i = c.prefix; i < bits.length; i++) bits[i] = 0
  var width = c.family === "v4" ? 8 : 16
  var parts = []
  for (var g = 0; g < bits.length; g += width) {
    var n = 0
    for (var b = 0; b < width; b++) n = n * 2 + bits[g + b]
    parts.push(c.family === "v4" ? String(n) : n.toString(16))
  }
  var addr = c.family === "v4" ? parts.join(".") : compressIPv6(parts)
  return addr + "/" + c.prefix
}

function compressIPv6(parts) {
  var best = -1, bestLen = 0
  for (var i = 0; i < parts.length; i++) {
    var j = i
    while (j < parts.length && parts[j] === "0") j++
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i }
    if (j > i) i = j - 1
  }
  if (best === -1) return parts.join(":")
  return parts.slice(0, best).join(":") + "::" + parts.slice(best + bestLen).join(":")
}

function splitInput(text) {
  return String(text || "").split(/[\s,;]+/).filter(function(p) { return p !== "" }).slice(0, 64)
}

// "1.1.1.1, fd00::53" -> { v4: [...], v6: [...], bad: [...] }
function parseDnsServers(text) {
  var out = { v4: [], v6: [], bad: [] }
  var items = splitInput(text)
  for (var i = 0; i < items.length; i++) {
    var item = items[i]
    if (parseIPv4(item)) { if (out.v4.indexOf(item) === -1) out.v4.push(item) }
    else if (parseIPv6(item)) { var v = item.toLowerCase(); if (out.v6.indexOf(v) === -1) out.v6.push(v) }
    else out.bad.push(clip(item))
  }
  return out
}

// "10.73.12.0/24 192.168.1.5" -> networks for ipv4.routes / ipv6.routes. A
// default route (/0) is refused: that is what "Route all traffic" is for.
function parseRoutes(text) {
  var out = { v4: [], v6: [], bad: [] }
  var items = splitInput(text)
  for (var i = 0; i < items.length; i++) {
    var c = parseCidr(items[i])
    if (!c || c.prefix === 0) { out.bad.push(clip(items[i])); continue }
    var t = cidrText(c)
    var list = c.family === "v4" ? out.v4 : out.v6
    if (list.indexOf(t) === -1) list.push(t)
  }
  return out
}

// nmcli -g ipv4.routes entries are "net/prefix [next-hop] [metric] [attr=..]".
function routePrefixes(specs) {
  return (specs || []).map(function(r) { return String(r).trim().split(/\s+/)[0] }).filter(function(r) { return r !== "" })
}

// Networks that go through the tunnel when it isn't routing everything: its
// own subnet(s), the extra routes, and peers' non-default allowed IPs.
function tunnelNetworks(tunnel) {
  if (!tunnel) return []
  var list = (tunnel.addresses || []).concat(tunnel.routes || [])
  var peers = tunnel.peers || []
  for (var i = 0; i < peers.length; i++) list = list.concat(peers[i].allowedIps || [])
  var out = []
  for (var j = 0; j < list.length; j++) {
    var c = parseCidr(list[j])
    if (c && c.prefix > 0) out.push(c)
  }
  return out
}

// Private, CGNAT and link-local ranges (and IPv6 ULA / link-local): where a
// tunnel's own resolver lives. A public resolver such as 1.1.1.1 answers
// over the normal connection just as well, so it's never "unreachable".
var PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"]

function isPrivateAddress(text) {
  var a = parseCidr(text)
  if (!a) return false
  for (var i = 0; i < PRIVATE_NETS.length; i++) if (cidrContains(parseCidr(PRIVATE_NETS[i]), a)) return true
  return false
}

// Private DNS servers a tunnel names that its routes don't reach. With
// "Route all traffic" off, they're asked over the normal connection instead,
// which can't reach them, so lookups time out.
function unroutedDns(tunnel) {
  if (!tunnel || !tunnel.dns || tunnel.dns.length === 0) return []
  var full = defaultRouteFamilies(tunnel)
  var nets = tunnelNetworks(tunnel)
  return tunnel.dns.filter(function(server) {
    var a = parseCidr(server)
    if (!a || !isPrivateAddress(server)) return false
    if (full.indexOf(a.family) !== -1) return false
    for (var i = 0; i < nets.length; i++) if (cidrContains(nets[i], a)) return false
    return true
  })
}

function sameList(a, b) {
  return (a || []).join(",") === (b || []).join(",")
}

// Entries for an address family the profile has switched off (ipv4.method
// disabled): NetworkManager refuses DNS servers and routes for it.
function familyOffEntries(tunnel, parsed) {
  var off = (tunnel && tunnel.familyOff) || {}
  return (off.v4 ? parsed.v4 : []).concat(off.v6 ? parsed.v6 : [])
}

// nmcli commands that set a profile's DNS servers. An active tunnel is
// reapplied so they take effect now. Clearing them takes the tunnel down and
// up again: with system DNS overriding NetworkManager, nothing else removes
// the old servers from the link (the DNS hook skips tunnels without DNS, and
// an in-place `connection up` keeps the same link).
function dnsCommands(tunnel, text) {
  var parsed = parseDnsServers(text)
  if (!tunnel || tunnel.kind !== "nm" || parsed.bad.length > 0) return { commands: [], bad: parsed.bad, off: [] }
  var off = familyOffEntries(tunnel, parsed)
  if (off.length > 0) return { commands: [], bad: [], off: off }
  var next = parsed.v4.concat(parsed.v6)
  if (sameList(next, tunnel.dns)) return { commands: [], bad: [], off: [] }
  var cmds = [["nmcli", "connection", "modify", "uuid", tunnel.uuid, "ipv4.dns", parsed.v4.join(","), "ipv6.dns", parsed.v6.join(",")]]
  if (tunnel.active && isInterfaceName(tunnel.device)) {
    if (next.length === 0) cmds.push(["nmcli", "connection", "down", "uuid", tunnel.uuid], ["nmcli", "connection", "up", "uuid", tunnel.uuid])
    else cmds.push(["nmcli", "device", "reapply", tunnel.device])
  }
  return { commands: cmds, bad: [], off: [] }
}

// Routing changes reconnect an active tunnel: `nmcli device reapply` can
// crash NetworkManager when the WireGuard default route comes back.
function reconnectCommand(tunnel) {
  return tunnel && tunnel.active ? [["nmcli", "connection", "up", "uuid", tunnel.uuid]] : []
}

// Networks to route so the tunnel's own DNS servers stay reachable once it
// stops routing everything: each unreachable server's /24 (IPv4) or /64
// (IPv6), the usual size of the LAN a router's resolver sits on. WireGuard
// has no route advertisement, so this is the one remote network the profile
// itself names.
function suggestedRoutes(tunnel) {
  if (!tunnel || tunnel.kind !== "nm") return []
  var split = Object.assign({}, tunnel, { neverDefault: { v4: true, v6: true } })
  var off = tunnel.familyOff || {}
  var out = []
  var missing = unroutedDns(split)
  for (var i = 0; i < missing.length; i++) {
    var a = parseCidr(missing[i])
    if (!a || off[a.family]) continue
    var net = cidrText({ family: a.family, bits: a.bits, prefix: a.family === "v4" ? 24 : 64 })
    if (out.indexOf(net) === -1) out.push(net)
  }
  return out
}

// Switching "Route all traffic" off also routes the networks above, so the
// tunnel's DNS keeps working without typing anything.
function routeAllCommands(tunnel, on) {
  if (!canRouteAll(tunnel) || routesAll(tunnel) === !!on) return []
  var nd = on ? "no" : "yes"
  var modify = ["nmcli", "connection", "modify", "uuid", tunnel.uuid, "ipv4.never-default", nd, "ipv6.never-default", nd]
  var extra = on ? [] : suggestedRoutes(tunnel)
  if (extra.length > 0) {
    var specs = { v4: [], v6: [] }
    var existing = tunnel.routeSpecs || []
    for (var i = 0; i < existing.length; i++) {
      var c = parseCidr(String(existing[i]).trim().split(/\s+/)[0])
      if (c) specs[c.family].push(String(existing[i]))
    }
    for (var j = 0; j < extra.length; j++) specs[parseCidr(extra[j]).family].push(extra[j])
    modify = modify.concat(["ipv4.routes", specs.v4.join(", "), "ipv6.routes", specs.v6.join(", ")])
  }
  return [modify].concat(reconnectCommand(tunnel))
}

// ---- which lookups a tunnel's DNS answers --------------------------------

// "~home.lan" entries in ipv4/ipv6.dns-search: the domains a split-DNS
// tunnel answers. "~" and "~." aren't domains.
function routingDomains(tunnel) {
  return ((tunnel && tunnel.dnsSearch) || []).filter(function(d) {
    d = String(d || "")
    return d.charAt(0) === "~" && d !== "~" && d !== "~."
  }).map(function(d) { return d.substring(1) })
}

// "all": every lookup while connected. "domains": only names under its
// routing domains; everything else uses the normal DNS.
function dnsScope(tunnel) {
  return hasRoutingDomains(tunnel) ? "domains" : "all"
}

function parseDomains(text) {
  var out = { list: [], bad: [] }
  var items = splitInput(text)
  for (var i = 0; i < items.length; i++) {
    var d = items[i].replace(/^~/, "").replace(/^\./, "").replace(/\.$/, "").toLowerCase()
    if (/^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*$/.test(d) && d.length <= 253) {
      if (out.list.indexOf(d) === -1) out.list.push(d)
    } else {
      out.bad.push(clip(items[i]))
    }
  }
  return out
}

// nmcli commands for the DNS scope. "domains" with an empty list changes
// nothing (empty: true): the panel keeps the domains field open until some
// are typed. Plain search domains are kept either way. Going split also
// drops a "use for all lookups" priority, which no longer applies.
function dnsScopeCommands(tunnel, scope, domainsText) {
  var none = { commands: [], bad: [], off: [], empty: false }
  if (!tunnel || tunnel.kind !== "nm") return none
  var keep = ((tunnel && tunnel.dnsSearch) || []).filter(function(d) {
    d = String(d || "")
    return d.charAt(0) !== "~" || d === "~" || d === "~."
  })
  var next = keep
  if (scope === "domains") {
    var parsed = parseDomains(domainsText)
    if (parsed.bad.length > 0) return { commands: [], bad: parsed.bad, off: [], empty: false }
    if (parsed.list.length === 0) return { commands: [], bad: [], off: [], empty: true }
    next = keep.concat(parsed.list.map(function(d) { return "~" + d }))
  }
  if (sameList(next, tunnel.dnsSearch)) return none
  var off = tunnel.familyOff || {}
  var v4 = off.v4 ? "" : next.join(",")
  var v6 = off.v4 && !off.v6 ? next.join(",") : ""
  var modify = ["nmcli", "connection", "modify", "uuid", tunnel.uuid, "ipv4.dns-search", v4, "ipv6.dns-search", v6]
  if (scope === "domains" && tunnel.dnsPriority < 0) modify = modify.concat(["ipv4.dns-priority", "0", "ipv6.dns-priority", "0"])
  var cmds = [modify]
  if (tunnel.active && isInterfaceName(tunnel.device)) cmds.push(["nmcli", "device", "reapply", tunnel.device])
  return { commands: cmds, bad: [], off: [], empty: false }
}

// Keeps an existing route's next-hop and metric when its network is kept.
function routesCommands(tunnel, text) {
  var parsed = parseRoutes(text)
  if (!tunnel || tunnel.kind !== "nm" || parsed.bad.length > 0) return { commands: [], bad: parsed.bad, off: [] }
  var off = familyOffEntries(tunnel, parsed)
  if (off.length > 0) return { commands: [], bad: [], off: off }
  if (sameList(parsed.v4.concat(parsed.v6), (tunnel.routes || []).map(function(r) { var c = parseCidr(r); return c ? cidrText(c) : r }))) return { commands: [], bad: [], off: [] }
  var specs = {}
  for (var i = 0; i < (tunnel.routeSpecs || []).length; i++) {
    var spec = String(tunnel.routeSpecs[i])
    var c = parseCidr(spec.trim().split(/\s+/)[0])
    if (c) specs[cidrText(c)] = spec
  }
  function full(list) { return list.map(function(n) { return specs[n] || n }).join(", ") }
  return {
    commands: [["nmcli", "connection", "modify", "uuid", tunnel.uuid, "ipv4.routes", full(parsed.v4), "ipv6.routes", full(parsed.v6)]].concat(reconnectCommand(tunnel)),
    bad: [],
    off: []
  }
}

// bin/wg-since output: "<device>\t<epoch seconds>" lines -> { device: ms }.
function parseActivations(raw) {
  var out = {}
  var lines = String(raw || "").split("\n").slice(0, 256)
  for (var i = 0; i < lines.length; i++) {
    var f = lines[i].split("\t")
    if (f.length !== 2 || !isInterfaceName(f[0]) || !/^\d{9,11}(\.\d+)?$/.test(f[1])) continue
    out[f[0]] = Math.round(Number(f[1]) * 1000)
  }
  return out
}

function isInterfaceName(name) {
  return /^[A-Za-z0-9_=+.-]{1,15}$/.test(String(name || ""))
}

function canToggle(tunnel) {
  return !!tunnel && (tunnel.kind === "nm" || tunnel.kind === "wgquick")
}

function upCommand(tunnel) {
  if (!tunnel) return []
  if (tunnel.kind === "nm") return ["nmcli", "connection", "up", "uuid", tunnel.uuid]
  if (tunnel.kind === "wgquick" && isInterfaceName(tunnel.name)) return ["pkexec", "wg-quick", "up", tunnel.name]
  return []
}

function downCommand(tunnel) {
  if (!tunnel) return []
  if (tunnel.kind === "nm") return ["nmcli", "connection", "down", "uuid", tunnel.uuid]
  if (tunnel.kind === "wgquick" && isInterfaceName(tunnel.name)) return ["pkexec", "wg-quick", "down", tunnel.name]
  return []
}

// Per-interface byte rates from two counter samples.
function throughput(previous, ifaces, now) {
  var prev = previous || { time: 0, counters: {} }
  var counters = {}
  var rates = {}
  var dt = prev.time > 0 ? (now - prev.time) / 1000 : 0
  var names = Object.keys(ifaces || {})
  for (var i = 0; i < names.length; i++) {
    var name = names[i]
    var cur = ifaces[name]
    counters[name] = { rx: cur.rx, tx: cur.tx }
    var old = prev.counters[name]
    // Counters reset when an interface is recreated; never report negatives.
    if (old && dt > 0 && cur.rx >= old.rx && cur.tx >= old.tx) rates[name] = { rx: (cur.rx - old.rx) / dt, tx: (cur.tx - old.tx) / dt }
    else rates[name] = { rx: 0, tx: 0 }
  }
  return { time: now, counters: counters, rates: rates }
}

// Keeps samples (each with an `at` timestamp in ms) from the last windowMs.
// Sampling is every second with the panel open and every few seconds when it
// is closed, so the graph is plotted by time, not by sample count.
function trimHistory(history, nowMs, windowMs) {
  return (history || []).filter(function(s) { return s && s.at >= nowMs - windowMs })
}

function pushHistory(history, sample, limit) {
  var next = (history || []).slice(Math.max(0, (history || []).length - (limit - 1)))
  next.push(sample)
  return next
}

function formatBytes(bytes, fmt) {
  var f = formatter(fmt)
  var n = toNumber(bytes)
  if (n < 1024) return f(Math.round(n)) + " B"
  if (n < 1024 * 1024) return f(n / 1024, 1) + " KB"
  if (n < 1024 * 1024 * 1024) return f(n / (1024 * 1024), 1) + " MB"
  if (n < 1024 * 1024 * 1024 * 1024) return f(n / (1024 * 1024 * 1024), 2) + " GB"
  return f(n / (1024 * 1024 * 1024 * 1024), 2) + " TB"
}

function formatRate(bytesPerSec, fmt) {
  return formatBytes(bytesPerSec, fmt) + "/s"
}

// Compact rate for the bar label: "1.2M", "830K", "0".
function formatRateShort(bytesPerSec, fmt) {
  var f = formatter(fmt)
  var n = toNumber(bytesPerSec)
  if (n < 1024) return f(Math.round(n))
  if (n < 1024 * 1024) return f(Math.round(n / 1024)) + "K"
  if (n < 1024 * 1024 * 1024) return f(n / (1024 * 1024), 1) + "M"
  return f(n / (1024 * 1024 * 1024), 1) + "G"
}

// Seconds → "12s", "4m 03s", "2h 15m", "3d 4h". Returns "" for <0.
function formatDuration(seconds) {
  var s = Math.floor(Number(seconds))
  if (!isFinite(s) || s < 0) return ""
  if (s < 60) return s + "s"
  var m = Math.floor(s / 60)
  if (m < 60) return m + "m " + (s % 60 < 10 ? "0" : "") + (s % 60) + "s"
  var h = Math.floor(m / 60)
  if (h < 24) return h + "h " + (m % 60) + "m"
  return Math.floor(h / 24) + "d " + (h % 24) + "h"
}

// "ok" | "stale" | "never" | "unknown" (no live stats).
function peerHealth(peer, nowSec) {
  if (!peer || !peer.live) return "unknown"
  if (!peer.handshake) return "never"
  var age = nowSec - peer.handshake
  // WireGuard re-handshakes every 2 minutes while traffic flows; idle peers
  // without keepalive legitimately go quiet, so only flag peers that should
  // be chatting.
  if (age > STALE_HANDSHAKE_SEC && peer.keepalive > 0) return "stale"
  return "ok"
}

// rxQuietSec: seconds since the interface's receive counter last moved (-1 if
// unknown). Without root we cannot see handshakes, but a peer with keepalive
// set triggers a re-handshake about every two minutes, and every handshake
// response bumps rx. So a long-silent rx on a keepalive tunnel means the
// other end has stopped answering.
function tunnelHealth(tunnel, nowSec, rxQuietSec) {
  if (!tunnel || !tunnel.active) return "off"
  var sawLive = false
  var wantsKeepalive = false
  for (var i = 0; i < tunnel.peers.length; i++) {
    var h = peerHealth(tunnel.peers[i], nowSec)
    if (h === "ok") return "ok"
    if (h !== "unknown") sawLive = true
    if (tunnel.peers[i].keepalive > 0) wantsKeepalive = true
  }
  if (sawLive) return "degraded"
  var quiet = Number(rxQuietSec)
  if (!isFinite(quiet) || quiet < 0) return "unknown"
  if (wantsKeepalive && quiet > STALE_HANDSHAKE_SEC) return "degraded"
  return "ok"
}

// Address families a tunnel's peers claim the whole of: "v4" and/or "v6".
// Counts 0.0.0.0/0 and ::/0, plus the 0.0.0.0/1 + 128.0.0.0/1 (and ::/1 +
// 8000::/1) split some configs use to outrank the normal default route.
// `zeroOnly`: true counts just the /0 form (the one never-default switches
// off), "halves" just the /1 pair.
function peerDefaultFamilies(tunnel, zeroOnly) {
  var all = []
  var peers = tunnel && tunnel.peers ? tunnel.peers : []
  for (var i = 0; i < peers.length; i++) all = all.concat(peers[i].allowedIps || [])
  var nets = all.map(function(a) { return String(a).trim().toLowerCase() })
  var has = function(n) { return nets.indexOf(n) !== -1 }
  var zero = { v4: has("0.0.0.0/0"), v6: has("::/0") }
  var halves = { v4: has("0.0.0.0/1") && has("128.0.0.0/1"), v6: has("::/1") && has("8000::/1") }
  var fams = []
  var families = ["v4", "v6"]
  for (var f = 0; f < families.length; f++) {
    var fam = families[f]
    if (zeroOnly === "halves" ? halves[fam] : (zero[fam] || (!zeroOnly && halves[fam]))) fams.push(fam)
  }
  return fams
}

// Which address families a tunnel actually takes the default route for.
// NetworkManager skips a peer's /0 route when ipv4/ipv6.never-default is set
// (the "Route all traffic" switch); the /1 halves are ordinary routes and
// still apply.
function defaultRouteFamilies(tunnel) {
  var nd = (tunnel && tunnel.neverDefault) || {}
  var halves = peerDefaultFamilies(tunnel, "halves")
  return peerDefaultFamilies(tunnel, false).filter(function(f) { return !nd[f] || halves.indexOf(f) !== -1 })
}

// Whether the "Route all traffic" switch means anything for this tunnel: a
// NetworkManager profile whose peer allows 0.0.0.0/0 or ::/0.
function canRouteAll(tunnel) {
  return !!tunnel && tunnel.kind === "nm" && peerDefaultFamilies(tunnel, true).length > 0
}

function routesAll(tunnel) {
  return defaultRouteFamilies(tunnel).length > 0
}

// Active tunnels that would fight `target` for the default route: they claim
// all traffic for an address family `target` also claims. Split tunnels
// (specific networks only) never conflict and can run side by side.
function routeConflicts(target, tunnels) {
  var mine = defaultRouteFamilies(target)
  if (mine.length === 0) return []
  return (tunnels || []).filter(function(t) {
    if (!t || !t.active || !target || t.id === target.id) return false
    return defaultRouteFamilies(t).some(function(f) { return mine.indexOf(f) !== -1 })
  })
}

// NetworkManager profiles are deleted outright (the profile, not any .conf
// you imported it from). wg-quick configs live in root-owned /etc/wireguard,
// so "removing" one only drops it from the widget's list.
function removeCommand(tunnel) {
  if (!tunnel || tunnel.kind !== "nm" || !/^[0-9a-fA-F-]{36}$/.test(String(tunnel.uuid || ""))) return []
  return ["nmcli", "connection", "delete", "uuid", tunnel.uuid]
}

function canRemove(tunnel) {
  return !!tunnel && (tunnel.kind === "nm" || tunnel.kind === "wgquick")
}

// ipinfo.io/json → { ip, place, org } with every field bounded and checked.
function parseIpInfo(raw) {
  var text = String(raw || "")
  if (text.length > 4096) return null
  var data
  try { data = JSON.parse(text) } catch (e) { return null }
  if (!data || typeof data !== "object") return null
  var ip = String(data.ip || "")
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip)) return null
  function field(v) {
    return String(v === undefined || v === null ? "" : v).replace(/[\u0000-\u001f]/g, "").substring(0, 64).trim()
  }
  var city = field(data.city)
  var country = field(data.country)
  var place = city !== "" && country !== "" ? city + ", " + country : (city || country)
  // "AS13335 Cloudflare, Inc." → "Cloudflare, Inc."
  var org = field(data.org).replace(/^AS\d+\s+/, "")
  return { ip: ip, place: place, org: org }
}

function shortKey(key) {
  var k = String(key || "")
  return k.length > 12 ? k.substring(0, 6) + "…" + k.substring(k.length - 5, k.length - 1) : k
}

function firstAddress(tunnel) {
  if (!tunnel || !tunnel.addresses || tunnel.addresses.length === 0) return ""
  return String(tunnel.addresses[0]).replace(/\/\d+$/, "")
}

if (typeof module !== "undefined") {
  module.exports = {
    splitTerse: splitTerse,
    parseNmPeers: parseNmPeers,
    parseSnapshot: parseSnapshot,
    mergeSnapshot: mergeSnapshot,
    emptySnapshot: emptySnapshot,
    buildTunnels: buildTunnels,
    isInterfaceName: isInterfaceName,
    dnsState: dnsState,
    canToggle: canToggle,
    upCommand: upCommand,
    downCommand: downCommand,
    throughput: throughput,
    pushHistory: pushHistory,
    trimHistory: trimHistory,
    DNS_HOOK_VERSION: DNS_HOOK_VERSION,
    PREFERRED_DNS_PRIORITY: PREFERRED_DNS_PRIORITY,
    dnsPriority: dnsPriority,
    hasRoutingDomains: hasRoutingDomains,
    dnsRole: dnsRole,
    dnsCatchAll: dnsCatchAll,
    preferredDnsTunnel: preferredDnsTunnel,
    dnsChoices: dnsChoices,
    preferDnsCommands: preferDnsCommands,
    formatBytes: formatBytes,
    formatRate: formatRate,
    formatRateShort: formatRateShort,
    formatDuration: formatDuration,
    peerHealth: peerHealth,
    tunnelHealth: tunnelHealth,
    defaultRouteFamilies: defaultRouteFamilies,
    peerDefaultFamilies: peerDefaultFamilies,
    canRouteAll: canRouteAll,
    routesAll: routesAll,
    parseCidr: parseCidr,
    cidrText: cidrText,
    parseDnsServers: parseDnsServers,
    parseRoutes: parseRoutes,
    unroutedDns: unroutedDns,
    isPrivateAddress: isPrivateAddress,
    parseActivations: parseActivations,
    dnsCommands: dnsCommands,
    routeAllCommands: routeAllCommands,
    routesCommands: routesCommands,
    suggestedRoutes: suggestedRoutes,
    routingDomains: routingDomains,
    dnsScope: dnsScope,
    parseDomains: parseDomains,
    dnsScopeCommands: dnsScopeCommands,
    routeConflicts: routeConflicts,
    removeCommand: removeCommand,
    canRemove: canRemove,
    parseIpInfo: parseIpInfo,
    shortKey: shortKey,
    firstAddress: firstAddress
  }
}
