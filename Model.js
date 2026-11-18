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
  return { ifaces: {}, conns: [], nm: {}, dump: {}, stats: "", resolved: {}, globalDns: false, dnsFix: false, full: false }
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
    } else if (tag === "G" && f.length >= 3) {
      snap.globalDns = f[1] === "yes"
      snap.dnsFix = f[2] === "yes"
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
    resolved: prev.resolved, globalDns: prev.globalDns, dnsFix: prev.dnsFix, full: false
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
      addresses: iface && iface.addresses.length > 0 ? iface.addresses : splitList(nm["ipv4.addresses"], ",").concat(splitList(nm["ipv6.addresses"], ",")),
      dns: splitList(nm["ipv4.dns"], ",").concat(splitList(nm["ipv6.dns"], ",")),
      dnsInUse: activated && c.device && snap.resolved[c.device] ? snap.resolved[c.device] : [],
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
      autoconnect: false, addresses: [], dns: [], dnsInUse: [], listenPort: 0, publicKey: "", mtu: 0, rx: 0, tx: 0, peers: []
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
    formatBytes: formatBytes,
    formatRate: formatRate,
    formatRateShort: formatRateShort,
    formatDuration: formatDuration,
    peerHealth: peerHealth,
    tunnelHealth: tunnelHealth,
    removeCommand: removeCommand,
    canRemove: canRemove,
    parseIpInfo: parseIpInfo,
    shortKey: shortKey,
    firstAddress: firstAddress
  }
}
