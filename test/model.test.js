const assert = require("assert")
const fs = require("fs")
const path = require("path")
const M = require("../Model.js")

const K1 = "wHtkTOnBb3RbJkod+0jT3pNjdTOUBT9HQ6y7cPg9LmY="
const K2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA="
const UUID = "57bb22c7-f66d-40bd-8da0-af495f9b541c"

assert.deepStrictEqual(M.splitTerse("a\\:b:c\\\\d:"), ["a:b", "c\\d", ""])

const peers = M.parseNmPeers(K1 + " allowed-ips=10.0.0.0/24;10.1.0.0/16 endpoint=vpn.example\\:51820 persistent-keepalive=25, " + K2 + " allowed-ips=0.0.0.0/0")
assert.strictEqual(peers.length, 2)
assert.strictEqual(peers[0].endpoint, "vpn.example:51820")
assert.deepStrictEqual(peers[0].allowedIps, ["10.0.0.0/24", "10.1.0.0/16"])
assert.strictEqual(peers[0].keepalive, 25)
assert.strictEqual(peers[1].endpoint, "")
assert.deepStrictEqual(M.parseNmPeers(""), [])
assert.deepStrictEqual(M.parseNmPeers("not-a-key allowed-ips=1.2.3.4/32"), [])

const raw = [
  "I\thome\t1000\t2000\t1420\t10.99.0.2/32,fd00::2/128",
  "I\twt0\t5\t6\t1280\t100.1.2.3/16",
  "I\troadwarrior\t1\t2\t1420\t10.7.0.2/32",
  "C\thome:" + UUID + ":wireguard:home:activated:/etc/NetworkManager/system-connections/home.nmconnection:yes",
  "C\tweird\\:name:11111111-2222-3333-4444-555555555555:wireguard:::/etc/NetworkManager/system-connections/weird.nmconnection:no",
  "C\twt0:be5e7f7e-151a-4ebe-a79a-b24c238800de:wireguard:wt0:activated:/run/NetworkManager/system-connections/wt0.nmconnection:yes",
  "N\t" + UUID + "\twireguard.peers\t" + K1 + " allowed-ips=10.99.0.0/24 endpoint=192.0.2.1\\:51820 persistent-keepalive=25",
  "N\t" + UUID + "\twireguard.listen-port\t51999",
  "D\thome\t(hidden)\t" + K2 + "\t51999\toff",
  "D\thome\t" + K1 + "\t(hidden)\t198.51.100.7:51820\t10.99.0.0/24\t1700000000\t111\t222\t25",
  "S\tok"
].join("\n")

const snap = M.parseSnapshot(raw)
assert.strictEqual(snap.full, true)
assert.strictEqual(snap.stats, "ok")
assert.strictEqual(snap.conns[1].name, "weird:name")

const tunnels = M.buildTunnels(snap, { excludeInterfaces: ["wt0"], wgQuickConfigs: ["roadwarrior", "office", "bad;name"] })
const ids = tunnels.map(t => t.id)
assert.deepStrictEqual(ids, ["nm:" + UUID, "nm:11111111-2222-3333-4444-555555555555", "if:roadwarrior", "if:office"])
const home = tunnels[0]
assert.strictEqual(home.active, true)
assert.strictEqual(home.autoconnect, true)
assert.deepStrictEqual(home.addresses, ["10.99.0.2/32", "fd00::2/128"])
assert.strictEqual(home.peers.length, 1)
assert.strictEqual(home.peers[0].endpoint, "198.51.100.7:51820", "live endpoint wins over configured")
assert.strictEqual(home.peers[0].live, true)
assert.strictEqual(home.publicKey, K2)
assert.strictEqual(tunnels[1].active, false)
assert.strictEqual(tunnels[2].kind, "wgquick")
assert.strictEqual(tunnels[2].active, true)
assert.strictEqual(tunnels[3].active, false)

// Without the exclude, a foreign live interface shows up read-only.
const ext = M.buildTunnels(snap, {}).filter(t => t.name === "wt0")[0]
assert.strictEqual(ext.kind, "external")
assert.strictEqual(M.canToggle(ext), false)
assert.deepStrictEqual(M.upCommand(ext), [])

assert.deepStrictEqual(M.upCommand(home), ["nmcli", "connection", "up", "uuid", UUID])
assert.deepStrictEqual(M.downCommand(tunnels[2]), ["pkexec", "wg-quick", "down", "roadwarrior"])
assert.strictEqual(M.isInterfaceName("a; rm -rf /"), false)

// Fast polls keep config from the last full poll.
const fast = M.parseSnapshot("I\thome\t5000\t9000\t1420\t10.99.0.2/32")
const merged = M.mergeSnapshot(snap, fast)
assert.strictEqual(merged.conns.length, 3)
assert.strictEqual(merged.ifaces.home.rx, 5000)

let tp = M.throughput(null, snap.ifaces, 1000)
assert.deepStrictEqual(tp.rates.home, { rx: 0, tx: 0 })
tp = M.throughput(tp, merged.ifaces, 3000)
assert.deepStrictEqual(tp.rates.home, { rx: 2000, tx: 3500 })
tp = M.throughput(tp, { home: { rx: 10, tx: 10 } }, 4000)
assert.deepStrictEqual(tp.rates.home, { rx: 0, tx: 0 }, "counter reset is not negative")

assert.strictEqual(M.peerHealth(home.peers[0], 1700000060), "ok")
assert.strictEqual(M.peerHealth(home.peers[0], 1700000500), "stale")
assert.strictEqual(M.peerHealth({ live: true, handshake: 0 }, 1), "never")
assert.strictEqual(M.peerHealth({ live: false }, 1), "unknown")
assert.strictEqual(M.tunnelHealth(home, 1700000500), "degraded")
assert.strictEqual(M.tunnelHealth(tunnels[1], 0), "off")

assert.strictEqual(M.formatBytes(1536), "1.5 KB")
assert.strictEqual(M.formatRate(0), "0 B/s")
assert.strictEqual(M.formatRateShort(1572864), "1.5M")
assert.strictEqual(M.formatDuration(243), "4m 03s")
assert.strictEqual(M.formatDuration(90061), "1d 1h")
assert.strictEqual(M.firstAddress(home), "10.99.0.2")

const hist = M.pushHistory([1, 2, 3], 4, 3)
assert.deepStrictEqual(hist, [2, 3, 4])

// Unprivileged health: keepalive tunnel with rx silent > 180s is degraded.
const blind = { active: true, peers: [{ live: false, keepalive: 25 }] }
assert.strictEqual(M.tunnelHealth(blind, 0, -1), "unknown")
assert.strictEqual(M.tunnelHealth(blind, 0, 30), "ok")
assert.strictEqual(M.tunnelHealth(blind, 0, 400), "degraded")
assert.strictEqual(M.tunnelHealth({ active: true, peers: [{ live: false, keepalive: 0 }] }, 0, 400), "ok", "idle peers without keepalive go quiet legitimately")

assert.deepStrictEqual(M.removeCommand(home), ["nmcli", "connection", "delete", "uuid", UUID])
assert.deepStrictEqual(M.removeCommand(tunnels[2]), [], "wg-quick configs are never deleted")
assert.deepStrictEqual(M.removeCommand({ kind: "nm", uuid: "x; rm -rf ~" }), [])
assert.strictEqual(M.canRemove(tunnels[2]), true)
assert.strictEqual(M.canRemove(ext), false)

assert.deepStrictEqual(M.parseIpInfo(JSON.stringify({ ip: "203.0.113.10", city: "Amsterdam", country: "NL", org: "AS64500 Example Networks Ltd" })),
  { ip: "203.0.113.10", place: "Amsterdam, NL", org: "Example Networks Ltd" })
assert.strictEqual(M.parseIpInfo("<html>"), null)
assert.strictEqual(M.parseIpInfo(JSON.stringify({ ip: "<img src=x>" })), null)
assert.strictEqual(M.parseIpInfo("x".repeat(5000)), null)
assert.strictEqual(M.parseIpInfo(JSON.stringify({ ip: "1.2.3.4", city: "a".repeat(500) })).place.length, 64)

// Tunnel DNS: configured vs what resolved actually uses on the link.
const dnsSnap = M.parseSnapshot([
  "I\thome\t1\t2\t1420\t10.99.0.2/32",
  "C\thome:" + UUID + ":wireguard:home:activated:/etc/NetworkManager/system-connections/home.nmconnection:yes",
  "N\t" + UUID + "\tipv4.dns\t10.0.0.53",
  "N\t" + UUID + "\tipv6.dns\t",
  "R\thome\t",
  "G\tyes\tno"
].join("\n"))
assert.strictEqual(dnsSnap.globalDns, true)
assert.strictEqual(dnsSnap.dnsFix, false)
let dnsT = M.buildTunnels(dnsSnap, {})[0]
assert.deepStrictEqual(dnsT.dns, ["10.0.0.53"])
assert.strictEqual(M.dnsState(dnsT), "missing")
dnsSnap.resolved.home = ["10.0.0.53"]
dnsT = M.buildTunnels(dnsSnap, {})[0]
assert.strictEqual(M.dnsState(dnsT), "ok")
assert.strictEqual(M.dnsState(Object.assign({}, dnsT, { active: false })), "none")
const keptDns = M.mergeSnapshot(dnsSnap, M.parseSnapshot("I\thome\t5\t6\t1420\t10.99.0.2/32"))
assert.strictEqual(keptDns.globalDns, true, "fast polls keep the DNS checks")

// Every Text in the plugin's QML must be PlainText: tunnel and peer names are user/network data.
for (const file of fs.readdirSync(path.join(__dirname, "..")).filter(f => f.endsWith(".qml"))) {
  const src = fs.readFileSync(path.join(__dirname, "..", file), "utf8")
  const lines = src.split("\n")
  lines.forEach((line, i) => {
    if (!/^\s*Text\s*\{/.test(line)) return
    let depth = 0, ok = false
    for (let j = i; j < lines.length; j++) {
      if (j > i && depth === 1 && /textFormat:\s*Text\.PlainText/.test(lines[j])) ok = true
      depth += (lines[j].match(/\{/g) || []).length
      depth -= (lines[j].match(/\}/g) || []).length
      if (depth === 0) break
    }
    assert.ok(ok, `${file}:${i + 1} Text without textFormat: Text.PlainText`)
  })
}

// ---- default-route conflicts ----------------------------------------------
{
  const mk = (id, active, ...ips) => ({ id, name: id, active, peers: [{ allowedIps: ips }] })
  const fullV4 = mk("a", true, "0.0.0.0/0")
  const fullBoth = mk("b", false, "0.0.0.0/0", "::/0")
  const split = mk("c", true, "10.0.0.0/24")
  const halves = mk("d", true, "0.0.0.0/1", "128.0.0.0/1")
  const onlyHalf = mk("e", true, "0.0.0.0/1")
  const v6 = mk("f", true, "::/0")
  assert.deepStrictEqual(M.defaultRouteFamilies(fullBoth), ["v4", "v6"])
  assert.deepStrictEqual(M.defaultRouteFamilies(split), [])
  assert.deepStrictEqual(M.defaultRouteFamilies(halves), ["v4"])
  assert.deepStrictEqual(M.defaultRouteFamilies(onlyHalf), [])
  assert.deepStrictEqual(M.defaultRouteFamilies({ peers: [] }), [])
  assert.deepStrictEqual(M.defaultRouteFamilies(null), [])
  const ids = (l) => l.map((t) => t.id).sort()
  // Full tunnel coming up displaces the active full ones of the same family, not split ones.
  assert.deepStrictEqual(ids(M.routeConflicts(fullBoth, [fullV4, split, halves, onlyHalf, v6, fullBoth])), ["a", "d", "f"])
  // Split tunnels never conflict, in either direction.
  assert.deepStrictEqual(M.routeConflicts(split, [fullV4, halves]), [])
  // v4-only and v6-only full tunnels coexist.
  assert.deepStrictEqual(M.routeConflicts(mk("g", false, "::/0"), [fullV4]), [])
  // Inactive tunnels and the target itself are ignored.
  assert.deepStrictEqual(M.routeConflicts(fullV4, [Object.assign({}, fullV4), mk("h", false, "0.0.0.0/0")]), [])
}

{
  const h = [{ at: 1000 }, { at: 30000 }, { at: 61000 }, { at: 90000 }]
  assert.deepStrictEqual(M.trimHistory(h, 90000, 60000).map((s) => s.at), [30000, 61000, 90000])
  assert.deepStrictEqual(M.trimHistory(null, 1, 1), [])
}

{
  assert.strictEqual(M.dnsPriority("0", "0"), 50)
  assert.strictEqual(M.dnsPriority("-50", "0"), -50)
  assert.strictEqual(M.dnsPriority("100", "-5"), -5)
  assert.strictEqual(M.dnsPriority(undefined, ""), 50)

  const snap = M.parseSnapshot([
    "R\twg0\t10.0.0.53",
    "Q\twg0\t~.",
    "R\twg1\t10.9.0.53",
    "Q\twg1\tcorp.example ~corp.example",
    "G\tyes\tyes\t2"
  ].join("\n"))
  assert.deepStrictEqual(snap.domains.wg1, ["corp.example", "~corp.example"])
  assert.strictEqual(snap.hookVersion, 2)
  assert.strictEqual(M.parseSnapshot("G\tyes\tyes").hookVersion, 1)
  assert.strictEqual(M.parseSnapshot("G\tyes\tno\t0").hookVersion, 0)
  const foreign = M.parseSnapshot("G\tyes\tforeign\t0")
  assert.strictEqual(foreign.dnsFix, false)
  assert.strictEqual(foreign.dnsFixForeign, true)
  assert.strictEqual(foreign.hookVersion, 0)
  assert.strictEqual(M.mergeSnapshot(foreign, M.parseSnapshot("I\twg0\t1\t2\t1420\t")).dnsFixForeign, true)
  assert.strictEqual(M.mergeSnapshot(snap, M.parseSnapshot("I\twg0\t1\t2\t1420\t")).hookVersion, 2)

  const mk = (id, extra) => Object.assign({ id: "nm:" + id, kind: "nm", uuid: id, device: id, active: true,
    dns: ["10.0.0.53"], dnsInUse: ["10.0.0.53"], dnsDomainsInUse: ["~."], dnsPriority: 50, dnsSearch: [] }, extra)
  const a = mk("a"), b = mk("b"), c = mk("c", { dnsDomainsInUse: ["~corp.example"], dnsSearch: ["~corp.example"] })
  assert.strictEqual(M.dnsRole(a), "all")
  assert.strictEqual(M.dnsRole(c), "domains")
  assert.strictEqual(M.dnsRole(mk("d", { active: false })), "none")
  assert.ok(M.hasRoutingDomains(c) && !M.hasRoutingDomains(mk("e", { dnsSearch: ["~"] })))
  assert.deepStrictEqual(M.dnsCatchAll([a, b, c]).map((t) => t.id), ["nm:a", "nm:b"])
  assert.strictEqual(M.preferredDnsTunnel([a, b]), null)

  // Choosing b: b goes negative, then connected ones are reapplied.
  assert.deepStrictEqual(M.preferDnsCommands([a, b, c], b), [
    ["nmcli", "connection", "modify", "uuid", "b", "ipv4.dns-priority", "-50", "ipv6.dns-priority", "-50"],
    ["nmcli", "device", "reapply", "b"]
  ])
  // Switching from b to a resets b; back to automatic resets everyone negative.
  const bPref = mk("b", { dnsPriority: -50 })
  assert.strictEqual(M.preferredDnsTunnel([a, bPref]).id, "nm:b")
  assert.deepStrictEqual(M.preferDnsCommands([a, bPref], a).map((cmd) => cmd.slice(0, 7).join(" ")), [
    "nmcli connection modify uuid a ipv4.dns-priority -50",
    "nmcli connection modify uuid b ipv4.dns-priority 0",
    "nmcli device reapply a",
    "nmcli device reapply b"
  ])
  assert.deepStrictEqual(M.preferDnsCommands([a, bPref], null).length, 2)
  assert.deepStrictEqual(M.preferDnsCommands([a, b], null), [])
  assert.deepStrictEqual(M.dnsChoices([a, b, c]).map((t) => t.id), ["nm:a", "nm:b"])
  // nmcli -g escapes colons in IPv6 values.
  const t6 = M.buildTunnels(M.parseSnapshot([
    "C\tv6:" + UUID + ":wireguard:::/etc/NetworkManager/system-connections/v6.nmconnection:no",
    "N\t" + UUID + "\tipv6.dns\tfd00\\:\\:53,fd00\\:\\:54",
    "N\t" + UUID + "\tipv6.addresses\tfd00\\:\\:2/64"
  ].join("\n")), {})[0]
  assert.deepStrictEqual(t6.dns, ["fd00::53", "fd00::54"])
  assert.deepStrictEqual(t6.addresses, ["fd00::2/64"])
  // wg-quick and DNS-less tunnels are never touched.
  assert.deepStrictEqual(M.preferDnsCommands([mk("w", { kind: "wgquick" }), mk("x", { dns: [] })], null), [])
}

// ---- custom DNS servers and "Route all traffic" ----
{
  const mkt = (over) => Object.assign({ id: "nm:x", kind: "nm", uuid: UUID, device: "home", active: true, addresses: ["10.1.0.2/24"], dns: ["10.73.12.53"], routes: [], routeSpecs: [], neverDefault: { v4: false, v6: false }, peers: [{ allowedIps: ["0.0.0.0/0"] }] }, over || {})
  // never-default switches the /0 route off, but not the /1 halves.
  assert.deepStrictEqual(M.defaultRouteFamilies(mkt()), ["v4"])
  assert.deepStrictEqual(M.defaultRouteFamilies(mkt({ neverDefault: { v4: true, v6: true } })), [])
  assert.deepStrictEqual(M.defaultRouteFamilies(mkt({ neverDefault: { v4: true }, peers: [{ allowedIps: ["0.0.0.0/1", "128.0.0.0/1"] }] })), ["v4"])
  assert.deepStrictEqual(M.defaultRouteFamilies(mkt({ neverDefault: { v4: true }, peers: [{ allowedIps: ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"] }] })), ["v4"])
  assert.strictEqual(M.canRouteAll(mkt()), true)
  assert.strictEqual(M.canRouteAll(mkt({ peers: [{ allowedIps: ["10.0.0.0/8"] }] })), false)
  assert.strictEqual(M.canRouteAll(mkt({ kind: "wgquick" })), false)
  // A split tunnel no longer fights a full one for the default route.
  const other = mkt({ id: "nm:y" })
  assert.deepStrictEqual(M.routeConflicts(mkt({ neverDefault: { v4: true, v6: true } }), [other]), [])
  assert.strictEqual(M.routeConflicts(mkt(), [other]).length, 1)

  assert.deepStrictEqual(M.parseDnsServers("1.1.1.1, fd00::53 1.1.1.1;FD00::54"), { v4: ["1.1.1.1"], v6: ["fd00::53", "fd00::54"], bad: [] })
  assert.deepStrictEqual(M.parseDnsServers("1.1.1.256 01.2.3.4 host.example ::1::2 $(x)").bad.length, 5)
  assert.deepStrictEqual(M.parseDnsServers(""), { v4: [], v6: [], bad: [] })
  assert.deepStrictEqual(M.parseRoutes("10.73.12.9/24 192.168.1.5 fd00:99::1/64"), { v4: ["10.73.12.0/24", "192.168.1.5/32"], v6: ["fd00:99::/64"], bad: [] })
  assert.deepStrictEqual(M.parseRoutes("0.0.0.0/0 ::/0 10.0.0.0/33 x").bad, ["0.0.0.0/0", "::/0", "10.0.0.0/33", "x"])
  assert.strictEqual(M.cidrText(M.parseCidr("2001:db8:0:0:1:0:0:1/128")), "2001:db8::1:0:0:1/128")

  // DNS outside the tunnel's networks is flagged only once routing is split.
  assert.deepStrictEqual(M.unroutedDns(mkt()), [])
  assert.deepStrictEqual(M.unroutedDns(mkt({ neverDefault: { v4: true, v6: true } })), ["10.73.12.53"])
  assert.deepStrictEqual(M.unroutedDns(mkt({ neverDefault: { v4: true, v6: true }, routes: ["10.73.12.0/24"] })), [])
  assert.deepStrictEqual(M.unroutedDns(mkt({ neverDefault: { v4: true, v6: true }, dns: ["10.1.0.1"] })), [])

  const d = M.dnsCommands(mkt(), "10.73.12.53, fd00::53")
  assert.deepStrictEqual(d.commands, [
    ["nmcli", "connection", "modify", "uuid", UUID, "ipv4.dns", "10.73.12.53", "ipv6.dns", "fd00::53"],
    ["nmcli", "device", "reapply", "home"]])
  assert.deepStrictEqual(M.dnsCommands(mkt(), "10.73.12.53").commands, [])
  assert.deepStrictEqual(M.dnsCommands(mkt(), "").commands.slice(1), [["nmcli", "connection", "down", "uuid", UUID], ["nmcli", "connection", "up", "uuid", UUID]])
  assert.deepStrictEqual(M.dnsCommands(mkt({ active: false }), "9.9.9.9").commands.length, 1)
  assert.deepStrictEqual(M.dnsCommands(mkt(), "9.9.9.9 nope"), { commands: [], bad: ["nope"], off: [] })
  // NetworkManager refuses DNS/routes for a family with method=disabled.
  const v6only = mkt({ familyOff: { v4: true, v6: false } })
  assert.deepStrictEqual(M.dnsCommands(v6only, "fd00::53, 1.1.1.1"), { commands: [], bad: [], off: ["1.1.1.1"] })
  assert.strictEqual(M.dnsCommands(v6only, "fd00::53").commands[0][6], "")
  assert.deepStrictEqual(M.routesCommands(v6only, "10.0.0.0/24").off, ["10.0.0.0/24"])
  assert.deepStrictEqual(M.dnsCommands(mkt({ kind: "wgquick" }), "9.9.9.9").commands, [])

  assert.deepStrictEqual(M.routeAllCommands(mkt(), false), [
    ["nmcli", "connection", "modify", "uuid", UUID, "ipv4.never-default", "yes", "ipv6.never-default", "yes", "ipv4.routes", "10.73.12.0/24", "ipv6.routes", ""],
    ["nmcli", "connection", "up", "uuid", UUID]])
  assert.deepStrictEqual(M.routeAllCommands(mkt(), true), [])
  assert.deepStrictEqual(M.routeAllCommands(mkt({ neverDefault: { v4: true, v6: true }, active: false }), true), [
    ["nmcli", "connection", "modify", "uuid", UUID, "ipv4.never-default", "no", "ipv6.never-default", "no"]])

  // An existing route keeps its next-hop and metric.
  const withRoute = mkt({ routes: ["192.168.1.0/24"], routeSpecs: ["192.168.1.0/24 10.1.0.1 50"] })
  assert.deepStrictEqual(M.routesCommands(withRoute, "192.168.1.0/24, 10.73.12.0/24").commands[0],
    ["nmcli", "connection", "modify", "uuid", UUID, "ipv4.routes", "192.168.1.0/24 10.1.0.1 50, 10.73.12.0/24", "ipv6.routes", ""])
  assert.deepStrictEqual(M.routesCommands(withRoute, "192.168.1.0/24").commands, [])
  assert.deepStrictEqual(M.routesCommands(withRoute, "0.0.0.0/0").bad, ["0.0.0.0/0"])

  // wg-status fields reach the tunnel.
  const tr = M.buildTunnels(M.parseSnapshot([
    "C\tr:" + UUID + ":wireguard:::/etc/NetworkManager/system-connections/r.nmconnection:no",
    "N\t" + UUID + "\tipv4.never-default\tyes",
    "N\t" + UUID + "\tipv4.method\tdisabled",
    "N\t" + UUID + "\tipv4.routes\t10.73.12.0/24, 192.168.1.0/24 10.0.0.1 50",
    "N\t" + UUID + "\tipv6.routes\tfd00\\:99\\:\\:/64"
  ].join("\n")), {})[0]
  assert.deepStrictEqual(tr.neverDefault, { v4: true, v6: false })
  assert.deepStrictEqual(tr.familyOff, { v4: true, v6: false })
  assert.deepStrictEqual(tr.routes, ["10.73.12.0/24", "192.168.1.0/24", "fd00:99::/64"])
}

// ---- suggested routes and DNS scope ----
{
  const mkt = (over) => Object.assign({ id: "nm:x", kind: "nm", uuid: UUID, device: "home", active: true, addresses: ["10.1.0.2/24"], dns: ["10.73.12.53"], dnsSearch: [], dnsPriority: 50, routes: [], routeSpecs: [], neverDefault: { v4: false, v6: false }, familyOff: { v4: false, v6: true }, peers: [{ allowedIps: ["0.0.0.0/0"] }] }, over || {})
  assert.deepStrictEqual(M.suggestedRoutes(mkt()), ["10.73.12.0/24"])
  assert.deepStrictEqual(M.suggestedRoutes(mkt({ dns: ["10.1.0.1"] })), [])
  assert.deepStrictEqual(M.suggestedRoutes(mkt({ routes: ["10.73.12.0/24"] })), [])
  // Turning routing off routes the DNS server's network, keeping old routes.
  assert.deepStrictEqual(M.routeAllCommands(mkt({ routeSpecs: ["192.168.1.0/24 10.1.0.1 50"], routes: ["192.168.1.0/24"] }), false)[0],
    ["nmcli", "connection", "modify", "uuid", UUID, "ipv4.never-default", "yes", "ipv6.never-default", "yes",
     "ipv4.routes", "192.168.1.0/24 10.1.0.1 50, 10.73.12.0/24", "ipv6.routes", ""])
  assert.strictEqual(M.routeAllCommands(mkt({ dns: [] }), false)[0].length, 9)

  assert.deepStrictEqual(M.routingDomains(mkt({ dnsSearch: ["~", "~.", "~home.lan", "lan"] })), ["home.lan"])
  assert.strictEqual(M.dnsScope(mkt({ dnsSearch: ["~"] })), "all")
  assert.strictEqual(M.dnsScope(mkt({ dnsSearch: ["~home.lan"] })), "domains")
  assert.deepStrictEqual(M.parseDomains("home.lan, ~corp.example .x.y. bad_domain -a.b"), { list: ["home.lan", "corp.example", "x.y"], bad: ["bad_domain", "-a.b"] })

  const r = M.dnsScopeCommands(mkt({ dnsSearch: ["~", "lan"], dnsPriority: -50 }), "domains", "home.lan")
  assert.deepStrictEqual(r.commands, [
    ["nmcli", "connection", "modify", "uuid", UUID, "ipv4.dns-search", "~,lan,~home.lan", "ipv6.dns-search", "", "ipv4.dns-priority", "0", "ipv6.dns-priority", "0"],
    ["nmcli", "device", "reapply", "home"]])
  assert.strictEqual(M.dnsScopeCommands(mkt(), "domains", "").empty, true)
  assert.deepStrictEqual(M.dnsScopeCommands(mkt(), "domains", "a_b").bad, ["a_b"])
  assert.deepStrictEqual(M.dnsScopeCommands(mkt({ dnsSearch: ["~home.lan", "lan"] }), "all", "").commands[0].slice(5, 9), ["ipv4.dns-search", "lan", "ipv6.dns-search", ""])
  assert.deepStrictEqual(M.dnsScopeCommands(mkt({ dnsSearch: ["lan"] }), "all", "").commands, [])
  // An IPv6-only profile keeps its domains on ipv6.
  assert.deepStrictEqual(M.dnsScopeCommands(mkt({ familyOff: { v4: true, v6: false }, active: false }), "domains", "home.lan").commands[0].slice(5),
    ["ipv4.dns-search", "", "ipv6.dns-search", "~home.lan"])
}

// ---- public resolvers and interface creation time ----
{
  const mkt = (over) => Object.assign({ id: "nm:x", kind: "nm", uuid: UUID, device: "home", active: true, addresses: ["10.1.0.2/24"], dns: ["1.1.1.1"], routes: [], routeSpecs: [], neverDefault: { v4: true, v6: true }, familyOff: { v4: false, v6: true }, peers: [{ allowedIps: ["0.0.0.0/0"] }] }, over || {})
  assert.deepStrictEqual(M.unroutedDns(mkt()), [])
  assert.deepStrictEqual(M.suggestedRoutes(mkt()), [])
  assert.deepStrictEqual(M.unroutedDns(mkt({ dns: ["1.1.1.1", "172.20.0.53", "fd12::53", "2606:4700:4700::1111"] })), ["172.20.0.53", "fd12::53"])
  assert.strictEqual(M.isPrivateAddress("100.100.100.100"), true)
  assert.strictEqual(M.isPrivateAddress("172.32.0.1"), false)
  assert.strictEqual(M.isPrivateAddress("nope"), false)
  assert.deepStrictEqual(M.parseActivations("home-router\t1795223443.069457\nbad name\t1795223443\nwg0\tsoon\nwg1\t1795223000\n"),
    { "home-router": 1795223443069, wg1: 1795223000000 })
}

console.log("model tests passed")
