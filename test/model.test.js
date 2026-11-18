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

console.log("model tests passed")
