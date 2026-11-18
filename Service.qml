import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model

// Polls bin/wg-status, keeps the tunnel list, computes throughput, and runs
// toggles. Never needs root for NetworkManager tunnels; wg-quick tunnels go
// through pkexec, and live peer stats through an optional sudo helper.
Item {
  id: root

  property var settings: ({})
  // Panel binds this; while open we sample once a second and fetch peer stats.
  property bool panelOpen: false
  property string barLabelMode: "none"

  readonly property string pluginDir: String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "").replace(/\/+$/, "")
  readonly property string statusScript: pluginDir + "/bin/wg-status"
  readonly property string setupScript: pluginDir + "/bin/setup-peer-stats"
  readonly property string dnsSetupScript: pluginDir + "/bin/setup-tunnel-dns"
  readonly property string dnsDispatcher: pluginDir + "/bin/tunnel-dns-dispatcher"
  readonly property string userName: Quickshell.env("USER") || Quickshell.env("LOGNAME") || ""

  readonly property int refreshIntervalSec: intSetting("refreshIntervalSec", 10, 3, 3600)
  readonly property var excludeInterfaces: listSetting("excludeInterfaces", "wt0")
  readonly property var wgQuickConfigs: listSetting("wgQuickConfigs", "")
  readonly property string defaultTunnel: String(setting("defaultTunnel", "") || "")
  readonly property string lastTunnel: String(setting("lastTunnel", "") || "")
  readonly property bool exclusive: setting("exclusive", false) === true
  readonly property bool notifyChanges: setting("notifyChanges", false) === true
  readonly property int historyWindowMs: 60000
  readonly property bool autoPublicIp: setting("autoPublicIp", true) !== false

  property bool nmAvailable: true
  property var snapshot: Model.emptySnapshot()
  property var tunnels: []
  property string _tunnelsSig: "[]"
  property var rates: ({})
  property real rxRate: 0
  property real txRate: 0
  property var history: []
  property var _throughput: null
  property string statsState: ""
  property bool _statsBlocked: false
  property var _upSince: ({})
  property var _lastActive: ({})
  property bool _haveFull: false

  // Optimistic state per tunnel id: true/false while a toggle catches up.
  property var pending: ({})
  property string actionStatus: ""
  property string lastError: ""
  // Exit address as seen from the internet: { ip, place, org } or null.
  property var publicIp: null
  property bool publicIpFailed: false
  property bool publicIpBusy: false
  property double _publicIpAt: 0
  property string _publicIpKey: ""
  // device → { rx, at }: when each interface last received anything.
  property var _rxSeen: ({})
  property double nowSec: Date.now() / 1000

  // System DNS (`omarchy dns`) makes NetworkManager drop per-tunnel DNS; the
  // dispatcher fix restores it. Only worth offering when some tunnel has DNS.
  readonly property bool dnsFixInstalled: snapshot.dnsFix === true
  readonly property bool dnsFixNeeded: snapshot.globalDns === true && !dnsFixInstalled
    && tunnels.some(function(t) { return t.kind === "nm" && t.dns.length > 0 })
  // An older hook gives every tunnel "~." and ignores the DNS choice below.
  readonly property bool dnsFixOutdated: dnsFixInstalled && (snapshot.hookVersion || 0) < Model.DNS_HOOK_VERSION
    && dnsChoices.length > 0
  // Which tunnel answers lookups when several are up: a NetworkManager
  // profile with a negative dns-priority, or null for automatic.
  readonly property var dnsChoices: Model.dnsChoices(tunnels)
  readonly property var preferredDns: Model.preferredDnsTunnel(tunnels)
  readonly property var dnsCatchAll: Model.dnsCatchAll(activeTunnels)

  readonly property var activeTunnels: tunnels.filter(function(t) { return isActive(t) })
  readonly property bool anyActive: activeTunnels.length > 0
  readonly property var primary: anyActive ? activeTunnels[0] : null
  readonly property bool toggleable: tunnels.some(function(t) { return Model.canToggle(t) })
  readonly property bool busy: actionProcess.running || Object.keys(pending).length > 0
  readonly property string health: {
    var worst = "off"
    for (var i = 0; i < activeTunnels.length; i++) {
      var h = Model.tunnelHealth(activeTunnels[i], nowSec, rxQuietFor(activeTunnels[i]))
      if (h === "degraded") return "degraded"
      if (h === "ok" || worst === "off") worst = h
    }
    return worst
  }
  // Answers the IPC status() call, so it stays English.
  readonly property string statusText: {
    if (!anyActive) return "Disconnected"
    var names = activeTunnels.map(function(t) { return t.name })
    return "Connected: " + names.join(", ")
  }

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function intSetting(name, fallback, min, max) {
    var n = parseInt(String(setting(name, fallback)), 10)
    if (!isFinite(n)) n = fallback
    return Math.max(min, Math.min(max, n))
  }

  function listSetting(name, fallback) {
    var raw = setting(name, fallback)
    var items = raw instanceof Array ? raw : String(raw || "").split(/[\s,]+/)
    var out = []
    for (var i = 0; i < items.length; i++) {
      var v = String(items[i] || "").trim()
      if (v !== "" && Model.isInterfaceName(v)) out.push(v)
    }
    return out
  }

  function isActive(t) {
    if (!t) return false
    var p = pending[t.id]
    return p === undefined ? t.active : p
  }

  function isPending(t) {
    return !!t && pending[t.id] !== undefined
  }

  function tunnelById(id) {
    for (var i = 0; i < tunnels.length; i++) if (tunnels[i].id === id) return tunnels[i]
    return null
  }

  function tunnelByName(name) {
    var n = String(name || "")
    for (var i = 0; i < tunnels.length; i++) if (tunnels[i].name === n || tunnels[i].device === n) return tunnels[i]
    return null
  }

  function rateFor(t) {
    if (!t || !t.device || !rates[t.device]) return { rx: 0, tx: 0 }
    return rates[t.device]
  }

  // Seconds since the tunnel's interface last received a byte; -1 if unknown.
  function rxQuietFor(t) {
    void nowSec
    if (!t || !t.device || !_rxSeen[t.device]) return -1
    return Math.max(0, (Date.now() - _rxSeen[t.device].at) / 1000)
  }

  function uptimeFor(t) {
    if (!t || !isActive(t) || !_upSince[t.id]) return -1
    return (Date.now() - _upSince[t.id]) / 1000
  }

  // ---- polling -----------------------------------------------------------

  function refresh(full) {
    var wantFull = full === true || !_haveFull
    if (statusProcess.running) {
      if (wantFull) _fullQueued = true
      return
    }
    _statusFull = wantFull
    var cmd = ["bash", statusScript, wantFull ? "full" : "fast"]
    if (wantFull && !_statsBlocked) cmd.push("stats")
    statusProcess.command = cmd
    statusProcess.running = true
    watchdog.restart()
  }

  property bool _statusFull: false
  property bool _fullQueued: false

  function applySnapshot(raw) {
    var next = Model.parseSnapshot(raw)
    var merged = Model.mergeSnapshot(snapshot, next)
    snapshot = merged
    if (next.full) {
      _haveFull = true
      statsState = next.stats
      // A helper that exists but sudo refuses would log an auth failure on
      // every poll; stop asking until the user re-runs setup.
      if (next.stats === "fail") _statsBlocked = true
    }

    var now = Date.now()
    var tp = Model.throughput(_throughput, merged.ifaces, now)
    _throughput = tp
    rates = tp.rates

    var built = Model.buildTunnels(merged, { excludeInterfaces: excludeInterfaces, wgQuickConfigs: wgQuickConfigs })
    var sig = JSON.stringify(built)
    if (sig !== _tunnelsSig) {
      _tunnelsSig = sig
      tunnels = built
    }

    var rx = 0, tx = 0
    var since = Object.assign({}, _upSince)
    var nowActive = {}
    for (var i = 0; i < built.length; i++) {
      var t = built[i]
      if (t.active) {
        nowActive[t.id] = true
        var r = tp.rates[t.device]
        if (r) { rx += r.rx; tx += r.tx }
        // Only time tunnels we watched come up; one already up when the
        // shell started has an unknown start.
        if (!since[t.id] && _lastActive[t.id] === false) since[t.id] = now
      } else {
        delete since[t.id]
      }
    }
    for (var j = 0; j < built.length; j++) {
      var tt = built[j]
      var was = _lastActive[tt.id]
      if (was !== undefined && was !== tt.active) notifyChange(tt, tt.active)
    }
    var lastActive = {}
    for (var k = 0; k < built.length; k++) lastActive[built[k].id] = !!nowActive[built[k].id]
    _lastActive = lastActive
    _upSince = since

    var seen = {}
    for (var d in merged.ifaces) {
      var cur = merged.ifaces[d]
      var old = _rxSeen[d]
      // First sight counts as "now": quiet time is measured from when we
      // started watching, never guessed backwards.
      seen[d] = old && old.rx === cur.rx ? old : { rx: cur.rx, at: now }
    }
    _rxSeen = seen

    // The exit address changes when tunnels come or go; re-check once the
    // routes have settled.
    var key = Object.keys(nowActive).sort().join(",")
    if (key !== _publicIpKey) {
      var first = _publicIpKey === "" && _publicIpAt === 0
      _publicIpKey = key
      if (autoPublicIp && _haveFull) {
        if (!first) publicIp = null
        publicIpDelay.restart()
      }
    }
    rxRate = rx
    txRate = tx
    history = Model.trimHistory(Model.pushHistory(history, { rx: rx, tx: tx, at: now }, 120), now, historyWindowMs + 2000)
    nowSec = now / 1000

    // Drop optimistic overrides once reality matches (or the tunnel vanished).
    var p = Object.assign({}, pending)
    var changed = false
    for (var id in p) {
      var found = tunnelById(id)
      if (!found || found.active === p[id] || (pendingSince[id] && now - pendingSince[id] > 30000)) {
        delete p[id]
        changed = true
      }
    }
    if (changed) pending = p
  }

  property var pendingSince: ({})

  function notifyChange(t, up) {
    if (!notifyChanges) return
    Quickshell.execDetached(["notify-send", "-a", "WireGuard", "-i", "network-vpn",
      up ? "WireGuard connected" : "WireGuard disconnected", String(t.name || "")])
  }

  // Always shown (unlike notifyChanges): a tunnel going down because another
  // came up should never be silent.
  function notifyReplaced(t, names) {
    Quickshell.execDetached(["notify-send", "-a", "WireGuard", "-i", "network-vpn",
      "WireGuard: switched to " + String(t.name || ""),
      "Disconnected " + names.join(", ") + ": both route all traffic, so only one can be up."])
  }

  // ---- actions -----------------------------------------------------------

  function setPending(t, value) {
    var p = Object.assign({}, pending)
    p[t.id] = value
    pending = p
    var s = Object.assign({}, pendingSince)
    s[t.id] = Date.now()
    pendingSince = s
  }

  function clearPending(id) {
    var p = Object.assign({}, pending)
    delete p[id]
    pending = p
  }

  property var _queue: []

  function enqueue(command, tunnelId, label) {
    if (!command || command.length === 0) return
    var q = _queue.slice()
    q.push({ command: command, id: tunnelId || "", label: label || "" })
    _queue = q
    runNext()
  }

  function runNext() {
    if (actionProcess.running || _queue.length === 0) return
    var q = _queue.slice()
    var job = q.shift()
    _queue = q
    actionProcess.currentId = job.id
    actionProcess.command = job.command
    if (job.label !== "") actionStatus = job.label
    actionProcess.running = true
  }

  function up(t) {
    if (!Model.canToggle(t) || isActive(t)) return
    if (exclusive) {
      for (var i = 0; i < activeTunnels.length; i++) {
        var other = activeTunnels[i]
        if (other.id !== t.id && Model.canToggle(other)) down(other)
      }
    } else {
      // Two full tunnels would fight over the default route, so the new one
      // replaces the old. Split tunnels are left alone.
      var clash = Model.routeConflicts(t, activeTunnels)
      var replaced = []
      for (var j = 0; j < clash.length; j++) {
        if (Model.canToggle(clash[j])) { down(clash[j]); replaced.push(clash[j].name) }
      }
      if (replaced.length > 0) notifyReplaced(t, replaced)
    }
    setPending(t, true)
    rememberLast(t)
    enqueue(Model.upCommand(t), t.id)
  }

  function down(t) {
    if (!Model.canToggle(t) || !isActive(t)) return
    setPending(t, false)
    enqueue(Model.downCommand(t), t.id)
  }

  function toggleTunnel(t) {
    if (!Model.canToggle(t)) return
    if (isActive(t)) down(t)
    else up(t)
  }

  function preferredTunnel() {
    var names = [defaultTunnel, lastTunnel]
    for (var i = 0; i < names.length; i++) {
      var t = names[i] !== "" ? tunnelByName(names[i]) : null
      if (t && Model.canToggle(t)) return t
    }
    for (var j = 0; j < tunnels.length; j++) if (Model.canToggle(tunnels[j])) return tunnels[j]
    return null
  }

  // Master switch: everything we can turn off goes off; otherwise bring up
  // the default (or last used, or first) tunnel.
  function toggleAll() {
    var downable = activeTunnels.filter(function(t) { return Model.canToggle(t) })
    if (downable.length > 0) {
      for (var i = 0; i < downable.length; i++) down(downable[i])
      return
    }
    var t = preferredTunnel()
    if (t) up(t)
  }

  function upByName(name) { var t = tunnelByName(name); if (t) up(t); return t ? "ok" : "unknown tunnel" }
  function downByName(name) { var t = tunnelByName(name); if (t) down(t); return t ? "ok" : "unknown tunnel" }

  function setAutoconnect(t, on) {
    if (!t || t.kind !== "nm") return
    enqueue(["nmcli", "connection", "modify", "uuid", t.uuid, "connection.autoconnect", on ? "yes" : "no"], "")
  }

  function rememberLast(t) {
    if (!t || t.name === lastTunnel) return
    root.persist({ lastTunnel: t.name })
  }

  // Set by the Panel: writes keys back into this widget's shell.json entry.
  property var persist: function(values) {}

  function importConfig() {
    if (importProcess.running) return
    importProcess.running = true
  }

  function enablePeerStats() {
    if (userName === "" || setupProcess.running) return
    _statsBlocked = false
    setupProcess.command = ["pkexec", "bash", setupScript, userName]
    actionStatus = "Waiting for authorization…"  // i18n: ignore
    setupProcess.running = true
  }

  function installDnsFix() {
    if (setupProcess.running) return
    setupProcess.command = ["pkexec", "bash", dnsSetupScript, dnsDispatcher]
    actionStatus = "Waiting for authorization…"  // i18n: ignore
    setupProcess.running = true
  }

  // Make `t` the tunnel whose DNS answers every lookup while it is up, or pass
  // null to go back to automatic (every full-DNS tunnel is asked, first
  // answer wins). Stored as NetworkManager's own ipv4/ipv6.dns-priority.
  function setPreferredDns(t) {
    var cmds = Model.preferDnsCommands(tunnels, t)
    for (var i = 0; i < cmds.length; i++) enqueue(cmds[i], "")
  }

  function checkPublicIp() {
    if (publicIpProcess.running) return
    publicIpBusy = true
    publicIpProcess.running = true
  }

  function removeTunnel(t) {
    if (!Model.canRemove(t)) return
    if (t.kind === "nm") {
      clearPending(t.id)
      enqueue(Model.removeCommand(t), "")
      return
    }
    // wg-quick: the .conf is root-owned; just stop listing it.
    var keep = wgQuickConfigs.filter(function(n) { return n !== t.name })
    persist({ wgQuickConfigs: keep.join(", ") })
  }

  function copy(text) {
    var value = String(text || "")
    if (value === "") return
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(value) + " | wl-copy"])
  }

  function elide(text) {
    var value = String(text || "").replace(/\s+/g, " ").trim()
    return value.length > 160 ? value.substring(0, 157) + "…" : value
  }

  // ---- timers & processes -----------------------------------------------

  Timer {
    id: fastTimer
    interval: root.panelOpen ? 1000 : (root.barLabelMode === "speed" ? 2000 : 5000)
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh(false)
  }

  Timer {
    id: fullTimer
    interval: (root.panelOpen ? Math.min(root.refreshIntervalSec, 5) : root.refreshIntervalSec) * 1000
    repeat: true
    running: true
    onTriggered: root.refresh(true)
  }

  Timer {
    id: delayedRefresh
    interval: 700
    onTriggered: root.refresh(true)
  }

  Timer {
    id: watchdog
    interval: 12000
    onTriggered: if (statusProcess.running) statusProcess.running = false
  }

  Timer {
    id: statusClear
    interval: 4000
    onTriggered: { root.actionStatus = ""; }
  }

  onPanelOpenChanged: if (panelOpen) {
    refresh(true)
    if (autoPublicIp && Date.now() - _publicIpAt > 60000) checkPublicIp()
  }

  Timer {
    id: publicIpDelay
    interval: 2500
    onTriggered: root.checkPublicIp()
  }
  onExcludeInterfacesChanged: if (_haveFull) refresh(true)
  onWgQuickConfigsChanged: if (_haveFull) refresh(true)

  Process {
    id: statusProcess
    stdout: StdioCollector { id: statusOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) root.applySnapshot(String(statusOut.text || ""))
      if (root._fullQueued) {
        root._fullQueued = false
        Qt.callLater(function() { root.refresh(true) })
      }
    }
  }

  Process {
    id: actionProcess
    property string currentId: ""
    stdout: StdioCollector { id: actionOut; waitForEnd: true }
    stderr: StdioCollector { id: actionErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        if (actionProcess.currentId !== "") root.clearPending(actionProcess.currentId)
        // pkexec exits 126 when the user dismisses the prompt.
        root.lastError = exitCode === 126 ? "" : root.elide(String(actionErr.text || actionOut.text || "Command failed"))
      } else {
        root.lastError = ""
      }
      root.actionStatus = ""
      delayedRefresh.restart()
      Qt.callLater(root.runNext)
    }
  }

  Process {
    id: importProcess
    // The chooser, then nmcli import; the profile is named after the file.
    command: ["bash", "-c",
      "f=$(omarchy-file-select --title 'Import WireGuard config' --extensions conf) || exit 0; " +
      "[ -n \"$f\" ] || exit 0; nmcli connection import type wireguard file \"$f\""]
    stdout: StdioCollector { id: importOut; waitForEnd: true }
    stderr: StdioCollector { id: importErr; waitForEnd: true }
    onExited: function(exitCode) {
      var out = String(importOut.text || "").trim()
      if (exitCode !== 0) root.lastError = root.elide(String(importErr.text || "Import failed"))
      else if (out !== "") { root.lastError = ""; root.actionStatus = root.elide(out); statusClear.restart() }
      delayedRefresh.restart()
    }
  }

  Process {
    id: setupProcess
    stderr: StdioCollector { id: setupErr; waitForEnd: true }
    onExited: function(exitCode) {
      root.actionStatus = ""
      if (exitCode !== 0 && exitCode !== 126) root.lastError = root.elide(String(setupErr.text || "Setup failed"))
      else if (exitCode === 0) root.lastError = ""
      root.refresh(true)
    }
  }

  Process {
    id: publicIpProcess
    // One HTTPS GET to a fixed endpoint, size- and time-capped. Runs when the
    // panel opens (at most once a minute) and when a tunnel goes up or down;
    // turn "Look up public IP automatically" off to only run it on demand.
    command: ["curl", "-fsS", "--max-time", "6", "--max-filesize", "4096", "-H", "Accept: application/json", "https://ipinfo.io/json"]
    stdout: StdioCollector { id: ipOut; waitForEnd: true }
    onExited: function(exitCode) {
      root.publicIpBusy = false
      root._publicIpAt = Date.now()
      var info = exitCode === 0 ? Model.parseIpInfo(String(ipOut.text || "")) : null
      root.publicIpFailed = info === null
      if (info) root.publicIp = info
    }
  }
}
