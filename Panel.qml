import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "tsmithscott.wireguard"
  ipcTarget: "tsmithscott.wireguard"
  manageIpc: false

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color accent: Commons.Color.accent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color barIconColor: wg.anyActive ? barForeground : Qt.darker(barForeground, 1.55)

  // "Icon only" | "Tunnel name" | "Speed" from the settings enum.
  readonly property string barLabelMode: {
    var v = String(settings.barLabel || "Icon only")
    if (v === "Tunnel name") return "name"
    if (v === "Speed") return "speed"
    return "none"
  }
  readonly property bool showGraph: settings.showGraph !== false

  readonly property string barLabel: {
    if (!wg.anyActive || (bar && bar.vertical)) return ""
    if (barLabelMode === "name") return wg.activeTunnels.length > 1 ? wg.primary.name + " +" + (wg.activeTunnels.length - 1) : wg.primary.name
    if (barLabelMode === "speed") return "↓" + Model.formatRateShort(wg.rxRate, Commons.I18n.formatNumber) + " ↑" + Model.formatRateShort(wg.txRate, Commons.I18n.formatNumber)
    return ""
  }

  // Which tunnel the stats and peers describe.
  property string selectedId: ""
  readonly property var selected: {
    var t = selectedId !== "" ? wg.tunnelById(selectedId) : null
    if (t) return t
    if (wg.primary) return wg.primary
    return wg.tunnels.length > 0 ? wg.tunnels[0] : null
  }
  readonly property bool selectedActive: wg.isActive(selected)
  readonly property var selectedRate: wg.rateFor(selected)

  // Keyboard cursor over: 0 = master switch, 1..N = tunnels, then actions.
  property bool cursorActive: false
  property int cursorIndex: 0
  readonly property var actionKeys: {
    var keys = ["import"]
    if (wg.dnsFixNeeded) keys.push("dnsFix")
    if (!wg.autoPublicIp) keys.push("publicIp")
    if (wg.statsState !== "ok" && settings.offerPeerStats !== false) keys.push("stats")
    return keys
  }
  // Cursor order: master switch, tunnels, action buttons, Settings header.
  readonly property int settingsCursor: 1 + wg.tunnels.length + actionKeys.length
  readonly property int cursorCount: settingsCursor + 1

  function fmtBytes(n) { return Model.formatBytes(n, Commons.I18n.formatNumber) }
  function fmtRate(n) { return Model.formatRate(n, Commons.I18n.formatNumber) }

  function kindLabel(t) {
    if (!t) return ""
    if (t.kind === "nm") return strings.t("kind.nm")
    if (t.kind === "wgquick") return strings.t("kind.wgquick")
    return strings.t("kind.external")
  }

  function stateLabel(t) {
    if (!t) return ""
    if (wg.isPending(t)) return wg.isActive(t) ? strings.t("state.connecting") : strings.t("state.disconnecting")
    if (t.state === "activating") return strings.t("state.connecting")
    if (t.state === "deactivating") return strings.t("state.disconnecting")
    return wg.isActive(t) ? strings.t("state.connected") : strings.t("state.off")
  }

  function handshakeText(peer) {
    if (!peer || !peer.live) return "--"
    if (!peer.handshake) return strings.t("peer.never")
    return strings.t("peer.ago").arg(Model.formatDuration(Math.max(0, wg.nowSec - peer.handshake)))
  }

  function persist(values) {
    if (!root.bar || !root.bar.shell || typeof root.bar.shell.updateEntryInline !== "function") return
    var entry = { id: root.moduleName }
    for (var key in settings) if (key !== "id") entry[key] = settings[key]
    for (var k in values) entry[k] = values[k]
    root.bar.shell.updateEntryInline(root.moduleName, entry)
  }

  function moveCursor(dy) {
    if (!cursorActive) { cursorActive = true; return }
    cursorIndex = Math.max(0, Math.min(cursorCount - 1, cursorIndex + dy))
    var ti = cursorIndex - 1
    if (ti >= 0 && ti < wg.tunnels.length) selectedId = wg.tunnels[ti].id
    scrollCursorIntoView()
  }

  // Opening Settings scrolls them up into view; they sit below the fold.
  function toggleSettings() {
    settingsOpen = !settingsOpen
    if (!settingsOpen) { scrollCursorIntoView(); return }
    Qt.callLater(function() {
      var c = panel.loadedContent
      if (!c || !c.flick || !c.settingsRow) return
      var top = c.settingsRow.mapToItem(c.flick.contentItem, 0, 0).y - Style.space(6)
      c.flick.contentY = Math.max(0, Math.min(top, c.flick.contentHeight - c.flick.height))
    })
  }

  // The panel caps its height and scrolls, so keep the keyboard cursor on screen.
  function scrollCursorIntoView() {
    Qt.callLater(function() {
      var c = panel.loadedContent
      var flick = c ? c.flick : null
      if (!flick) return
      var item = null
      var ti = cursorIndex - 1
      if (cursorIndex === 0) { flick.contentY = 0; return }
      if (ti < wg.tunnels.length) item = c.tunnelRepeater.itemAt(ti)
      else if (cursorIndex === settingsCursor) item = c.settingsRow
      else item = c.actionRepeater.itemAt(ti - wg.tunnels.length)
      if (!item) return
      var margin = Style.space(6)
      var top = item.mapToItem(flick.contentItem, 0, 0).y
      var bottom = top + item.height
      var maxY = Math.max(0, flick.contentHeight - flick.height)
      if (top < flick.contentY + margin) flick.contentY = Math.max(0, top - margin)
      else if (bottom > flick.contentY + flick.height - margin) flick.contentY = Math.min(maxY, bottom + margin - flick.height)
    })
  }

  function activateCursor() {
    if (cursorIndex === 0) { wg.toggleAll(); return }
    var ti = cursorIndex - 1
    if (ti < wg.tunnels.length) { wg.toggleTunnel(wg.tunnels[ti]); return }
    if (cursorIndex === settingsCursor) { toggleSettings(); return }
    runAction(actionKeys[ti - wg.tunnels.length])
  }

  // Tunnel waiting on the remove confirmation, or null.
  property var removeTarget: null
  readonly property bool confirmOpen: removeTarget !== null

  function askRemove(t) {
    if (!Model.canRemove(t)) return
    removeTarget = t
  }

  function confirmRemove() {
    var t = removeTarget
    removeTarget = null
    if (!t) return
    if (selectedId === t.id) selectedId = ""
    wg.removeTunnel(t)
  }

  function cancelRemove() {
    removeTarget = null
  }

  function publicIpText() {
    if (wg.publicIp) {
      var parts = [wg.publicIp.ip]
      if (wg.publicIp.place !== "") parts.push(wg.publicIp.place)
      if (wg.publicIp.org !== "") parts.push(wg.publicIp.org)
      return parts.join(" · ")
    }
    if (wg.publicIpBusy) return strings.t("stat.checking")
    if (wg.publicIpFailed) return strings.t("stat.unavailable")
    return wg.autoPublicIp ? strings.t("stat.checking") : strings.t("stat.checkHint")
  }

  // Omarchy has no settings screen for plugins (the manifest schema is never
  // rendered), so the panel edits its own shell.json entry.
  property bool settingsOpen: false

  function setSetting(key, value) {
    var v = {}
    v[key] = value
    persist(v)
  }

  function cycle(options, current) {
    var i = options.indexOf(current)
    return options[(i + 1) % options.length]
  }

  readonly property var defaultTunnelOptions: {
    var names = [""]
    for (var i = 0; i < wg.tunnels.length; i++) if (Model.canToggle(wg.tunnels[i])) names.push(wg.tunnels[i].name)
    return names
  }

  function runAction(key) {
    if (key === "import") wg.importConfig()
    else if (key === "publicIp") wg.checkPublicIp()
    else if (key === "stats") wg.enablePeerStats()
    else if (key === "dnsFix") wg.installDnsFix()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    removeTarget = null
    cursorActive = false
    cursorIndex = 0
    selectedId = ""
    Qt.callLater(function() { if (panel.loadedContent) panel.loadedContent.forceActiveFocus() })
  }
  onCursorCountChanged: if (cursorIndex >= cursorCount) cursorIndex = Math.max(0, cursorCount - 1)

  Service {
    id: wg
    settings: root.settings
    panelOpen: root.opened
    barLabelMode: root.barLabelMode
    persist: root.persist
  }

  ShellIpc {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function toggleAll(): string { wg.toggleAll(); return "ok" }
    function up(name: string): string { return wg.upByName(name) }
    function down(name: string): string { return wg.downByName(name) }
    function refresh(): string { wg.refresh(true); return "ok" }
    function status(): string { return wg.statusText }
  }

  TextMetrics {
    id: labelMetrics
    font.family: root.fontFamily
    font.pixelSize: Style.bar.iconFont
    text: root.barLabel
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    labelText: root.barLabel
    slotSize: Style.bar.iconSlot + (root.barLabel !== "" ? Math.ceil(labelMetrics.advanceWidth) + Style.space(6) : 0)
    tooltipText: root.opened ? "" : (wg.anyActive
      ? wg.activeTunnels.map(function(t) { return t.name }).join(", ") + "  ↓ " + root.fmtRate(wg.rxRate) + "  ↑ " + root.fmtRate(wg.txRate)
      : strings.t("bar.disconnected"))
    iconComponent: Component {
      Item {
        WireguardIcon {
          x: (parent.width - width) / 2
          y: (parent.height - height) / 2
          iconSize: button.iconSize
          color: root.barIconColor
          badgeColor: root.urgent
          crossed: !wg.anyActive
          warning: wg.health === "degraded"
          fontFamily: root.fontFamily
        }
      }
    }
    onPressed: function(code) {
      if (code === Qt.RightButton) wg.toggleAll()
      else if (code === Qt.MiddleButton) wg.refresh(true)
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(400))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(640))

    content: PanelKeyCatcher {
      id: keyCatcher
      readonly property alias flick: panelFlick
      readonly property alias tunnelRepeater: tunnelRepeater
      readonly property alias actionRepeater: actionRepeater
      readonly property alias settingsRow: settingsRow
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      blocked: root.confirmOpen
      onDeleteRequested: {
        var ti = root.cursorIndex - 1
        if (root.cursorActive && ti >= 0 && ti < wg.tunnels.length) root.askRemove(wg.tunnels[ti])
      }
      onMoveRequested: function(dx, dy) { if (dy !== 0) root.moveCursor(dy) }
      onActivateRequested: if (root.cursorActive) root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "t" || t === "T") wg.toggleAll()
        else if (t === "c" || t === "C") wg.copy(Model.firstAddress(root.selected))
        else if (t === "i" || t === "I") wg.importConfig()
        else if (t === "p" || t === "P") wg.checkPublicIp()
        else if (t === "r" || t === "R") wg.refresh(true)
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(12)

          // ---- hero + master switch ------------------------------------
          Item {
            id: header
            width: parent.width
            implicitHeight: hero.implicitHeight
            readonly property bool ringVisible: root.cursorActive && root.cursorIndex === 0

            PanelHero {
              id: hero
              width: parent.width
              title: wg.anyActive ? wg.primary.name : "WireGuard"
              meta: {
                if (!wg.anyActive) return wg.tunnels.length === 0 ? strings.t("hero.noTunnels") : strings.t("hero.disconnected")
                var addr = Model.firstAddress(wg.primary)
                if (wg.activeTunnels.length > 1) return strings.tn("hero.multiple", wg.activeTunnels.length).arg(Commons.I18n.formatNumber(wg.activeTunnels.length))
                return addr !== "" ? strings.t("hero.connectedAddr").arg(addr) : strings.t("state.connected")
              }
              foreground: root.foreground
              fontFamily: root.fontFamily
              iconOpacity: wg.anyActive ? 1.0 : 0.5
              iconComponent: Component {
                WireguardIcon {
                  iconSize: Style.font.display
                  color: wg.anyActive ? root.foreground : root.dim
                  badgeColor: root.urgent
                  crossed: !wg.anyActive
                  warning: wg.health === "degraded"
                  fontFamily: root.fontFamily
                }
              }
              trailingControl: Component {
                ToggleSwitch {
                  id: masterSwitch
                  visible: wg.toggleable
                  checked: wg.anyActive
                  busy: wg.busy
                  hasCursor: header.ringVisible
                  foreground: hero.foreground
                  onHovered: function(on) { if (on) { root.cursorActive = true; root.cursorIndex = 0 } }
                  onToggled: wg.toggleAll()

                  PanelToolTip {
                    visible: masterSwitch.containsMouse
                    text: wg.anyActive ? strings.t("hero.turnOffAll") : strings.t("hero.turnOn")
                    fontFamily: hero.fontFamily
                  }
                }
              }
            }
          }

          Item {
            width: parent.width
            implicitHeight: ipRow.implicitHeight

            RowLayout {
              id: ipRow
              width: parent.width
              spacing: Style.space(8)

              InfoLabel { text: strings.t("stat.publicIp") }

              DetailValue {
                id: ipValue
                text: root.publicIpText()
                copyable: wg.publicIp !== null
                copyText: wg.publicIp ? wg.publicIp.ip : ""
                opacity: wg.publicIpBusy && wg.publicIp !== null ? 0.5 : 1.0
              }

              PanelActionButton {
                iconText: "󰑐"
                tooltipText: strings.t("stat.recheck")
                foreground: root.foreground
                fontFamily: root.fontFamily
                enabled: !wg.publicIpBusy
                Layout.alignment: Qt.AlignVCenter
                onClicked: wg.checkPublicIp()
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: text !== ""
            width: parent.width
            text: wg.actionStatus !== "" ? wg.actionStatus : wg.lastError
            color: wg.lastError !== "" && wg.actionStatus === "" ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Text {
            textFormat: Text.PlainText
            visible: wg.dnsFixNeeded
            width: parent.width
            text: strings.t("dns.overridden")
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // ---- live stats for the selected tunnel ----------------------
          Column {
            visible: root.selected !== null && root.selectedActive
            width: parent.width
            spacing: Style.space(10)

            PanelSectionHeader {
              text: root.selected ? strings.t("section.stats").arg(root.selected.name) : ""
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            GridLayout {
              width: parent.width
              columns: 4
              columnSpacing: Style.space(20)
              rowSpacing: Style.spacing.labelGap

              InfoLabel { text: strings.t("stat.receiving") }
              DetailValue { text: root.fmtRate(root.selectedRate.rx); color: root.accent }
              InfoLabel { text: strings.t("stat.sending") }
              DetailValue { text: root.fmtRate(root.selectedRate.tx) }

              InfoLabel { text: strings.t("stat.downloaded") }
              DetailValue { text: root.selected ? root.fmtBytes(root.selected.rx) : "--" }
              InfoLabel { text: strings.t("stat.uploaded") }
              DetailValue { text: root.selected ? root.fmtBytes(root.selected.tx) : "--" }

              InfoLabel { text: strings.t("stat.address") }
              DetailValue {
                text: Model.firstAddress(root.selected) || "--"
                copyable: text !== "--"
              }
              InfoLabel { text: strings.t("stat.uptime") }
              DetailValue {
                text: {
                  var s = wg.uptimeFor(root.selected)
                  void wg.nowSec
                  return s >= 0 ? Model.formatDuration(s) : "--"
                }
              }

              InfoLabel { text: strings.t("stat.port") }
              DetailValue { text: root.selected && root.selected.listenPort ? String(root.selected.listenPort) : "--" }
              InfoLabel { text: strings.t("stat.mtu") }
              DetailValue { text: root.selected && root.selected.mtu ? String(root.selected.mtu) : "--" }

              InfoLabel { text: strings.t("stat.dns") }
              DetailValue {
                Layout.columnSpan: 3
                readonly property string dnsStatus: Model.dnsState(root.selected)
                text: {
                  var t = root.selected
                  if (!t) return "--"
                  if (dnsStatus === "none") return t.dnsInUse && t.dnsInUse.length > 0 ? t.dnsInUse.join(", ") : strings.t("dns.system")
                  return strings.t(dnsStatus === "ok" ? "dns.applied" : "dns.notApplied").arg(t.dns.join(", "))
                }
                color: dnsStatus === "missing" ? root.urgent : root.foreground
              }

              InfoLabel { text: strings.t("stat.lastRx") }
              DetailValue {
                Layout.columnSpan: 3
                text: {
                  if (root.selected && root.selected.active && !(root.selected.rx > 0)) return strings.t("stat.never")
                  var q = wg.rxQuietFor(root.selected)
                  if (q < 0) return "--"
                  return q < 2 ? strings.t("stat.justNow") : strings.t("peer.agoShort").arg(Model.formatDuration(q))
                }
                // This tunnel's health, not the bar's worst-of-all.
                color: Model.tunnelHealth(root.selected, wg.nowSec, wg.rxQuietFor(root.selected)) === "degraded" ? root.urgent : root.foreground
              }
            }

            // Throughput sparkline: receive in accent, send in foreground.
            Item {
              visible: root.showGraph
              width: parent.width
              height: Style.space(56)

              Canvas {
                id: graph
                anchors.fill: parent
                property var samples: wg.history
                property color rxColor: root.accent
                property color txColor: root.dim
                onSamplesChanged: requestPaint()
                onWidthChanged: requestPaint()
                onPaint: {
                  var ctx = getContext("2d")
                  ctx.reset()
                  var data = samples || []
                  var n = wg.historyLength
                  var max = 1024
                  for (var i = 0; i < data.length; i++) max = Math.max(max, data[i].rx, data[i].tx)
                  var step = width / Math.max(1, n - 1)
                  var offset = n - data.length
                  function line(key, color, fill) {
                    if (data.length < 2) return
                    ctx.beginPath()
                    for (var j = 0; j < data.length; j++) {
                      var x = (offset + j) * step
                      var y = height - 1 - (data[j][key] / max) * (height - 4)
                      if (j === 0) ctx.moveTo(x, y)
                      else ctx.lineTo(x, y)
                    }
                    ctx.strokeStyle = color
                    ctx.lineWidth = 1.5
                    ctx.stroke()
                    if (fill) {
                      ctx.lineTo((offset + data.length - 1) * step, height)
                      ctx.lineTo(offset * step, height)
                      ctx.closePath()
                      ctx.fillStyle = Qt.rgba(color.r, color.g, color.b, 0.15)
                      ctx.fill()
                    }
                  }
                  line("tx", txColor, false)
                  line("rx", rxColor, true)
                }
              }

              Text {
                textFormat: Text.PlainText
                anchors.top: parent.top
                anchors.right: parent.right
                text: strings.t("graph.legend")
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }
          }

          // ---- tunnels ---------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          Column {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: strings.t("section.tunnels")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              textFormat: Text.PlainText
              visible: wg.tunnels.length === 0
              width: parent.width
              text: strings.t("tunnels.empty")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Repeater {
              id: tunnelRepeater
              model: wg.tunnels
              TunnelRow {
                required property var modelData
                required property int index
                width: parent.width
                tunnel: modelData
                rowIndex: index
              }
            }
          }

          // ---- peers of the selected tunnel -----------------------------
          PanelSeparator {
            visible: root.selected !== null && root.selected.peers.length > 0
            foreground: root.foreground
          }

          Column {
            visible: root.selected !== null && root.selected.peers.length > 0
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: root.selected ? strings.tn("section.peers", root.selected.peers.length).arg(Commons.I18n.formatNumber(root.selected.peers.length)) : ""
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              model: root.selected ? root.selected.peers : []
              PeerRow {
                required property var modelData
                width: parent.width
                peer: modelData
              }
            }
          }

          // ---- actions ---------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          Flow {
            width: parent.width
            spacing: Style.space(8)

            Repeater {
              id: actionRepeater
              model: root.actionKeys
              Button {
                required property string modelData
                required property int index
                text: strings.t("action." + modelData)
                iconText: ({ "import": "󰈔", "publicIp": "󰩟", "dnsFix": "󰇖", "stats": "󰒃" })[modelData] || ""
                tooltipText: strings.t("action." + modelData + ".hint")
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                hasCursor: root.cursorActive && root.cursorIndex === 1 + wg.tunnels.length + index
                onHovered: function(on) { if (on) { root.cursorActive = true; root.cursorIndex = 1 + wg.tunnels.length + index } }
                onClicked: root.runAction(modelData)
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: wg.statsState !== "ok"
            width: parent.width
            text: strings.t("stats.hint")
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          // ---- settings --------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          CursorSurface {
            id: settingsRow
            width: parent.width
            foreground: root.foreground
            hasCursor: root.cursorActive && root.cursorIndex === root.settingsCursor
            implicitHeight: settingsHeader.implicitHeight + Style.spacing.rowPaddingX

            MouseArea {
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onEntered: { root.cursorActive = true; root.cursorIndex = root.settingsCursor }
              onClicked: root.toggleSettings()
            }

            RowLayout {
              id: settingsHeader
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)

              Text {
                textFormat: Text.PlainText
                text: "󰒓  " + strings.t("settings.title")
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                Layout.fillWidth: true
              }

              Text {
                textFormat: Text.PlainText
                text: root.settingsOpen ? "󰅀" : "󰅂"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.icon
              }
            }
          }

          Column {
            visible: root.settingsOpen
            width: parent.width
            spacing: Style.space(8)

            SettingChoice {
              label: strings.t("settings.barLabel")
              value: String(root.settings.barLabel || "Icon only")
              display: strings.t("settings.barLabel." + value)
              onChosen: root.setSetting("barLabel", root.cycle(["Icon only", "Tunnel name", "Speed"], value))
            }

            SettingChoice {
              label: strings.t("settings.defaultTunnel")
              hint: strings.t("settings.defaultTunnel.hint")
              value: String(root.settings.defaultTunnel || "")
              display: value === "" ? strings.t("settings.lastUsed") : value
              onChosen: root.setSetting("defaultTunnel", root.cycle(root.defaultTunnelOptions, value))
            }

            SettingToggle {
              label: strings.t("settings.autoPublicIp")
              hint: strings.t("settings.autoPublicIp.hint")
              checked: root.settings.autoPublicIp !== false
              onFlipped: root.setSetting("autoPublicIp", !checked)
            }

            SettingToggle {
              label: strings.t("settings.showGraph")
              checked: root.settings.showGraph !== false
              onFlipped: root.setSetting("showGraph", !checked)
            }

            SettingToggle {
              label: strings.t("settings.exclusive")
              hint: strings.t("settings.exclusive.hint")
              checked: root.settings.exclusive === true
              onFlipped: root.setSetting("exclusive", !checked)
            }

            SettingToggle {
              label: strings.t("settings.notify")
              checked: root.settings.notifyChanges === true
              onFlipped: root.setSetting("notifyChanges", !checked)
            }

            SettingToggle {
              label: strings.t("settings.offerPeerStats")
              hint: strings.t("settings.offerPeerStats.hint")
              checked: root.settings.offerPeerStats !== false
              onFlipped: root.setSetting("offerPeerStats", !checked)
            }

            SettingText {
              label: strings.t("settings.exclude")
              hint: strings.t("settings.exclude.hint")
              value: String(root.settings.excludeInterfaces === undefined ? "wt0" : root.settings.excludeInterfaces)
              onCommitted: function(text) { root.setSetting("excludeInterfaces", text) }
            }

            SettingText {
              label: strings.t("settings.wgQuick")
              hint: strings.t("settings.wgQuick.hint")
              value: String(root.settings.wgQuickConfigs || "")
              onCommitted: function(text) { root.setSetting("wgQuickConfigs", text) }
            }
          }
        }
      }

      ConfirmDialog {
        id: removeConfirm
        anchors.fill: parent
        z: 10
        opened: root.confirmOpen
        message: {
          var t = root.removeTarget
          if (!t) return ""
          if (t.kind === "wgquick") return strings.t("remove.hideMessage").arg(t.name)
          return (t.active ? strings.t("remove.activeMessage") : strings.t("remove.message")).arg(t.name)
        }
        confirmText: root.removeTarget && root.removeTarget.kind === "wgquick" ? strings.t("tunnel.hide") : strings.t("tunnel.remove")
        foreground: root.foreground
        fontFamily: root.fontFamily
        onCanceled: root.cancelRemove()
        onConfirmed: root.confirmRemove()
        onOpenedChanged: {
          if (opened) {
            selectedIndex = 0  // default to Cancel
            Qt.callLater(function() { confirmKeys.forceActiveFocus() })
          } else {
            Qt.callLater(function() { keyCatcher.forceActiveFocus() })
          }
        }
      }

      Item {
        id: confirmKeys
        Keys.onPressed: function(event) { if (removeConfirm.handleKey(event)) event.accepted = true }
      }
    }
  }

  // ---- components ------------------------------------------------------

  component TunnelRow: CursorSurface {
    id: row
    property var tunnel: null
    property int rowIndex: 0
    readonly property bool on: wg.isActive(tunnel)
    readonly property bool toggleable: Model.canToggle(tunnel)

    hasCursor: root.cursorActive && root.cursorIndex === rowIndex + 1
    current: root.selected !== null && tunnel !== null && root.selected.id === tunnel.id
    foreground: root.foreground
    implicitHeight: rowLayout.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: { root.cursorActive = true; root.cursorIndex = row.rowIndex + 1 }
      onClicked: if (row.tunnel) root.selectedId = row.tunnel.id
    }

    RowLayout {
      id: rowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(8)
      spacing: Style.space(10)

      Text {
        textFormat: Text.PlainText
        text: "󰖂"
        color: row.on ? root.accent : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon
        Layout.alignment: Qt.AlignVCenter
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: row.tunnel ? row.tunnel.name : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: row.on
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: {
            var t = row.tunnel
            if (!t) return ""
            var parts = [root.stateLabel(t), root.kindLabel(t)]
            var addr = Model.firstAddress(t)
            if (addr !== "") parts.push(addr)
            if (row.on) {
              var r = wg.rateFor(t)
              parts.push("↓ " + root.fmtRate(r.rx) + "  ↑ " + root.fmtRate(r.tx))
            }
            if (t.kind === "nm" && t.autoconnect) parts.push(strings.t("tunnel.auto"))
            return parts.join(" · ")
          }
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      PanelActionButton {
        visible: row.tunnel !== null && row.tunnel.kind === "nm"
        iconText: row.tunnel && row.tunnel.autoconnect ? "󰁪" : "󰁫"
        tooltipText: row.tunnel && row.tunnel.autoconnect ? strings.t("tunnel.autoOff") : strings.t("tunnel.autoOn")
        foreground: root.foreground
        fontFamily: root.fontFamily
        Layout.alignment: Qt.AlignVCenter
        onClicked: wg.setAutoconnect(row.tunnel, !row.tunnel.autoconnect)
      }

      PanelActionButton {
        visible: Model.canRemove(row.tunnel)
        iconText: "󰆴"
        tooltipText: row.tunnel && row.tunnel.kind === "wgquick" ? strings.t("tunnel.hide") : strings.t("tunnel.remove")
        foreground: root.foreground
        hoverColor: root.urgent
        fontFamily: root.fontFamily
        Layout.alignment: Qt.AlignVCenter
        onClicked: root.askRemove(row.tunnel)
      }

      ToggleSwitch {
        visible: row.toggleable
        checked: row.on
        busy: wg.isPending(row.tunnel)
        cursorRing: false
        foreground: root.foreground
        Layout.alignment: Qt.AlignVCenter
        onToggled: wg.toggleTunnel(row.tunnel)
      }

      Text {
        textFormat: Text.PlainText
        visible: !row.toggleable
        text: strings.t("tunnel.readOnly")
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        Layout.alignment: Qt.AlignVCenter
      }
    }
  }

  component PeerRow: CursorSurface {
    id: peerRow
    property var peer: null
    readonly property string health: Model.peerHealth(peer, wg.nowSec)

    foreground: root.foreground
    implicitHeight: peerLayout.implicitHeight + Style.spacing.rowPaddingX

    RowLayout {
      id: peerLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(8)
      spacing: Style.space(10)

      Rectangle {
        width: Style.space(8)
        height: width
        radius: width / 2
        Layout.alignment: Qt.AlignVCenter
        color: peerRow.health === "ok" ? root.accent : (peerRow.health === "unknown" ? root.dim : root.urgent)
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: peerRow.peer ? (peerRow.peer.endpoint !== "" ? peerRow.peer.endpoint : Model.shortKey(peerRow.peer.publicKey)) : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: peerRow.peer ? strings.t("peer.allowed").arg(peerRow.peer.allowedIps.join(", ") || "--") : ""
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          visible: peerRow.peer !== null && peerRow.peer.live
          text: peerRow.peer ? strings.t("peer.live").arg(root.handshakeText(peerRow.peer)).arg(root.fmtBytes(peerRow.peer.rx)).arg(root.fmtBytes(peerRow.peer.tx)) : ""
          color: peerRow.health === "stale" || peerRow.health === "never" ? root.urgent : root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      PanelActionButton {
        iconText: "󰆏"
        tooltipText: strings.t("peer.copyKey")
        foreground: root.foreground
        fontFamily: root.fontFamily
        Layout.alignment: Qt.AlignVCenter
        onClicked: wg.copy(peerRow.peer ? peerRow.peer.publicKey : "")
      }
    }
  }

  component SettingLabel: ColumnLayout {
    property string label: ""
    property string hint: ""
    Layout.fillWidth: true
    spacing: Style.space(1)

    Text {
      textFormat: Text.PlainText
      Layout.fillWidth: true
      text: parent.label
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Text {
      textFormat: Text.PlainText
      Layout.fillWidth: true
      visible: parent.hint !== ""
      text: parent.hint
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }
  }

  component SettingToggle: RowLayout {
    id: toggleRow
    property string label: ""
    property string hint: ""
    property bool checked: false
    signal flipped()
    width: parent ? parent.width : 0
    spacing: Style.space(10)

    SettingLabel { label: toggleRow.label; hint: toggleRow.hint }

    ToggleSwitch {
      checked: toggleRow.checked
      cursorRing: false
      foreground: root.foreground
      Layout.alignment: Qt.AlignVCenter
      onToggled: toggleRow.flipped()
    }
  }

  component SettingChoice: RowLayout {
    id: choiceRow
    property string label: ""
    property string hint: ""
    property string value: ""
    property string display: value
    signal chosen()
    width: parent ? parent.width : 0
    spacing: Style.space(10)

    SettingLabel { label: choiceRow.label; hint: choiceRow.hint }

    Button {
      text: choiceRow.display
      iconText: "󰑐"
      tooltipText: strings.t("settings.cycle")
      bordered: true
      foreground: root.foreground
      fontFamily: root.fontFamily
      fontSize: Style.font.bodySmall
      Layout.alignment: Qt.AlignVCenter
      onClicked: choiceRow.chosen()
    }
  }

  component SettingText: ColumnLayout {
    id: textRow
    property string label: ""
    property string hint: ""
    property string value: ""
    signal committed(string text)
    width: parent ? parent.width : 0
    spacing: Style.space(4)

    SettingLabel { label: textRow.label; hint: textRow.hint }

    TextField {
      id: field
      Layout.fillWidth: true
      foreground: root.foreground
      text: textRow.value
      // Save on Enter or when focus leaves, only if something changed.
      function commit() {
        var next = text.trim()
        if (next !== textRow.value) textRow.committed(next)
      }
      onAccepted: { commit(); field.focus = false }
      onEditingFinished: commit()
      Keys.onEscapePressed: { text = textRow.value; field.focus = false }
    }
  }

  component DetailValue: InfoValue {
    property bool copyable: false
    property string copyText: text
    Layout.fillWidth: true
    horizontalAlignment: Text.AlignRight

    MouseArea {
      id: valueMouse
      anchors.fill: parent
      enabled: parent.copyable
      hoverEnabled: enabled
      cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: wg.copy(parent.copyText)
    }

    PanelToolTip {
      visible: valueMouse.enabled && valueMouse.containsMouse
      text: strings.t("copy")
      fontFamily: root.fontFamily
    }
  }

  component InfoLabel: Text {
    textFormat: Text.PlainText
    color: root.foreground
    opacity: 0.6
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  component InfoValue: Text {
    textFormat: Text.PlainText
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    elide: Text.ElideRight
  }
}
