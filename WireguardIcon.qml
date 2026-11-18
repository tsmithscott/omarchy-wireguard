import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// VPN glyph with a slash when no tunnel is up and an urgent "!" badge when a
// tunnel's peers have stopped handshaking.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Commons.Color.foreground
  property color badgeColor: Commons.Color.urgent
  property string fontFamily: Style.font.family
  property bool crossed: false
  property bool warning: false

  width: iconSize
  height: iconSize
  implicitWidth: iconSize
  implicitHeight: iconSize

  Text {
    textFormat: Text.PlainText
    anchors.centerIn: parent
    text: "󰖂"
    color: root.color
    font.family: root.fontFamily
    font.pixelSize: root.iconSize
    renderType: Text.NativeRendering
  }

  Rectangle {
    visible: root.crossed
    anchors.centerIn: parent
    width: parent.width * 1.15
    height: Math.max(2, parent.height * 0.12)
    radius: height / 2
    color: root.color
    rotation: -45
  }

  BorderSurface {
    visible: root.warning
    width: Math.max(7, parent.width * 0.42)
    height: width
    radius: width / 2
    color: root.badgeColor
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    borderSpec: Border.flat(Commons.Color.popups.background, 1)

    Text {
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: "!"
      color: Commons.Color.background
      font.family: Style.font.family
      font.pixelSize: Math.max(6, parent.height * 0.72)
      font.bold: true
    }
  }
}
