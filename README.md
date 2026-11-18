# WireGuard for Omarchy

A bar widget for [Omarchy](https://omarchy.org/) that shows your WireGuard tunnels' status, live speed and traffic stats, and peer handshakes, with one-click toggles.

> Community project. Not affiliated with or endorsed by WireGuard or Jason A. Donenfeld.

## Install

```bash
omarchy plugin add https://github.com/tsmithscott/omarchy-wireguard.git --enable
```

Requirements: Omarchy with shell plugin support, NetworkManager (Omarchy's default), `wireguard-tools` for `wg`/`wg-quick`, and `curl`.

## Features

- **Bar:** VPN icon, slashed when nothing is up, with a `!` badge when a peer stops handshaking. Optional label showing the tunnel name or live ↓/↑ speed. The hover tooltip shows the active tunnels and their speeds.
  Left click opens the panel, right click runs the master toggle, middle click refreshes.
- **Panel:** a master switch, plus for the selected tunnel: live receive/send rate, total received/sent, address, uptime, listen port, MTU, time since data was last received, and a 60-second throughput graph. Your public exit IP (with city and provider) is shown at the top and refreshes automatically. Every tunnel has its own switch, an autoconnect toggle, and a remove button (with confirmation; Delete key too). Removing a NetworkManager tunnel deletes its profile; removing a wg-quick entry just hides it, since `/etc/wireguard` is root-owned. Peers show their endpoint and allowed IPs, plus handshake age and per-peer traffic when peer stats are on. The panel also has "Import config" (a file chooser, then `nmcli connection import`).
- **Settings:** a collapsible Settings section at the bottom of the panel covers bar label, default tunnel, automatic public IP, graph, one-tunnel-at-a-time, notifications, peer-stats button, hidden interfaces, and wg-quick configs. Omarchy has no settings screen for plugins, so they live in the panel. They're saved to this widget's entry in `~/.config/omarchy/shell.json`, so `omarchy bar set tsmithscott.wireguard <key> <value>` works too.
- **Keys:** j/k or arrows move, Enter toggles, `t` master toggle, `c` copy address, `i` import, `p` public IP, `r` refresh.

## Tunnel sources

| Kind | Where from | Toggle |
|---|---|---|
| NetworkManager | saved `wireguard` profiles | `nmcli connection up/down`, no root |
| wg-quick | names listed in the `wgQuickConfigs` setting | `pkexec wg-quick up/down` |
| unmanaged | any other live WireGuard interface | read-only |

`wt0` (NetBird) is hidden by default via `excludeInterfaces`.

## Peer stats (optional)

The kernel only shows handshake times and per-peer counters to root. "Enable peer stats" runs
`pkexec bin/setup-peer-stats $USER`, which installs:

- `/usr/local/bin/omarchy-wg-dump`, a wrapper around `wg show all dump` that replaces every private and preshared key with `(hidden)`
- `/etc/sudoers.d/omarchy-wg-dump`, which lets you run only that wrapper, with no arguments, without a password and without filling the journal

Undo: `pkexec ~/.config/omarchy/plugins/tsmithscott.wireguard/bin/setup-peer-stats --remove`

## IPC

```
omarchy-shell tsmithscott.wireguard status | toggleAll | up <name> | down <name> | refresh | open
```

## Network access

The plugin makes one kind of network request: an HTTPS GET to `https://ipinfo.io/json` to look up your public IP (6s timeout, 4 KB cap, response validated). It runs when the panel opens (at most once a minute) and a couple of seconds after any tunnel goes up or down. Turn off "Look up public IP automatically" in the panel's Settings section and it only runs when you click ↻.

## Without peer stats

Connection health still works without the root helper. If a tunnel with keepalive set receives nothing for 3 minutes, the icon gets the `!` badge, because with keepalive WireGuard re-handshakes about every 2 minutes. Only the exact per-peer handshake time and per-peer byte counts need the helper.

## Tests

`node test/model.test.js`

## Tunnel DNS

`omarchy dns` (Cloudflare/Google/Custom) writes a NetworkManager `[global-dns]` block, and while that block exists NetworkManager ignores every connection's own DNS. A tunnel's `DNS =` line is silently dropped. The panel's DNS row shows whether the tunnel's servers are actually in use, and **Fix tunnel DNS** (one password prompt) installs `bin/tunnel-dns-dispatcher` as `/etc/NetworkManager/dispatcher.d/90-omarchy-wireguard-dns`. When a WireGuard profile comes up, the hook sets that link's DNS in systemd-resolved, the way wg-quick does:

- **Which lookups use the tunnel:** if the profile's search domains include `~domain` entries, only lookups for those domains go through the tunnel (split DNS). Otherwise `~.` sends every lookup through the tunnel while it's up, so nothing leaks to the system DNS.
- **DNS-over-TLS** is turned off for the tunnel link, because tunnel resolvers rarely support it.
- **Re-applied automatically** on NetworkManager's `dns-change` event, in case NetworkManager rewrites the link.

Your system DNS choice is untouched and still applies whenever no tunnel is up. The hook works for `nmcli connection up` too, not only the plugin.

Undo: `pkexec ~/.config/omarchy/plugins/tsmithscott.wireguard/bin/setup-tunnel-dns --remove`

## Uninstalling

The peer-stats helper and the tunnel-DNS hook are root-owned copies outside the plugin folder, so `omarchy plugin remove` doesn't remove them. Remove them first, with one password prompt:

```
pkexec ~/.config/omarchy/plugins/tsmithscott.wireguard/bin/uninstall-system-files
```

That removes `/etc/NetworkManager/dispatcher.d/90-omarchy-wireguard-dns`, `/usr/local/bin/omarchy-wg-dump`, and `/etc/sudoers.d/omarchy-wg-dump`. Your imported tunnels are NetworkManager profiles and stay until you delete them.
