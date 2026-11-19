# Shared by setup-peer-stats, setup-tunnel-dns, uninstall-system-files and
# wg-status (sourced, not run). Decides whether a file outside the home
# directory is one this plugin installed, so the plugin never overwrites or
# deletes a file an administrator put at the same path.
#
# A file counts as the plugin's only if it is a regular, root-owned file (not
# a symlink) and either
#   - contains the marker line below (every file installed since 1.5.1), or
#   - is byte-for-byte a file an earlier release installed (before the marker
#     existed): one of the SHA-256 sums below, or the exact sudoers rule
#     setup-peer-stats used to write.
# Anything else at those paths is left alone.

WG_PLUGIN_MARKER='# omarchy-plugin-file: tsmithscott.wireguard'

WG_PLUGIN_HELPER=/usr/local/bin/omarchy-wg-dump
WG_PLUGIN_RULE=/etc/sudoers.d/omarchy-wg-dump
WG_PLUGIN_HOOK=/etc/NetworkManager/dispatcher.d/90-omarchy-wireguard-dns
WG_PLUGIN_OWNER_UID=0 # everything the plugin installs is root-owned

WG_PLUGIN_LEGACY_SHA256=(
  62c8208f27f7fe34bf558cc19e2c3426339b07b6a6c12fee5df7eb2d76354f82 # dispatcher hook, 1.2.0-1.4.x
  dd8dccf34d26147ef049e1b608bf96621ed6715a6fcb8403293b57fd54d2ab46 # dispatcher hook, 1.5.0
  4999500bccd1c6706109f1c10955f42c7e04a1db25f29c4bad57763080f74ce1 # omarchy-wg-dump, 1.0.0-1.5.0
)

# The sudoers rule releases before 1.5.1 wrote, for user $1.
wg_plugin_legacy_rule() {
  printf '%s ALL=(root) NOPASSWD: %s ""\nDefaults!%s !log_allowed\n' "$1" "$WG_PLUGIN_HELPER" "$WG_PLUGIN_HELPER"
}

# Prints absent, ours or foreign for path $1.
wg_plugin_file_state() {
  local f=$1 sum s user
  if [[ ! -e $f && ! -L $f ]]; then echo absent; return; fi
  if [[ -L $f || ! -f $f ]] || [[ $(stat -c %u -- "$f" 2>/dev/null) != "$WG_PLUGIN_OWNER_UID" ]]; then
    echo foreign; return
  fi
  if grep -qxF -- "$WG_PLUGIN_MARKER" "$f" 2>/dev/null; then echo ours; return; fi
  sum=$(sha256sum -- "$f" 2>/dev/null) && sum=${sum%% *}
  for s in "${WG_PLUGIN_LEGACY_SHA256[@]}"; do
    [[ $sum == "$s" ]] && { echo ours; return; }
  done
  if [[ $f == "$WG_PLUGIN_RULE" ]]; then
    user=$(head -c 64 -- "$f" 2>/dev/null | head -n 1) && user=${user%% *}
    if [[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && cmp -s -- "$f" <(wg_plugin_legacy_rule "$user"); then
      echo ours; return
    fi
  fi
  echo foreign
}

# Fails (with a message) if $1 exists and is not the plugin's to replace.
wg_plugin_may_write() {
  [[ $(wg_plugin_file_state "$1") != foreign ]] && return 0
  echo "$1 already exists and was not installed by the WireGuard plugin; leaving it in place. Remove or rename it yourself if you want the plugin's version." >&2
  return 3
}

# Removes $1 only if the plugin installed it.
wg_plugin_remove() {
  case $(wg_plugin_file_state "$1") in
    ours) rm -f -- "$1" && echo "Removed $1" ;;
    foreign) echo "Left $1 in place: it was not installed by the WireGuard plugin" ;;
    absent) ;;
  esac
}
