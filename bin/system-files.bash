# Shared by setup-peer-stats, setup-tunnel-dns, uninstall-system-files and
# wg-status (sourced, not run). Decides whether a file outside the home
# directory is one this plugin installed AND still exactly as installed, so
# the plugin never overwrites or deletes a file an administrator put at the
# same path, or changes an administrator made to a file the plugin installed.
#
# A file counts as the plugin's only if it is a regular, root-owned file (not
# a symlink) whose contents are unchanged since the plugin wrote it:
#   - files installed since 1.5.2 carry a sealed marker line,
#       # omarchy-plugin-file: tsmithscott.wireguard sha256=<hex>
#     where <hex> is the SHA-256 of the file without that line. Any edit to
#     the rest of the file (or to the line) breaks the seal.
#   - the dispatcher hook and helper that earlier releases installed have
#     fixed contents (no per-install choices), so an exact SHA-256 match
#     below shows the file is still what the plugin wrote.
#   - a sudoers rule from before 1.5.2 is never the plugin's to replace or
#     remove. Its text names a user, and nothing on disk (contents,
#     timestamps, ownership) can show whether the plugin or an administrator
#     chose that user, for example after an administrator moved the
#     permission to another account, then restored or migrated the file.
#     Setup and removal leave such a rule in place and explain how to check
#     and remove it by hand (wg_plugin_legacy_rule_note).
# Anything else at those paths, including an edited copy of a plugin file, is
# left alone.

WG_PLUGIN_MARKER='# omarchy-plugin-file: tsmithscott.wireguard'

WG_PLUGIN_HELPER=/usr/local/bin/omarchy-wg-dump
WG_PLUGIN_RULE=/etc/sudoers.d/omarchy-wg-dump
WG_PLUGIN_HOOK=/etc/NetworkManager/dispatcher.d/90-omarchy-wireguard-dns
WG_PLUGIN_OWNER_UID=0 # everything the plugin installs is root-owned

WG_PLUGIN_LEGACY_SHA256=(
  62c8208f27f7fe34bf558cc19e2c3426339b07b6a6c12fee5df7eb2d76354f82 # dispatcher hook, 1.2.0-1.4.x
  dd8dccf34d26147ef049e1b608bf96621ed6715a6fcb8403293b57fd54d2ab46 # dispatcher hook, 1.5.0
  7494162bee6f5ffb325f31f5d64ec041ac00dfd4f52f276101154cb1cb8e2b74 # dispatcher hook, 1.5.1 (unsealed marker)
  4999500bccd1c6706109f1c10955f42c7e04a1db25f29c4bad57763080f74ce1 # omarchy-wg-dump, 1.0.0-1.5.0
  fcdf84a8ed116007812609694d07c28648c1217b8b4741bf7ebbb5aad371072f # omarchy-wg-dump, 1.5.1 (unsealed marker)
)

# The sudoers rule setup-peer-stats writes for user $1, before the marker
# line is added and sealed. Releases before 1.5.2 installed it unsealed.
wg_plugin_legacy_rule() {
  printf '%s ALL=(root) NOPASSWD: %s ""\nDefaults!%s !log_allowed\n' "$1" "$WG_PLUGIN_HELPER" "$WG_PLUGIN_HELPER"
}

# Copies $1 to $2, turning its one bare marker line into a sealed one.
wg_plugin_seal() {
  local src=$1 dst=$2 sum
  [[ $(grep -cxF -- "$WG_PLUGIN_MARKER" "$src") == 1 ]] || { echo "$src: expected exactly one '$WG_PLUGIN_MARKER' line" >&2; return 2; }
  sum=$(grep -vxF -- "$WG_PLUGIN_MARKER" "$src" | sha256sum) && sum=${sum%% *}
  awk -v m="$WG_PLUGIN_MARKER" -v s="$sum" '$0 == m { $0 = m " sha256=" s } { print }' "$src" >"$dst"
}

# Succeeds if $1 has exactly one sealed marker line and the rest of the file
# still hashes to the value in it.
wg_plugin_seal_intact() {
  local f=$1 line want got
  line=$(awk -v p="$WG_PLUGIN_MARKER sha256=" '
    index($0, p) == 1 && $0 ~ /sha256=[0-9a-f]+$/ && length($0) == length(p) + 64 { n++; l = $0 }
    END { if (n == 1) print l }' "$f" 2>/dev/null)
  [[ -n $line ]] || return 1
  want=${line##*sha256=}
  got=$(grep -vxF -- "$line" "$f" | sha256sum) && got=${got%% *}
  [[ $got == "$want" ]]
}

# Succeeds if $1 is a regular, root-owned file, not a symlink.
wg_plugin_plain_root_file() {
  [[ ! -L $1 && -f $1 && $(stat -c %u -- "$1" 2>/dev/null) == "$WG_PLUGIN_OWNER_UID" ]]
}

# Prints absent, ours or foreign for path $1.
wg_plugin_file_state() {
  local f=$1 sum s
  if [[ ! -e $f && ! -L $f ]]; then echo absent; return; fi
  wg_plugin_plain_root_file "$f" || { echo foreign; return; }
  if wg_plugin_seal_intact "$f"; then echo ours; return; fi
  sum=$(sha256sum -- "$f" 2>/dev/null) && sum=${sum%% *}
  for s in "${WG_PLUGIN_LEGACY_SHA256[@]}"; do
    [[ $sum == "$s" ]] && { echo ours; return; }
  done
  echo foreign
}

# If $1 is the sudoers rule path and holds an unsealed rule in the format
# releases before 1.5.2 wrote, prints how to deal with it by hand.
wg_plugin_legacy_rule_note() {
  [[ $1 == "$WG_PLUGIN_RULE" ]] && wg_plugin_plain_root_file "$1" || return 0
  grep -qF -- "$WG_PLUGIN_MARKER sha256=" "$1" 2>/dev/null && return 0
  grep -qF -- "NOPASSWD: $WG_PLUGIN_HELPER \"\"" "$1" 2>/dev/null || return 0
  echo "$1 looks like a peer-stats rule from a WireGuard plugin release before 1.5.2. Those rules carry no seal, so the plugin cannot tell whether the account it names was chosen by the plugin or by an administrator, and never replaces or removes one. Check it with 'sudo cat $1'; to let the plugin manage it again, remove it with 'sudo rm $1' and enable peer stats again."
}

# Fails (with a message) if $1 exists and is not the plugin's to replace.
wg_plugin_may_write() {
  [[ $(wg_plugin_file_state "$1") != foreign ]] && return 0
  wg_plugin_legacy_rule_note "$1" >&2
  echo "$1 already exists and either was not installed by the WireGuard plugin or has been changed since; leaving it in place. Remove or rename it yourself if you want the plugin's version." >&2
  return 3
}

# Removes each of $@ that the plugin installed and is unchanged. Every state
# is decided before anything is deleted.
wg_plugin_remove() {
  local f states=()
  for f in "$@"; do states+=("$(wg_plugin_file_state "$f")"); done
  for f in "$@"; do
    case ${states[0]} in
      ours) rm -f -- "$f" && echo "Removed $f" ;;
      foreign)
        echo "Left $f in place: it was not installed by the WireGuard plugin, or has been changed since"
        wg_plugin_legacy_rule_note "$f" ;;
      absent) ;;
    esac
    states=("${states[@]:1}")
  done
}
