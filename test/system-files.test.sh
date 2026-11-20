#!/bin/bash
# Tests for bin/system-files.bash: which files the plugin may replace/remove.
# Run: bash test/system-files.test.sh
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source -- "$here/../bin/system-files.bash"
plugin_bin=$here/../bin

t=$(mktemp -d)
trap 'rm -rf -- "$t"' EXIT
WG_PLUGIN_OWNER_UID=$(id -u)
WG_PLUGIN_HELPER=$t/omarchy-wg-dump
WG_PLUGIN_RULE=$t/sudoers-omarchy-wg-dump
WG_PLUGIN_HOOK=$t/90-omarchy-wireguard-dns
fail=0
check() { # <expected> <path> <label>
  local got; got=$(wg_plugin_file_state "$2")
  if [[ $got == "$1" ]]; then echo "ok   $3"; else echo "FAIL $3: expected $1, got $got"; fail=1; fi
}

check absent "$t/nothing" "missing file is absent"

wg_plugin_seal "$plugin_bin/tunnel-dns-dispatcher" "$WG_PLUGIN_HOOK"
check ours "$WG_PLUGIN_HOOK" "sealed dispatcher (as setup installs it) is ours"
bash -n "$WG_PLUGIN_HOOK" && echo "ok   sealed dispatcher still parses" || { echo "FAIL sealed dispatcher does not parse"; fail=1; }
sed -i 's/^# hook-version: .*/&\n# admin tweak/' "$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "sealed dispatcher edited by an admin (marker kept) is foreign"
wg_plugin_seal "$plugin_bin/tunnel-dns-dispatcher" "$WG_PLUGIN_HOOK"
sed -i 's/\(sha256=\)[0-9a-f]/\1x/' "$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "dispatcher with a damaged seal is foreign"
wg_plugin_seal "$plugin_bin/tunnel-dns-dispatcher" "$WG_PLUGIN_HOOK"
seal_line=$(grep -F "$WG_PLUGIN_MARKER sha256=" "$WG_PLUGIN_HOOK")
echo "$seal_line" >>"$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "dispatcher with two seal lines is foreign"
printf '#!/bin/sh\necho admin\n%s\n' "$seal_line" >"$t/copied-seal"
check foreign "$t/copied-seal" "admin file with a seal line copied from ours is foreign"

git -C "$here/.." show 95a26f7:bin/tunnel-dns-dispatcher >"$WG_PLUGIN_HOOK"
check ours "$WG_PLUGIN_HOOK" "1.5.1 dispatcher (bare marker, legacy hash) is ours"
echo "# admin tweak" >>"$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "1.5.1 dispatcher edited by an admin (marker kept) is foreign"
printf '#!/bin/sh\n%s\necho admin\n' "$WG_PLUGIN_MARKER" >"$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "admin file with a bare marker line is foreign"

git -C "$here/.." show bf39a36:bin/tunnel-dns-dispatcher >"$WG_PLUGIN_HOOK"
check ours "$WG_PLUGIN_HOOK" "1.2 dispatcher (legacy hash) is ours"
git -C "$here/.." show ce2cc15:bin/tunnel-dns-dispatcher >"$WG_PLUGIN_HOOK"
check ours "$WG_PLUGIN_HOOK" "1.5.0 dispatcher (legacy hash) is ours"
echo "# local tweak" >>"$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "edited legacy dispatcher is foreign"

printf '#!/bin/sh\n# admin hook\n' >"$WG_PLUGIN_HOOK"
check foreign "$WG_PLUGIN_HOOK" "admin's own dispatcher is foreign"

ln -sf -- "$plugin_bin/tunnel-dns-dispatcher" "$t/link"
check foreign "$t/link" "symlink (even to our file) is foreign"
mkdir -- "$t/dir"
check foreign "$t/dir" "directory is foreign"

git -C "$here/.." show bf39a36:bin/setup-peer-stats | sed -n '/<<.HELPER.$/,/^HELPER$/p' | sed '1d;$d' >"$WG_PLUGIN_HELPER"
check ours "$WG_PLUGIN_HELPER" "1.x helper (legacy hash) is ours"
# The helper setup-peer-stats writes, rendered the way 1.5.1 and now it does.
render_helper() { { echo "WG_PLUGIN_MARKER='$WG_PLUGIN_MARKER'"; git -C "$here/.." show "$1":bin/setup-peer-stats 2>/dev/null || cat "$plugin_bin/setup-peer-stats"; } | sed -n '1p;/<<HELPER$/,/^HELPER$/p' | sed '2s/.*/cat <<HELPER/' | bash; }
render_helper 95a26f7 >"$WG_PLUGIN_HELPER"
check ours "$WG_PLUGIN_HELPER" "1.5.1 helper (bare marker, legacy hash) is ours"
render_helper WORKTREE >"$t/plain-helper"
wg_plugin_seal "$t/plain-helper" "$WG_PLUGIN_HELPER"
check ours "$WG_PLUGIN_HELPER" "sealed helper is ours"
sed -i 's/(hidden)/KEY/' "$WG_PLUGIN_HELPER"
check foreign "$WG_PLUGIN_HELPER" "sealed helper edited by an admin is foreign"

# Unsealed (pre-1.5.2) rules name a user nobody can prove the plugin chose,
# so they are never ours, however they got there (install, edit, restore).
render_helper 95a26f7 >"$WG_PLUGIN_HELPER"; wg_plugin_legacy_rule alice >"$WG_PLUGIN_RULE"
check foreign "$WG_PLUGIN_RULE" "legacy sudoers rule, even written with its helper, is foreign"
wg_plugin_legacy_rule bob >"$WG_PLUGIN_RULE"
check foreign "$WG_PLUGIN_RULE" "legacy rule reassigned to another account is foreign"
render_helper 95a26f7 >"$WG_PLUGIN_HELPER"; wg_plugin_legacy_rule bob >"$WG_PLUGIN_RULE"
check foreign "$WG_PLUGIN_RULE" "reassigned legacy rule restored together with its helper is foreign"
{ echo "$WG_PLUGIN_MARKER"; wg_plugin_legacy_rule bob; } >"$WG_PLUGIN_RULE"
check foreign "$WG_PLUGIN_RULE" "1.5.1 sudoers rule (bare marker) is foreign"
wg_plugin_legacy_rule_note "$WG_PLUGIN_RULE" | grep -qF "sudo rm $WG_PLUGIN_RULE" && echo "ok   legacy rule gets a how-to-remove note" || { echo "FAIL no note for legacy rule"; fail=1; }
wg_plugin_may_write "$WG_PLUGIN_RULE" 2>"$t/err" && { echo "FAIL may_write allowed a legacy rule"; fail=1; } || echo "ok   may_write refuses a legacy rule"
grep -q "before 1.5.2" "$t/err" && echo "ok   setup refusal explains the legacy rule" || { echo "FAIL setup refusal lacks legacy note"; fail=1; }
wg_plugin_remove "$WG_PLUGIN_HELPER" "$WG_PLUGIN_RULE" >"$t/out"
[[ ! -e $WG_PLUGIN_HELPER && -e $WG_PLUGIN_RULE ]] && echo "ok   removal deletes the helper but keeps a legacy rule" || { echo "FAIL removal with legacy rule"; fail=1; }
grep -q "sudo rm" "$t/out" && echo "ok   removal explains the kept legacy rule" || { echo "FAIL removal lacks legacy note"; fail=1; }
printf '#!/bin/sh\n# admin hook\n' >"$t/hook-note"
[[ -z $(wg_plugin_legacy_rule_note "$t/hook-note") ]] && echo "ok   no legacy note for other paths" || { echo "FAIL legacy note on another path"; fail=1; }
{ echo "$WG_PLUGIN_MARKER"; wg_plugin_legacy_rule alice; } >"$t/plain-rule"
wg_plugin_seal "$t/plain-rule" "$WG_PLUGIN_RULE"
check ours "$WG_PLUGIN_RULE" "sealed sudoers rule is ours"
echo 'alice ALL=(ALL) ALL' >>"$WG_PLUGIN_RULE"
check foreign "$WG_PLUGIN_RULE" "sealed sudoers rule plus an admin line is foreign"
wg_plugin_seal "$t/plain-rule" "$WG_PLUGIN_RULE"

printf '#!/bin/sh\n# admin hook\n' >"$WG_PLUGIN_HOOK"
wg_plugin_may_write "$WG_PLUGIN_HOOK" 2>/dev/null && { echo "FAIL may_write allowed a foreign file"; fail=1; } || echo "ok   may_write refuses foreign file"
wg_plugin_remove "$WG_PLUGIN_HOOK" >/dev/null
[[ -e $WG_PLUGIN_HOOK ]] && echo "ok   remove leaves foreign file" || { echo "FAIL remove deleted foreign file"; fail=1; }
wg_plugin_may_write "$WG_PLUGIN_RULE" && echo "ok   may_write allows our file" || { echo "FAIL may_write refused our file"; fail=1; }
wg_plugin_remove "$WG_PLUGIN_RULE" >/dev/null
[[ ! -e $WG_PLUGIN_RULE ]] && echo "ok   remove deletes our file" || { echo "FAIL remove kept our file"; fail=1; }
wg_plugin_may_write "$t/nothing" && echo "ok   may_write allows absent path" || { echo "FAIL may_write refused absent path"; fail=1; }

exit $fail
