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

cp -- "$plugin_bin/tunnel-dns-dispatcher" "$WG_PLUGIN_HOOK"
check ours "$WG_PLUGIN_HOOK" "current dispatcher (marker) is ours"

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

wg_plugin_legacy_rule alice >"$WG_PLUGIN_RULE"
check ours "$WG_PLUGIN_RULE" "legacy sudoers rule is ours"
{ wg_plugin_legacy_rule alice; echo 'alice ALL=(ALL) ALL'; } >"$WG_PLUGIN_RULE"
check foreign "$WG_PLUGIN_RULE" "legacy rule plus extra line is foreign"
wg_plugin_legacy_rule alice >"$t/other-rule"
check foreign "$t/other-rule" "legacy rule text at another path is foreign"
{ echo "$WG_PLUGIN_MARKER"; wg_plugin_legacy_rule alice; } >"$WG_PLUGIN_RULE"
check ours "$WG_PLUGIN_RULE" "new sudoers rule (marker) is ours"

printf '#!/bin/sh\n# admin hook\n' >"$WG_PLUGIN_HOOK"
wg_plugin_may_write "$WG_PLUGIN_HOOK" 2>/dev/null && { echo "FAIL may_write allowed a foreign file"; fail=1; } || echo "ok   may_write refuses foreign file"
wg_plugin_remove "$WG_PLUGIN_HOOK" >/dev/null
[[ -e $WG_PLUGIN_HOOK ]] && echo "ok   remove leaves foreign file" || { echo "FAIL remove deleted foreign file"; fail=1; }
wg_plugin_may_write "$WG_PLUGIN_RULE" && echo "ok   may_write allows our file" || { echo "FAIL may_write refused our file"; fail=1; }
wg_plugin_remove "$WG_PLUGIN_RULE" >/dev/null
[[ ! -e $WG_PLUGIN_RULE ]] && echo "ok   remove deletes our file" || { echo "FAIL remove kept our file"; fail=1; }
wg_plugin_may_write "$t/nothing" && echo "ok   may_write allows absent path" || { echo "FAIL may_write refused absent path"; fail=1; }

exit $fail
