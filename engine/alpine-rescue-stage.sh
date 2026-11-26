#!/bin/sh
# Sourced by bootie-main after offline preflight and public key collection.
# Variables and prompt functions are supplied by bootie-main.
# shellcheck shell=sh disable=SC2154
$SUDO python3 "$here/engine/alpine_rescue.py" precheck "$work" "$rescue_console"
if [ -z "$console_only" ]; then
    command -v ssh-keygen >/dev/null || { echo "SSH mode requires ssh-keygen" >&2; exit 1; }
    ssh-keygen -l -f "$work/keys" >/dev/null || { echo "no usable SSH public key" >&2; exit 1; }
fi

python3 - "$work/plan.json" "$rescue_console" "$console_only" "$carried_keys" <<'PY'
import json
from pathlib import Path
import sys
plan = json.loads(Path(sys.argv[1]).read_text())
facts = plan["facts"]
print(f"Experimental Alpine 3.24.4 rescue on {plan['host']}, disk {facts['disk_path']}")
print(f"IPv4: {facts['ipv4_addr']} via {facts['ipv4_gateway']}, MAC {facts['net_mac']}")
print(f"Required provider console: {sys.argv[2]} (root shell)")
print("Access: console only" if sys.argv[3] else f"Access: console and key-only SSH ({sys.argv[4]} keys)")
print("Staging downloads a pinned Alpine ISO and builds a temporary RAM image.")
PY
confirm "assemble the experimental Alpine rescue image?" || exit 1
python3 "$here/engine/alpine_rescue.py" assemble "$work" "$rescue_console" "$console_only"
if [ -n "$no_reboot" ]; then
    echo "Alpine assembly verified locally. Temporary files will be removed. No kexec load attempted."
    exit 0
fi
approval=$(python3 "$here/engine/preflight.py" approval --plan "$work/plan.json")
echo "Type $approval to authorize kexec and shut down this OS:"
prompt_read "" && [ "$REPLY" = "$approval" ] || { echo "Alpine handoff cancelled" >&2; exit 1; }
$SUDO "$here/engine/facts.sh" > "$work/facts.handoff"
cmp -s "$work/facts" "$work/facts.handoff" || { echo "source facts changed; run rescue again" >&2; exit 1; }
$SUDO python3 "$here/engine/alpine_rescue.py" handoff "$work" "$rescue_console"
