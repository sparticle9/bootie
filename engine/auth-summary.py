#!/usr/bin/env python3
"""Print the reviewed authentication shape for a bootie plan.

Usage: auth-summary.py PLAN_JSON CARRIED_KEY_COUNT
Stdout is a compact shell-safe summary. The literal token FATAL means no
authentication material exists at all and the caller must refuse before
staging.
"""
import json
import sys


def main(argv):
    if len(argv) != 3:
        print("usage: auth-summary.py PLAN_JSON CARRIED_KEY_COUNT", file=sys.stderr)
        return 2
    plan = json.load(open(argv[1]))
    carried = int(argv[2])
    users = (plan.get("cloud_ops") or {}).get("users") or []
    manifest_keys = sum(len(user.get("keys") or []) for user in users)
    password_users = [
        user["name"] for user in users
        if user.get("passwd") and not user.get("lock_passwd")
    ]
    total_keys = carried + manifest_keys
    parts = [
        f"keys={total_keys} carried={carried} manifest_keys={manifest_keys}"
    ]
    if password_users:
        parts.append(f"password_users={','.join(password_users)}")
    if total_keys == 0 and not password_users:
        parts.append("FATAL")
    elif total_keys == 0:
        parts.append("password-only")
    else:
        parts.append("key")
    print(" ".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
