#!/usr/bin/env python3
"""password.py — per-install password generation and SHA-512 crypt hashing (stdlib only).

Used by bootie-main during install staging to:
  - generate a unique per-install alphanumeric password for desktop manifests
    (e.g. omarchy-4.5) so sudo and local/desktop login work without embedding
    a static default password in public manifests;
  - hash operator-provided (--password / --password-file) or generated
    passwords using standard SHA-512 crypt ($6$...) with zero external
    dependencies (works on Python 3.10+ including 3.13+ where `crypt` was
    removed);
  - patch the target user entry in a staged plan.json (chmod 600).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

# Unambiguous alphanumeric sets (omit 0/O and 1/l/I for easy manual entry).
ALPHABET_LOWER = "abcdefghijkmnopqrstuvwxyz"
ALPHABET_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
ALPHABET_DIGITS = "23456789"
ALPHABET_ALL = ALPHABET_LOWER + ALPHABET_UPPER + ALPHABET_DIGITS
CRYPT_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

DEFAULT_ROUNDS = 5000
MIN_ROUNDS = 1000
MAX_ROUNDS = 999999999


def generate_password(length=10):
    """Return a cryptographically random alphanumeric password."""
    if not isinstance(length, int) or length < 8:
        raise ValueError("password length must be an integer >= 8")
    chars = [
        secrets.choice(ALPHABET_LOWER),
        secrets.choice(ALPHABET_UPPER),
        secrets.choice(ALPHABET_DIGITS),
    ] + [secrets.choice(ALPHABET_ALL) for _ in range(length - 3)]
    # Fisher-Yates shuffle with unbiased CSPRNG indices.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def _b64_from_24bit(b2, b1, b0, n):
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(CRYPT_B64[w & 0x3F])
        w >>= 6
    return "".join(out)


def _repeat_bytes(buf, length):
    if not length:
        return b""
    reps, rem = divmod(length, len(buf))
    return buf * reps + buf[:rem]


def sha512_crypt(password, salt=None, rounds=DEFAULT_ROUNDS):
    """Compute a standard glibc/Drepper SHA-512 crypt hash ($6$...)."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if "\x00" in password or "\n" in password or "\r" in password:
        raise ValueError("password must not contain NUL or newline characters")

    rounds_custom = rounds != DEFAULT_ROUNDS
    if not isinstance(rounds, int):
        raise ValueError("rounds must be an integer")
    rounds = max(MIN_ROUNDS, min(MAX_ROUNDS, rounds))

    if salt is None:
        salt = "".join(secrets.choice(CRYPT_B64) for _ in range(16))
    else:
        if not isinstance(salt, str) or not salt:
            raise ValueError("salt must be a non-empty string")
        if any(ch not in CRYPT_B64 for ch in salt):
            raise ValueError("salt contains invalid crypt base64 characters")
        salt = salt[:16]

    pw = password.encode("utf-8")
    sb = salt.encode("ascii")

    # Step 1-8: digest B = SHA512(pw + salt + pw)
    b = hashlib.sha512(pw + sb + pw).digest()

    # Step 1-12: digest A
    a_ctx = hashlib.sha512()
    a_ctx.update(pw)
    a_ctx.update(sb)
    a_ctx.update(_repeat_bytes(b, len(pw)))
    n = len(pw)
    while n > 0:
        a_ctx.update(b if (n & 1) else pw)
        n >>= 1
    a = a_ctx.digest()

    # Step 13-16: byte sequence P from DP = SHA512(pw * len(pw))
    dp = hashlib.sha512(pw * len(pw)).digest()
    p = _repeat_bytes(dp, len(pw))

    # Step 17-20: byte sequence S from DS = SHA512(salt * (16 + A[0]))
    ds = hashlib.sha512(sb * (16 + a[0])).digest()
    s = _repeat_bytes(ds, len(sb))

    # Step 21: rounds loop
    c = a
    for i in range(rounds):
        ctx = hashlib.sha512()
        ctx.update(p if (i & 1) else c)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        ctx.update(c if (i & 1) else p)
        c = ctx.digest()

    # Step 22: base64 encoding in SHA-512 crypt permutation order
    groups = (
        (0, 21, 42, 4), (22, 43, 1, 4), (44, 2, 23, 4), (3, 24, 45, 4),
        (25, 46, 4, 4), (47, 5, 26, 4), (6, 27, 48, 4), (28, 49, 7, 4),
        (50, 8, 29, 4), (9, 30, 51, 4), (31, 52, 10, 4), (53, 11, 32, 4),
        (12, 33, 54, 4), (34, 55, 13, 4), (56, 14, 35, 4), (15, 36, 57, 4),
        (37, 58, 16, 4), (59, 17, 38, 4), (18, 39, 60, 4), (40, 61, 19, 4),
        (62, 20, 41, 4),
    )
    encoded = "".join(_b64_from_24bit(c[i2], c[i1], c[i0], n) for i2, i1, i0, n in groups)
    encoded += _b64_from_24bit(0, 0, c[63], 2)

    prefix = f"$6$rounds={rounds}$" if rounds_custom else "$6$"
    return f"{prefix}{salt}${encoded}"


def resolve_target_user(plan, explicit_user=None):
    """Find the target user dict in plan['cloud_ops']['users']."""
    users = (plan.get("cloud_ops") or {}).get("users") or []
    if not users:
        raise ValueError("plan declares no cloud_ops users")
    wanted = explicit_user or (plan.get("postinstall") or {}).get("managed_user")
    if wanted:
        for user in users:
            if user.get("name") == wanted:
                return user
        raise ValueError(f"target user '{wanted}' not found in plan cloud_ops.users")
    return users[0]


def needs_auto_password(plan):
    """Return the managed username if a desktop plan needs a per-install password."""
    postinstall = plan.get("postinstall") or {}
    if postinstall.get("boot_target") != "desktop":
        return ""
    try:
        user = resolve_target_user(plan)
    except ValueError:
        return ""
    if user.get("passwd"):
        return ""
    return user.get("name") or ""


def apply_password(plan, password, username=None):
    """Hash password with SHA-512 crypt and unlock the target user in plan."""
    user = resolve_target_user(plan, explicit_user=username)
    user["passwd"] = sha512_crypt(password)
    user["lock_passwd"] = False
    return user["name"]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bootie-password")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("generate", help="generate a per-install alphanumeric password")
    p.add_argument("--length", type=int, default=10)

    p = sub.add_parser("needs-auto", help="print target user if desktop plan needs an auto password")
    p.add_argument("--plan", required=True)

    p = sub.add_parser("target-user", help="print target user for --password")
    p.add_argument("--plan", required=True)

    p = sub.add_parser("apply", help="read plaintext password from stdin and patch plan.json")
    p.add_argument("--plan", required=True)
    p.add_argument("--user")

    args = ap.parse_args(argv)
    if args.cmd == "generate":
        try:
            print(generate_password(args.length))
        except ValueError as exc:
            print(f"password error: {exc}", file=sys.stderr)
            return 2
        return 0

    plan_path = Path(args.plan)
    try:
        plan = json.loads(plan_path.read_text())
    except (OSError, ValueError) as exc:
        print(f"password error: {exc}", file=sys.stderr)
        return 1

    if args.cmd == "needs-auto":
        user = needs_auto_password(plan)
        if user:
            print(user)
        return 0

    if args.cmd == "target-user":
        try:
            user = resolve_target_user(plan)
        except ValueError as exc:
            print(f"password error: {exc}", file=sys.stderr)
            return 1
        print(user["name"])
        return 0

    if args.cmd == "apply":
        raw = sys.stdin.readline()
        pw = raw.rstrip("\r\n")
        try:
            name = apply_password(plan, pw, username=args.user)
        except ValueError as exc:
            print(f"password error: {exc}", file=sys.stderr)
            return 2
        tmp_path = plan_path.with_suffix(".json.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(plan, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp_path, plan_path)
            os.chmod(plan_path, 0o600)
        except OSError as exc:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            print(f"password error: {exc}", file=sys.stderr)
            return 1
        print(name)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
