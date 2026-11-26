"""Unit tests for per-install password generation, SHA-512 crypt, and desktop password flow."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import password as pw  # noqa: E402
import preflight as rp  # noqa: E402


def sample_plan(boot_target="desktop", managed_user="omarchy", users=None):
    if users is None:
        users = [{
            "name": "omarchy",
            "groups": [],
            "shell": "",
            "sudo": "ALL=(ALL:ALL) ALL",
            "lock_passwd": True,
            "passwd": "",
            "keys": [],
        }]
    return {
        "host": "testhost",
        "postinstall": {
            "boot_target": boot_target,
            "managed_user": managed_user,
        },
        "cloud_ops": {"users": users},
    }


class PasswordGenerationTests(unittest.TestCase):
    def test_generate_password_default_length_and_charset(self):
        seen = set()
        for _ in range(30):
            val = pw.generate_password()
            self.assertEqual(len(val), 10)
            self.assertTrue(any(c in pw.ALPHABET_LOWER for c in val), val)
            self.assertTrue(any(c in pw.ALPHABET_UPPER for c in val), val)
            self.assertTrue(any(c in pw.ALPHABET_DIGITS for c in val), val)
            self.assertTrue(all(c in pw.ALPHABET_ALL for c in val), val)
            for ambiguous in "0O1lI":
                self.assertNotIn(ambiguous, val)
            seen.add(val)
        self.assertGreater(len(seen), 25)

    def test_generate_password_rejects_short_or_non_int_length(self):
        for bad in (0, 7, "10", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    pw.generate_password(bad)


class Sha512CryptTests(unittest.TestCase):
    def test_drepper_official_sha512_crypt_test_vectors(self):
        # Official reference vectors from Ulrich Drepper's SHA-crypt specification.
        vectors = [
            (
                "Hello world!",
                "saltstring",
                5000,
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
            ),
            (
                "Hello world!",
                "saltstringsaltstring",
                10000,
                "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
            ),
            (
                "This is just a test",
                "toolongsaltstring",
                5000,
                "$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
            ),
            (
                "a very much longer text to encrypt.  This one even stretches over morethan one line.",
                "anotherlongsaltstring",
                1400,
                "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
            ),
            (
                "we have a short salt string but not a short password",
                "short",
                77777,
                "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
            ),
            (
                "a short string",
                "asaltof16chars..",
                123456,
                "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
            ),
        ]
        for secret, salt, rounds, expected in vectors:
            with self.subTest(secret=secret[:16], rounds=rounds):
                self.assertEqual(pw.sha512_crypt(secret, salt=salt, rounds=rounds), expected)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_matches_openssl_passwd_6(self):
        r = subprocess.run(
            ["openssl", "passwd", "-6", "-salt", "salttest", "K7mP2xR9qL"],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(pw.sha512_crypt("K7mP2xR9qL", salt="salttest"), r.stdout.strip())

    def test_random_salt_and_input_validation(self):
        h1 = pw.sha512_crypt("MyPass123")
        h2 = pw.sha512_crypt("MyPass123")
        self.assertRegex(h1, r"^\$6\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$")
        self.assertNotEqual(h1, h2)
        for bad in ("", "line1\nline2", "bad\rpass", "bad\x00pass", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    pw.sha512_crypt(bad)


class PlanPasswordIntegrationTests(unittest.TestCase):
    def test_needs_auto_password_only_for_desktop_without_existing_passwd(self):
        self.assertEqual(pw.needs_auto_password(sample_plan("desktop", "omarchy")), "omarchy")
        self.assertEqual(pw.needs_auto_password(sample_plan("console", "omarchy")), "")
        with_pw = sample_plan("desktop", "omarchy")
        with_pw["cloud_ops"]["users"][0]["passwd"] = "$6$existing$hash"
        self.assertEqual(pw.needs_auto_password(with_pw), "")

    def test_shipped_manifests_auto_password_behavior(self):
        omarchy = rp.load_manifest(ROOT / "manifests" / "omarchy-4.5.yml")
        self.assertEqual(omarchy["cloud_config"]["users"][0]["sudo"], "ALL=(ALL:ALL) ALL")
        om_plan = {"postinstall": omarchy["postinstall"],
                   "cloud_ops": rp.transpile_cloud_config(omarchy["cloud_config"])}
        self.assertEqual(pw.needs_auto_password(om_plan), "omarchy")

        for server_name in ("debian-13", "ubuntu-24.04", "ubuntu-26.04"):
            with self.subTest(manifest=server_name):
                m = rp.load_manifest(ROOT / "manifests" / f"{server_name}.yml")
                p = {"postinstall": m["postinstall"],
                     "cloud_ops": rp.transpile_cloud_config(m["cloud_config"])}
                self.assertEqual(pw.needs_auto_password(p), "")

    def test_cli_apply_hashes_password_sets_mode_600_and_never_prints_hash(self):
        with tempfile.TemporaryDirectory() as td:
            plan_path = Path(td) / "plan.json"
            plan_path.write_text(json.dumps(sample_plan()))
            out, err = io.StringIO(), io.StringIO()
            old_stdin = sys.stdin
            sys.stdin = io.StringIO("K7mP2xR9qL\n")
            try:
                with redirect_stdout(out), redirect_stderr(err):
                    rc = pw.main(["apply", "--plan", str(plan_path)])
            finally:
                sys.stdin = old_stdin
            self.assertEqual(rc, 0, err.getvalue())
            self.assertEqual(out.getvalue().strip(), "omarchy")
            self.assertNotIn("$6$", out.getvalue() + err.getvalue())
            self.assertNotIn("K7mP2xR9qL", out.getvalue() + err.getvalue())
            mode = os.stat(plan_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            updated = json.loads(plan_path.read_text())
            user = updated["cloud_ops"]["users"][0]
            self.assertFalse(user["lock_passwd"])
            self.assertRegex(user["passwd"], r"^\$6\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$")


if __name__ == "__main__":
    unittest.main()
