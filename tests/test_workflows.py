"""Offline guardrails for CI triggers, dependencies, and publication boundaries."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def workflow(name):
    # GitHub uses YAML 1.2; BaseLoader keeps the event key `on` from becoming
    # the YAML 1.1 boolean True, and is sufficient for these structural checks.
    return yaml.load((WORKFLOWS / name).read_text(), Loader=yaml.BaseLoader)


def steps(doc):
    return next(iter(doc["jobs"].values()))["steps"]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = workflow("ci.yml")
        self.release = workflow("release.yml")

    def test_ci_triggers_cover_push_pr_and_manual_runs(self):
        self.assertEqual(set(self.ci["on"]), {"push", "pull_request", "workflow_dispatch"})

    def test_ci_has_read_only_permissions_and_no_publication_steps(self):
        self.assertEqual(self.ci["permissions"], {"contents": "read"})
        self.assertEqual(
            [step["uses"].split("@")[0] for step in steps(self.ci) if "uses" in step],
            ["actions/checkout", "astral-sh/setup-uv"],
        )
        for step in steps(self.ci):
            self.assertNotIn("GH_TOKEN", step.get("env", {}))

    def test_actions_are_pinned_to_full_commit_shas(self):
        for name, doc in (("ci.yml", self.ci), ("release.yml", self.release)):
            for step in steps(doc):
                if "uses" in step:
                    with self.subTest(workflow=name, action=step["uses"]):
                        self.assertRegex(step["uses"], r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")

    def test_checkout_does_not_persist_credentials(self):
        for doc in (self.ci, self.release):
            checkout = steps(doc)[0]
            self.assertEqual(checkout["uses"].split("@")[0], "actions/checkout")
            self.assertEqual(checkout["with"]["persist-credentials"], "false")

    def test_uv_owns_python_and_uses_locked_dependencies(self):
        for doc in (self.ci, self.release):
            with self.subTest(workflow=doc["name"]):
                setup = next(s for s in steps(doc) if s.get("uses", "").startswith("astral-sh/setup-uv@"))
                self.assertEqual(setup["with"]["python-version"], "3.12")
                self.assertEqual(setup["with"]["version"], "latest-known")
                self.assertEqual(setup["with"]["require-checksums"], "true")
                self.assertEqual(setup["with"]["enable-cache"], "false")
                commands = "\n".join(s.get("run", "") for s in steps(doc))
                self.assertIn("uv sync --locked", commands)
                self.assertIn("uv run --locked python -m compileall", commands)
                self.assertIn("uv run --locked python -m unittest", commands)
                self.assertIn("uv run --locked sh scripts/test-bundle", commands)
                self.assertNotRegex(commands, r"\b(?:apt(?:-get)?|pip)\s+(?:update|install)\b")
                self.assertFalse(any(s.get("uses", "").startswith("actions/setup-python@") for s in steps(doc)))

    def test_shellcheck_uses_runner_tool_and_documented_severity(self):
        for doc in (self.ci, self.release):
            commands = "\n".join(s.get("run", "") for s in steps(doc))
            self.assertIn("shellcheck --version", commands)
            self.assertIn("shellcheck -S info -s sh", commands)
            self.assertIn("shellcheck -S info -s bash", commands)

    def test_ci_and_release_share_verification_commands(self):
        release_steps = {s["name"]: s for s in steps(self.release)}
        for step in steps(self.ci):
            if "run" in step:
                with self.subTest(step=step["name"]):
                    self.assertEqual(step["run"], release_steps[step["name"]]["run"])

    def test_release_publication_is_tag_gated(self):
        self.assertEqual(self.release["on"]["push"]["tags"], ["v*"])
        self.assertIn("workflow_dispatch", self.release["on"])
        release_steps = {s["name"]: s for s in steps(self.release)}
        for name in ("Attest bootie.sh build provenance", "Create GitHub Release"):
            self.assertEqual(release_steps[name]["if"], "startsWith(github.ref, 'refs/tags/v')")
        self.assertIn("--verify-tag", release_steps["Create GitHub Release"]["run"])
        self.assertIn("uv run --locked bash scripts/bundle", release_steps["Build release artifact"]["run"])

    def test_jobs_have_bounded_timeouts(self):
        for doc in (self.ci, self.release):
            for job in doc["jobs"].values():
                self.assertGreater(int(job["timeout-minutes"]), 0)
                self.assertLessEqual(int(job["timeout-minutes"]), 20)


if __name__ == "__main__":
    unittest.main()
