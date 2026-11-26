"""Validate schema/manifest-v2.schema.json and check every shipped/example manifest against it."""
import json
from pathlib import Path
import re
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "manifest-v2.schema.json"
sys.path.insert(0, str(ROOT / "engine"))

import preflight as rp  # noqa: E402


def _matches_type(value, expected):
    if isinstance(expected, list):
        return any(_matches_type(value, t) for t in expected)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    raise AssertionError(f"unsupported JSON Schema type in test validator: {expected!r}")


def validate_against_schema(value, schema, root_schema=None, path="$"):
    """Validate a JSON/YAML value against the JSON Schema subset used in manifest-v2.schema.json."""
    if root_schema is None:
        root_schema = schema
    errors = []

    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise AssertionError(f"only local $ref supported: {ref}")
        target = root_schema
        for part in ref[2:].split("/"):
            target = target[part]
        return validate_against_schema(value, target, root_schema, path)

    if "oneOf" in schema:
        matches = 0
        branch_errors = []
        for idx, sub in enumerate(schema["oneOf"]):
            errs = validate_against_schema(value, sub, root_schema, path)
            if not errs:
                matches += 1
            else:
                branch_errors.append((idx, errs))
        if matches != 1:
            errors.append(
                f"{path}: expected exactly 1 oneOf match, got {matches} (branches: {branch_errors})"
            )
        return errors

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")
        return errors

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum {schema['enum']!r}")
        return errors

    if "not" in schema:
        if not validate_against_schema(value, schema["not"], root_schema, path):
            errors.append(f"{path}: value {value!r} matched disallowed 'not' schema")

    if "type" in schema and not _matches_type(value, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']!r}, got {type(value).__name__}")
        return errors

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: string shorter than minLength {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match pattern {schema['pattern']!r}")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} > maximum {schema['maximum']}")

    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors.extend(validate_against_schema(item, schema["items"], root_schema, f"{path}[{i}]"))

    if isinstance(value, dict):
        for req in schema.get("required") or []:
            if req not in value:
                errors.append(f"{path}: missing required key {req!r}")
        props = schema.get("properties") or {}
        pat_props = schema.get("patternProperties") or {}
        additional = schema.get("additionalProperties", True)
        for key, val in value.items():
            matched = False
            if key in props:
                matched = True
                errors.extend(validate_against_schema(val, props[key], root_schema, f"{path}.{key}"))
            for pattern, sub in pat_props.items():
                if re.search(pattern, key):
                    matched = True
                    errors.extend(validate_against_schema(val, sub, root_schema, f"{path}.{key}"))
            if not matched and additional is False:
                errors.append(f"{path}: unexpected additional property {key!r}")

    return errors


class ManifestSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text())

    def test_schema_metadata_and_preflight_parity(self):
        self.assertIn("$schema", self.schema)
        self.assertIn("2020-12", self.schema["$schema"])
        self.assertEqual(self.schema["properties"]["manifest_version"]["const"], 2)

        defs = self.schema["$defs"]
        self.assertEqual(set(defs["cloud_config"]["properties"].keys()), rp.CC_TOP_SUPPORTED)
        self.assertEqual(set(defs["cloud_config_user"]["properties"].keys()), rp.CC_USER_KEYS)
        self.assertEqual(set(defs["cloud_config_file"]["properties"].keys()), rp.CC_FILE_KEYS)
        self.assertEqual(
            set(defs["postinstall"]["properties"].keys()),
            {"managed_user", "boot_target", "install_om_desktop"},
        )

    def test_every_shipped_and_example_manifest_validates_against_schema(self):
        manifest_paths = sorted((ROOT / "manifests").glob("*.yml")) + sorted(
            (ROOT / "examples" / "manifests").glob("*.yml")
        )
        self.assertGreaterEqual(len(manifest_paths), 4)
        for path in manifest_paths:
            with self.subTest(manifest=str(path.relative_to(ROOT))):
                doc = yaml.safe_load(path.read_text())
                errors = validate_against_schema(doc, self.schema)
                self.assertEqual(errors, [], f"Schema errors in {path.name}: {errors}")
                # Confirm runtime loader agrees.
                rp.load_manifest(path)

    def test_schema_rejects_invalid_manifest_mutations(self):
        base = yaml.safe_load((ROOT / "manifests" / "debian-13.yml").read_text())
        self.assertEqual(validate_against_schema(base, self.schema), [])

        mutations = {
            "unknown_top_key": lambda d: d.__setitem__("typo_key", True),
            "conflicting_artifact_sources": lambda d: d["artifact"].__setitem__(
                "index_url", "https://nightly.omarchy.org/stable/latest.json"
            ),
            "invalid_rootfs": lambda d: d["personalize"].__setitem__("rootfs", "zfs"),
            "invalid_connectivity_host": lambda d: d["personalize"].__setitem__(
                "connectivity_host", "https://deb.debian.org"
            ),
            "unsupported_cloud_config_network": lambda d: d["cloud_config"].__setitem__(
                "network", {"version": 2}
            ),
            "invalid_boot_target": lambda d: d["postinstall"].__setitem__("boot_target", "kiosk"),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                doc = yaml.safe_load(yaml.safe_dump(base))
                mutate(doc)
                errors = validate_against_schema(doc, self.schema)
                self.assertTrue(errors, f"Expected schema rejection for {name}")


if __name__ == "__main__":
    unittest.main()
