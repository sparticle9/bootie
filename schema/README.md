# Manifest Schemas

This directory holds the machine-validatable JSON Schema definitions for
`bootie` manifests:

- [`manifest-v2.schema.json`](manifest-v2.schema.json) — JSON Schema (Draft
  2020-12) for version-2 manifests under `manifests/` and `examples/manifests/`.

For the human-readable field reference and execution semantics, see
[`../SCHEMA.md`](../SCHEMA.md).

## Validation

Every manifest in `manifests/*.yml` and `examples/manifests/*.yml` is validated
against `manifest-v2.schema.json` (and kept in lockstep with
`engine/preflight.py`) by `tests/test_schema.py`:

```sh
uv run python -m unittest tests/test_schema.py -v
```

Editors with YAML language-server support can also reference the schema directly
via a modeline at the top of a custom manifest:

```yaml
# yaml-language-server: $schema=./schema/manifest-v2.schema.json
```
