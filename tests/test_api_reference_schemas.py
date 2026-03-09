"""Schema validation for the HITL API reference."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).parent.parent
API_REFERENCE_PATH = REPO_ROOT / "docs" / "api-reference.md"

_SCHEMA_BLOCK_RE = re.compile(
    r"\*\*(?:Approve|Deny|Structured error) [^\n]*schema\*\*\n\n```json\n(.*?)\n```",
    re.DOTALL,
)


def test_hitl_api_reference_schema_blocks_are_present() -> None:
    content = API_REFERENCE_PATH.read_text(encoding="utf-8")
    blocks = _SCHEMA_BLOCK_RE.findall(content)
    assert len(blocks) >= 5, (
        "Expected request, response, and error schema blocks in api-reference.md"
    )


def test_hitl_api_reference_schema_blocks_are_valid_draft7() -> None:
    content = API_REFERENCE_PATH.read_text(encoding="utf-8")
    blocks = _SCHEMA_BLOCK_RE.findall(content)
    for idx, block in enumerate(blocks, start=1):
        schema = json.loads(block)
        Draft7Validator.check_schema(schema)
        assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#", (
            f"Schema block {idx} is missing the draft-07 schema marker"
        )

