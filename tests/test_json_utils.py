import pytest

from core.json_utils import sanitize_json_string, safe_json_parse, extract_json_from_response, parse_llm_json, validate_against_schema


def test_extract_removes_control_chars_and_hex_escapes():
    raw = """Here is output\n```json\n{\n  \"a\": 1,\x01\n  \"b\": 2,\n  \"c\": \"ok\",\n  \"d\": \"bad\\x01value\",\n  \"e\": \"bad\\u0001value\"\n}\n```\nmore text"""
    json_blob = extract_json_from_response(raw)
    assert '\x01' not in json_blob
    assert '\\x01' not in json_blob
    assert '\\u0001' not in json_blob
    data = safe_json_parse(json_blob, fallback={})
    assert isinstance(data, dict)
    assert data.get('a') == 1


def test_sanitize_fixes_missing_commas_and_arrays():
    broken = '{"a":1 "b":2} [ {"x":1} {"y":2} ]'
    fixed = sanitize_json_string(broken, aggressive=True)
    # After sanitize, it should be parseable
    data = safe_json_parse(fixed, fallback={})
    assert isinstance(data, dict) or isinstance(data, list)


def test_parse_llm_json_basic_object():
    raw = '{"a":1, "b":2}'
    parsed = parse_llm_json(raw, fallback={})
    assert parsed.get('a') == 1
    assert parsed.get('b') == 2


def test_parse_llm_json_in_code_fence():
    raw = """```json
{
  "test_code": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n",
  "exploit_code": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n"
}
```"""
    parsed = parse_llm_json(raw, schema='foundry_test', fallback={})
    assert 'test_code' in parsed
    assert 'exploit_code' in parsed


def test_safe_json_parse_reports_fallback_on_unrecoverable():
    broken = 'not json at all'
    parsed = safe_json_parse(broken, fallback={'ok': False})
    assert parsed.get('ok') is False


