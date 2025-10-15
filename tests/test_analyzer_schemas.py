from core.json_utils import parse_llm_json, validate_against_schema


def test_analyzer_schema_accepts_minimal_valid_shape():
    raw = '{"vulnerabilities": [], "summary": {"total_vulnerabilities": 0, "high_severity_count": 0, "execution_time": 0.1}}'
    data = parse_llm_json(raw, schema='analyzer', fallback={})
    assert isinstance(data, dict)
    assert validate_against_schema(data, 'analyzer') is True


def test_analyzer_schema_rejects_wrong_types():
    raw = '{"vulnerabilities": {}, "summary": 123}'
    data = parse_llm_json(raw, schema='analyzer', fallback={})
    # With pydantic available, invalid should fallback to {}
    assert isinstance(data, dict)
    # If schema rejected, we expect fallback (empty)
    assert not data or isinstance(data.get('vulnerabilities', []), list)


def test_fp_validation_schema_parsing():
    raw = '{"is_false_positive": false, "confidence": 0.75, "reasoning": "ok"}'
    data = parse_llm_json(raw, schema='fp_validation', fallback={})
    assert data.get('is_false_positive') is False
    assert 0 <= data.get('confidence', 0) <= 1
    assert 'reasoning' in data


