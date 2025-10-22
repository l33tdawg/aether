"""
JSON utilities for handling malformed LLM responses.
"""
import re
import json
import logging
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field, ValidationError
    HAS_PYDANTIC = True
except Exception:
    HAS_PYDANTIC = False
import os

logger = logging.getLogger(__name__)

def sanitize_json_string(json_str: str, aggressive: bool = False) -> str:
    """
    Sanitize JSON string to handle common LLM response issues.
    
    Args:
        json_str: Raw JSON string from LLM
        aggressive: Apply extra structural repairs
        
    Returns:
        Sanitized JSON string
    """
    if not json_str:
        return "{}"
    
    # Step 1: Remove control characters that cause JSON parsing errors
    # Convert to bytes and back to remove any encoding issues
    try:
        json_str = json_str.encode('utf-8', errors='ignore').decode('utf-8')
    except:
        pass
    
    # Remove all control characters (0x00-0x1F) and DEL (0x7F) - THIS IS THE KEY FIX
    # Gemini returns findings with embedded \x01 characters between items
    json_str = re.sub(r'[\x00-\x08\x0B-\x1F\x7F]', '', json_str)

    # Also strip textual hex-escape sequences that models sometimes emit literally (e.g. "\\x01")
    json_str = re.sub(r'\\x[0-9A-Fa-f]{2}', '', json_str)

    # And textual unicode control escapes (e.g. "\\u0001" .. "\\u001F")
    json_str = re.sub(r'\\u00[0-1][0-9A-Fa-f]{2}', '', json_str)
    
    # Step 2: Extract JSON from surrounding text
    # Try to find JSON in code blocks first (object or array)
    code_block_patterns = [
        r'```(?:json)?\s*(\{[\s\S]*?\})\s*```',  # Object in code block
        r'```(?:json)?\s*(\[[\s\S]*?\])\s*```',  # Array in code block
    ]
    
    for pattern in code_block_patterns:
        code_block_match = re.search(pattern, json_str, re.DOTALL)
        if code_block_match:
            return code_block_match.group(1)
    
    # Try to find JSON object first (prioritize objects with braces)
    json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', json_str, re.DOTALL)
    if json_match:
        return json_match.group(0)
    
    # Try to find JSON array second (if no object found)
    array_match = re.search(r'\[.*\]', json_str, re.DOTALL)
    if array_match:
        return array_match.group(0)
    
    # Step 3: Fix common structural issues ONLY IF NEEDED
    # Remove trailing commas before closing braces/brackets
    json_str = re.sub(r',\s*([}\]])', r'\1', json_str)
    
    # Fix missing commas between objects in arrays
    json_str = re.sub(r'}\s*{', '},{', json_str)
    json_str = re.sub(r']\s*\[', '],[', json_str)
    
    # Fix unquoted numeric values and ranges (e.g., 800 - 1300 becomes "800 - 1300")
    # Match pattern: ": <unquoted_value>," where value contains numbers and operators
    json_str = re.sub(r':\s*([0-9]+\s*[-+*/]\s*[0-9]+)\s*,', r': "\1",', json_str)
    
    # Ensure proper JSON structure
    open_braces = json_str.count('{')
    close_braces = json_str.count('}')
    open_brackets = json_str.count('[')
    close_brackets = json_str.count(']')
    
    # Add missing closing braces/brackets
    if open_braces > close_braces:
        json_str += '}' * (open_braces - close_braces)
    if open_brackets > close_brackets:
        json_str += ']' * (open_brackets - close_brackets)
    
    return json_str

def safe_json_parse(json_str: str, fallback: dict = None) -> dict:
    """
    Safely parse JSON string with fallback.
    
    Args:
        json_str: JSON string to parse
        fallback: Fallback dictionary if parsing fails
        
    Returns:
        Parsed JSON dictionary or fallback
    """
    if fallback is None:
        fallback = {}
    
    # Add stack trace to identify caller
    import traceback
    caller = traceback.extract_stack()[-2]
    logger.debug(f"safe_json_parse called from {caller.filename}:{caller.lineno} in {caller.name}")
    
    try:
        # First try direct parsing
        return json.loads(json_str)
    except json.JSONDecodeError:
        # Try lenient decoder
        try:
            decoder = json.JSONDecoder(strict=False)
            return decoder.decode(json_str)
        except json.JSONDecodeError:
            pass
        # Try minimal sanitation
        try:
            sanitized = sanitize_json_string(json_str, aggressive=False)
            try:
                return json.loads(sanitized)
            except json.JSONDecodeError:
                decoder = json.JSONDecoder(strict=False)
                return decoder.decode(sanitized)
        except json.JSONDecodeError as e:
            logger.debug(f"JSON parsing failed after sanitization: {e}")
            logger.debug(f"Original JSON (first 200 chars): {json_str[:200]}")
            sanitized = sanitize_json_string(json_str, aggressive=False)
            logger.debug(f"Sanitized JSON (first 200 chars): {sanitized[:200]}")
            
            # Debug the exact character causing the issue
            if hasattr(e, 'pos') and e.pos < len(sanitized):
                char_at_pos = sanitized[e.pos]
                logger.debug(f"Character at position {e.pos}: {repr(char_at_pos)} (ord: {ord(char_at_pos)})")
                logger.debug(f"Context around error: {repr(sanitized[max(0, e.pos-10):e.pos+10])}")
                # Intentionally do not log full sanitized string to avoid noise
            
            # Last resort: aggressive sanitize + lenient
            try:
                sanitized2 = sanitize_json_string(json_str, aggressive=True)
                try:
                    return json.loads(sanitized2)
                except json.JSONDecodeError:
                    decoder = json.JSONDecoder(strict=False)
                    return decoder.decode(sanitized2)
            except Exception:
                return fallback

def extract_json_from_response(response: str) -> str:
    """
    Extract JSON from LLM response text.
    
    Args:
        response: Raw LLM response
        
    Returns:
        Extracted JSON string
    """
    # First, clean control characters from the response
    response = re.sub(r'[\x00-\x1F\x7F]', '', response)
    # Also remove literal hex/unicode control escape sequences the model might include as text
    response = re.sub(r'\\x[0-9A-Fa-f]{2}', '', response)
    response = re.sub(r'\\u00[0-1][0-9A-Fa-f]{2}', '', response)
    
    # Try to find JSON in code blocks first (object or array)
    # Look for both ``` and ```json markers
    code_block_patterns = [
        r'```(?:json)?\s*(\{[\s\S]*?\})\s*```',  # Object in code block
        r'```(?:json)?\s*(\[[\s\S]*?\])\s*```',  # Array in code block
    ]
    
    for pattern in code_block_patterns:
        code_block_match = re.search(pattern, response, re.DOTALL)
        if code_block_match:
            candidate = code_block_match.group(1)
            # Normalize separators inside the candidate as well
            candidate = re.sub(r'[\x00-\x1F\x7F]', '', candidate)
            # Also strip textual hex/unicode control escape sequences inside the block
            candidate = re.sub(r'\\x[0-9A-Fa-f]{2}', '', candidate)
            candidate = re.sub(r'\\u00[0-1][0-9A-Fa-f]{2}', '', candidate)
            # Decode any remaining unicode escape sequences then strip controls again
            try:
                decoded = candidate.encode('utf-8').decode('unicode_escape')
                candidate = re.sub(r'[\x00-\x1F\x7F]', '', decoded)
            except Exception:
                pass
            candidate = re.sub(r'}\s*[^{}\[\]]*\s*{', '}, {', candidate)
            candidate = re.sub(r']\s*[^{}\[\]]*\s*\[', '], [', candidate)
            return candidate
    
    # Try to find JSON object first (prioritize objects with braces)
    json_match = re.search(r'\{.*\}', response, re.DOTALL)
    if json_match:
        candidate = json_match.group(0)
        candidate = re.sub(r'[\x00-\x1F\x7F]', '', candidate)
        candidate = re.sub(r'\\x[0-9A-Fa-f]{2}', '', candidate)
        candidate = re.sub(r'\\u00[0-1][0-9A-Fa-f]{2}', '', candidate)
        try:
            decoded = candidate.encode('utf-8').decode('unicode_escape')
            candidate = re.sub(r'[\x00-\x1F\x7F]', '', decoded)
        except Exception:
            pass
        candidate = re.sub(r'}\s*[^{}\[\]]*\s*{', '}, {', candidate)
        candidate = re.sub(r']\s*[^{}\[\]]*\s*\[', '], [', candidate)
        return candidate
    
    # Try to find JSON array second (if no object found)
    array_match = re.search(r'\[.*\]', response, re.DOTALL)
    if array_match:
        candidate = array_match.group(0)
        candidate = re.sub(r'[\x00-\x1F\x7F]', '', candidate)
        candidate = re.sub(r'\\x[0-9A-Fa-f]{2}', '', candidate)
        candidate = re.sub(r'\\u00[0-1][0-9A-Fa-f]{2}', '', candidate)
        try:
            decoded = candidate.encode('utf-8').decode('unicode_escape')
            candidate = re.sub(r'[\x00-\x1F\x7F]', '', decoded)
        except Exception:
            pass
        candidate = re.sub(r'}\s*[^{}\[\]]*\s*{', '}, {', candidate)
        candidate = re.sub(r']\s*[^{}\[\]]*\s*\[', '], [', candidate)
        return candidate
    
    # Return empty JSON if nothing found
    return "{}"

# Schema models for strict validation (optional if pydantic available)
if HAS_PYDANTIC:
    class VulnerabilityModel(BaseModel):
        title: Optional[str] = None
        vulnerability_type: Optional[str] = None
        severity: Optional[str] = None
        confidence: Optional[float] = None
        line: Optional[int] = None
        line_number: Optional[int] = None
        description: Optional[str] = None
        swc_id: Optional[str] = None
        category: Optional[str] = None

    class AnalyzerSummaryModel(BaseModel):
        total_vulnerabilities: Optional[int] = 0
        high_severity_count: Optional[int] = 0
        execution_time: Optional[float] = 0.0

    class AnalyzerResponseModel(BaseModel):
        vulnerabilities: List[VulnerabilityModel] = []
        summary: Optional[AnalyzerSummaryModel] = None

    class FPValidationResponseModel(BaseModel):
        is_false_positive: bool
        confidence: float
        reasoning: str
        corrected_severity: Optional[str] = None
        corrected_description: Optional[str] = None

    class FoundryTestResponseModel(BaseModel):
        test_code: str
        exploit_code: str
        fixed_code: Optional[str] = None

def validate_against_schema(data: Dict[str, Any], schema: str) -> bool:
    if not HAS_PYDANTIC:
        return True
    try:
        if schema == 'analyzer':
            AnalyzerResponseModel(**data)
        elif schema == 'fp_validation':
            FPValidationResponseModel(**data)
        elif schema == 'foundry_test':
            FoundryTestResponseModel(**data)
        else:
            return True
        return True
    except Exception:
        return False

def parse_llm_json(raw_response: str, schema: Optional[str] = None, fallback: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Extract, sanitize, parse, and optionally schema-validate an LLM JSON response.

    Args:
        raw_response: The raw text returned by the LLM.
        schema: Optional schema key to validate against ('analyzer' | 'fp_validation').
        fallback: Fallback dict to use if parsing/validation fails.

    Returns:
        Parsed dict (or fallback if invalid).
    """
    if fallback is None:
        fallback = {}
    try:
        json_str = extract_json_from_response(raw_response or "")
        if not json_str or json_str == "{}":
            return fallback
        data = safe_json_parse(json_str, fallback)
        # Accept both dict and list responses - don't force dict-only return
        if isinstance(data, (dict, list)):
            if schema and isinstance(data, dict) and not validate_against_schema(data, schema):
                return fallback
            return data
        return fallback
    except Exception:
        return fallback
