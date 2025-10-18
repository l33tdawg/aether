"""
Enhanced LLM analyzer with improved accuracy and reduced hallucinations.
Implements validation and fact-checking to prevent false positives.
"""

import os
import re
import asyncio
import json
import time
import requests
from typing import Dict, List, Any, Optional

from openai import OpenAI


class EnhancedLLMAnalyzer:
    """Enhanced LLM-powered smart contract analysis with validation."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4.1-mini-2025-04-14"):
        # Try to get OpenAI API key from multiple sources
        self.api_key = api_key
        if not self.api_key:
            self.api_key = os.getenv("OPENAI_API_KEY")
        
        # Try to get Gemini API key
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        
        if not self.api_key or not self.gemini_api_key:
            # Try config manager for stored keys
            try:
                from core.config_manager import ConfigManager
                cm = ConfigManager()
                if not self.api_key and getattr(cm.config, 'openai_api_key', ''):
                    self.api_key = cm.config.openai_api_key
                    os.environ['OPENAI_API_KEY'] = self.api_key
                if not self.gemini_api_key and getattr(cm.config, 'gemini_api_key', ''):
                    self.gemini_api_key = cm.config.gemini_api_key
                    os.environ['GEMINI_API_KEY'] = self.gemini_api_key
            except Exception:
                pass
        
        self.has_api_key = bool(self.api_key) or bool(self.gemini_api_key)
        self.model = model
        
        # Updated fallback models to include Gemini
        self.fallback_models = ["gemini-2.5-flash", "gpt-4o-mini", "gpt-4.1-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
        
        # Context limits for different models (Gemini has 2M token context)
        self.model_context_limits = {
            "gpt-4.1-mini-2025-04-14": 1000000,  # 1M tokens
            "gpt-4.1-mini": 1000000,  # 1M tokens
            "gpt-4o-mini": 128000,    # 128k tokens
            "gpt-4o": 128000,         # 128k tokens
            "gpt-4-turbo": 128000,    # 128k tokens
            "gpt-4": 8192,            # 8k tokens
            "gpt-3.5-turbo": 16384,   # 16k tokens
            "gemini-2.5-flash": 2000000,  # 2M tokens
            "gemini-1.5-pro": 2000000,    # 2M tokens
            "gemini-1.5-flash": 1000000,  # 1M tokens
        }

        if self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None
            
        if not self.has_api_key:
            print("⚠️  No API keys found in environment or config - LLM features disabled")

    async def analyze_vulnerabilities(
        self,
        contract_content: str,
        static_analysis_results: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze contract for vulnerabilities using enhanced AI with validation."""
        print("🤖 Running enhanced AI-powered vulnerability analysis...")

        if not self.has_api_key:
            print("⚠️  Skipping LLM analysis - no API key provided")
            return {
                'success': True,
                'analysis': {
                    'vulnerabilities': [],
                    'gas_optimizations': [],
                    'best_practices': [],
                    'note': 'LLM analysis disabled - no OpenAI API key'
                },
                'raw_response': '',
                'model': 'disabled'
            }

        # Create enhanced analysis prompt
        prompt = self._create_enhanced_analysis_prompt(contract_content, static_analysis_results)

        try:
            # Use the configured model
            response = await self._call_llm(prompt, model=self.model)
            
            if response:
                # Parse and validate the response
                analysis_result = self._parse_and_validate_response(response, contract_content)
                return analysis_result
            else:
                return self._create_fallback_response()

        except Exception as e:
            print(f"❌ LLM analysis failed: {e}")
            return self._create_fallback_response()

    def _create_enhanced_analysis_prompt(self, contract_content: str, static_results: Dict[str, Any]) -> str:
        """Create enhanced analysis prompt with validation requirements."""
        
        # Use model-specific context limits - GPT-4.1-mini can handle much larger contracts
        context_limit = self.model_context_limits.get(self.model, 8192)
        # Conservative token estimation: reserve space for prompt overhead and completion
        max_contract_tokens = context_limit - 2000  # Reserve 2000 tokens for prompt overhead and completion
        max_contract_chars = max_contract_tokens * 3  # ~3 chars per token
        
        if len(contract_content) > max_contract_chars:
            print(f"⚠️  Contract large ({len(contract_content)} chars), truncating to {max_contract_chars} for {self.model}")
            contract_content = contract_content[:max_contract_chars] + "\n\n[Note: Contract truncated for model compatibility]"
        
        prompt = f"""
You are an elite smart contract security auditor. Your task is to identify ONLY real, exploitable vulnerabilities.

**CRITICAL REQUIREMENTS:**
1. **NO HALLUCINATIONS**: Only report vulnerabilities that actually exist in the code
2. **VALIDATION REQUIRED**: Each finding must be verifiable by code analysis
3. **CONTEXT AWARENESS**: Understand OpenZeppelin patterns and common security practices
4. **FALSE POSITIVE PREVENTION**: Do not flag standard, secure patterns as vulnerabilities

**CONTRACT CODE:**
```solidity
{contract_content}
```

**STATIC ANALYSIS CONTEXT:**
"""
        
        # Add static analysis results
        if static_results.get('vulnerabilities'):
            prompt += "\nPrevious static analysis found:\n"
            for vuln in static_results['vulnerabilities'][:3]:
                title = getattr(vuln, 'title', 'Unknown')
                description = getattr(vuln, 'description', '')
                prompt += f"- {title}: {description[:100]}...\n"

        prompt += """

**ANALYSIS GUIDELINES:**

1. **Access Control Analysis**:
   - Check if public functions call internal authorization functions (like _authorizeUpgrade)
   - Understand that functions can be protected by internal calls, not just modifiers
   - Do not flag functions that are properly protected internally

2. **Initialization Analysis**:
   - Understand OpenZeppelin's versioning system: reinitializer(2) can follow initializer
   - Check if initialization functions are actually vulnerable, not just different versions
   - Consider if the versioning difference actually creates a security issue

3. **Upgrade Authorization Analysis**:
   - Verify if the authorization logic is actually flawed
   - Check if the function has proper validation and access control
   - Do not assume vulnerabilities without concrete evidence

4. **General Security Analysis**:
   - Focus on actual exploitability, not theoretical issues
   - Consider if the issue can be exploited in practice
   - Verify that the vulnerability exists in the actual code flow

**OUTPUT FORMAT:**
IMPORTANT: Return ONLY a valid JSON object. Do not include any text before or after the JSON. Quote all keys/values. If unsure, return an empty array for vulnerabilities.

Provide a structured JSON response with ONLY verified vulnerabilities:

{
  "vulnerabilities": [
    {
      "swc_id": "SWC-XXX",
      "title": "Brief title",
      "description": "Detailed description with code references",
      "severity": "low|medium|high|critical",
      "confidence": 0.0-1.0,
      "exploitability": "Assessment of exploitability",
      "attack_vector": "Specific attack steps if exploitable",
      "financial_impact": "Potential impact",
      "exploit_complexity": "low|medium|high",
      "detection_difficulty": "low|medium|high",
      "immunefi_bounty_value": "Estimated bounty range",
      "working_poc": "Proof of concept if applicable",
      "fix_suggestion": "Specific fix recommendation",
      "validation_evidence": "Code evidence supporting the finding"
    }
  ],
  "gas_optimizations": [],
  "best_practices": [],
  "summary": "Overall assessment"
}

CRITICAL: Your response must be valid JSON that can be parsed directly. Ensure:
- All strings are properly quoted with double quotes
- No trailing commas
- All brackets and braces are properly closed
- No unescaped quotes within string values
- No explanatory text outside the JSON object

**VALIDATION CHECKLIST:**
Before reporting any vulnerability, verify:
- [ ] The issue actually exists in the code
- [ ] The issue can be exploited in practice
- [ ] The issue is not a standard, secure pattern
- [ ] The issue has concrete code evidence
- [ ] The issue is not already mitigated by other mechanisms

**IMPORTANT**: If no real vulnerabilities are found, return an empty vulnerabilities array. It's better to miss a vulnerability than to report a false positive.
"""

        return prompt

    async def _call_llm(self, prompt: str, model: str = "gpt-4.1-mini-2025-04-14") -> Optional[str]:
        """Call the LLM with the given prompt. Supports both OpenAI and Gemini models."""
        if not self.has_api_key:
            print("⚠️  No API key available for LLM calls")
            return None
            
        # Try primary model first, then fallbacks
        models_to_try = [model] + [m for m in self.fallback_models if m != model]
        
        for current_model in models_to_try:
            try:
                # Check if this is a Gemini model
                is_gemini = current_model.startswith('gemini-')
                
                # Skip if we don't have the right API key
                if is_gemini and not self.gemini_api_key:
                    print(f"⚠️  Skipping {current_model} - no Gemini API key")
                    continue
                elif not is_gemini and not self.api_key:
                    print(f"⚠️  Skipping {current_model} - no OpenAI API key")
                    continue
                
                # Get context limit for current model
                context_limit = self.model_context_limits.get(current_model, 8192)
                # More conservative token estimation: ~3 chars per token
                max_prompt_tokens = context_limit - 20000  # Reserve for completion (Gemini thinking + output)
                max_prompt_chars = max_prompt_tokens * 3  # ~3 chars per token
                # Gemini 2.5 Flash uses thinking mode - balance between thinking and output
                # 8K tokens is reasonable: ~4K for thinking + 4K for actual output
                max_completion_tokens = 8000 if is_gemini else 4000
                
                # Truncate prompt if needed for current model
                truncated_prompt = prompt
                if len(prompt) > max_prompt_chars:
                    print(f"⚠️  Prompt too large for {current_model} ({len(prompt)} chars), truncating to {max_prompt_chars}")
                    truncated_prompt = prompt[:max_prompt_chars] + "\n\n[Note: Content truncated for model compatibility]"
                
                if is_gemini:
                    # Use Google Gemini API
                    response_text = await self._call_gemini_api(current_model, truncated_prompt, max_completion_tokens)
                else:
                    # Use OpenAI API
                    response_text = await self._call_openai_api(current_model, truncated_prompt, max_completion_tokens)
                
                if response_text:
                    if current_model != model:
                        print(f"✅ Using fallback model: {current_model}")
                    
                    # Clean the response text of control characters
                    response_text = re.sub(r'[\x00-\x1F\x7F]', '', response_text)
                    return response_text
                    
            except Exception as e:
                print(f"❌ Model {current_model} failed: {e}")
                if current_model == model:
                    print(f"🔍 Primary model {model} failed, trying fallbacks...")
                continue
        
        print("❌ All LLM models failed")
        return None
    
    async def _call_openai_api(self, model: str, prompt: str, max_tokens: int) -> Optional[str]:
        """Call OpenAI API."""
        try:
            if not self.client:
                return None
                
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are an expert smart contract security auditor. Provide accurate, validated analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for more consistent results
                max_tokens=max_tokens
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            raise e
    
    async def _call_gemini_api(self, model: str, prompt: str, max_tokens: int) -> Optional[str]:
        """Call Google Gemini API (similar to ai_ensemble.py implementation)."""
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.gemini_api_key}"
            
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": 0.1,  # Low temperature for consistent results
                }
            }
            
            # Gemini API with thinking mode can be slow, use longer timeout with retry logic
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Increased timeout for thinking mode (can take 90-120 seconds)
                    response = requests.post(url, json=payload, timeout=120)
                    response.raise_for_status()
                    break  # Success, exit retry loop
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    if attempt < max_retries - 1:
                        print(f"⚠️  Gemini timeout on attempt {attempt + 1}/{max_retries}, retrying...")
                        time.sleep(3)  # Wait before retry
                    else:
                        raise e
            
            result = response.json()
            
            # Parse Gemini response structure
            candidates = result.get('candidates') or []
            if candidates:
                content = candidates[0].get('content') or {}
                parts = content.get('parts') or []
                
                if parts and isinstance(parts, list):
                    # Find text in parts (could be at any index)
                    for part in parts:
                        if isinstance(part, dict) and 'text' in part:
                            return part['text']
                    
                    print(f"⚠️  No text found in Gemini response parts")
                else:
                    print(f"⚠️  Gemini parts is not a list or is empty")
            else:
                print(f"⚠️  No candidates in Gemini response")
                if 'promptFeedback' in result:
                    print(f"⚠️  Gemini prompt feedback: {result['promptFeedback']}")
            
            return None
            
        except Exception as e:
            raise e

    def _parse_and_validate_response(self, response: str, contract_content: str) -> Dict[str, Any]:
        """Parse and validate the LLM response."""
        try:
            from .json_utils import parse_llm_json
            
            analysis_data = parse_llm_json(response, schema='analyzer', fallback=self._create_fallback_response())

            # Optional: strict schema validation
            # Already validated in parse_llm_json when schema='analyzer'
            
            # Validate each vulnerability
            validated_vulnerabilities = []
            for vuln in analysis_data.get('vulnerabilities', []):
                if self._validate_vulnerability(vuln, contract_content):
                    validated_vulnerabilities.append(vuln)
                else:
                    print(f"⚠️  Filtered out unvalidated vulnerability: {vuln.get('title', 'Unknown')}")
            
            analysis_data['vulnerabilities'] = validated_vulnerabilities
            
            return {
                'success': True,
                'analysis': analysis_data,
                'raw_response': response,
                'model': 'gpt-4',
                'validation_summary': {
                    'total_found': len(analysis_data.get('vulnerabilities', [])),
                    'validated': len(validated_vulnerabilities),
                    'filtered': len(analysis_data.get('vulnerabilities', [])) - len(validated_vulnerabilities)
                }
            }
            
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse LLM response: {e}")
            # One-shot repair retry: send schema error hint back to model
            try:
                hint = "Your previous output was invalid JSON. Return ONLY JSON matching: {\"vulnerabilities\":[], \"gas_optimizations\":[], \"best_practices\":[], \"summary\":\"...\"}."
                repair_prompt = hint + "\n\nPrior response (sanitize and fix):\n" + response[:4000]
                repaired = asyncio.run(self._call_llm(repair_prompt, model=self.model))
                from .json_utils import parse_llm_json
                analysis_data = parse_llm_json(repaired or "{}", schema='analyzer', fallback=self._create_fallback_response())
                return {
                    'success': True,
                    'analysis': analysis_data,
                    'raw_response': repaired or response,
                    'model': 'gpt-4',
                    'validation_summary': {
                        'total_found': len(analysis_data.get('vulnerabilities', [])),
                        'validated': len(analysis_data.get('vulnerabilities', [])),
                        'filtered': 0
                    }
                }
            except Exception:
                return self._create_fallback_response()
        except Exception as e:
            print(f"❌ Error processing LLM response: {e}")
            return self._create_fallback_response()
    
    def _fix_json_string(self, json_str: str) -> str:
        """Fix common JSON formatting issues."""
        import re
        import json
        
        # Remove control characters that cause JSON parsing errors
        # Replace common control characters with escaped versions
        control_chars = {
            '\x00': '\\u0000',  # NULL
            '\x01': '\\u0001',  # SOH
            '\x02': '\\u0002',  # STX
            '\x03': '\\u0003',  # ETX
            '\x04': '\\u0004',  # EOT
            '\x05': '\\u0005',  # ENQ
            '\x06': '\\u0006',  # ACK
            '\x07': '\\u0007',  # BEL
            '\x08': '\\u0008',  # BS
            '\x0b': '\\u000b',  # VT
            '\x0c': '\\u000c',  # FF
            '\x0e': '\\u000e',  # SO
            '\x0f': '\\u000f',  # SI
            '\x10': '\\u0010',  # DLE
            '\x11': '\\u0011',  # DC1
            '\x12': '\\u0012',  # DC2
            '\x13': '\\u0013',  # DC3
            '\x14': '\\u0014',  # DC4
            '\x15': '\\u0015',  # NAK
            '\x16': '\\u0016',  # SYN
            '\x17': '\\u0017',  # ETB
            '\x18': '\\u0018',  # CAN
            '\x19': '\\u0019',  # EM
            '\x1a': '\\u001a',  # SUB
            '\x1b': '\\u001b',  # ESC
            '\x1c': '\\u001c',  # FS
            '\x1d': '\\u001d',  # GS
            '\x1e': '\\u001e',  # RS
            '\x1f': '\\u001f',  # US
        }
        
        for char, escaped in control_chars.items():
            json_str = json_str.replace(char, escaped)
        
        # Remove trailing commas before closing braces/brackets
        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
        
        # Fix unterminated strings by finding incomplete quoted strings and closing them
        # Look for patterns like "text without closing quote followed by } or ]
        json_str = re.sub(r'"([^"]*?)(\s*[}\]])', r'"\1"\2', json_str)
        
        # Fix unescaped quotes within strings
        json_str = re.sub(r'([^\\])"([^",\s}]+)"([^,}\s])', r'\1"\2"\3', json_str)
        
        # Fix malformed JSON objects by ensuring proper structure
        # Remove any non-JSON content before the first { and after the last }
        first_brace = json_str.find('{')
        last_brace = json_str.rfind('}')
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            json_str = json_str[first_brace:last_brace + 1]
        
        # Fix common JSON formatting issues
        # Remove any trailing content after the JSON
        json_str = re.sub(r'}\s*[^}]*$', '}', json_str)
        
        # Fix incomplete strings by ensuring they're properly closed
        # Look for unclosed strings at the end
        quote_count = json_str.count('"')
        if quote_count % 2 != 0:
            # Odd number of quotes, add a closing quote at the end
            json_str = json_str.rstrip() + '"'
        
        # Fix missing commas between JSON objects/arrays
        # Add commas between consecutive objects/arrays
        json_str = re.sub(r'}\s*{', '},{', json_str)
        json_str = re.sub(r']\s*\[', '],[', json_str)
        
        # Fix missing commas between key-value pairs
        json_str = re.sub(r'"\s*"', '","', json_str)
        
        # Fix trailing commas before closing braces/brackets (again, more comprehensive)
        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
        
        # Fix malformed JSON by ensuring proper structure
        # Remove any content that's not valid JSON
        lines = json_str.split('\n')
        cleaned_lines = []
        in_json = False
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('{') or in_json:
                in_json = True
                cleaned_lines.append(line)
                if stripped.endswith('}') and stripped.count('{') <= stripped.count('}'):
                    break
        
        if cleaned_lines:
            json_str = '\n'.join(cleaned_lines)
        
        # Fix incomplete JSON objects/arrays by ensuring proper closing
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

    def _validate_vulnerability(self, vuln: Dict[str, Any], contract_content: str) -> bool:
        """Validate a vulnerability finding."""
        # Check if the vulnerability has required fields
        required_fields = ['title', 'description', 'severity', 'confidence']
        if not all(field in vuln for field in required_fields):
            return False
        
        # Check confidence threshold
        if vuln.get('confidence', 0) < 0.7:
            return False
        
        # Check if the vulnerability is actually in the code
        if not self._verify_vulnerability_in_code(vuln, contract_content):
            return False
        
        # Check for common false positive patterns
        if self._is_likely_false_positive(vuln, contract_content):
            return False
        
        return True

    def _verify_vulnerability_in_code(self, vuln: Dict[str, Any], contract_content: str) -> bool:
        """Verify that the vulnerability actually exists in the code."""
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        
        # Check for specific vulnerability patterns
        if 'access control' in title or 'access control' in description:
            # Check if there are actually unprotected public functions
            return self._check_access_control_vulnerability(contract_content)
        
        elif 'initialization' in title or 'initialization' in description:
            # Check if there are actually initialization issues
            return self._check_initialization_vulnerability(contract_content)
        
        elif 'upgrade' in title or 'upgrade' in description:
            # Check if there are actually upgrade issues
            return self._check_upgrade_vulnerability(contract_content)
        
        return True  # Default to valid if we can't verify

    def _check_access_control_vulnerability(self, contract_content: str) -> bool:
        """Check if there are actual access control vulnerabilities."""
        # Find public functions
        public_functions = re.findall(r'function\s+(\w+)\s*\([^)]*\)\s*public', contract_content)
        
        for func_name in public_functions:
            # Check if function has internal protection
            func_body = self._extract_function_body(contract_content, func_name)
            if func_body:
                # Check for internal authorization calls
                if '_authorizeUpgrade' in func_body or 'onlyOwner' in func_body:
                    continue  # Function is protected
                
                # Check for other protection mechanisms
                if 'require(' in func_body and 'msg.sender' in func_body:
                    continue  # Function has access control
                
                # If we find an unprotected public function, it's a real vulnerability
                return True
        
        return False

    def _check_initialization_vulnerability(self, contract_content: str) -> bool:
        """Check if there are actual initialization vulnerabilities."""
        # Look for initialization functions
        init_functions = re.findall(r'function\s+(\w+)\s*\([^)]*\)\s*.*?(initializer|reinitializer)', contract_content)
        
        if len(init_functions) > 1:
            # Check if there are conflicting versions
            versions = []
            for func_name, modifier in init_functions:
                if 'reinitializer' in modifier:
                    version_match = re.search(r'reinitializer\s*\(\s*(\d+)\s*\)', modifier)
                    if version_match:
                        versions.append(int(version_match.group(1)))
                else:
                    versions.append(1)  # initializer is version 1
            
            # Check if versions are properly ordered
            if len(set(versions)) > 1:
                return True  # Potential versioning issue
        
        return False

    def _check_upgrade_vulnerability(self, contract_content: str) -> bool:
        """Check if there are actual upgrade vulnerabilities."""
        # Look for upgrade authorization function
        if '_authorizeUpgrade' in contract_content:
            # Check if the function has proper validation
            auth_func = re.search(r'function\s+_authorizeUpgrade[^{]*\{[^}]*\}', contract_content, re.DOTALL)
            if auth_func:
                func_body = auth_func.group(0)
                # Check for proper validation
                if 'require(' in func_body and 'onlyOwner' in func_body:
                    return False  # Function is properly protected
                else:
                    return True  # Function lacks proper protection
        
        return False

    def _extract_function_body(self, contract_content: str, func_name: str) -> str:
        """Extract the body of a specific function."""
        pattern = rf'function\s+{func_name}\s*\([^)]*\)\s*[^{{]*\{{([^}}]*)\}}'
        match = re.search(pattern, contract_content, re.DOTALL)
        return match.group(1) if match else ""

    def _is_likely_false_positive(self, vuln: Dict[str, Any], contract_content: str) -> bool:
        """Check if the vulnerability is likely a false positive."""
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        
        # Common false positive patterns
        false_positive_patterns = [
            'standard openzeppelin pattern',
            'properly protected',
            'internal authorization',
            'valid versioning',
            'no actual vulnerability',
            'false positive'
        ]
        
        for pattern in false_positive_patterns:
            if pattern in description:
                return True
        
        return False

    def _create_fallback_response(self) -> Dict[str, Any]:
        """Create a fallback response when LLM analysis fails."""
        return {
            'success': True,
            'analysis': {
                'vulnerabilities': [],
                'gas_optimizations': [],
                'best_practices': [],
                'note': 'LLM analysis failed - using static analysis only'
            },
            'raw_response': '',
            'model': 'failed'
        }
