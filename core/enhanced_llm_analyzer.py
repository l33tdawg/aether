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

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
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
        
        # Get model from config if not specified (supports mixed OpenAI/Gemini)
        if model:
            self.model = model
        else:
            try:
                from core.config_manager import get_model_for_task
                # Default to analysis model (for vulnerability detection)
                self.model = get_model_for_task('analysis')
            except Exception:
                self.model = 'gpt-5-chat-latest'  # Fallback
        
        # Updated fallback models to include Gemini
        self.fallback_models = ["gemini-2.5-flash", "gpt-4o-mini", "gpt-4.1-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
        
        # Context limits for different models
        # NOTE: These are COMBINED input + output limits
        self.model_context_limits = {
            # GPT-5 models (400K combined input+output, better retrieval from large inputs)
            "gpt-5-chat-latest": 400000,  # 400k tokens combined
            "gpt-5-pro": 400000,          # 400k tokens combined
            "gpt-5-pro-2025-10-06": 400000,  # 400k tokens combined
            "gpt-5-mini": 400000,         # 400k tokens combined
            "gpt-5-mini-2025-08-07": 400000,  # 400k tokens combined
            "gpt-5-codex": 400000,        # 400k tokens combined
            "gpt-5-nano": 400000,         # 400k tokens combined
            "gpt-5-nano-2025-08-07": 400000,  # 400k tokens combined
            # GPT-4 models
            "gpt-4.1-mini-2025-04-14": 1000000,  # 1M tokens combined
            "gpt-4.1-mini": 1000000,  # 1M tokens combined
            "gpt-4o-mini": 128000,    # 128k tokens combined
            "gpt-4o": 128000,         # 128k tokens combined
            "gpt-4-turbo": 128000,    # 128k tokens combined
            "gpt-4": 8192,            # 8k tokens combined
            "gpt-3.5-turbo": 16384,   # 16k tokens combined
            # Gemini models (2M combined)
            "gemini-2.5-flash": 2000000,  # 2M tokens combined
            "gemini-1.5-pro": 2000000,    # 2M tokens combined
            "gemini-1.5-flash": 1000000,  # 1M tokens combined
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
        """Create enhanced analysis prompt with validation requirements and Solidity version awareness."""
        
        # Extract Solidity version for version-aware prompting
        solidity_version = self._extract_solidity_version(contract_content)
        version_guidance = self._generate_version_specific_guidance(solidity_version)
        
        # Use model-specific context limits (COMBINED input + output)
        context_limit = self.model_context_limits.get(self.model, 128000)  # Default to 128k for unknown models
        
        # Reserve space for output based on model capabilities
        is_gpt5 = self.model.startswith('gpt-5')
        is_gemini = self.model.startswith('gemini-')
        
        if is_gemini:
            reserved_tokens = 12000  # 12K for thinking + output
        elif is_gpt5:
            reserved_tokens = 8000   # 8K for output (GPT-5's superior retrieval)
        else:
            reserved_tokens = 4000   # 4K for older models
        
        # Calculate max contract size
        # GPT-5: Can handle up to 392K tokens of input (1.176M chars!)
        max_contract_tokens = max(context_limit - reserved_tokens - 2000, 1000)  # Reserve 2K for prompt structure
        max_contract_chars = max_contract_tokens * 3  # ~3 chars per token
        
        if len(contract_content) > max_contract_chars:
            print(f"⚠️  Contract large ({len(contract_content)} chars), truncating to {max_contract_chars} for {self.model}")
            contract_content = contract_content[:max_contract_chars] + "\n\n[Note: Contract truncated for model compatibility]"
        else:
            print(f"✅ Contract size ({len(contract_content)} chars) fits within {self.model} context window")
        
        prompt = f"""
You are an elite smart contract security auditor. Your task is to identify ONLY real, exploitable vulnerabilities.

{version_guidance}

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

**PATTERN RECOGNITION - COMMON FALSE POSITIVES:**

IMPORTANT: Before flagging a vulnerability, check these secure-by-design patterns:

1. **SafeCast Type Narrowing (Integer Overflow FALSE POSITIVE)**
   Pattern: SafeCast.toUint96(), SafeCast.toUint128(), etc.
   Why it's secure: SafeCast REVERTS if value exceeds target type max - this prevents overflow
   How to identify: Look for "SafeCast.toUint96" + description mentions "revert" or "exceeds"
   Action: DO NOT flag as exploitable overflow - this is intentional safety mechanism
   Reality check: Is there a maxSupply or cap check? That's intentional bounding.
   
2. **Inherited Access Control (Access Control FALSE POSITIVE)**
   Pattern: Finding claims "missing onlyOwner" on inherited function
   Why it's secure: Parent class modifiers apply transitively through inheritance
   Examples: ERC20WithPermit, MisfundRecovery, OpenZeppelin's Ownable/AccessControl
   How to identify: Description mentions "inherit", "MisfundRecovery", "ERC20WithPermit"
   Action: DO NOT flag if parent contract has proper access control
   Reality check: Check if function is actually callable without permission (verify parent code)
   
3. **Type Narrowing for Storage Optimization**
   Pattern: uint256 narrowed to uint96/uint128 (common in voting/checkpoint contracts)
   Why it's secure: Intentional design to enforce maximum values and optimize storage
   Action: DO NOT flag as precision loss or overflow risk - this is design intent
   
4. **External Package Trust**
   Pattern: OpenZeppelin, @thesis, or other battle-tested package functionality flagged
   Why it's secure: Widely audited by professional auditors, used in 1000s of projects
   Action: Unless concrete evidence of misconfiguration, DO NOT flag
   
5. **Read-Only ERC20 Function Calls (External Trust FALSE POSITIVE)**
   Pattern: IERC20(...).balanceOf(), IERC20(...).allowance(), IERC20(...).totalSupply(), etc.
   Why it's secure: These are view functions that cannot modify state or cause trust issues
   How to identify: balanceOf, allowance, totalSupply, name, symbol, decimals in code
   Action: DO NOT flag as external trust issue - these are pure read operations
   Reality check: If function is view/pure and only reads data, it's not a vulnerability
   
6. **Access-Controlled Reentrancy (Reentrancy FALSE POSITIVE)**
   Pattern: External call in function with onlyOwner/onlyRole modifier followed by state changes
   Why it's less critical: Requires privileged access (owner/role) to exploit - not externally exploitable
   How to identify: Function has onlyOwner, onlyRole, or similar access control modifier
   Action: Only flag if function handles critical operations (flash loans, user funds) OR if it can be front-run
   Reality check: If function requires owner/role access, reentrancy attack requires attacker to BE the owner/role
   
7. **Intentional Error Suppression (Error Handling FALSE POSITIVE)**
   Pattern: try/catch blocks that suppress errors with comments like "don't want to revert", "if X fails, we don't want to revert Y"
   Why it's intentional: Sometimes you want secondary operations to fail gracefully without reverting primary operations
   How to identify: Comments explaining intent ("if liquidation fails, we don't want to revert the made challenge")
   Action: DO NOT flag if there's documented intent explaining why errors should be suppressed
   Reality check: Check if the suppressed operation is secondary to a primary operation that should succeed independently
   
8. **Flash Loan Configuration vs Execution (Flash Loan FALSE POSITIVE)**
   Pattern: Code sets flash loan configuration (e.g., _config.flashLender = flashLender) vs actual flash loan execution
   Why it's not a vulnerability: Setting default values is not executing a flash loan
   How to identify: Look for assignment patterns (_config.flashLender = ...) vs actual calls (flashLoan(...))
   Action: Only flag actual flashLoan() calls, not configuration/setup code
   Reality check: If it's just variable assignment or configuration, not actual execution

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
- [ ] The issue can be exploited in practice (by external attackers, not just privileged users)
- [ ] The issue is not a standard, secure pattern
- [ ] The issue has concrete code evidence
- [ ] The issue is not already mitigated by other mechanisms (access control, guards, etc.)
- [ ] If inheritance is involved, parent class protections were verified
- [ ] If SafeCast is used, revert-on-overflow is considered intentional
- [ ] If function has onlyOwner/onlyRole, verify it's actually exploitable by non-privileged users
- [ ] If try/catch suppresses errors, check for documented intent explaining why
- [ ] If external call is balanceOf/allowance/totalSupply, it's a read-only operation (not a trust issue)
- [ ] If flash loan is mentioned, verify it's actual execution not just configuration

**IMPORTANT**: If no real vulnerabilities are found, return an empty vulnerabilities array. It's better to miss a vulnerability than to report a false positive.
"""

        return prompt

    async def _call_llm(self, prompt: str, model: str = "gpt-4.1-mini-2025-04-14") -> Optional[str]:
        """Call the LLM with the given prompt. Supports both OpenAI and Gemini models."""
        if not self.has_api_key:
            print("⚠️  No API key available for LLM calls")
            return None
        
        # Estimate token usage for monitoring (silent)
        estimated_input_tokens = len(prompt) // 3  # Rough estimate: 3 chars per token
        # Removed: print(f"📊 Estimated request: ~{estimated_input_tokens:,} input tokens for {model}")
            
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
                
                # Get context limit for current model (COMBINED input + output)
                context_limit = self.model_context_limits.get(current_model, 128000)  # Default to 128k for unknown models
                
                # Reserve space for completion output
                # GPT-5: Superior retrieval from large inputs means we can be aggressive
                # Reserve only what we need for output (~8K tokens for comprehensive responses)
                # Gemini 2.5 Flash uses thinking mode - needs more (4K thinking + 8K output = 12K)
                is_gpt5 = current_model.startswith('gpt-5')
                if is_gemini:
                    max_completion_tokens = 12000  # 12K for thinking + output
                elif is_gpt5:
                    max_completion_tokens = 8000   # 8K for output (GPT-5's better retrieval allows aggressive input)
                else:
                    max_completion_tokens = 4000   # 4K for older models
                
                # Calculate max prompt size
                # GPT-5: 400K total - 8K output = 392K input (1.176M chars!)
                max_prompt_tokens = max(context_limit - max_completion_tokens, 1000)  # Ensure at least 1k tokens for prompt
                max_prompt_chars = max_prompt_tokens * 3  # ~3 chars per token
                
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
            
            # GPT-5 models require max_completion_tokens instead of max_tokens
            # GPT-5-mini only supports temperature=1.0 (default)
            is_gpt5 = model.startswith('gpt-5')
            is_gpt5_mini = 'gpt-5-mini' in model
            
            api_params = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are an expert smart contract security auditor. Provide accurate, validated analysis."},
                    {"role": "user", "content": prompt}
                ],
            }
            
            # Set temperature - GPT-5-mini only supports default (1.0)
            if is_gpt5_mini:
                # Don't set temperature for mini models - they only support default
                pass
            elif is_gpt5:
                api_params["temperature"] = 0.1  # Low temperature for more consistent results
            else:
                api_params["temperature"] = 0.1  # Low temperature for more consistent results
            
            if is_gpt5:
                api_params["max_completion_tokens"] = max_tokens
            else:
                api_params["max_tokens"] = max_tokens
                
            response = self.client.chat.completions.create(**api_params)
            
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
            
            # NEW: Validate and correct line numbers
            try:
                from .line_number_validator import LineNumberValidator
                line_validator = LineNumberValidator()
                line_validated_vulns = []
                line_validation_stats = {'corrected': 0, 'invalid': 0}
                
                for vuln in analysis_data.get('vulnerabilities', []):
                    validated_vuln = line_validator.validate_finding_line_number(vuln, contract_content)
                    validation_status = validated_vuln.get('line_validation', {}).get('status', 'unknown')
                    
                    if validation_status == 'invalid' and 'corrected_to' not in validated_vuln.get('line_validation', {}):
                        # Line invalid and couldn't be corrected - skip this finding
                        line_validation_stats['invalid'] += 1
                        print(f"⚠️  Filtered finding with invalid line number: {vuln.get('title', 'Unknown')} (line {vuln.get('line_number', vuln.get('line', 'unknown'))})")
                        continue
                    
                    if validation_status == 'corrected':
                        line_validation_stats['corrected'] += 1
                    
                    line_validated_vulns.append(validated_vuln)
                
                if line_validation_stats['corrected'] > 0 or line_validation_stats['invalid'] > 0:
                    print(f"📍 Line validation: {line_validation_stats['corrected']} corrected, {line_validation_stats['invalid']} filtered")
                
                # Use line-validated vulnerabilities for further processing
                analysis_data['vulnerabilities'] = line_validated_vulns
            except ImportError:
                # Line validator not available, continue without it
                pass
            except Exception as e:
                print(f"⚠️  Line validation error (continuing without): {e}")
            
            # Validate each vulnerability and apply severity calibration
            validated_vulnerabilities = []
            for vuln in analysis_data.get('vulnerabilities', []):
                if self._validate_vulnerability(vuln, contract_content):
                    # NEW: Apply automatic severity adjustment based on impact type
                    adjusted_vuln = self._apply_severity_calibration(vuln, contract_content)
                    validated_vulnerabilities.append(adjusted_vuln)
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
    
    def _apply_severity_calibration(self, vuln: Dict[str, Any], contract_content: str) -> Dict[str, Any]:
        """
        Apply automatic severity adjustment based on impact type and exploitability.
        
        Uses the financial impact classifier and TOCTOU detector to adjust severity:
        - Fund drain → Keep HIGH/CRITICAL
        - Profit reduction → Downgrade to MEDIUM
        - Flash loan (atomic) → Keep HIGH
        - TOCTOU/MEV → Downgrade to MEDIUM
        
        Returns:
            Vulnerability dict with adjusted severity
        """
        try:
            # Import impact analyzer
            from core.impact_analyzer import ImpactAnalyzer, FinancialImpactType
            from core.mev_detector import MEVDetector
            
            impact_analyzer = ImpactAnalyzer()
            mev_detector = MEVDetector()
            
            # Classify financial impact
            financial_impact, severity_multiplier = impact_analyzer.classify_financial_impact(vuln)
            
            # Check for TOCTOU pattern (misclassified flash loan)
            toctou_result = mev_detector.detect_toctou_pattern(contract_content, vuln)
            
            original_severity = vuln.get('severity', 'medium').lower()
            adjusted_severity = original_severity
            adjustment_reason = []
            
            # Apply TOCTOU adjustment (highest priority)
            if toctou_result and toctou_result['is_toctou']:
                adjusted_severity = toctou_result['severity_adjustment'].lower()
                adjustment_reason.append(f"TOCTOU pattern detected (not atomic flash loan): {original_severity} → {adjusted_severity}")
                vuln['attack_type'] = toctou_result['attack_type']
                vuln['toctou_classification'] = toctou_result
            
            # Apply financial impact adjustment
            elif financial_impact != FinancialImpactType.NONE:
                severity_map = {
                    'critical': 4,
                    'high': 3,
                    'medium': 2,
                    'low': 1
                }
                
                reverse_map = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}
                
                original_level = severity_map.get(original_severity, 2)
                adjusted_level = round(original_level * severity_multiplier)  # Use round for proper rounding
                adjusted_level = max(1, min(4, adjusted_level))  # Clamp to 1-4
                
                adjusted_severity = reverse_map[adjusted_level]
                
                if adjusted_severity != original_severity:
                    impact_name = financial_impact.value.replace('_', ' ').title()
                    adjustment_reason.append(
                        f"Financial impact classification ({impact_name}): {original_severity} → {adjusted_severity}"
                    )
                    vuln['financial_impact_type'] = financial_impact.value
                    vuln['severity_multiplier'] = severity_multiplier
            
            # Update vulnerability if adjusted
            if adjusted_severity != original_severity:
                vuln['original_severity'] = original_severity
                vuln['severity'] = adjusted_severity
                vuln['severity_adjustment_reason'] = '; '.join(adjustment_reason)
                
                print(f"📊 Severity adjusted: {original_severity.upper()} → {adjusted_severity.upper()}")
                print(f"   Reason: {adjustment_reason[0]}")
            
            return vuln
            
        except Exception as e:
            # If calibration fails, return original vulnerability
            print(f"⚠️  Severity calibration failed: {e}")
            return vuln

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
        import re
        
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        vuln_type = vuln.get('vulnerability_type', '').lower()
        code_snippet = vuln.get('code_snippet', '')
        
        # Common false positive patterns
        false_positive_patterns = [
            'standard openzeppelin pattern',
            'properly protected',
            'internal authorization',
            'valid versioning',
            'no actual vulnerability',
            'false positive'
        ]
        
        # Check text-based patterns
        for pattern in false_positive_patterns:
            if pattern in description:
                return True
        
        # NEW: Check for OpenZeppelin proxy false positives
        if any(vuln_type in vt for vt in ['upgradeability', 'delegatecall_initialization', 'storage_slot_conflict']):
            # Check if this is OpenZeppelin proxy code
            if re.search(r'@openzeppelin/contracts/proxy', contract_content):
                # Check if vulnerability is in standard proxy patterns
                if any(proxy_type in contract_content for proxy_type in [
                    'ERC1967Proxy', 'TransparentUpgradeableProxy', 
                    'BeaconProxy', 'ProxyAdmin'
                ]):
                    # Check if description mentions standard proxy behavior
                    proxy_false_positive_keywords = [
                        'admin can upgrade',
                        'initialowner',
                        'delegatecall.*data.*constructor',
                        'storage slot.*implementation',
                        'eoa.*private key',
                        'malicious deployer',
                        'arbitrary.*initialization'
                    ]
                    
                    for keyword in proxy_false_positive_keywords:
                        if re.search(keyword, description, re.IGNORECASE):
                            return True
        
        # NEW: Check for deployment-time only issues
        deployment_time_keywords = [
            'constructor.*accept',
            'during deployment',
            'at deployment time',
            'malicious deployer',
            'compromised factory'
        ]
        
        if any(re.search(kw, description, re.IGNORECASE) for kw in deployment_time_keywords):
            # Check if code is actually in constructor
            if 'constructor' in code_snippet.lower() or 'constructor' in title:
                return True
        
        # NEW: Check for centralization concerns disguised as vulnerabilities
        centralization_keywords = [
            'eoa.*private key.*compromised',
            'without multisig',
            'time-delayed administrative',
            'governance.*not implemented',
            'owner.*not.*multisig'
        ]
        
        if any(re.search(kw, description, re.IGNORECASE) for kw in centralization_keywords):
            # This is a governance/centralization concern, not a code vulnerability
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
    
    def _extract_solidity_version(self, contract_content: str) -> Optional[str]:
        """Extract Solidity version from pragma statement."""
        import re
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', contract_content)
        if pragma_match:
            version_spec = pragma_match.group(1).strip()
            # Extract actual version number (e.g., "^0.8.0" -> "0.8.0")
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_spec)
            if version_match:
                return version_match.group(1)
            # Handle range specs like ">=0.7.6 <0.9.0"
            version_match = re.search(r'(\d+\.\d+)', version_spec)
            if version_match:
                return version_match.group(1) + ".0"
        return None
    
    def _generate_version_specific_guidance(self, solidity_version: Optional[str]) -> str:
        """
        Generate version-specific guidance for the LLM based on Solidity version.
        
        This helps the LLM understand critical differences between Solidity versions:
        - <0.8.0: No automatic overflow/underflow checks
        - >=0.8.0: Automatic overflow/underflow checks (unless in unchecked blocks)
        """
        if not solidity_version:
            return """
**SOLIDITY VERSION: UNKNOWN**
- Proceed with caution - unable to determine Solidity version
- Check for SafeMath usage for overflow protection
- Look for explicit bounds checking
"""
        
        # Parse version
        try:
            major, minor = map(int, solidity_version.split('.')[:2])
        except (ValueError, AttributeError):
            return ""
        
        if major == 0 and minor < 8:
            # Solidity <0.8.0
            return f"""
**SOLIDITY VERSION: {solidity_version} (<0.8.0)**

**CRITICAL OVERFLOW/UNDERFLOW CONTEXT:**
- ⚠️  **NO automatic overflow/underflow protection**
- Arithmetic operations can silently overflow/underflow
- **Required protections:**
  1. SafeMath library (OpenZeppelin)
  2. Manual bounds checking with require()
  3. Documented intentional overflow (see comments for "overflow is acceptable")

**FALSE POSITIVE PREVENTION:**
- ✅ SafeMath.add/sub/mul/div → SAFE (reverts on overflow)
- ✅ require(a + b <= max) → SAFE (explicit bounds check)
- ✅ Comments like "overflow is acceptable" + documentation → MAY BE SAFE (check context)
- ❌ Unchecked arithmetic → VULNERABLE (unless explicitly documented as safe)

**IMPORTANT:** Check for comments like "overflow is acceptable" - in protocols like Uniswap V3, 
uint128 overflow is intentionally allowed with documentation. This is NOT a vulnerability if:
1. There's explicit documentation explaining the behavior
2. The protocol has safety mechanisms (e.g., "must withdraw before type(uint128).max")
3. Related library files (Position.sol, Tick.sol) document the design decision
"""
        else:
            # Solidity >=0.8.0
            return f"""
**SOLIDITY VERSION: {solidity_version} (≥0.8.0)**

**CRITICAL OVERFLOW/UNDERFLOW CONTEXT:**
- ✅ **Automatic overflow/underflow protection ENABLED**
- All arithmetic operations revert on overflow/underflow by default
- unchecked blocks opt out of protection

**FALSE POSITIVE PREVENTION:**
- ✅ Normal arithmetic (a + b, a - b, etc.) → SAFE (auto-protected)
- ✅ SafeCast.toUint96/toUint128 → SAFE (intentional type narrowing with revert)
- ⚠️  unchecked {{ a + b }} → POTENTIALLY UNSAFE (intentionally bypassing protection)
- ✅ External library calls → Check library's Solidity version

**IMPORTANT:** Do NOT flag normal arithmetic as overflow vulnerabilities in Solidity ≥0.8.0 
unless it's inside an `unchecked` block. The compiler automatically adds overflow checks.

**SafeCast Pattern:** 
- SafeCast.toUintXX() is intentional type narrowing that REVERTS on overflow
- This is a SAFE pattern, NOT a vulnerability
- Example: `SafeCast.toUint96(votes)` will revert if votes > type(uint96).max
"""
