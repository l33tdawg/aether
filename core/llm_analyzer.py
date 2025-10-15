"""
LLM-powered smart contract analysis using OpenAI GPT-5.
"""

import os
import re
import asyncio
from typing import Dict, List, Any, Optional

from openai import OpenAI
# LangChain is optional; we use OpenAI client directly to avoid encoding issues


class LLMAnalyzer:
    """LLM-powered smart contract vulnerability analysis."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        # Force UTF-8 to avoid ascii codec issues during API calls
        os.environ.setdefault('PYTHONIOENCODING', 'UTF-8')
        os.environ.setdefault('LC_ALL', 'en_US.UTF-8')
        os.environ.setdefault('LANG', 'en_US.UTF-8')
        self.has_api_key = bool(self.api_key)

        if self.has_api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            print("⚠️  No OpenAI API key provided - LLM features disabled")

        # Ensure stdout/stderr use UTF-8 to avoid ascii codec errors when printing exceptions
        try:
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
            if hasattr(sys.stderr, 'reconfigure'):
                sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass

    async def analyze_vulnerabilities(
        self,
        contract_content: str,
        static_analysis_results: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze contract for vulnerabilities using AI."""
        print("🤖 Running AI-powered vulnerability analysis...")

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

        # Create analysis prompt (ASCII only)
        prompt = self._create_analysis_prompt(contract_content, static_analysis_results)
        prompt = prompt.encode('ascii', errors='ignore').decode('ascii')

        # Try different models if the primary one fails
        # Prefer latest configured model; fall back to known stable models
        preferred_models = []
        cfg_model = os.getenv('AETHER_LLM_MODEL') or None
        if not cfg_model:
            try:
                from core.config_manager import ConfigManager
                cm = ConfigManager()
                cfg_model = getattr(cm.config, 'openai_model', None)
            except Exception:
                cfg_model = None
        if cfg_model:
            preferred_models.append(cfg_model)
        
        # Prioritize gpt-5-chat-latest as the primary model
        preferred_models.insert(0, 'gpt-5-chat-latest')
        
        # Dynamically list and choose latest available model
        try:
            models = self.client.models.list()
            model_ids = [m.id for m in getattr(models, 'data', [])]
            # Prefer GPT-5 chat models, then other GPT-5, then GPT-4.x/4o, then GPT-4
            priorities = [
                r"gpt-5-chat.*", r"gpt-5-.*", r"gpt-5", r"gpt-5-turbo",
                r"gpt-4\.1.*", r"gpt-4o.*", r"gpt-4-turbo.*", r"gpt-4.*"
            ]
            import re
            for pat in priorities:
                candidates = [m for m in model_ids if re.fullmatch(pat, m)]
                # sort lexicographically as a proxy for recency
                candidates.sort(reverse=True)
                preferred_models += candidates
        except Exception:
            # Fall back to a static preference order with gpt-5-chat-latest first
            preferred_models += ['gpt-5-chat-latest', 'gpt-5', 'gpt-5-turbo', 'gpt-4.1', 'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4']

        for model_name in preferred_models:
            try:
                print(f"🤖 Trying LLM analysis with model: {model_name}")

                # Sanitize messages and call OpenAI directly to avoid encoding issues
                sys_msg = (
                    "You are an expert smart contract security auditor with deep knowledge of Solidity, DeFi protocols, and blockchain security. Analyze the provided contract for vulnerabilities, gas optimizations, and security best practices. Provide detailed findings with confidence scores and remediation suggestions."
                ).encode('ascii', errors='ignore').decode('ascii')
                user_msg = prompt

                # Set appropriate temperature based on model
                temperature = 0.2
                if 'gpt-5-nano' in model_name:
                    temperature = 1.0  # Default temperature for these models
                
                # GPT-4.1-mini has 1M context window, so we can handle much larger prompts
                max_tokens_estimate = len(prompt) // 4  # Rough estimate
                if max_tokens_estimate > 800000:  # Conservative limit for 1M token context
                    print(f"⚠️  Prompt extremely large ({max_tokens_estimate} tokens), truncating...")
                    user_msg = prompt[:3200000]  # Truncate to ~800k tokens
                    user_msg += "\n\n[Note: Contract content truncated due to size limits]"

                response = self.client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": sys_msg},
                        {"role": "user", "content": user_msg}
                    ],
                    temperature=temperature,
                    max_tokens=8000  # Increased for GPT-4.1-mini's large context window
                )

                content = (response.choices[0].message.content or "").encode('utf-8', errors='ignore').decode('utf-8')
                analysis_result = self._parse_llm_response(content)

                print(f"✅ LLM analysis successful with {model_name}")
                return {
                    'success': True,
                    'analysis': analysis_result,
                    'raw_response': content,
                    'model': model_name
                }

            except Exception as e:
                print(f"❌ Model {model_name} failed: {str(e)}")
                continue

        # If all models fail, return fallback analysis
        print("⚠️  All LLM models failed, using fallback analysis")
        return {
            'success': True,
            'analysis': {
                'vulnerabilities': [
                    {
                        'swc_id': 'SWC-000',
                        'title': 'Manual Review Required',
                        'description': 'LLM analysis unavailable due to API limitations. Manual security review recommended.',
                        'severity': 'info',
                        'confidence': 1.0,
                        'line_numbers': [],
                        'exploitability': 'Unknown',
                        'fix_suggestion': 'Enable OpenAI API access or perform manual security audit'
                    }
                ],
                'gas_optimizations': [],
                'best_practices': [],
                'note': 'LLM analysis failed due to API quota/model access limitations'
            },
            'raw_response': 'LLM analysis unavailable',
            'model': 'fallback'
        }

    def _detect_contract_type(self, contract_content: str) -> str:
        """Detect the type of smart contract for context-aware analysis."""
        content_lower = contract_content.lower()

        # Check for specific contract types
        if any(keyword in content_lower for keyword in ['oracle', 'aggregator', 'pricefeed']):
            return 'Oracle/Price Feed'
        elif any(keyword in content_lower for keyword in ['lendingpool', 'pool', 'borrow', 'supply']):
            return 'Lending Pool'
        elif any(keyword in content_lower for keyword in ['governance', 'governor', 'proposal', 'vote']):
            return 'Governance'
        elif any(keyword in content_lower for keyword in ['token', 'erc20', 'mint', 'burn']):
            return 'Token/ERC20'
        elif any(keyword in content_lower for keyword in ['flashloan', 'flash loan']):
            return 'Flash Loan'
        elif any(keyword in content_lower for keyword in ['liquidation', 'liquidate']):
            return 'Liquidation'
        elif any(keyword in content_lower for keyword in ['bridge', 'cross-chain']):
            return 'Cross-chain Bridge'
        elif any(keyword in content_lower for keyword in ['staking', 'stake']):
            return 'Staking'
        elif any(keyword in content_lower for keyword in ['dex', 'exchange', 'swap']):
            return 'DEX/Exchange'
        else:
            return 'Generic DeFi'

    def _create_analysis_prompt(self, contract_content: str, static_results: Dict[str, Any]) -> str:
        """Create exploit-focused analysis prompt for the LLM."""
        # Detect contract type for context-aware analysis
        contract_type = self._detect_contract_type(contract_content)

        prompt = f"""
        You are an elite smart contract security auditor specializing in DeFi protocols for bug bounty programs.

        **CONTRACT CONTEXT:**
        This is a {contract_type} smart contract. Focus your analysis on vulnerabilities that could lead to actual financial losses or protocol manipulation.

        **IMMUNEFI BOUNTY CONTEXT:**
        - Critical ($50K-$1M): Direct theft of funds, permanent locking, governance manipulation
        - High ($10K-$75K): Treasury theft, temporary locking, major logic flaws
        - Medium ($10K): Contract logic issues, access control problems

        **PRIORITY ATTACK VECTORS:**
        1. **Fund Theft**: Direct or indirect theft of user/principal funds
        2. **Permanent Locks**: Scenarios that permanently lock user funds
        3. **Governance Manipulation**: Admin function abuse or proposal hijacking
        4. **Oracle Manipulation**: Price feed attacks and stale data exploitation
        5. **Liquidation Attacks**: Griefing or manipulating liquidation processes
        6. **Flash Loan Attacks**: Complex multi-step attacks using flash loans
        7. **Access Control Bypass**: Unauthorized function execution

        **CONTRACT CODE:**
        ```solidity
        {contract_content}
        ```

        **Static Analysis Context:**
        """

        # Add static analysis results with exploit focus
        if static_results.get('slither'):
            slither_vulns = static_results['slither'].get('vulnerabilities', [])
            if slither_vulns:
                prompt += "\nPotential Issues from Static Analysis:\n"
                for vuln in slither_vulns[:5]:  # Focus on top issues
                    prompt += f"- {vuln.get('title', 'Unknown')}: {vuln.get('description', '')[:150]}...\n"

        if static_results.get('mythril'):
            mythril_vulns = static_results['mythril'].get('vulnerabilities', [])
            if mythril_vulns:
                prompt += "\nSymbolic Execution Findings:\n"
                for vuln in mythril_vulns[:5]:
                    prompt += f"- {vuln.get('title', 'Unknown')}: {vuln.get('description', '')[:150]}...\n"

        prompt += """

        **EXPLOIT-FOCUSED ANALYSIS REQUIREMENTS:**

        1. **Real Vulnerability Assessment**: Only identify issues that are actually exploitable
        2. **Attack Vector Analysis**: Describe specific attack scenarios with step-by-step reproduction
        3. **Financial Impact**: Calculate potential financial losses (in USD terms)
        4. **Exploit Complexity**: Rate difficulty (Low/Medium/High) and required skills
        5. **Detection Difficulty**: How likely is this to be caught in testing?
        6. **Immunefi Bounty Value**: Estimate potential bounty payout
        7. **Working PoC**: Provide concrete exploit code or attack sequence

        **CRITICAL FOCUS AREAS FOR THIS CONTRACT TYPE:**
        """

        # Add contract-type specific focus areas
        if 'oracle' in contract_type.lower():
            prompt += """
            - Price manipulation through stale data or malicious feeds
            - Fallback oracle dependency vulnerabilities
            - Chainlink aggregator exploitation vectors
            - Cross-chain oracle bridge attacks
            """
        elif 'lending' in contract_type.lower() or 'pool' in contract_type.lower():
            prompt += """
            - Flash loan attack vectors and manipulation
            - Liquidation mechanism exploitation
            - Interest rate manipulation scenarios
            - Collateral valuation attacks
            """
        elif 'governance' in contract_type.lower() or 'admin' in contract_type.lower():
            prompt += """
            - Admin function abuse and privilege escalation
            - Proposal manipulation and voting attacks
            - Timelock bypass vulnerabilities
            - Multi-sig wallet compromise vectors
            """

        prompt += """

        **OUTPUT FORMAT:**
        IMPORTANT: Return ONLY valid JSON object. Ensure all strings are properly quoted and escaped. Do not include any explanatory text before or after the JSON.
        
        Provide a structured JSON response focusing ONLY on exploitable vulnerabilities:
        {
          "vulnerabilities": [
            {
              "swc_id": "SWC-107",
              "title": "Reentrancy",
              "description": "Detailed description of the exploitable vulnerability",
              "severity": "critical",
              "confidence": 0.95,
              "exploitability": "High - External call before state update allows reentrancy",
              "attack_vector": "Step-by-step attack reproduction guide",
              "financial_impact": "$X,XXX,XXX potential loss",
              "exploit_complexity": "Medium - Requires custom contract deployment",
              "detection_difficulty": "Medium - Requires runtime testing",
              "immunefi_bounty_value": "$XX,XXX",
              "working_poc": "```solidity\\n// Concrete exploit code\\n```",
              "fix_suggestion": "Use Checks-Effects-Interactions pattern"
            }
          ],
          "gas_optimizations": [
            {
              "issue": "Unnecessary storage writes",
              "savings_estimate": "5,000 gas",
              "fix_suggestion": "Cache storage variables in memory"
            }
          ],
          "best_practices": [
            {
              "issue": "Missing access control",
              "recommendation": "Add proper access control modifiers"
            }
          ]
        }

        Focus on finding real vulnerabilities, not false positives. Be thorough but practical.
        
        CRITICAL: Your response must be valid JSON that can be parsed directly. Ensure:
        - All strings are properly quoted with double quotes
        - No trailing commas
        - All brackets and braces are properly closed
        - No unescaped quotes within string values
        - No explanatory text outside the JSON object
        """

        return prompt

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured format with robust fallback mechanisms."""
        import json
        import re

        print(f"DEBUG: LLM Parser - Response length: {len(response)}")
        print(f"DEBUG: LLM Parser - Response preview: {response[:200]}...")

        # Strategy 1: Extract JSON from markdown code blocks
        from .json_utils import extract_json_from_response, safe_json_parse
        
        json_str = extract_json_from_response(response)
        if json_str and json_str != "{}":
            print("DEBUG: LLM Parser - Found JSON in response")
            return safe_json_parse(json_str, self._create_fallback_response())

        # Strategy 2: Extract JSON object with proper brace matching
        try:
            start_idx = response.find('{')
            if start_idx != -1:
                brace_count = 0
                end_idx = start_idx
                for i, char in enumerate(response[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break

                if brace_count == 0:
                    json_str = response[start_idx:end_idx]
                    print("DEBUG: LLM Parser - Extracted JSON object")
                    try:
                        return json.loads(json_str)
                    except json.JSONDecodeError as e:
                        print(f"DEBUG: LLM Parser - Extracted JSON still failed: {e}")
                        # Try to fix common JSON issues
                        json_str = self._fix_json_string(json_str)
                        try:
                            return json.loads(json_str)
                        except json.JSONDecodeError:
                            print("DEBUG: LLM Parser - Fixed JSON still failed")
        except Exception as e:
            print(f"DEBUG: LLM Parser - Brace matching failed: {e}")

        # Strategy 3: Manual extraction of vulnerabilities from text
        vulnerabilities = self._extract_vulnerabilities_manually(response)
        if vulnerabilities:
            print(f"DEBUG: LLM Parser - Extracted {len(vulnerabilities)} vulnerabilities manually")
            return {
                'vulnerabilities': vulnerabilities,
                'gas_optimizations': self._extract_gas_optimizations(response),
                'best_practices': self._extract_best_practices(response),
                'raw_analysis': response
            }

        # Strategy 4: Try to parse entire response as JSON (last resort)
        try:
            print("DEBUG: LLM Parser - Trying to parse entire response as JSON")
            return json.loads(response)
        except json.JSONDecodeError as e:
            print(f"DEBUG: LLM Parser - Full response JSON parsing failed: {e}")

        # Final fallback: Return empty structure with raw response
        print("DEBUG: LLM Parser - All parsing strategies failed, returning fallback")
        return {
            'vulnerabilities': [],
            'gas_optimizations': [],
            'best_practices': [],
            'raw_analysis': response,
            'parsing_failed': True,
            'error': 'Failed to parse LLM response'
        }

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

        # Fix unescaped quotes in strings (basic fix)
        # This is tricky - only fix obvious cases to avoid breaking valid JSON
        json_str = re.sub(r'([^\\])"([^",\s}]+)"([^,}\s])', r'\1"\2"\3', json_str)

        # Fix common formatting issues
        json_str = re.sub(r'(\w+):(\s*)(\w+)', r'\1: "\2\3"', json_str)  # Add quotes around unquoted values

        return json_str

    def _extract_vulnerabilities_manually(self, response: str) -> List[Dict[str, Any]]:
        """Extract vulnerability information manually from LLM response."""
        vulnerabilities = []

        try:
            # Look for structured vulnerability mentions
            vuln_sections = re.findall(r'(\d+\.\s*|\*\s*)?(SWC-\d+|"[^"]*")\s*[:\-]?\s*([^\n]+)', response, re.IGNORECASE | re.MULTILINE)

            for match in vuln_sections:
                swc_or_title = match[1].strip('"')
                description = match[2].strip()

                # Try to extract SWC ID
                swc_match = re.search(r'SWC-(\d+)', swc_or_title, re.IGNORECASE)
                swc_id = f"SWC-{swc_match.group(1)}" if swc_match else swc_or_title

                # Determine severity (basic heuristic)
                severity = 'medium'
                if any(word in description.lower() for word in ['critical', 'severe', 'dangerous', 'exploit']):
                    severity = 'high'
                elif any(word in description.lower() for word in ['minor', 'low', 'informational']):
                    severity = 'low'

                vuln_data = {
                    'swc_id': swc_id,
                    'title': swc_or_title,
                    'description': description,
                    'severity': severity,
                    'confidence': 0.8,  # High confidence for manual extraction
                    'line_numbers': [],
                    'exploitability': 'Medium - Requires specific conditions',
                    'attack_vector': 'Not specified in response',
                    'financial_impact': 'Not assessed',
                    'exploit_complexity': 'Medium',
                    'detection_difficulty': 'Medium',
                    'immunefi_bounty_value': 'Not estimated',
                    'working_poc': 'Not provided',
                    'fix_suggestion': 'Review and implement appropriate security measures'
                }
                vulnerabilities.append(vuln_data)

        except Exception as e:
            print(f"DEBUG: LLM Parser - Manual vulnerability extraction failed: {e}")

        return vulnerabilities

    def _extract_gas_optimizations(self, response: str) -> List[Dict[str, Any]]:
        """Extract gas optimization suggestions from response."""
        optimizations = []

        try:
            # Look for gas-related suggestions
            gas_sections = re.findall(r'(?:gas|optimization)[^.!?]*[.!?]', response, re.IGNORECASE)

            for section in gas_sections:
                if len(section.strip()) > 20:  # Only meaningful suggestions
                    optimizations.append({
                        'issue': section.strip(),
                        'savings_estimate': 'Unknown',
                        'fix_suggestion': 'Review gas usage patterns'
                    })

        except Exception as e:
            print(f"DEBUG: LLM Parser - Gas optimization extraction failed: {e}")

        return optimizations

    def _extract_best_practices(self, response: str) -> List[Dict[str, Any]]:
        """Extract best practice recommendations from response."""
        practices = []

        try:
            # Look for best practice mentions
            practice_keywords = ['best practice', 'should', 'recommend', 'consider', 'avoid']
            practice_sections = []

            for keyword in practice_keywords:
                matches = re.findall(f'{keyword}[^.!?]*[.!?]', response, re.IGNORECASE)
                practice_sections.extend(matches)

            for section in practice_sections:
                if len(section.strip()) > 15:
                    practices.append({
                        'issue': section.strip(),
                        'recommendation': 'Follow security best practices'
                    })

        except Exception as e:
            print(f"DEBUG: LLM Parser - Best practice extraction failed: {e}")

        return practices

    async def generate_fix_suggestions(
        self,
        contract_content: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate fix suggestions for identified vulnerabilities."""
        print("🔧 Generating AI-powered fix suggestions...")

        if not vulnerabilities:
            return {'fixes': [], 'success': True}

        if not self.has_api_key:
            print("⚠️  Skipping LLM fix generation - no API key provided")
            return {
                'fixes': [],
                'success': True,
                'note': 'LLM fix generation disabled - no OpenAI API key'
            }

        # Create fix generation prompt
        prompt = f"""
        Please provide specific fix suggestions for the following vulnerabilities in this Solidity contract:

        ```solidity
        {contract_content}
        ```

        Vulnerabilities to fix:
        """

        for i, vuln in enumerate(vulnerabilities[:5]):  # Limit to avoid token overflow
            prompt += f"{i+1}. {vuln.get('title', 'Unknown')} (SWC-{vuln.get('swc_id', 'Unknown')}): {vuln.get('description', '')}\n"

        prompt += """

        **Requirements:**
        1. Provide specific code changes for each vulnerability
        2. Follow Solidity best practices and security patterns
        3. Ensure fixes don't introduce new vulnerabilities
        4. Consider gas efficiency where applicable
        5. Include before/after code examples

        **Output Format** (JSON):
        {
          "fixes": [
            {
              "vulnerability_id": 1,
              "title": "Reentrancy Fix",
              "description": "Fix for reentrancy vulnerability",
              "code_changes": [
                {
                  "file": "contract.sol",
                  "line_start": 47,
                  "line_end": 52,
                  "old_code": "// original problematic code",
                  "new_code": "// fixed code with Checks-Effects-Interactions pattern"
                }
              ],
              "gas_impact": "+200 gas (due to additional checks)",
              "security_improvement": "Prevents reentrancy attacks"
            }
          ]
        }
        """

        try:
            messages = [
                SystemMessage(content="You are a senior Solidity developer specializing in security fixes. Provide precise, secure code modifications."),
                HumanMessage(content=prompt)
            ]

            response = await self.langchain_llm.ainvoke(messages)
            return {
                'success': True,
                'fixes': self._parse_fix_response(response.content),
                'raw_response': response.content
            }

        except Exception as e:
            print(f"❌ Fix generation failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'fixes': []
            }

    def _parse_fix_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse fix suggestions from LLM response."""
        import json
        import re

        try:
            # Try to extract JSON from the response
            json_match = re.search(r'```json\s*(\{.+?\})\s*```', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(1))
                return data.get('fixes', [])
            else:
                return json.loads(response).get('fixes', [])
        except (json.JSONDecodeError, ValueError):
            return []

    async def validate_fixes(
        self,
        original_contract: str,
        fixed_contract: str,
        original_vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate that fixes resolve vulnerabilities without introducing new issues."""
        print("✅ Validating fix effectiveness...")

        if not self.has_api_key:
            print("⚠️  Skipping LLM fix validation - no API key provided")
            return {
                'success': True,
                'validation': {
                    'validation_results': [],
                    'overall_assessment': {
                        'security_score': 5.0,
                        'gas_efficiency': 'Unknown',
                        'code_quality': 'Unknown',
                        'recommendations': ['Manual review required - no LLM validation']
                    }
                },
                'note': 'LLM fix validation disabled - no OpenAI API key'
            }

        prompt = f"""
        Please validate that the fixes applied to this Solidity contract are effective:

        **Original Contract:**
        ```solidity
        {original_contract}
        ```

        **Fixed Contract:**
        ```solidity
        {fixed_contract}
        ```

        **Original Vulnerabilities:**
        """

        for vuln in original_vulnerabilities:
            prompt += f"- {vuln.get('title', 'Unknown')}: {vuln.get('description', '')}\n"

        prompt += """

        **Validation Requirements:**
        1. Verify that each original vulnerability has been addressed
        2. Check for new vulnerabilities introduced by the fixes
        3. Assess overall security improvement
        4. Evaluate gas efficiency impact
        5. Confirm adherence to Solidity best practices

        **Output Format** (JSON):
        {
          "validation_results": [
            {
              "vulnerability_id": 1,
              "original_vulnerability": "Reentrancy",
              "fix_effective": true,
              "new_vulnerabilities": [],
              "gas_impact": "+200 gas",
              "security_improvement": "Prevents reentrancy attacks"
            }
          ],
          "overall_assessment": {
            "security_score": 8.5,
            "gas_efficiency": "Improved",
            "code_quality": "Enhanced",
            "recommendations": []
          }
        }
        """

        try:
            messages = [
                SystemMessage(content="You are a security expert validating smart contract fixes. Be thorough and identify any remaining issues."),
                HumanMessage(content=prompt)
            ]

            response = await self.langchain_llm.ainvoke(messages)
            return {
                'success': True,
                'validation': self._parse_validation_response(response.content),
                'raw_response': response.content
            }

        except Exception as e:
            print(f"❌ Fix validation failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'validation': {}
            }

    def _parse_validation_response(self, response: str) -> Dict[str, Any]:
        """Parse validation results from LLM response."""
        import json
        import re

        try:
            json_match = re.search(r'```json\s*(\{.+?\})\s*```', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            else:
                return json.loads(response)
        except (json.JSONDecodeError, ValueError):
            return {
                'validation_results': [],
                'overall_assessment': {
                    'security_score': 5.0,
                    'gas_efficiency': 'Unknown',
                    'code_quality': 'Unknown',
                    'recommendations': ['Manual review required']
                }
            }