#!/usr/bin/env python3
"""
LLM-based False Positive Filter

Uses LLM to validate vulnerabilities and filter out false positives.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from .enhanced_llm_analyzer import EnhancedLLMAnalyzer

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of LLM validation."""
    is_false_positive: bool
    confidence: float
    reasoning: str
    corrected_severity: Optional[str] = None
    corrected_description: Optional[str] = None

class LLMFalsePositiveFilter:
    """LLM-based false positive filter for vulnerability findings."""
    
    def __init__(self, llm_analyzer: Optional[EnhancedLLMAnalyzer] = None):
        self.llm_analyzer = llm_analyzer or EnhancedLLMAnalyzer()
        self.validation_cache = {}
        
    async def validate_vulnerabilities(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        contract_code: str,
        contract_name: str
    ) -> List[Dict[str, Any]]:
        """Validate vulnerabilities and filter out false positives."""
        
        logger.info(f"Validating {len(vulnerabilities)} vulnerabilities with LLM")
        print(f"DEBUG: LLM Filter - Starting validation of {len(vulnerabilities)} vulnerabilities")
        
        validated_vulnerabilities = []
        # Track full validation details for reporting
        self.last_validation_details = { 'validated': [], 'filtered': [] }
        
        for i, vuln in enumerate(vulnerabilities):
            try:
                logger.info(f"Validating vulnerability {i+1}/{len(vulnerabilities)}: {vuln.get('vulnerability_type', 'unknown')}")
                
                # Use code snippet from vulnerability if available, otherwise use contract code
                vuln_code = vuln.get('code_snippet', contract_code)
                vuln_contract_name = vuln.get('contract_name', contract_name)

                validation_result = await self._validate_single_vulnerability(
                    vuln, vuln_code, vuln_contract_name
                )
                
                if not validation_result.is_false_positive:
                    # Update vulnerability with corrected information
                    validated_vuln = vuln.copy()
                    if validation_result.corrected_severity:
                        validated_vuln['severity'] = validation_result.corrected_severity
                    if validation_result.corrected_description:
                        validated_vuln['description'] = validation_result.corrected_description
                    
                    validated_vuln['validation_confidence'] = validation_result.confidence
                    validated_vuln['validation_reasoning'] = validation_result.reasoning
                    
                    validated_vulnerabilities.append(validated_vuln)
                    # Record for reporting
                    self.last_validation_details['validated'].append(validated_vuln)
                    print(f"DEBUG: LLM Filter - Validated vulnerability {i+1}: {vuln.get('vulnerability_type', 'unknown')}")
                else:
                    logger.info(f"Filtered out false positive: {vuln.get('vulnerability_type', 'unknown')}")
                    print(f"DEBUG: LLM Filter - Filtered out false positive {i+1}: {vuln.get('vulnerability_type', 'unknown')}")
                    filtered_entry = vuln.copy()
                    filtered_entry['validation_confidence'] = validation_result.confidence
                    filtered_entry['validation_reasoning'] = validation_result.reasoning
                    filtered_entry['status'] = 'false_positive'
                    self.last_validation_details['filtered'].append(filtered_entry)
                    
            except Exception as e:
                logger.error(f"Error validating vulnerability {i+1}: {e}")
                print(f"DEBUG: LLM Filter - Error validating vulnerability {i+1}: {e}")
                # Keep the vulnerability if validation fails
                validated_vulnerabilities.append(vuln)
                print(f"DEBUG: LLM Filter - Kept vulnerability {i+1} due to validation error")
        
        logger.info(f"Filtered {len(vulnerabilities) - len(validated_vulnerabilities)} false positives")
        print(f"DEBUG: LLM Filter - Final result: {len(validated_vulnerabilities)}/{len(vulnerabilities)} vulnerabilities validated")
        return validated_vulnerabilities

    def get_last_validation_details(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return last run's validated/filtered collections for reporting."""
        return getattr(self, 'last_validation_details', { 'validated': [], 'filtered': [] })
    
    async def _validate_single_vulnerability(
        self, 
        vulnerability: Dict[str, Any], 
        contract_code: str, 
        contract_name: str
    ) -> ValidationResult:
        """Validate a single vulnerability using LLM."""
        
        # Create cache key
        cache_key = f"{vulnerability.get('vulnerability_type', '')}_{vulnerability.get('line_number', 0)}_{hash(contract_code) % 10000}"
        
        if cache_key in self.validation_cache:
            return self.validation_cache[cache_key]
        
        # Prepare context for LLM
        context = self._prepare_validation_context(vulnerability, contract_code, contract_name)
        
        # Get LLM validation
        validation_prompt = self._create_validation_prompt(context)
        
        # Get validation model from config (supports mixed OpenAI/Gemini)
        try:
            from core.config_manager import get_model_for_task
            validation_model = get_model_for_task('validation')
        except Exception:
            validation_model = 'gpt-5-chat-latest'  # Fallback
        
        try:
            response = await self.llm_analyzer._call_llm(
                validation_prompt,
                model=validation_model  # Use configured validation model (OpenAI or Gemini)
            )
            
            print(f"DEBUG: LLM Filter - Raw LLM response: {response[:200]}...")
            result = self._parse_validation_response(response)
            print(f"DEBUG: LLM Filter - Parsed result: is_false_positive={result.is_false_positive}, confidence={result.confidence}")
            self.validation_cache[cache_key] = result
            return result
            
        except Exception as e:
            logger.error(f"LLM validation failed: {e}")
            # Return neutral result if validation fails
            return ValidationResult(
                is_false_positive=False,
                confidence=0.5,
                reasoning=f"Validation failed: {str(e)}"
            )
    
    def _prepare_validation_context(
        self, 
        vulnerability: Dict[str, Any], 
        contract_code: str, 
        contract_name: str
    ) -> Dict[str, Any]:
        """Prepare context for vulnerability validation."""
        
        # Extract relevant code around the vulnerability
        line_number = vulnerability.get('line_number', 0)

        # ALWAYS use full contract code for validation - no more 10-line limitation!
        # This allows the LLM to see imports, parent classes, and design comments
        context_lines = contract_code
        
        # Detect oracle type if contract uses oracles
        oracle_type = self._detect_oracle_type(contract_code)
        
        # Extract design intent from comments
        design_intent = self._extract_design_intent(contract_code, line_number)

        return {
            'vulnerability': vulnerability,
            'contract_name': contract_name,
            'vulnerability_type': vulnerability.get('vulnerability_type', 'unknown'),
            'severity': vulnerability.get('severity', 'medium'),
            'description': vulnerability.get('description', ''),
            'line_number': line_number,
            'code_context': context_lines,  # Full contract code
            'contract_code': contract_code,
            'oracle_type': oracle_type,
            'design_intent': design_intent,
            'has_code_snippet': 'code_snippet' in vulnerability
        }
    
    def _extract_code_context(self, contract_code: str, line_number: int, context_size: int = 10) -> str:
        """Extract code context around a specific line."""
        
        lines = contract_code.split('\n')
        start_line = max(0, line_number - context_size)
        end_line = min(len(lines), line_number + context_size)
        
        context_lines = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == line_number - 1 else "    "
            context_lines.append(f"{prefix}{i+1:4d}| {lines[i]}")
        
        return '\n'.join(context_lines)
    
    def _detect_oracle_type(self, contract_code: str) -> str:
        """Detect the type of oracle being used in the contract."""
        import re
        
        oracle_info = []
        
        # Check for Chainlink oracles (off-chain, flash-loan resistant)
        if re.search(r'AggregatorV3Interface|ChainlinkClient|@chainlink', contract_code, re.IGNORECASE):
            oracle_info.append("Chainlink (off-chain aggregated, resistant to flash loan manipulation)")
        
        # Check for AMM-based oracles (on-chain, vulnerable to manipulation)
        if re.search(r'IUniswapV2Pair|getReserves|UniswapV3Pool|slot0', contract_code, re.IGNORECASE):
            oracle_info.append("AMM-based (on-chain, potentially vulnerable to flash loan manipulation)")
        
        # Check for TWAP oracles
        if re.search(r'TWAP|timeWeightedAverage|observe\(', contract_code, re.IGNORECASE):
            oracle_info.append("TWAP (time-weighted average, more resistant to manipulation)")
        
        # Check for Pyth oracles
        if re.search(r'IPyth|PythStructs|updatePriceFeeds', contract_code, re.IGNORECASE):
            oracle_info.append("Pyth (off-chain, Solana-based oracle network)")
        
        # Check for custom oracles
        if re.search(r'function\s+getPrice|function\s+latestPrice', contract_code, re.IGNORECASE) and not oracle_info:
            oracle_info.append("Custom oracle implementation")
        
        if oracle_info:
            return "; ".join(oracle_info)
        else:
            return "No oracle usage detected"
    
    def _extract_design_intent(self, contract_code: str, line_number: int) -> str:
        """Extract design intent from comments near the vulnerability."""
        import re
        
        lines = contract_code.split('\n')
        design_hints = []
        
        # Search area: 30 lines before and 10 lines after the vulnerability
        search_start = max(0, line_number - 30)
        search_end = min(len(lines), line_number + 10)
        
        # Keywords that indicate intentional design
        intent_keywords = [
            r'intentional(?:ly)?',
            r'by design',
            r'disable(?:d|s)?',
            r'allow(?:s|ed)? setting .* to (?:zero|0)',
            r'can be set to (?:zero|0)',
            r'optional(?:ly)?',
            r'feature',
            r'when .*=.*0',
            r'to create',
            r'can intentionally'
        ]
        
        # Extract comments in the search area
        for i in range(search_start, search_end):
            line = lines[i]
            
            # Single-line comments
            single_comment = re.search(r'//(.*)', line)
            if single_comment:
                comment_text = single_comment.group(1).strip()
                for keyword in intent_keywords:
                    if re.search(keyword, comment_text, re.IGNORECASE):
                        design_hints.append(f"Line {i+1}: {comment_text}")
                        break
            
            # Multi-line comments and NatSpec
            multi_comment = re.search(r'/\*\*(.*?)\*/', line, re.DOTALL)
            if multi_comment:
                comment_text = multi_comment.group(1).strip()
                for keyword in intent_keywords:
                    if re.search(keyword, comment_text, re.IGNORECASE):
                        design_hints.append(f"Line {i+1}: {comment_text[:200]}...")
                        break
        
        # Also check for common patterns in the contract
        if re.search(r'set.*to (?:zero|0) to (?:disable|create)', contract_code, re.IGNORECASE):
            design_hints.append("Contract allows zero values to disable certain features")
        
        if re.search(r'SelfReferential|self-referential', contract_code, re.IGNORECASE):
            design_hints.append("Contract uses self-referential pattern (intentional design)")
        
        if design_hints:
            return "\n".join(design_hints)
        else:
            return "No explicit design intent comments found"
    
    def _create_validation_prompt(self, context: Dict[str, Any]) -> str:
        """Create validation prompt for LLM."""
        
        return f"""
You are an expert smart contract security auditor. Your task is to validate whether a reported vulnerability is a real security issue or a false positive.

CONTRACT: {context['contract_name']}
VULNERABILITY TYPE: {context['vulnerability_type']}
SEVERITY: {context['severity']}
LINE: {context['line_number']}
DESCRIPTION: {context['description']}

**ORACLE TYPE DETECTED:**
{context.get('oracle_type', 'No oracle usage detected')}

**DESIGN INTENT FROM CODE COMMENTS:**
{context.get('design_intent', 'No explicit design intent comments found')}

**FULL CONTRACT CODE:**
```solidity
{context['code_context']}
```

**CRITICAL: FALSE POSITIVE PATTERNS TO CHECK FIRST**

Before marking any vulnerability as real, check these common false positive patterns:

1. **SafeCast Integer Narrowing (SWC-101 FALSE POSITIVE)**
   - Pattern: Code uses SafeCast.toUint96(), SafeCast.toUint128(), etc.
   - Why it's safe: SafeCast INTENTIONALLY REVERTS if the value exceeds the target type's maximum
   - This is SECURE BY DESIGN - revert-on-overflow is a validated security mechanism
   - Check: Is there a maxSupply or similar cap check? That's intentional bounding.
   - VERDICT: If finding mentions SafeCast and revert behavior → LIKELY FALSE POSITIVE
   - Real vulnerability would require: Actual silent overflow (not revert) OR bypass of cap enforcement

2. **Inherited Access Control (Access Control FALSE POSITIVE)**
   - Pattern: Finding claims "privileged function missing onlyOwner" but function is inherited
   - Why it's safe: Solidity inheritance applies modifiers transitively
   - If parent contract has "onlyOwner" on mint(), the child contract inherits that protection
   - Examples: ERC20WithPermit, MisfundRecovery, OpenZeppelin Ownable/AccessControl
   - Check: Did the finding analyze the PARENT contract's access control?
   - VERDICT: If finding only checked child contract → LIKELY FALSE POSITIVE
   - Real vulnerability would require: Evidence that the function is actually callable without proper permission

3. **Type Narrowing for Storage Optimization**
   - Pattern: uint256 → uint96/uint128 narrowing with SafeCast
   - Common in: Voting contracts, checkpoints, delegation tracking
   - Why it's safe: Intentional design to enforce maximum values and save gas
   - VERDICT: If described as precision loss or overflow risk → LIKELY FALSE POSITIVE

4. **External Package Security Assumptions**
   - Pattern: @openzeppelin, @thesis, or battle-tested external package is flagged
   - Why it's safe: These are widely audited, maintained, and used by thousands of projects
   - VERDICT: Unless concrete evidence of misconfiguration → LIKELY FALSE POSITIVE

5. **Chainlink Oracle Flash Loan "Vulnerability" (FALSE POSITIVE)**
   - Pattern: Finding claims "oracle can be manipulated by flash loans"
   - Why it's safe: Chainlink oracles are OFF-CHAIN aggregators, not on-chain AMM prices
   - Flash loans only affect on-chain state within the same block
   - Chainlink prices come from multiple off-chain data providers
   - Check: Does the contract use AggregatorV3Interface or Chainlink imports?
   - VERDICT: If oracle is Chainlink → Flash loan manipulation is IMPOSSIBLE → FALSE POSITIVE
   - Real vulnerability would require: AMM-based oracle (Uniswap TWAP, etc.) OR actual oracle compromise

6. **Intentional Configuration Options (FALSE POSITIVE)**
   - Pattern: Finding claims "allows setting X to 0" as a vulnerability
   - Why it's safe: Many contracts intentionally allow zero values to disable features
   - Check: Look for comments like "intentionally", "by design", "set to zero to disable"
   - Examples: defaultThreshold=0 to create SelfReferentialCollateral
   - VERDICT: If code comments explain the intent → LIKELY FALSE POSITIVE
   - Real vulnerability would require: No documented intent + actual exploit path

Please analyze this vulnerability and determine:
1. Is this a real security vulnerability or a false positive?
2. What is your confidence level (0.0 to 1.0)?
3. Provide detailed reasoning for your decision.
4. If it's real, suggest corrected severity and description if needed.

Consider these factors:
- Is the reported vulnerability actually exploitable in practice?
- Are there proper mitigations already in place (bounds checks, reverts, access control)?
- Is this expected behavior for the contract's design (intentional revert pattern)?
- Are there any access controls or validations that prevent exploitation?
- Is this a common false positive pattern (SafeCast, inherited access control)?
- If accessing inherited functions, was parent contract's protection verified?
- **USE THE ORACLE TYPE INFO**: If Chainlink is detected, flash loan manipulation is impossible
- **USE THE DESIGN INTENT INFO**: If comments explain the behavior, it's likely intentional
- Does the full contract code show imports/inheritance that provide protections?
- Are there protective patterns (staleness checks, timeouts, price decay) in the full code?

Respond ONLY in JSON format (no extra text):
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation",
    "corrected_severity": "high/medium/low" (if different),
    "corrected_description": "improved description" (if needed)
}}
"""
    
    def _parse_validation_response(self, response: str) -> ValidationResult:
        """Parse LLM validation response."""
        
        try:
            # Try to extract JSON from response
            from .json_utils import parse_llm_json
            
            data = parse_llm_json(response, schema='fp_validation', fallback={})
            if data:
                return ValidationResult(
                    is_false_positive=data.get('is_false_positive', False),
                    confidence=float(data.get('confidence', 0.5)),
                    reasoning=data.get('reasoning', 'No reasoning provided'),
                    corrected_severity=data.get('corrected_severity'),
                    corrected_description=data.get('corrected_description')
                )
            # Fallback parsing
            is_false_positive = 'false positive' in response.lower()
            confidence = 0.5
            return ValidationResult(
                is_false_positive=is_false_positive,
                confidence=confidence,
                reasoning=response[:500]
            )
                
        except Exception as e:
            logger.error(f"Failed to parse validation response: {e}")
            return ValidationResult(
                is_false_positive=False,
                confidence=0.5,
                reasoning=f"Parse error: {str(e)}"
            )
    
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
        
        # Fix missing commas between JSON objects/arrays
        json_str = re.sub(r'}\s*{', '},{', json_str)
        json_str = re.sub(r']\s*\[', '],[', json_str)
        
        # Fix missing commas between key-value pairs
        json_str = re.sub(r'"\s*"', '","', json_str)
        
        # Fix malformed JSON by ensuring proper structure
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
        
        return json_str
    
    async def validate_with_iterative_feedback(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        contract_code: str,
        contract_name: str,
        max_iterations: int = 3
    ) -> List[Dict[str, Any]]:
        """Validate vulnerabilities with iterative LLM feedback."""
        
        current_vulnerabilities = vulnerabilities.copy()
        
        for iteration in range(max_iterations):
            logger.info(f"Iterative validation iteration {iteration + 1}/{max_iterations}")
            
            # Validate current set
            validated = await self.validate_vulnerabilities(
                current_vulnerabilities, contract_code, contract_name
            )
            
            # Check if we've converged (no changes)
            if len(validated) == len(current_vulnerabilities):
                logger.info("Validation converged, no more changes needed")
                break
            
            current_vulnerabilities = validated
        
        return current_vulnerabilities
    
    def get_validation_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary of validation results."""
        
        total = len(vulnerabilities)
        high_confidence = len([v for v in vulnerabilities if v.get('validation_confidence', 0) > 0.8])
        medium_confidence = len([v for v in vulnerabilities if 0.5 <= v.get('validation_confidence', 0) <= 0.8])
        low_confidence = len([v for v in vulnerabilities if v.get('validation_confidence', 0) < 0.5])
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_vulnerabilities': total,
            'high_confidence': high_confidence,
            'medium_confidence': medium_confidence,
            'low_confidence': low_confidence,
            'severity_distribution': severity_counts,
            'average_confidence': sum(v.get('validation_confidence', 0) for v in vulnerabilities) / total if total > 0 else 0
        }
