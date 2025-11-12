#!/usr/bin/env python3
"""
LLM-based False Positive Filter

Uses LLM to validate vulnerabilities and filter out false positives.
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from .enhanced_llm_analyzer import EnhancedLLMAnalyzer

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of LLM validation with governance awareness."""
    is_false_positive: bool
    confidence: float
    reasoning: str
    corrected_severity: Optional[str] = None
    corrected_description: Optional[str] = None
    governance_controlled: Optional[bool] = None
    has_validation: Optional[bool] = None
    attack_vector: Optional[str] = None

class LLMFalsePositiveFilter:
    """LLM-based false positive filter for vulnerability findings."""
    
    def __init__(self, llm_analyzer: Optional[EnhancedLLMAnalyzer] = None, project_path: Optional[Path] = None):
        self.llm_analyzer = llm_analyzer or EnhancedLLMAnalyzer()
        self.validation_cache = {}
        self.project_path = project_path
        
        # Initialize protocol pattern library for enhanced validation
        try:
            from core.protocol_patterns import ProtocolPatternLibrary
            self.protocol_patterns = ProtocolPatternLibrary()
        except ImportError:
            self.protocol_patterns = None
        
    async def validate_vulnerabilities(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        contract_code: str,
        contract_name: str
    ) -> List[Dict[str, Any]]:
        """Validate vulnerabilities and filter out false positives."""
        
        logger.info(f"Validating {len(vulnerabilities)} vulnerabilities with multi-stage pipeline")
        
        # Stage 0: Run validation pipeline first (fast, deterministic)
        try:
            from core.validation_pipeline import ValidationPipeline
            
            pipeline = ValidationPipeline(self.project_path, contract_code)
            pipeline_filtered = []
            
            for vuln in vulnerabilities:
                pipeline_results = pipeline.validate(vuln)
                
                # Check if any stage marked as false positive
                if any(stage.is_false_positive for stage in pipeline_results):
                    false_positive_stage = next(s for s in pipeline_results if s.is_false_positive)
                    print(f"   ✗ FILTERED by {false_positive_stage.stage_name}: {vuln.get('vulnerability_type', 'unknown')}")
                    print(f"      {false_positive_stage.reasoning}")
                    continue
                
                pipeline_filtered.append(vuln)
            
            logger.info(f"Pipeline filtered: {len(vulnerabilities)} → {len(pipeline_filtered)} vulnerabilities")
            vulnerabilities = pipeline_filtered
            
        except ImportError:
            logger.warning("Validation pipeline not available, skipping pipeline stage")
        
        # Stage 0.5: Pre-filtering with function context (NEW - saves LLM costs)
        try:
            from core.enhanced_prompts import should_pre_filter
            from core.function_context_analyzer import FunctionContextAnalyzer
            
            func_analyzer = FunctionContextAnalyzer()
            pre_filtered = []
            
            for vuln in vulnerabilities:
                # Extract function context for pre-filtering
                function_name = vuln.get('function', '')
                if function_name:
                    # Try to get function code
                    import re
                    pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{'
                    match = re.search(pattern, contract_code)
                    
                    if match:
                        # Extract minimal function signature for quick analysis
                        func_sig = contract_code[match.start():match.end() + 100]
                        context = func_analyzer.analyze_function(func_sig, function_name)
                        
                        # Check pre-filter
                        should_filter, reason = should_pre_filter(vuln, context)
                        if should_filter:
                            print(f"   ✗ PRE-FILTERED: {vuln.get('vulnerability_type', 'unknown')}")
                            print(f"      {reason}")
                            continue
                
                pre_filtered.append(vuln)
            
            logger.info(f"Pre-filtering: {len(vulnerabilities)} → {len(pre_filtered)} vulnerabilities (saved {len(vulnerabilities) - len(pre_filtered)} LLM calls)")
            vulnerabilities = pre_filtered
            
        except Exception as e:
            logger.warning(f"Pre-filtering failed: {e}, continuing with full list")
        
        logger.info(f"Validating {len(vulnerabilities)} vulnerabilities with LLM")
        
        validated_vulnerabilities = []
        # Track full validation details for reporting
        self.last_validation_details = { 'validated': [], 'filtered': [] }
        
        for i, vuln in enumerate(vulnerabilities):
            try:
                logger.debug(f"Validating vulnerability {i+1}/{len(vulnerabilities)}: {vuln.get('vulnerability_type', 'unknown')}")
                
                # Always pass FULL contract code to validation, not snippet
                vuln_contract_name = vuln.get('contract_name', contract_name)

                validation_result = await self._validate_single_vulnerability(
                    vuln, contract_code, vuln_contract_name
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
                    print(f"   ✓ REAL VULNERABILITY: {vuln.get('vulnerability_type', 'unknown')}")
                    print(f"      Confidence: {validation_result.confidence:.2f}")
                    print(f"      Is False Positive (parsed): {validation_result.is_false_positive}")
                    print(f"      Reason: {validation_result.reasoning[:200]}...")
                else:
                    print(f"   ✗ FALSE POSITIVE: {vuln.get('vulnerability_type', 'unknown')}")
                    print(f"      Confidence: {validation_result.confidence:.2f}")
                    print(f"      Is False Positive (parsed): {validation_result.is_false_positive}")
                    print(f"      Reason: {validation_result.reasoning[:200]}...")
                    filtered_entry = vuln.copy()
                    filtered_entry['validation_confidence'] = validation_result.confidence
                    filtered_entry['validation_reasoning'] = validation_result.reasoning
                    filtered_entry['status'] = 'false_positive'
                    self.last_validation_details['filtered'].append(filtered_entry)
                    
            except Exception as e:
                logger.error(f"Error validating vulnerability {i+1}: {e}")
                # Keep the vulnerability if validation fails
                validated_vulnerabilities.append(vuln)
                logger.warning(f"Kept vulnerability due to validation error")
        
        logger.info(f"LLM validation: {len(validated_vulnerabilities)}/{len(vulnerabilities)} confirmed")
        
        # Stage 2: Bug bounty relevance assessment (AFTER LLM validation)
        # This marks findings as bug-bounty-worthy but doesn't filter them
        try:
            from core.bug_bounty_relevance_validator import BugBountyRelevanceValidator
            
            logger.info("Assessing bug bounty relevance for validated findings...")
            bounty_validator = BugBountyRelevanceValidator()
            
            for vuln in validated_vulnerabilities:
                assessment = bounty_validator.validate(vuln, contract_code)
                
                # Add bug bounty assessment metadata (don't filter, just mark)
                vuln['bug_bounty_assessment'] = {
                    'is_relevant': assessment.is_relevant,
                    'relevance_level': assessment.relevance_level.value,
                    'impact_type': assessment.impact_type,
                    'exploitability_score': assessment.exploitability_score,
                    'would_qualify': assessment.would_qualify,
                    'reasoning': assessment.reasoning,
                }
                
                # Add visual marker for bug bounty worthy findings
                if assessment.is_relevant and assessment.would_qualify:
                    vuln['bug_bounty_worthy'] = True
                    print(f"   🎯 BUG BOUNTY WORTHY: {vuln.get('vulnerability_type', 'unknown')}")
                    print(f"      Impact: {assessment.impact_type}, Exploitability: {assessment.exploitability_score:.2f}")
                elif assessment.relevance_level.value == 'review':
                    vuln['bug_bounty_worthy'] = False
                    vuln['bug_bounty_needs_review'] = True
                    print(f"   ⚠️  NEEDS REVIEW: {vuln.get('vulnerability_type', 'unknown')} - {assessment.reasoning[0] if assessment.reasoning else 'Borderline case'}")
                else:
                    vuln['bug_bounty_worthy'] = False
                    if assessment.downgrade_to:
                        vuln['bug_bounty_downgrade'] = assessment.downgrade_to
            
            logger.info("Bug bounty assessment complete - all findings marked")
            
        except ImportError:
            logger.warning("Bug bounty validator not available, skipping assessment")
        except Exception as e:
            logger.warning(f"Bug bounty assessment failed: {e}, continuing without assessment")
        
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
        """Validate a single vulnerability using protocol patterns first, then LLM if needed."""
        
        # Create cache key
        cache_key = f"{vulnerability.get('vulnerability_type', '')}_{vulnerability.get('line_number', 0)}_{hash(contract_code) % 10000}"
        
        if cache_key in self.validation_cache:
            return self.validation_cache[cache_key]
        
        # Pre-validation: Check protocol patterns first (fast, deterministic)
        if self.protocol_patterns:
            logger.info(f"🔍 Checking protocol patterns for {vulnerability.get('vulnerability_type', 'unknown')}")
            pattern_result = self._check_protocol_patterns(vulnerability, contract_code)
            if pattern_result:
                # Protocol pattern found a match - mark as false positive
                logger.info(f"✓ Protocol pattern matched: {pattern_result.reasoning}")
                self.validation_cache[cache_key] = pattern_result
                return pattern_result
            else:
                logger.info(f"✗ No protocol pattern match found, proceeding to LLM validation")
        
        # Prepare context for LLM - ALWAYS use full contract code
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
            logger.debug(f"Validating with context: code={len(context.get('contract_code',''))} chars, imports={len(context.get('imports', []) or [])}")
            
            response = await self.llm_analyzer._call_llm(
                validation_prompt,
                model=validation_model  # Use configured validation model (OpenAI or Gemini)
            )
            
            result = self._parse_validation_response(response)
            logger.debug(f"Validation result: is_fp={result.is_false_positive}, confidence={result.confidence}")
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

        # Pull extended metadata from vulnerability/context if available
        vuln_ctx = vulnerability.get('context', {}) or {}
        file_path = (
            vuln_ctx.get('contract_path') or
            vuln_ctx.get('file_location') or
            vuln_ctx.get('file_path') or
            ''
        )
        pattern_match = vuln_ctx.get('pattern_match', '')
        function_context = vuln_ctx.get('function_context', '')
        surrounding_context = vuln_ctx.get('surrounding_context', '')
        swc_id = vulnerability.get('swc_id', '')
        category = vulnerability.get('category', '')
        detector_confidence = vulnerability.get('confidence', 0.0)

        # Extract imports and inheritance information from the full contract code
        imports = self._extract_imports(contract_code)
        inheritance = self._extract_inheritance(contract_code)
        
        # Attempt to resolve related imported sources if we have a base path
        base_path = file_path if file_path and os.path.isabs(file_path) else None
        related_sources = self._resolve_related_sources(contract_code, base_path)
        
        return {
            'vulnerability': vulnerability,
            'contract_name': contract_name,
            'vulnerability_type': vulnerability.get('vulnerability_type', 'unknown'),
            'severity': vulnerability.get('severity', 'medium'),
            'description': vulnerability.get('description', ''),
            'line_number': line_number,
            'code_context': context_lines,  # Full contract code
            'contract_code': contract_code,
            'code_snippet': vulnerability.get('code_snippet', ''),  # Original flagged snippet
            'oracle_type': oracle_type,
            'design_intent': design_intent,
            'has_code_snippet': 'code_snippet' in vulnerability,
            # Extended context
            'file_path': file_path,
            'pattern_match': pattern_match,
            'function_context': function_context,
            'surrounding_context': surrounding_context,
            'swc_id': swc_id,
            'category': category,
            'detector_confidence': detector_confidence,
            'imports': imports,
            'inheritance': inheritance,
            'related_sources': related_sources
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
    
    def _extract_imports(self, contract_code: str) -> List[str]:
        """Extract Solidity import statements from the contract code."""
        import re
        imports: List[str] = []
        for line in contract_code.split('\n'):
            if re.match(r'^\s*import\s+[^;]+;', line):
                imports.append(line.strip())
        return imports

    def _extract_inheritance(self, contract_code: str) -> List[str]:
        """Extract inheritance declarations from contract definitions."""
        import re
        inheritance_info: List[str] = []
        pattern = re.compile(r'contract\s+([A-Za-z0-9_]+)\s+is\s+([^\{]+)\{')
        for match in pattern.finditer(contract_code):
            contract_name = match.group(1).strip()
            bases = [b.strip() for b in match.group(2).split(',')]
            inheritance_info.append(f"{contract_name} is {', '.join(bases)}")
        return inheritance_info

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
        """Create enhanced governance-aware validation prompt for LLM."""
        
        # Detect contract architecture patterns
        architecture_analysis = self._analyze_contract_architecture(context)
        
        return f"""
You are an expert smart contract security auditor validating a potential vulnerability.

**CRITICAL VALIDATION CHECKLIST:**

1. GOVERNANCE CONTROLS
   - Is this parameter set by governance (onlyOwner, onlyGovernor, onlyGuardian, etc.)?
   - Does the setter function have validation (require checks, monotonic checks)?
   - If yes to both: This is a GOVERNANCE RISK, not a vulnerability
   - Action: Check for access control modifiers in setter functions

2. BUILT-IN PROTECTIONS
   - Does Solidity 0.8+ provide automatic protection (overflow/underflow)?
   - Are there SafeMath/SafeCast libraries used?
   - Is there a require() or if-revert before the operation?
   - If protected: Mark as FALSE POSITIVE unless unsafe operations (unchecked{{}}) are used
   - Action: Check pragma solidity version and protection patterns

3. DEPLOYMENT STATUS
   - Is this code path actually reachable in production?
   - Are there comments suggesting "not implemented" or "future feature"?
   - Does the feature appear to be dead code?
   - If unreachable: Mark as FALSE POSITIVE
   - Action: Look for deployment evidence and code usage patterns

4. CONTEXT VALIDATION
   - Look at 30 lines BEFORE the vulnerability
   - Look at the function signature for modifiers
   - Check parent contracts for inherited protections
   - Verify the issue exists in the actual code flow
   - Action: Full context analysis required

**VULNERABILITY TO VALIDATE:**

CONTRACT: {context['contract_name']}
Type: {context.get('vulnerability_type')}
Severity: {context.get('severity')}
Line: {context.get('line_number')}
Description: {context.get('description')}

**FILE INFO:**
|- Path: {context.get('file_path', 'N/A')}
|- SWC: {context.get('swc_id', 'N/A')} | Category: {context.get('category', 'N/A')}
|- Detector confidence: {context.get('detector_confidence', 0.0)}

**ARCHITECTURE ANALYSIS:**
{architecture_analysis}

**PROTOCOL-LEVEL PROTECTION CONTEXT:**
Before flagging a vulnerability, check if:
1. Off-chain observers validate the vulnerable parameters before processing
2. Contract is marked as legacy/deprecated (lower priority)
3. Multi-component security boundaries provide protection
4. Protocol-level mitigations prevent systemic exploits (but may allow user errors)

If off-chain validation prevents exploitation:
- Mark as FALSE POSITIVE for security exploit
- Note: User errors may still be possible
- Adjust severity: HIGH → MEDIUM (user error risk, not security exploit)

**ORACLE TYPE DETECTED:**
{context.get('oracle_type', 'No oracle usage detected')}

**DESIGN INTENT FROM CODE COMMENTS:**
{context.get('design_intent', 'No explicit design intent comments found')}

**CODE SNIPPET:**
```solidity
{context.get('code_snippet', 'N/A')}
```

**LOCAL CONTEXT (nearby lines):**
```solidity
{context.get('surrounding_context', 'N/A')}
```

**FUNCTION CONTEXT:**
```solidity
{context.get('function_context', 'N/A')}
```

**IMPORTS:**
{chr(10).join(context.get('imports', []) or ['N/A'])}

**INHERITANCE:**
{chr(10).join(context.get('inheritance', []) or ['N/A'])}

**RELATED SOURCES:**
{chr(10).join([f"--- {p} ---\n```solidity\n{src}\n```" for p, src in (context.get('related_sources', {}) or {}).items()]) or 'N/A'}

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

7. **Gateway-Controlled Architecture (FALSE POSITIVE) - COMMON IN MANAGED TOKEN SYSTEMS**
   - Pattern: Finding claims "owner/admin can do privileged action" (mint, transfer ownership, configure)
   - Architecture: Contract inherits from GatewayGuarded, GatewayGuardedOwnable, or similar
   - Why it's safe: The ENTIRE SYSTEM is designed around centralized gateway control
   - This is INTENTIONAL - tokens/NFTs are managed via a gateway, not decentralized
   - Check: 
     * Does contract inherit from GatewayGuarded* or similar gateway base?
     * Are privileged functions protected with onlyGateway or onlyGatewayOrOwner?
     * Is there a Gateway interface being used for these functions?
     * Are comments/NatSpec mentioning "gateway", "manager", "managed token"?
   - INDICATORS TO LOOK FOR:
     * Import statements: "import ... GatewayGuarded"
     * Inheritance: "contract X is ... GatewayGuarded..."
     * Modifiers: onlyGateway, onlyGatewayOrOwner
     * Comments: "gateway", "managed", "controlled", "manager"
   - VERDICT: If contract is architecture for centralized gateway control → LIKELY FALSE POSITIVE
   - Real vulnerability would require: Function that SHOULD be protected but ISN'T, OR unintended access path

8. **Manager Transition Grace Period (FALSE POSITIVE)**
   - Pattern: Finding claims "previous manager retains access for 24 hours after reassignment"
   - Why it's safe: This is INTENTIONAL - documented feature for safe manager transitions
   - Function context: setManagerOf() or similar manager assignment function
   - Comment pattern: "grace period", "previous manager", "transition", "retains access"
   - Real purpose: Prevents "manager locked out" scenarios, allows rollback if new manager is misconfigured
   - VERDICT: If NatSpec/comments explain this as documented feature → LIKELY FALSE POSITIVE
   - Real vulnerability would require: Grace period not actually enforced OR allowing privilege escalation

9. **Mock/Test Oracle Contracts (FALSE POSITIVE)**
   - Pattern: Finding claims "oracle price can be manipulated" on Aggregator-like contract
   - Why it's safe: Contract has updateRoundData(onlyOwner) with NO Chainlink inheritance
   - This is clearly a MOCK/TEST oracle, not production oracle
   - Check:
     * Does contract implement AggregatorV3Interface OR is it standalone?
     * Does it have updateRoundData() allowing owner to set prices?
     * Is it named "Mock*", "Test*", or "Aggregator" without Chainlink integration?
   - VERDICT: If it's a mock/test contract → Price manipulation is EXPECTED behavior → FALSE POSITIVE
   - Real vulnerability would require: Production oracle being compromised (Chainlink with proven breach)

10. **Ownership Transfer via Gateway (FALSE POSITIVE)**
    - Pattern: Finding claims "gateway can transfer contract ownership"
    - Why it's safe: This is the INTENDED DESIGN - gateway is the owner manager
    - The vulnerability assumes gateway shouldn't have this power, but gateway IS SUPPOSED to manage ownership
    - Check:
      * Function: resetOwner(address newOwner) with onlyGateway modifier
      * Is this part of owner migration/rotation flow?
      * Is gateway documented as the central control point?
    - VERDICT: If gateway is designed to manage ownership → NOT A VULNERABILITY
    - Real vulnerability would require: Unauthorized gateway access OR malicious gateway that wasn't compromised through proper channels

11. **Read-Only ERC20 Calls (FALSE POSITIVE)**
    - Pattern: Finding flags IERC20(...).balanceOf(), .allowance(), .totalSupply() as external trust issues
    - Why it's safe: These are view functions that CANNOT modify state - pure read operations
    - balanceOf(), allowance(), totalSupply(), name(), symbol(), decimals() are all view functions
    - Check: Does the finding mention "balanceOf", "allowance", "totalSupply"?
    - VERDICT: If it's a read-only ERC20 function → FALSE POSITIVE
    - Real vulnerability would require: State-modifying call OR manipulation of return values in critical calculations

12. **Access-Controlled Reentrancy (FALSE POSITIVE)**
    - Pattern: Finding flags reentrancy in function with onlyOwner/onlyRole modifier
    - Why it's less critical: Attack requires privileged access (attacker must BE the owner/role)
    - Check:
      * Does function have onlyOwner, onlyRole, onlyAdmin, or similar modifier?
      * Does finding acknowledge that attacker needs to be privileged user?
    - VERDICT: If function is access-controlled AND not handling critical flash loans/user funds → FALSE POSITIVE
    - Real vulnerability would require: Function without access control OR critical operation that can be front-run

13. **Intentional Error Suppression (FALSE POSITIVE)**
    - Pattern: Finding flags try/catch blocks that suppress errors
    - Why it's intentional: Secondary operations may intentionally fail without reverting primary operations
    - Check:
      * Are there comments explaining intent? ("if X fails, we don't want to revert Y")
      * Is suppressed operation secondary to a primary operation?
      * Does comment mention "graceful failure", "don't want to revert", "intentionally"?
    - Example: "// if liquidation fails, we don't want to revert the made challenge"
    - VERDICT: If there's documented intent explaining why errors should be suppressed → LIKELY FALSE POSITIVE
    - Real vulnerability would require: Suppression of critical errors without documented intent OR actual fund loss risk

14. **Flash Loan Configuration (FALSE POSITIVE)**
    - Pattern: Finding flags flash loan "vulnerability" on variable assignment
    - Why it's not vulnerable: Setting configuration (_config.flashLender = flashLender) is not executing a flash loan
    - Check:
      * Is it actual flashLoan() call or just assignment?
      * Pattern: _config.flashLender = ... vs flashLoan(...)
    - VERDICT: If it's just variable assignment/configuration → FALSE POSITIVE
    - Real vulnerability would require: Actual flash loan execution with exploitable logic

15. **Standard OpenZeppelin Proxy Patterns (FALSE POSITIVE)**
    - Pattern: Finding flags upgradeability, admin controls, or delegatecall in proxy constructors
    - Why it's safe: OpenZeppelin proxies (ERC1967Proxy, TransparentUpgradeableProxy, BeaconProxy) are battle-tested standards
    - Check:
      * Does contract import from @openzeppelin/contracts/proxy/?
      * Is it ERC1967Proxy, TransparentUpgradeableProxy, or BeaconProxy?
      * Is the "vulnerability" in the proxy library itself or in contract using it?
      * Does finding reference line numbers in OpenZeppelin library code?
    - Common false positive descriptions:
      * "admin can upgrade the proxy" → That's the DESIGN of upgradeable proxies
      * "delegatecall in constructor with arbitrary data" → Standard proxy initialization, only runs ONCE
      * "EOA controls ProxyAdmin" → Deployment decision, not code bug
      * "implementation could overwrite storage slots" → Trust assumption of upgrade pattern
    - VERDICT: If it's standard OpenZeppelin proxy code → FALSE POSITIVE
    - Real vulnerability would require: Actual bug in how proxy is USED, not in proxy pattern itself

16. **Deployment-Time Configuration vs Runtime Exploit (FALSE POSITIVE)**
    - Pattern: Finding claims vulnerability in constructor or initialization that accepts parameters
    - Why it's not exploitable: Constructor runs ONCE during deployment under deployer control
    - Check:
      * Is the flagged code in a constructor or initialize() function?
      * Can this code path be called after deployment?
      * Does exploit require malicious deployer?
    - Examples:
      * "Constructor accepts arbitrary data for delegatecall" → Deployer controls this
      * "initialOwner can be set to malicious address" → Deployer decision
    - VERDICT: If it only executes during deployment → FALSE POSITIVE (governance concern, not exploit)
    - Real vulnerability would require: Post-deployment exploit path

17. **Centralization vs Vulnerability (FALSE POSITIVE)**  
    - Pattern: Finding claims "admin/owner can do X" as a vulnerability
    - Why it's not a vulnerability: Centralization is a DESIGN CHOICE, not a code bug
    - Check:
      * Is the concern about WHO has power (EOA vs multisig)?
      * Is the code functioning correctly for its design?
      * Would using a multisig address as owner "fix" the issue?
    - Examples:
      * "Admin key held by EOA could be compromised" → Deployment choice
      * "Owner can upgrade to malicious implementation" → Inherent to upgradeable design
    - VERDICT: If it's about deployment parameters or governance model → FALSE POSITIVE (centralization risk)
    - Real vulnerability would require: Code that allows unauthorized escalation or bypass of admin

**OUTPUT FORMAT (JSON):**

Respond ONLY in valid JSON format with these fields:

{{
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "Clear explanation with specific code references",
  "actual_severity": "critical/high/medium/low/info" or null,
  "governance_controlled": true/false,
  "has_validation": true/false,
  "attack_vector": "Specific attack steps" or null,
  "corrected_severity": "high/medium/low" (if different from original),
  "corrected_description": "improved description" (if needed)
}}

**IMPORTANT VALIDATION RULES:**
- If governance-controlled (onlyOwner/onlyGovernor + validation): Mark as FALSE POSITIVE
- If protected by Solidity 0.8+ without unchecked{{}}: Mark as FALSE POSITIVE
- If no concrete attack vector exists: Mark as FALSE POSITIVE
- If SafeCast with intentional revert: Mark as FALSE POSITIVE
- If Chainlink oracle + flash loan claim: Mark as FALSE POSITIVE
- If gateway-controlled architecture + centralized control claim: Mark as FALSE POSITIVE
- If standard OpenZeppelin proxy pattern: Mark as FALSE POSITIVE
- If deployment-time only issue (constructor/initialize): Mark as FALSE POSITIVE
- If centralization concern (EOA vs multisig choice): Mark as FALSE POSITIVE

**CONTEXT TO USE:**
|- Oracle type detected: {context.get('oracle_type', 'N/A')}
|- Design intent: {context.get('design_intent', 'N/A')}
|- Architecture: Gateway-controlled or decentralized?
|- Imports/Inheritance: Check for inherited protections
|- Full contract: Look for protective patterns

Be STRICT: Only mark as REAL if you can describe exact exploitation steps.
"""

    def _analyze_contract_architecture(self, context: Dict[str, Any]) -> str:
        """Analyze contract architecture to detect gateway systems and managed tokens."""
        import re
        
        contract_code = context.get('contract_code', '')
        inheritance = context.get('inheritance', [])
        imports = context.get('imports', [])
        
        findings = []
        
        # NEW: Check for protocol-level protections
        try:
            from core.protocol_protection_detector import ProtocolProtectionDetector
            
            # Get project root from context if available
            file_path = context.get('file_path', '')
            project_root = None
            if file_path:
                from pathlib import Path
                project_root = Path(file_path).parent
                # Try to find project root
                for _ in range(5):
                    if (project_root / 'package.json').exists() or (project_root / 'foundry.toml').exists():
                        break
                    parent = project_root.parent
                    if parent == project_root:
                        break
                    project_root = parent
            
            if project_root:
                detector = ProtocolProtectionDetector(enabled=True)
                architecture = detector.analyze_architecture(
                    contract_code=contract_code,
                    project_root=project_root
                )
                
                if architecture:
                    # Check for off-chain components
                    observers = detector.find_observers(project_root)
                    if observers:
                        findings.append("🔵 **OFF-CHAIN OBSERVER COMPONENTS DETECTED**")
                        findings.append(f"   - Found {len(observers)} observer/validator component(s)")
                        for obs in observers[:3]:  # Show first 3
                            findings.append(f"   - {obs.name} ({obs.language})")
                            if obs.validation_functions:
                                findings.append(f"     Validates: {', '.join(obs.validation_functions[:2])}")
                        findings.append("   - Implication: Contract may have off-chain validation")
                        findings.append("   - Action: Check if observer validates vulnerable parameters")
                    
                    # Check for security boundaries
                    if architecture.security_boundaries:
                        findings.append("🔵 **SECURITY BOUNDARIES DETECTED**")
                        for boundary in architecture.security_boundaries[:2]:
                            findings.append(f"   - {boundary.boundary_name}: {boundary.description}")
        except Exception:
            # Fail silently to not break existing functionality
            pass
        
        # Check for gateway patterns
        if any('Gateway' in inh for inh in inheritance):
            findings.append("🔴 **GATEWAY-CONTROLLED ARCHITECTURE DETECTED**")
            findings.append("   - Contract inherits from GatewayGuarded, GatewayGuardedOwnable, or similar")
            findings.append("   - This means: Access control is CENTRALIZED via gateway by design")
            findings.append("   - Implication: 'Admin can do X' findings are likely FALSE POSITIVES")
        
        # Check for managed token patterns
        if any('ERC20' in inh or 'ERC721' in inh or 'ERC1155' in inh for inh in inheritance):
            if any('Gateway' in inh for inh in inheritance):
                findings.append("🟡 **MANAGED TOKEN SYSTEM**")
                findings.append("   - Token inherits from both ERC* and Gateway*")
                findings.append("   - This is a CENTRALIZED token system (not decentralized DeFi)")
        
        # Check for onlyGateway or onlyGatewayOrOwner modifiers
        if 'onlyGateway' in contract_code or 'onlyGatewayOrOwner' in contract_code:
            findings.append("🟡 **GATEWAY ACCESS CONTROL MODIFIERS FOUND**")
            findings.append("   - Functions use onlyGateway or onlyGatewayOrOwner modifiers")
            findings.append("   - These functions are PROTECTED by design - not exploitable by end users")
        
        # Check for grace period patterns
        if 'grace' in contract_code.lower() or 'previous.*manager' in contract_code.lower():
            findings.append("🟡 **GRACE PERIOD / TRANSITION FEATURE DETECTED**")
            findings.append("   - Contract implements manager/ownership grace periods")
            findings.append("   - This is INTENTIONAL for safe transitions")
        
        # Check for mock oracle patterns
        if 'updateRoundData' in contract_code and 'Aggregator' in context.get('contract_name', ''):
            if 'ChainLink' not in imports and 'AggregatorV3Interface' not in contract_code:
                findings.append("🔴 **MOCK/TEST ORACLE DETECTED**")
                findings.append("   - Contract has updateRoundData() but no Chainlink integration")
                findings.append("   - This is a test/mock oracle, not production")
                findings.append("   - Price manipulation is EXPECTED in test environments")
        
        # Check for Chainlink oracles
        if any('Chainlink' in imp or 'AggregatorV3Interface' in imp for imp in imports):
            findings.append("✅ **CHAINLINK ORACLE DETECTED**")
            findings.append("   - Contract uses Chainlink off-chain aggregators")
            findings.append("   - Chainlink is IMMUNE to flash loan attacks")
            findings.append("   - Any 'flash loan oracle manipulation' findings are likely FALSE POSITIVES")
        
        if not findings:
            findings.append("ℹ️  No special architecture patterns detected - analyze as standard contract")
        
        return "\n".join(findings)
    
    def _clean_reasoning_text(self, reasoning: str) -> str:
        """Clean reasoning text to remove JSON formatting and markdown code fences."""
        import re
        if not reasoning:
            return 'No reasoning provided'
        
        # Remove markdown code fences (```json, ```, etc.)
        reasoning = re.sub(r'```(?:json)?\s*', '', reasoning)
        reasoning = re.sub(r'```\s*$', '', reasoning)
        reasoning = reasoning.strip()
        
        # If reasoning contains a JSON object, try to extract just the reasoning field from it
        # This handles cases where the LLM returns the full JSON in the reasoning field
        json_match = re.search(r'\{[\s\S]*"reasoning"\s*:\s*"([^"]+)"[\s\S]*\}', reasoning)
        if json_match:
            # Extract the actual reasoning text from nested JSON
            reasoning = json_match.group(1)
        else:
            # Remove any JSON-like structures that might be embedded
            # Keep only the text content, not the JSON structure
            reasoning = re.sub(r'\{"is_false_positive"\s*:\s*(?:true|false)[^}]*\}', '', reasoning)
            reasoning = re.sub(r'"is_false_positive"\s*:\s*(?:true|false)[,\s]*', '', reasoning)
            reasoning = re.sub(r'"confidence"\s*:\s*[\d.]+[,\s]*', '', reasoning)
        
        return reasoning.strip() or 'No reasoning provided'
    
    def _parse_validation_response(self, response: str) -> ValidationResult:
        """Parse LLM validation response with governance-aware fields."""
        
        try:
            # Try to extract JSON from response
            from .json_utils import parse_llm_json
            
            data = parse_llm_json(response, schema='fp_validation', fallback={})
            if data:
                # Extract and clean the reasoning field
                raw_reasoning = data.get('reasoning', 'No reasoning provided')
                cleaned_reasoning = self._clean_reasoning_text(raw_reasoning)
                
                # Get the actual is_false_positive value (ensure it's a boolean)
                is_fp = data.get('is_false_positive', False)
                if isinstance(is_fp, str):
                    # Handle string booleans
                    is_fp = is_fp.lower() in ('true', '1', 'yes')
                elif not isinstance(is_fp, bool):
                    is_fp = bool(is_fp)
                
                return ValidationResult(
                    is_false_positive=is_fp,
                    confidence=float(data.get('confidence', 0.5)),
                    reasoning=cleaned_reasoning,
                    corrected_severity=data.get('corrected_severity'),
                    corrected_description=data.get('corrected_description'),
                    governance_controlled=data.get('governance_controlled'),
                    has_validation=data.get('has_validation'),
                    attack_vector=data.get('attack_vector')
                )
            # Fallback parsing
            is_false_positive = 'false positive' in response.lower()
            confidence = 0.5
            cleaned_reasoning = self._clean_reasoning_text(response[:500])
            return ValidationResult(
                is_false_positive=is_false_positive,
                confidence=confidence,
                reasoning=cleaned_reasoning
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

    def _resolve_related_sources(self, contract_code: str, base_path: Optional[str]) -> Dict[str, str]:
        """
        Attempt to resolve imported Solidity files, protocol documentation, and related contracts.
        Returns a map of path -> content. Best-effort only.
        
        Enhancements:
        1. Resolves imported Solidity files
        2. Discovers protocol documentation (README.md, bug-bounty.md, SECURITY.md)
        3. Finds related library files mentioned in comments
        4. Discovers interface files
        """
        import re
        from pathlib import Path as PathLib
        
        related: Dict[str, str] = {}
        
        # Strategy 1: Resolve imported Solidity files
        for m in re.finditer(r"import\s+['\"]([^'\"]+)['\"]\s*;", contract_code):
            imp = m.group(1).strip()
            
            # Try to resolve package imports from common locations
            if imp.startswith('@'):
                # Try common package locations
                package_locations = [
                    'node_modules',
                    'lib',
                    '../node_modules',
                    '../../node_modules',
                ]
                if base_path:
                    for pkg_loc in package_locations:
                        pkg_path = os.path.join(os.path.dirname(base_path), pkg_loc, imp[1:])  # Remove '@'
                        if os.path.exists(pkg_path) and os.path.isfile(pkg_path):
                            try:
                                with open(pkg_path, 'r') as f:
                                    related[pkg_path] = f.read()
                                    break
                            except Exception:
                                continue
                continue
            
            # Try relative to base_path, then cwd
            candidates = []
            if base_path:
                candidates.append(os.path.join(os.path.dirname(base_path), imp))
            candidates.append(os.path.abspath(imp))
            
            for c in candidates:
                try:
                    if os.path.exists(c) and os.path.isfile(c) and c.endswith('.sol'):
                        with open(c, 'r') as f:
                            related[c] = f.read()
                            break
                except Exception:
                    continue
        
        # Strategy 2: Discover protocol documentation files
        if base_path:
            project_root = self._find_project_root(base_path)
            if project_root:
                doc_files = [
                    'README.md',
                    'SECURITY.md',
                    'bug-bounty.md',
                    'BUG_BOUNTY.md',
                    'AUDIT.md',
                    'docs/README.md',
                    'docs/SECURITY.md',
                ]
                
                for doc_file in doc_files:
                    doc_path = os.path.join(project_root, doc_file)
                    if os.path.exists(doc_path) and os.path.isfile(doc_path):
                        try:
                            with open(doc_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                # Only include if it mentions relevant security/design info
                                if any(keyword in content.lower() for keyword in [
                                    'overflow', 'underflow', 'security', 'assumption',
                                    'design', 'intentional', 'acceptable', 'known issue'
                                ]):
                                    related[doc_path] = content[:5000]  # Limit to 5K chars
                        except Exception:
                            continue
        
        # Strategy 3: Discover related library files mentioned in comments
        # Look for patterns like "See Position.sol", "documented in Tick.sol", etc.
        referenced_files = re.findall(
            r'(?:see|documented in|refer to|defined in)\s+([A-Z][a-zA-Z0-9_]+\.sol)',
            contract_code,
            re.IGNORECASE
        )
        
        if base_path and referenced_files:
            contract_dir = os.path.dirname(base_path)
            for ref_file in set(referenced_files):
                # Search in common locations
                search_locations = [
                    os.path.join(contract_dir, ref_file),
                    os.path.join(contract_dir, 'libraries', ref_file),
                    os.path.join(contract_dir, '..', 'libraries', ref_file),
                    os.path.join(contract_dir, 'interfaces', ref_file),
                ]
                
                for loc in search_locations:
                    if os.path.exists(loc) and os.path.isfile(loc):
                        try:
                            with open(loc, 'r') as f:
                                related[loc] = f.read()
                                break
                        except Exception:
                            continue
        
        # Strategy 4: Discover interface files
        # Look for interface names in the code and try to find their definitions
        interface_patterns = re.findall(r'interface\s+([A-Z][a-zA-Z0-9_]+)', contract_code)
        if base_path and interface_patterns:
            contract_dir = os.path.dirname(base_path)
            for interface_name in set(interface_patterns):
                interface_file = f"{interface_name}.sol"
                search_locations = [
                    os.path.join(contract_dir, 'interfaces', interface_file),
                    os.path.join(contract_dir, '..', 'interfaces', interface_file),
                    os.path.join(contract_dir, interface_file),
                ]
                
                for loc in search_locations:
                    if os.path.exists(loc) and os.path.isfile(loc):
                        try:
                            with open(loc, 'r') as f:
                                related[loc] = f.read()
                                break
                        except Exception:
                            continue
        
        return related
    
    def _find_project_root(self, file_path: str) -> Optional[str]:
        """
        Find the project root directory by looking for common markers.
        Returns the root directory path or None.
        """
        current_dir = os.path.dirname(os.path.abspath(file_path))
        
        # Markers that indicate project root
        root_markers = [
            'package.json',
            'hardhat.config.js',
            'hardhat.config.ts',
            'foundry.toml',
            'truffle-config.js',
            '.git',
            'contracts',  # Directory
        ]
        
        # Walk up the directory tree
        max_levels = 5
        for _ in range(max_levels):
            # Check if any marker exists in current directory
            for marker in root_markers:
                marker_path = os.path.join(current_dir, marker)
                if os.path.exists(marker_path):
                    return current_dir
            
            # Move up one level
            parent_dir = os.path.dirname(current_dir)
            if parent_dir == current_dir:  # Reached filesystem root
                break
            current_dir = parent_dir
        
        return None
    
    def _check_protocol_patterns(
        self, 
        vulnerability: Dict[str, Any], 
        contract_code: str
    ) -> Optional[ValidationResult]:
        """
        Check if vulnerability matches known protocol-specific false positive patterns.
        Returns ValidationResult if it's a false positive, None otherwise.
        """
        if not self.protocol_patterns:
            return None
        
        vuln_type = vulnerability.get('vulnerability_type', vulnerability.get('type', ''))
        logger.debug(f"  Vulnerability type: {vuln_type}")
        
        # Build context for pattern matching
        context = {
            'file_path': vulnerability.get('context', {}).get('file_path', ''),
            'code_snippet': vulnerability.get('code_snippet', ''),
            'surrounding_context': contract_code,
            'function_context': vulnerability.get('context', {}).get('function_context', ''),
            'line_number': vulnerability.get('line_number', 0),
        }
        logger.debug(f"  Context file_path: {context['file_path']}")
        logger.debug(f"  Code snippet length: {len(context['code_snippet'])} chars")
        
        # Check if it matches a protocol pattern
        pattern = self.protocol_patterns.check_pattern_match(
            vuln_type, contract_code, context
        )
        
        if pattern:
            logger.debug(f"  Pattern found: {pattern.reason}")
        else:
            logger.debug(f"  No pattern matched for vulnerability type: {vuln_type}")
        
        if pattern and pattern.acceptable_behavior:
            # Check Solidity version compatibility if specified
            if pattern.solidity_version_specific:
                version = self.protocol_patterns.extract_solidity_version(contract_code)
                if version and not self.protocol_patterns.check_solidity_version_compatibility(pattern, version):
                    # Version mismatch - not a false positive
                    return None
            
            # This is a known false positive pattern
            return ValidationResult(
                is_false_positive=True,
                confidence=0.95,  # High confidence for protocol patterns
                reasoning=f"Matched protocol pattern: {pattern.reason}",
                corrected_severity=None,
                corrected_description=None
            )
        
        return None
