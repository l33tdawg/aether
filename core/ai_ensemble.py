"""
Enhanced AI Ensemble Module for AetherAudit
Implements specialized GPT-5-mini agents with learning capabilities using SQLite datastore
"""

import asyncio
import json
import sqlite3
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import logging
import hashlib

from core.database_manager import DatabaseManager, LearningPattern, AuditMetrics
from core.config_manager import ConfigManager

logger = logging.getLogger(__name__)

@dataclass
class ModelResult:
    """Result from a single AI model"""
    model_name: str
    findings: List[Dict[str, Any]]
    confidence: float
    processing_time: float
    metadata: Dict[str, Any]

@dataclass
class ConsensusResult:
    """Consensus result from multiple models"""
    consensus_findings: List[Dict[str, Any]]
    model_agreement: float
    confidence_score: float
    processing_time: float
    individual_results: List[ModelResult]

class BaseAIModel:
    """Base class for specialized AI agents"""

    def __init__(self, agent_name: str, role: str, focus_areas: List[str], confidence_weight: float = 1.0):
        self.agent_name = agent_name
        self.role = role
        self.focus_areas = focus_areas
        self.confidence_weight = confidence_weight
        self.db_manager = DatabaseManager()
        self.config = ConfigManager()
    
    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract and return results with learning integration"""
        raise NotImplementedError
    
    def get_focus_areas(self) -> List[str]:
        """Get agent's focus areas"""
        return self.focus_areas

    def _get_persona_prompt(self) -> str:
        """Get the persona-specific system prompt"""
        raise NotImplementedError

    def _apply_learning_patterns(self, contract_content: str) -> Dict[str, Any]:
        """Apply learned patterns from database to improve analysis"""
        try:
            # Get relevant learning patterns for this agent's focus areas
            context_enhancements = {
                'learned_patterns': [],
                'confidence_adjustments': {},
                'focus_areas': self.focus_areas
            }

            for focus_area in self.focus_areas:
                patterns = self.db_manager.get_learning_patterns(pattern_type=focus_area)
                for pattern in patterns:
                    if pattern.get('success_rate', 0) > 0.7:  # Only use high-confidence patterns
                        context_enhancements['learned_patterns'].append({
                            'type': pattern.get('pattern_type', ''),
                            'original': pattern.get('original_classification', ''),
                            'corrected': pattern.get('corrected_classification', ''),
                            'confidence_threshold': pattern.get('confidence_threshold', 0.8),
                            'reasoning': pattern.get('reasoning', '')
                        })

            return context_enhancements
        except Exception as e:
            logger.warning(f"Failed to apply learning patterns: {e}")
            return {'learned_patterns': [], 'confidence_adjustments': {}, 'focus_areas': self.focus_areas}

    def _store_analysis_result(self, result: ModelResult, contract_hash: str):
        """Store analysis result for learning"""
        try:
            # Store metrics for this analysis
            metrics = AuditMetrics(
                id=f"ensemble_{self.agent_name}_{int(time.time())}",
                audit_result_id=contract_hash,
                total_findings=len(result.findings),
                confirmed_findings=0,  # Will be updated later
                false_positives=0,
                accuracy_score=result.confidence,
                precision_score=0.0,
                recall_score=0.0,
                f1_score=0.0,
                execution_time=result.processing_time,
                llm_calls=1,
                cache_hits=0,
                created_at=time.time()
            )

            self.db_manager.store_audit_metrics(metrics)
        except Exception as e:
            logger.warning(f"Failed to store analysis result: {e}")


class DeFiSecurityExpert(BaseAIModel):
    """DeFi Protocol Security Expert - Focuses on DeFi-specific vulnerabilities"""

    def __init__(self):
        super().__init__(
            agent_name="defi_expert",
            role="DeFi Protocol Security Expert",
            focus_areas=["defi", "flash_loans", "yield_farming", "dex", "lending", "staking"]
        )

    def _get_persona_prompt(self) -> str:
        return """You are a **DeFi Protocol Security Expert** with deep expertise in decentralized finance vulnerabilities.

**Your Mission:** Identify DeFi-specific security risks that could lead to fund losses or protocol exploits.

**Focus Areas:**
- **Flash Loan Attacks**: Complex multi-step attacks using flash loans
- **Yield Farming Exploits**: Manipulation of reward distribution and staking mechanisms
- **DEX Vulnerabilities**: Price oracle manipulation, front-running, sandwich attacks
- **Lending Protocol Risks**: Liquidation manipulation, oracle failures, governance attacks
- **Staking Contract Issues**: Reward calculation errors, withdrawal vulnerabilities

**Analysis Approach:**
1. **Pattern Recognition**: Look for DeFi-specific attack patterns and anti-patterns
2. **Economic Analysis**: Consider incentive structures and economic attack vectors
3. **Protocol Integration**: Analyze how this contract interacts with other DeFi protocols
4. **Governance Risks**: Check for admin key management and upgrade mechanism security

**Output Format:** JSON array of findings with DeFi-specific context"""

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract from DeFi security perspective"""
        start_time = time.time()

        try:
            # Apply learning patterns
            learning_context = self._apply_learning_patterns(contract_content)

            # Create contract hash for tracking
            contract_hash = hashlib.md5(contract_content.encode()).hexdigest()

            # Build specialized prompt
            prompt = f"""
{self._get_persona_prompt()}

**CONTRACT TO ANALYZE:**
```solidity
{contract_content[:40000]}  # Limit for API constraints
```

**LEARNING CONTEXT:**
{json.dumps(learning_context, indent=2)}

**REQUIRED OUTPUT:**
Return a JSON array of vulnerabilities found. Each finding should include:
- type: Specific vulnerability type (e.g., "flash_loan_arbitrage", "oracle_manipulation")
- severity: "low" | "medium" | "high" | "critical"
- confidence: 0.0-1.0 (how certain you are about this finding)
- description: Detailed explanation of the vulnerability
- line: Approximate line number (or -1 if unclear)
- swc_id: Relevant SWC ID if applicable
- exploit_scenario: How an attacker could exploit this
- defi_impact: Potential financial impact on users/protocol
- mitigation: How to fix this issue

Focus on DeFi-specific issues and real-world exploit scenarios.
"""

            # Get OpenAI API key - check multiple sources for robustness
            import os
            api_key = os.getenv("OPENAI_API_KEY")  # First check environment variable
            
            if not api_key:
                # Fall back to config manager
                api_key = self.config.config.openai_api_key
            
            if not api_key:
                raise Exception("OpenAI API key not found in environment (OPENAI_API_KEY) or config file (~/.aether/config.yaml)")

            # Call GPT-4o-mini
            import openai
            client = openai.OpenAI(api_key=api_key)

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self._get_persona_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )

            # Parse response
            response_text = response.choices[0].message.content
            findings = self._parse_defi_findings(response_text)

            processing_time = time.time() - start_time

            result = ModelResult(
                model_name=self.agent_name,
                findings=findings,
                confidence=0.85,
                processing_time=processing_time,
                metadata={
                    "role": self.role,
                    "focus_areas": self.focus_areas,
                    "learning_patterns_applied": len(learning_context.get('learned_patterns', [])),
                    "contract_hash": contract_hash
                }
            )

            # Store result for learning
            self._store_analysis_result(result, contract_hash)

            return result

        except Exception as e:
            logger.error(f"DeFi Expert failed: {e}")
            processing_time = time.time() - start_time

            return ModelResult(
                model_name=self.agent_name,
                findings=[],
                confidence=0.0,
                processing_time=processing_time,
                metadata={"error": str(e), "role": self.role}
            )

    def _parse_defi_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse DeFi-specific findings from LLM response"""
        try:
            # Try to extract JSON array
            import re
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                findings = json.loads(json_match.group())
                if isinstance(findings, list):
                    return findings

            return []
        except Exception as e:
            logger.error(f"Failed to parse DeFi findings: {e}")
            return []


class GasOptimizationExpert(BaseAIModel):
    """Gas Optimization Expert - Focuses on gas efficiency and optimization opportunities"""

    def __init__(self):
        super().__init__(
            agent_name="gas_expert",
            role="Gas Optimization Expert",
            focus_areas=["gas_optimization", "efficiency", "storage", "computation"]
        )

    def _get_persona_prompt(self) -> str:
        return """You are a **Gas Optimization Expert** specializing in Ethereum gas efficiency and smart contract optimization.

**Your Mission:** Identify gas inefficiencies and optimization opportunities that can reduce transaction costs and improve contract performance.

**Focus Areas:**
- **Storage Optimization**: Expensive SLOAD/SSTORE operations, struct packing
- **Computation Efficiency**: Loop optimization, unnecessary calculations
- **Function Optimization**: Batch operations, view vs pure functions
- **Memory Management**: Memory vs storage usage, calldata optimization
- **Event Optimization**: Event emission efficiency

**Analysis Approach:**
1. **Gas Cost Analysis**: Calculate potential gas savings for each optimization
2. **Trade-off Evaluation**: Balance gas savings vs code complexity/readability
3. **Upgrade Compatibility**: Ensure optimizations don't break existing functionality
4. **Batch Processing**: Identify opportunities for batching operations

**Output Format:** JSON array of gas optimization opportunities"""

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract for gas optimization opportunities"""
        start_time = time.time()

        try:
            learning_context = self._apply_learning_patterns(contract_content)
            contract_hash = hashlib.md5(contract_content.encode()).hexdigest()

            prompt = f"""
{self._get_persona_prompt()}

**CONTRACT TO ANALYZE:**
```solidity
{contract_content[:40000]}
```

**LEARNING CONTEXT:**
{json.dumps(learning_context, indent=2)}

**REQUIRED OUTPUT:**
Return a JSON array of gas optimization opportunities. Each optimization should include:
- type: "gas_optimization"
- severity: "low" | "medium" | "high" (based on potential savings)
- confidence: 0.0-1.0
- description: What can be optimized
- line: Line number where optimization applies
- gas_savings_estimate: Estimated gas savings per call
- implementation_complexity: "low" | "medium" | "high"
- optimization_details: Technical details of the optimization
- code_suggestion: Suggested code changes

Focus on high-impact optimizations that provide significant gas savings.
"""

            # Get OpenAI API key - check multiple sources for robustness
            import os
            api_key = os.getenv("OPENAI_API_KEY")  # First check environment variable
            
            if not api_key:
                # Fall back to config manager
                api_key = self.config.config.openai_api_key
            
            if not api_key:
                raise Exception("OpenAI API key not found in environment (OPENAI_API_KEY) or config file (~/.aether/config.yaml)")

            import openai
            client = openai.OpenAI(api_key=api_key)

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self._get_persona_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )

            response_text = response.choices[0].message.content
            findings = self._parse_gas_findings(response_text)

            processing_time = time.time() - start_time

            result = ModelResult(
                model_name=self.agent_name,
                findings=findings,
                confidence=0.85,
                processing_time=processing_time,
                metadata={
                    "role": self.role,
                    "focus_areas": self.focus_areas,
                    "learning_patterns_applied": len(learning_context.get('learned_patterns', [])),
                    "contract_hash": contract_hash
                }
            )

            self._store_analysis_result(result, contract_hash)
            return result

        except Exception as e:
            logger.error(f"Gas Expert failed: {e}")
            processing_time = time.time() - start_time

            return ModelResult(
                model_name=self.agent_name,
                findings=[],
                confidence=0.0,
                processing_time=processing_time,
                metadata={"error": str(e), "role": self.role}
            )

    def _parse_gas_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse gas optimization findings from LLM response"""
        try:
            import re
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                findings = json.loads(json_match.group())
                if isinstance(findings, list):
                    return findings

            return []
        except Exception as e:
            logger.error(f"Failed to parse gas findings: {e}")
            return []


class SecurityBestPracticesExpert(BaseAIModel):
    """Security Best Practices Expert - Focuses on code quality and security standards"""

    def __init__(self):
        super().__init__(
            agent_name="best_practices_expert",
            role="Security Best Practices Expert",
            focus_areas=["code_quality", "security_standards", "access_control", "input_validation"]
        )

    def _get_persona_prompt(self) -> str:
        return """You are a **Security Best Practices Expert** focused on code quality, security standards, and development best practices.

**Your Mission:** Identify code quality issues, security anti-patterns, and deviations from established best practices.

**Focus Areas:**
- **Access Control**: Proper authorization, role-based access, ownership patterns
- **Input Validation**: Parameter validation, bounds checking, sanitization
- **Error Handling**: Proper error handling, fail-safe defaults, graceful degradation
- **Code Quality**: Readability, maintainability, documentation, testing
- **Security Standards**: Compliance with security best practices and standards

**Analysis Approach:**
1. **Standards Compliance**: Check against established security standards (SWC, best practices)
2. **Code Review**: Analyze code structure, patterns, and maintainability
3. **Security Anti-patterns**: Identify common security mistakes and bad practices
4. **Documentation**: Check for proper documentation and comments

**Output Format:** JSON array of best practice violations and recommendations"""

    async def analyze_contract(self, contract_content: str, contract_path: str = "", context: Dict[str, Any] = None) -> ModelResult:
        """Analyze contract for security best practices"""
        start_time = time.time()

        try:
            learning_context = self._apply_learning_patterns(contract_content)
            contract_hash = hashlib.md5(contract_content.encode()).hexdigest()

            prompt = f"""
{self._get_persona_prompt()}

**CONTRACT TO ANALYZE:**
```solidity
{contract_content[:40000]}
```

**LEARNING CONTEXT:**
{json.dumps(learning_context, indent=2)}

**REQUIRED OUTPUT:**
Return a JSON array of best practice issues. Each finding should include:
- type: "best_practice_violation"
- severity: "low" | "medium" | "high" | "info"
- confidence: 0.0-1.0
- description: What best practice is being violated
- line: Line number where issue occurs
- standard: Relevant standard (SWC-XXX, best practice name)
- impact: Why this matters for security/maintainability
- recommendation: How to fix or improve

Focus on actionable improvements that enhance security and maintainability.
"""

            # Get OpenAI API key - check multiple sources for robustness
            import os
            api_key = os.getenv("OPENAI_API_KEY")  # First check environment variable
            
            if not api_key:
                # Fall back to config manager
                api_key = self.config.config.openai_api_key
            
            if not api_key:
                raise Exception("OpenAI API key not found in environment (OPENAI_API_KEY) or config file (~/.aether/config.yaml)")

            import openai
            client = openai.OpenAI(api_key=api_key)

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self._get_persona_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )

            response_text = response.choices[0].message.content
            findings = self._parse_best_practices_findings(response_text)

            processing_time = time.time() - start_time

            result = ModelResult(
                model_name=self.agent_name,
                findings=findings,
                confidence=0.85,
                processing_time=processing_time,
                metadata={
                    "role": self.role,
                    "focus_areas": self.focus_areas,
                    "learning_patterns_applied": len(learning_context.get('learned_patterns', [])),
                    "contract_hash": contract_hash
                }
            )

            self._store_analysis_result(result, contract_hash)
            return result

        except Exception as e:
            logger.error(f"Best Practices Expert failed: {e}")
            processing_time = time.time() - start_time

            return ModelResult(
                model_name=self.agent_name,
                findings=[],
                confidence=0.0,
                processing_time=processing_time,
                metadata={"error": str(e), "role": self.role}
            )

    def _parse_best_practices_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse best practices findings from LLM response"""
        try:
            import re
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                findings = json.loads(json_match.group())
                if isinstance(findings, list):
                    return findings

            return []
        except Exception as e:
            logger.error(f"Failed to parse best practices findings: {e}")
            return []

class EnhancedAIEnsemble:
    """Enhanced AI ensemble with specialized agents and database learning"""

    def __init__(self):
        self.db_manager = DatabaseManager()
        self.config = ConfigManager()

        # Initialize the three specialized agents
        self.agents = [
            DeFiSecurityExpert(),
            GasOptimizationExpert(),
            SecurityBestPracticesExpert()
        ]

        logger.info(f"Initialized Enhanced AI Ensemble with {len(self.agents)} specialized agents")

    async def analyze_contract_ensemble(self, contract_content: str, contract_path: str = "") -> ConsensusResult:
        """Run all specialized agents and generate consensus results
        
        🔍 DEBUGGING INFO:
        This method now provides detailed insights into why model_agreement may be 0.0:
        
        1. **Agent Failures**: Shows which agents failed and why (usually missing OpenAI API key)
        2. **No Findings**: Shows when agents completed but found no vulnerabilities  
        3. **No Consensus**: Shows when agents found vulnerabilities but didn't agree (different types/severity)
        4. **Consensus Success**: Shows when 2+ agents agreed on the same finding
        
        ⚠️  COMMON ISSUE - Model Agreement = 0.0 Causes:
        - All agents fail (missing OPENAI_API_KEY) → all return empty findings
        - Agents find different vulnerabilities → no overlap between agents  
        - Agents are disabled or return empty results
        
        ✅ SOLUTION:
        - Set OPENAI_API_KEY environment variable: export OPENAI_API_KEY="your-key"
        - Or configure via: aether config --openai-key "your-key"
        - Check debug output for which agents are failing and why
        """
        start_time = time.time()

        try:
            # Run all agents in parallel
            tasks = []
            for agent in self.agents:
                task = agent.analyze_contract(contract_content, contract_path)
                tasks.append(task)

            # Execute all agent analyses concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and filter out exceptions
            valid_results = []
            for i, result in enumerate(results):
                agent_name = self.agents[i].agent_name if i < len(self.agents) else "unknown"
                
                if isinstance(result, Exception):
                    logger.error(f"❌ Agent {agent_name} failed with exception: {result}")
                    print(f"❌ AI Agent '{agent_name}' failed: {str(result)[:100]}")
                    continue

                if isinstance(result, ModelResult):
                    if result.findings:
                        valid_results.append(result)
                        logger.info(f"✅ Agent {agent_name} found {len(result.findings)} findings")
                        print(f"✅ AI Agent '{agent_name}' found {len(result.findings)} findings")
                    else:
                        if result.confidence == 0.0 and result.metadata.get('error'):
                            logger.warning(f"⚠️  Agent {agent_name} returned no findings - Error: {result.metadata.get('error')}")
                            print(f"⚠️  AI Agent '{agent_name}' failed: {result.metadata.get('error', 'Unknown error')[:100]}")
                        else:
                            logger.info(f"ℹ️  Agent {agent_name} completed but found no vulnerabilities")
                            print(f"ℹ️  AI Agent '{agent_name}' found no vulnerabilities in the contract")

            print(f"\n📊 AI Ensemble Summary:")
            print(f"   Total agents: {len(self.agents)}")
            print(f"   Successful agents: {len(valid_results)}")
            print(f"   Failed/No findings: {len(self.agents) - len(valid_results)}")

            # Generate consensus analysis
            consensus = self._generate_consensus(valid_results)

            processing_time = time.time() - start_time

            return ConsensusResult(
                consensus_findings=consensus['findings'],
                model_agreement=consensus['agreement'],
                confidence_score=consensus['confidence'],
                processing_time=processing_time,
                individual_results=valid_results
            )

        except Exception as e:
            logger.error(f"Enhanced ensemble analysis failed: {e}")
            print(f"❌ AI Ensemble analysis failed: {e}")
            processing_time = time.time() - start_time

            return ConsensusResult(
                consensus_findings=[],
                model_agreement=0.0,
                confidence_score=0.0,
                processing_time=processing_time,
                individual_results=[]
            )

    def _generate_consensus(self, results: List[ModelResult]) -> Dict[str, Any]:
        """Generate consensus from multiple agent results"""
        if not results:
            logger.warning("No valid AI agent results to generate consensus from")
            print("⚠️  No AI agents produced valid results - skipping consensus generation")
            return {
                'findings': [],
                'agreement': 0.0,
                'confidence': 0.0
            }

        # Collect all findings
        all_findings = []
        findings_by_agent = {}
        for result in results:
            findings_by_agent[result.model_name] = len(result.findings)
            all_findings.extend(result.findings)

        if not all_findings:
            logger.info("AI agents found no vulnerabilities to reach consensus on")
            print("ℹ️  AI agents analyzed contract but found no vulnerabilities to create consensus")
            return {
                'findings': [],
                'agreement': 0.0,
                'confidence': 0.0
            }

        # Log findings by each agent
        print(f"\n📋 Findings by Agent:")
        for agent_name, count in findings_by_agent.items():
            print(f"   - {agent_name}: {count} findings")

        # Group findings by similarity (simplified approach)
        consensus_findings = []
        processed_findings = set()

        for finding in all_findings:
            finding_key = self._get_finding_key(finding)

            if finding_key in processed_findings:
                continue

            # Find similar findings
            similar_findings = [f for f in all_findings if self._get_finding_key(f) == finding_key]

            if len(similar_findings) >= 2:  # Require agreement from at least 2 agents
                # Create consensus finding
                consensus_finding = self._merge_similar_findings(similar_findings)
                consensus_findings.append(consensus_finding)
                processed_findings.add(finding_key)
                logger.info(f"✅ Consensus reached on: {finding_key} (agreement: {len(similar_findings)} agents)")
            else:
                logger.debug(f"No consensus for: {finding_key} (only {len(similar_findings)} agent(s) found it)")

        # Calculate overall agreement and confidence
        total_agents = len(self.agents)
        agreement_score = len(consensus_findings) / len(all_findings) if all_findings else 0.0

        # Weight by agent confidence
        avg_confidence = sum(r.confidence for r in results) / len(results) if results else 0.0

        if consensus_findings:
            logger.info(f"🎯 Consensus reached: {len(consensus_findings)} findings from {len(all_findings)} total findings ({agreement_score:.1%} agreement)")
        else:
            logger.warning(f"❌ No consensus reached: {len(all_findings)} findings found but no multi-agent agreement (different vulnerability types/severity per agent)")
            print(f"❌ AI Consensus: {len(all_findings)} findings but NO multi-agent agreement")
            print(f"   Requires at least 2 agents to agree on same vulnerability type, severity, and line")

        return {
            'findings': consensus_findings,
            'agreement': min(agreement_score, 1.0),
            'confidence': min(avg_confidence, 1.0)
        }

    def _get_finding_key(self, finding: Dict[str, Any]) -> str:
        """Generate a key for finding similarity comparison"""
        # Use type, severity, and line number for similarity
        return f"{finding.get('type', '')}_{finding.get('severity', '')}_{finding.get('line', -1)}"

    def _merge_similar_findings(self, similar_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge similar findings into a consensus finding"""
        # Take the finding with highest confidence as base
        base_finding = max(similar_findings, key=lambda f: f.get('confidence', 0))

        # Average confidence across similar findings
        avg_confidence = sum(f.get('confidence', 0) for f in similar_findings) / len(similar_findings)

        # Update with consensus confidence
        consensus_finding = base_finding.copy()
        consensus_finding['confidence'] = avg_confidence
        consensus_finding['consensus_count'] = len(similar_findings)
        # Track which models agreed on this finding
        consensus_finding['models'] = []
        
        return consensus_finding

    def get_learning_patterns(self) -> Dict[str, Any]:
        """Get current learning patterns from database"""
        try:
            # Get patterns for all agent focus areas
            all_patterns = []
            for agent in self.agents:
                patterns = self.db_manager.get_learning_patterns_by_type(agent.focus_areas)
                all_patterns.extend(patterns)

            return {
                'total_patterns': len(all_patterns),
                'high_confidence_patterns': len([p for p in all_patterns if p.success_rate > 0.7]),
                'patterns_by_type': {}
            }
        except Exception as e:
            logger.error(f"Failed to get learning patterns: {e}")
            return {'total_patterns': 0, 'high_confidence_patterns': 0, 'patterns_by_type': {}}

    def store_learning_pattern(self, pattern_type: str, original_classification: str,
                             corrected_classification: str, reasoning: str, source_audit_id: str):
        """Store a new learning pattern in the database"""
        try:
            pattern = LearningPattern(
                id=f"pattern_{int(time.time())}_{hashlib.md5(f'{pattern_type}_{original_classification}'.encode()).hexdigest()[:8]}",
                pattern_type=pattern_type,
                contract_pattern="",  # Could be enhanced to store actual patterns
                vulnerability_type=original_classification,
                original_classification=original_classification,
                corrected_classification=corrected_classification,
                confidence_threshold=0.8,
                reasoning=reasoning,
                source_audit_id=source_audit_id,
                created_at=time.time(),
                usage_count=0,
                success_rate=1.0  # New pattern starts with perfect score
            )

            self.db_manager.store_learning_pattern(pattern)
            logger.info(f"Stored learning pattern: {pattern_type}")

        except Exception as e:
            logger.error(f"Failed to store learning pattern: {e}")


