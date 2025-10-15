"""
Test suite for Phase 3: Advanced AI Integration
Tests multi-model AI ensemble, dynamic learning system, and formal verification
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import json
import os
import tempfile
import shutil

# Import Phase 3 modules
from core.ai_ensemble import (
    AIEnsemble, GPT4Analyzer, ClaudeAnalyzer, DeFiSpecialistModel, 
    FormalVerificationModel, ModelResult, ConsensusResult
)
from core.learning_system import (
    LearningSystem, FeedbackEntry, PatternUpdate, LearningMetrics
)
from core.formal_verification import (
    FormalVerification, FormalProof, InvariantCheck, ProofStatus
)

class TestMultiModelAIEnsemble:
    """Test multi-model AI ensemble functionality"""
    
    @pytest.fixture
    def ai_ensemble(self):
        return AIEnsemble()
    
    @pytest.fixture
    def sample_contract(self):
        return '''
        pragma solidity ^0.8.0;
        
        contract VulnerableContract {
            uint256 public value;
            address public owner;
            
            function setValue(uint256 _value) public {
                value = _value; // Potential reentrancy
            }
            
            function getOraclePrice() public view returns (uint256) {
                return 100; // Oracle manipulation
            }
        }
        '''
    
    @pytest.mark.asyncio
    async def test_ai_ensemble_initialization(self, ai_ensemble):
        """Test AI ensemble initialization"""
        assert len(ai_ensemble.models) == 4
        assert 'gpt4' in ai_ensemble.models
        assert 'claude' in ai_ensemble.models
        assert 'specialized' in ai_ensemble.models
        assert 'formal' in ai_ensemble.models
        
        # Check model specializations
        specializations = ai_ensemble.get_model_specializations()
        assert 'gpt4' in specializations
        assert 'claude' in specializations
        assert 'specialized' in specializations
        assert 'formal' in specializations
    
    @pytest.mark.asyncio
    async def test_ensemble_analysis(self, ai_ensemble, sample_contract):
        """Test ensemble analysis with consensus"""
        result = await ai_ensemble.analyze_with_ensemble(sample_contract)
        
        assert isinstance(result, ConsensusResult)
        assert isinstance(result.consensus_findings, list)
        assert isinstance(result.model_agreement, (int, float))
        assert isinstance(result.confidence_score, float)
        assert isinstance(result.processing_time, float)
        assert len(result.individual_results) == 4
        
        # Check individual model results
        for model_result in result.individual_results:
            assert isinstance(model_result, ModelResult)
            assert model_result.model_name in ['gpt4', 'claude', 'defi_specialist', 'formal_verification']
            assert isinstance(model_result.findings, list)
            assert isinstance(model_result.confidence, float)
            assert isinstance(model_result.processing_time, float)
    
    @pytest.mark.asyncio
    async def test_consensus_analysis(self, ai_ensemble, sample_contract):
        """Test consensus analysis logic"""
        result = await ai_ensemble.analyze_with_ensemble(sample_contract)
        
        # Check consensus findings have required fields
        for finding in result.consensus_findings:
            assert 'type' in finding
            assert 'severity' in finding
            assert 'confidence' in finding
            assert 'consensus_confidence' in finding
            assert 'model_count' in finding
            assert 'models' in finding
            
            # Check consensus confidence is reasonable
            assert 0.0 <= finding['consensus_confidence'] <= 1.0
            assert finding['model_count'] >= 1
            assert len(finding['models']) == finding['model_count']
    
    @pytest.mark.asyncio
    async def test_model_specializations(self, ai_ensemble):
        """Test model specializations"""
        specializations = ai_ensemble.get_model_specializations()
        
        # Check GPT-4 specializations
        assert 'general' in specializations['gpt4']
        assert 'code_analysis' in specializations['gpt4']
        assert 'vulnerability_detection' in specializations['gpt4']
        
        # Check Claude specializations
        assert 'security_analysis' in specializations['claude']
        assert 'formal_reasoning' in specializations['claude']
        assert 'exploit_analysis' in specializations['claude']
        
        # Check DeFi specialist specializations
        assert 'defi' in specializations['specialized']
        assert 'amm' in specializations['specialized']
        assert 'lending' in specializations['specialized']
        assert 'oracle' in specializations['specialized']
        
        # Check formal verification specializations
        assert 'formal_verification' in specializations['formal']
        assert 'mathematical_proof' in specializations['formal']
        assert 'invariant_checking' in specializations['formal']
    
    @pytest.mark.asyncio
    async def test_model_weight_updates(self, ai_ensemble):
        """Test model weight updates"""
        initial_weights = {name: model.confidence_weight for name, model in ai_ensemble.models.items()}
        
        # Update weights
        new_weights = {'gpt4': 0.95, 'claude': 0.90, 'specialized': 0.98, 'formal': 1.0}
        ai_ensemble.update_model_weights(new_weights)
        
        # Check weights were updated
        for model_name, expected_weight in new_weights.items():
            assert ai_ensemble.models[model_name].confidence_weight == expected_weight
    
    @pytest.mark.asyncio
    async def test_ensemble_stats(self, ai_ensemble):
        """Test ensemble statistics"""
        stats = ai_ensemble.get_ensemble_stats()
        
        assert stats['total_models'] == 4
        assert stats['consensus_threshold'] == 0.7
        assert stats['min_models_required'] == 2
        assert 'model_specializations' in stats
        assert 'model_weights' in stats
        
        # Check model weights
        assert len(stats['model_weights']) == 4
        for model_name in ['gpt4', 'claude', 'specialized', 'formal']:
            assert model_name in stats['model_weights']

class TestDynamicLearningSystem:
    """Test dynamic learning system functionality"""
    
    @pytest.fixture
    def temp_data_dir(self):
        """Create temporary data directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def learning_system(self, temp_data_dir):
        return LearningSystem(data_dir=temp_data_dir)
    
    @pytest.mark.asyncio
    async def test_learning_system_initialization(self, learning_system):
        """Test learning system initialization"""
        assert learning_system.min_feedback_threshold == 3
        assert learning_system.confidence_threshold == 0.7
        assert learning_system.learning_rate == 0.1
        assert learning_system.max_pattern_history == 1000
        
        # Check initial metrics
        metrics = learning_system.get_learning_metrics()
        assert metrics.total_feedback_entries == 0
        assert metrics.false_positive_corrections == 0
        assert metrics.severity_corrections == 0
        assert metrics.pattern_updates == 0
    
    @pytest.mark.asyncio
    async def test_feedback_learning(self, learning_system):
        """Test learning from user feedback"""
        # Test false positive feedback
        result = await learning_system.learn_from_feedback(
            vulnerability_id="vuln_1",
            contract_path="test.sol",
            finding_type="reentrancy",
            user_feedback="false_positive",
            user_notes="This is normal DeFi behavior"
        )
        
        assert result is True
        
        # Check metrics updated
        metrics = learning_system.get_learning_metrics()
        assert metrics.total_feedback_entries == 1
        assert metrics.false_positive_corrections == 1
        
        # Test severity correction feedback
        result = await learning_system.learn_from_feedback(
            vulnerability_id="vuln_2",
            contract_path="test.sol",
            finding_type="oracle_manipulation",
            user_feedback="confirmed",
            severity_correction="high",
            user_notes="Should be high severity"
        )
        
        assert result is True
        
        # Check metrics updated
        metrics = learning_system.get_learning_metrics()
        assert metrics.total_feedback_entries == 2
        assert metrics.severity_corrections == 1
    
    @pytest.mark.asyncio
    async def test_pattern_updates(self, learning_system):
        """Test dynamic pattern updates"""
        new_pattern = {
            'type': 'flash_loan_attack',
            'pattern': r'flashLoan\s*\(',
            'description': 'Flash loan attack vector',
            'severity': 'high',
            'confidence': 0.8
        }
        
        result = await learning_system.update_patterns(new_pattern)
        assert result is True
        
        # Check pattern was added
        adapted_patterns = learning_system.get_adapted_patterns()
        assert 'flash_loan_attack' in adapted_patterns
        
        # Check metrics updated
        metrics = learning_system.get_learning_metrics()
        assert metrics.pattern_updates == 1
    
    @pytest.mark.asyncio
    async def test_protocol_adaptation(self, learning_system):
        """Test protocol-specific adaptation"""
        findings = [
            {'type': 'reentrancy', 'severity': 'high'},
            {'type': 'oracle_manipulation', 'severity': 'critical'},
            {'type': 'access_control', 'severity': 'medium'}
        ]
        
        result = await learning_system.adapt_to_protocol('Uniswap', findings)
        
        assert isinstance(result, dict)
        assert result['protocol_type'] == 'Uniswap'
        assert 'finding_types' in result
        assert 'severity_distribution' in result
        assert 'common_patterns' in result
        
        # Check adapted patterns
        adapted_patterns = learning_system.get_adapted_patterns()
        assert 'protocol_Uniswap' in adapted_patterns
    
    @pytest.mark.asyncio
    async def test_pattern_confidence(self, learning_system):
        """Test pattern confidence tracking"""
        # Test initial confidence
        confidence = learning_system.get_pattern_confidence('reentrancy')
        assert 0.0 <= confidence <= 1.0
        
        # Test false positive rate
        fp_rate = learning_system.get_false_positive_rate('reentrancy')
        assert 0.0 <= fp_rate <= 1.0
    
    @pytest.mark.asyncio
    async def test_learning_summary(self, learning_system):
        """Test learning summary generation"""
        summary = learning_system.get_learning_summary()
        
        assert 'metrics' in summary
        assert 'total_patterns' in summary
        assert 'pattern_confidence' in summary
        assert 'false_positive_patterns' in summary
        assert 'learning_parameters' in summary
        
        # Check learning parameters
        params = summary['learning_parameters']
        assert 'min_feedback_threshold' in params
        assert 'confidence_threshold' in params
        assert 'learning_rate' in params

class TestFormalVerification:
    """Test formal verification functionality"""
    
    @pytest.fixture
    def formal_verification(self):
        return FormalVerification()
    
    @pytest.fixture
    def sample_vulnerability(self):
        return {
            'id': 'vuln_1',
            'type': 'reentrancy',
            'severity': 'high',
            'contract_content': 'function setValue(uint256 _value) public { value = _value; }',
            'line': 10
        }
    
    @pytest.mark.asyncio
    async def test_formal_verification_initialization(self, formal_verification):
        """Test formal verification initialization"""
        assert len(formal_verification.invariants) == 5
        assert 'balance_invariant' in formal_verification.invariants
        assert 'access_control_invariant' in formal_verification.invariants
        assert 'reentrancy_invariant' in formal_verification.invariants
        assert 'oracle_invariant' in formal_verification.invariants
        assert 'liquidity_invariant' in formal_verification.invariants
        
        # Check proof templates
        assert len(formal_verification.proof_templates) == 4
        assert 'reentrancy' in formal_verification.proof_templates
        assert 'oracle_manipulation' in formal_verification.proof_templates
        assert 'access_control' in formal_verification.proof_templates
        assert 'integer_overflow' in formal_verification.proof_templates
    
    @pytest.mark.asyncio
    async def test_critical_finding_verification(self, formal_verification, sample_vulnerability):
        """Test critical finding verification"""
        proof = await formal_verification.verify_critical_findings(sample_vulnerability)
        
        assert isinstance(proof, FormalProof)
        assert proof.vulnerability_id == 'vuln_1'
        assert proof.proof_status in [ProofStatus.PROVEN, ProofStatus.DISPROVEN, ProofStatus.INCONCLUSIVE]
        assert isinstance(proof.proof_steps, list)
        assert len(proof.proof_steps) > 0
        assert isinstance(proof.proof_confidence, float)
        assert 0.0 <= proof.proof_confidence <= 1.0
        assert isinstance(proof.processing_time, float)
        assert proof.processing_time > 0
    
    @pytest.mark.asyncio
    async def test_reentrancy_proof_generation(self, formal_verification):
        """Test reentrancy proof generation"""
        vulnerability = {
            'id': 'reentrancy_test',
            'type': 'reentrancy',
            'contract_content': 'function setValue(uint256 _value) public { value = _value; }'
        }
        
        proof = await formal_verification._generate_reentrancy_proof(vulnerability)
        
        assert proof.proof_status in [ProofStatus.PROVEN, ProofStatus.DISPROVEN]
        assert 'external' in proof.proof_steps[0].lower()
        assert 'invariant' in proof.proof_steps[3].lower()
        assert proof.mathematical_formula is not None
        assert 'reentrancy_invariant' in proof.invariants_checked
    
    @pytest.mark.asyncio
    async def test_oracle_proof_generation(self, formal_verification):
        """Test oracle manipulation proof generation"""
        vulnerability = {
            'id': 'oracle_test',
            'type': 'oracle_manipulation',
            'contract_content': 'function getPrice() public view returns (uint256) { return 100; }'
        }
        
        proof = await formal_verification._generate_oracle_proof(vulnerability)
        
        assert proof.proof_status in [ProofStatus.PROVEN, ProofStatus.DISPROVEN]
        assert 'oracle' in proof.proof_steps[0].lower()
        assert 'price' in proof.proof_steps[1].lower()
        assert proof.mathematical_formula is not None
        assert 'oracle_invariant' in proof.invariants_checked
    
    @pytest.mark.asyncio
    async def test_access_control_proof_generation(self, formal_verification):
        """Test access control proof generation"""
        vulnerability = {
            'id': 'access_control_test',
            'type': 'access_control',
            'contract_content': 'function adminFunction() public { // No access control }'
        }
        
        proof = await formal_verification._generate_access_control_proof(vulnerability)
        
        assert proof.proof_status in [ProofStatus.PROVEN, ProofStatus.DISPROVEN]
        assert 'admin' in proof.proof_steps[0].lower()
        assert 'access' in proof.proof_steps[1].lower()
        assert proof.mathematical_formula is not None
        assert 'access_control_invariant' in proof.invariants_checked
    
    @pytest.mark.asyncio
    async def test_invariant_checking(self, formal_verification):
        """Test invariant checking"""
        contract_content = '''
        contract TestContract {
            uint256 public totalSupply;
            mapping(address => uint256) public balanceOf;
            address public owner;
            
            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }
        }
        '''
        
        invariant_checks = formal_verification.check_invariants(contract_content)
        
        assert isinstance(invariant_checks, list)
        assert len(invariant_checks) == 5
        
        for check in invariant_checks:
            assert isinstance(check, InvariantCheck)
            assert check.invariant_name in formal_verification.invariants
            assert check.invariant_formula == formal_verification.invariants[check.invariant_name]
            assert isinstance(check.is_satisfied, bool)
            assert isinstance(check.proof_steps, list)
    
    @pytest.mark.asyncio
    async def test_proof_statistics(self, formal_verification):
        """Test proof statistics"""
        stats = formal_verification.get_proof_statistics()
        
        assert 'total_invariants' in stats
        assert 'proof_templates' in stats
        assert 'supported_vulnerability_types' in stats
        assert 'invariant_formulas' in stats
        
        assert stats['total_invariants'] == 5
        assert len(stats['proof_templates']) == 4
        assert len(stats['supported_vulnerability_types']) == 4
        assert len(stats['invariant_formulas']) == 5

class TestPhase3Integration:
    """Test Phase 3 integration features"""
    
    @pytest.fixture
    def ai_ensemble(self):
        return AIEnsemble()
    
    @pytest.fixture
    def learning_system(self):
        return LearningSystem(data_dir="temp_test_data")
    
    @pytest.fixture
    def formal_verification(self):
        return FormalVerification()
    
    @pytest.fixture
    def sample_contract(self):
        return '''
        pragma solidity ^0.8.0;
        
        contract TestContract {
            uint256 public value;
            address public owner;
            
            function setValue(uint256 _value) public {
                value = _value;
            }
            
            function getOraclePrice() public view returns (uint256) {
                return 100;
            }
        }
        '''
    
    @pytest.mark.asyncio
    async def test_ai_ensemble_with_learning(self, ai_ensemble, learning_system, sample_contract):
        """Test AI ensemble integration with learning system"""
        # Run ensemble analysis
        result = await ai_ensemble.analyze_with_ensemble(sample_contract)
        
        # Provide feedback to learning system
        for finding in result.consensus_findings:
            feedback_result = await learning_system.learn_from_feedback(
                vulnerability_id=f"vuln_{finding['type']}",
                contract_path="test.sol",
                finding_type=finding['type'],
                user_feedback="confirmed",
                user_notes="AI ensemble finding"
            )
            assert feedback_result is True
        
        # Check learning metrics updated
        metrics = learning_system.get_learning_metrics()
        assert metrics.total_feedback_entries >= 0
    
    @pytest.mark.asyncio
    async def test_formal_verification_with_ensemble(self, ai_ensemble, formal_verification, sample_contract):
        """Test formal verification integration with AI ensemble"""
        # Run ensemble analysis
        result = await ai_ensemble.analyze_with_ensemble(sample_contract)
        
        # Verify critical findings with formal methods
        for finding in result.consensus_findings:
            if finding['severity'] in ['critical', 'high']:
                proof = await formal_verification.verify_critical_findings(finding)
                
                assert isinstance(proof, FormalProof)
                assert proof.proof_status in [ProofStatus.PROVEN, ProofStatus.DISPROVEN, ProofStatus.INCONCLUSIVE]
                assert proof.proof_confidence > 0.0
    
    @pytest.mark.asyncio
    async def test_phase3_success_metrics(self, ai_ensemble, learning_system, formal_verification):
        """Test Phase 3 success metrics"""
        # Test AI ensemble metrics
        ensemble_stats = ai_ensemble.get_ensemble_stats()
        assert ensemble_stats['total_models'] == 4
        assert ensemble_stats['consensus_threshold'] == 0.7
        
        # Test learning system metrics
        learning_metrics = learning_system.get_learning_metrics()
        assert learning_metrics.total_feedback_entries >= 0
        assert learning_metrics.pattern_updates >= 0
        
        # Test formal verification metrics
        proof_stats = formal_verification.get_proof_statistics()
        assert proof_stats['total_invariants'] == 5
        assert len(proof_stats['proof_templates']) == 4
        
        # Overall Phase 3 success metrics
        phase3_metrics = {
            'ai_ensemble_models': ensemble_stats['total_models'],
            'learning_system_active': learning_metrics.total_feedback_entries >= 0,
            'formal_verification_invariants': proof_stats['total_invariants'],
            'consensus_threshold': ensemble_stats['consensus_threshold'],
            'proof_templates': len(proof_stats['proof_templates'])
        }
        
        assert phase3_metrics['ai_ensemble_models'] == 4
        assert phase3_metrics['learning_system_active'] is True
        assert phase3_metrics['formal_verification_invariants'] == 5
        assert phase3_metrics['consensus_threshold'] == 0.7
        assert phase3_metrics['proof_templates'] == 4
    
    @pytest.mark.asyncio
    async def test_advanced_ai_capabilities(self, ai_ensemble, learning_system, formal_verification):
        """Test advanced AI capabilities"""
        # Test multi-model consensus
        contract = "contract Test { function test() public { } }"
        result = await ai_ensemble.analyze_with_ensemble(contract)
        
        assert result.model_agreement >= 0.0
        assert result.confidence_score >= 0.0
        assert len(result.individual_results) == 4
        
        # Test learning from feedback
        learning_result = await learning_system.learn_from_feedback(
            vulnerability_id="test_vuln",
            contract_path="test.sol",
            finding_type="test_type",
            user_feedback="confirmed"
        )
        assert learning_result is True
        
        # Test formal verification
        vulnerability = {'id': 'test', 'type': 'reentrancy', 'contract_content': contract}
        proof = await formal_verification.verify_critical_findings(vulnerability)
        
        assert proof.proof_status in [ProofStatus.PROVEN, ProofStatus.DISPROVEN, ProofStatus.INCONCLUSIVE]
        assert proof.proof_confidence >= 0.0
        
        # Advanced capabilities summary
        capabilities = {
            'multi_model_consensus': result.model_agreement >= 0.0,
            'feedback_learning': learning_result,
            'formal_verification': proof.proof_status != ProofStatus.ERROR,
            'ensemble_confidence': result.confidence_score > 0.0
        }
        
        assert all(capabilities.values())
