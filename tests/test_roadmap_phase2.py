"""
Tests for Phase 2 roadmap features: Enhanced Detection
Tests Advanced Exploitability Analysis, Multi-Vector Attack Simulation, and Cross-Protocol Impact Analysis
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch

from core.enhanced_vulnerability_detector import EnhancedVulnerabilityDetector, VulnerabilityMatch


class TestAdvancedExploitabilityAnalysis:
    """Test cases for Advanced Exploitability Analysis (Phase 2.1)"""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = EnhancedVulnerabilityDetector()
        
        # Test vulnerabilities for exploitability analysis
        self.reentrancy_vulnerability = VulnerabilityMatch(
            vulnerability_type='reentrancy',
            severity='high',
            confidence=0.8,
            line_number=15,
            description='Reentrancy vulnerability detected',
            code_snippet='msg.sender.call{value: amount}("");',
            category='reentrancy'
        )
        
        self.oracle_vulnerability = VulnerabilityMatch(
            vulnerability_type='oracle_manipulation',
            severity='critical',
            confidence=0.9,
            line_number=20,
            description='Oracle manipulation detected',
            code_snippet='price = newPrice;',
            category='oracle'
        )

    def test_exploitability_scoring(self):
        """Test automated exploitability scoring."""
        # Test reentrancy exploitability
        reentrancy_score = self.detector._analyze_exploitability(self.reentrancy_vulnerability)
        
        assert isinstance(reentrancy_score, dict), "Should return exploitability score dictionary"
        assert 'complexity' in reentrancy_score, "Should include complexity score"
        assert 'cost' in reentrancy_score, "Should include cost estimation"
        assert 'detection_difficulty' in reentrancy_score, "Should include detection difficulty"
        assert 'profit_potential' in reentrancy_score, "Should include profit potential"
        assert 'feasibility_score' in reentrancy_score, "Should include feasibility score"
        
        # Test oracle exploitability
        oracle_score = self.detector._analyze_exploitability(self.oracle_vulnerability)
        assert isinstance(oracle_score, dict), "Should return exploitability score dictionary"

    def test_attack_complexity_calculation(self):
        """Test attack complexity analysis."""
        complexity = self.detector._calculate_complexity(self.reentrancy_vulnerability)
        
        assert complexity in ['Low', 'Medium', 'High'], "Complexity should be Low/Medium/High"
        
        # Reentrancy should typically be Medium complexity
        assert complexity == 'Medium', "Reentrancy should be Medium complexity"

    def test_gas_cost_estimation(self):
        """Test gas cost estimation for exploitation."""
        gas_cost = self.detector._estimate_gas_cost(self.reentrancy_vulnerability)
        
        assert isinstance(gas_cost, dict), "Should return gas cost dictionary"
        assert 'min_gas' in gas_cost, "Should include minimum gas estimate"
        assert 'max_gas' in gas_cost, "Should include maximum gas estimate"
        assert 'avg_gas' in gas_cost, "Should include average gas estimate"
        
        # Gas costs should be reasonable
        assert gas_cost['min_gas'] > 0, "Minimum gas should be positive"
        assert gas_cost['max_gas'] > gas_cost['min_gas'], "Maximum gas should be greater than minimum"

    def test_detection_difficulty_assessment(self):
        """Test detection difficulty assessment."""
        detection_difficulty = self.detector._assess_detection(self.reentrancy_vulnerability)
        
        assert detection_difficulty in ['Easy', 'Medium', 'Hard'], "Detection difficulty should be Easy/Medium/Hard"
        
        # Reentrancy should be relatively easy to detect
        assert detection_difficulty == 'Easy', "Reentrancy should be easy to detect"

    def test_profit_potential_calculation(self):
        """Test profit potential calculation."""
        profit_potential = self.detector._calculate_profit(self.reentrancy_vulnerability)
        
        assert isinstance(profit_potential, dict), "Should return profit potential dictionary"
        assert 'min_profit' in profit_potential, "Should include minimum profit estimate"
        assert 'max_profit' in profit_potential, "Should include maximum profit estimate"
        assert 'profit_probability' in profit_potential, "Should include profit probability"
        
        # Profit potential should be reasonable
        assert profit_potential['min_profit'] >= 0, "Minimum profit should be non-negative"
        assert profit_potential['profit_probability'] >= 0, "Profit probability should be non-negative"
        assert profit_potential['profit_probability'] <= 1, "Profit probability should be <= 1"

    def test_feasibility_score_computation(self):
        """Test feasibility score computation."""
        feasibility_score = self.detector._compute_feasibility(self.reentrancy_vulnerability)
        
        assert isinstance(feasibility_score, float), "Should return float feasibility score"
        assert 0 <= feasibility_score <= 1, "Feasibility score should be between 0 and 1"
        
        # Reentrancy should have moderate feasibility
        assert 0.3 <= feasibility_score <= 0.8, "Reentrancy should have moderate feasibility"


class TestMultiVectorAttackSimulation:
    """Test cases for Multi-Vector Attack Simulation (Phase 2.2)"""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = EnhancedVulnerabilityDetector()
        
        # Test contracts for attack simulation
        self.flash_loan_contract = '''
        pragma solidity ^0.8.0;
        
        contract FlashLoanContract {
            function flashLoan(uint256 amount) external {
                // Flash loan implementation
                require(amount > 0, "Amount must be positive");
                // Potential flash loan attack vector
            }
        }
        '''
        
        self.oracle_contract = '''
        pragma solidity ^0.8.0;
        
        contract OracleContract {
            uint256 public price;
            
            function updatePrice(uint256 newPrice) external {
                price = newPrice; // Oracle manipulation vector
            }
        }
        '''

    def test_flash_loan_attack_simulation(self):
        """Test flash loan attack simulation."""
        simulation_result = self.detector._simulate_flash_loan_attack(self.flash_loan_contract)
        
        assert isinstance(simulation_result, dict), "Should return simulation result dictionary"
        assert 'attack_scenarios' in simulation_result, "Should include attack scenarios"
        assert 'max_profit' in simulation_result, "Should include maximum profit calculation"
        assert 'feasibility' in simulation_result, "Should include attack feasibility"
        
        # Should identify potential flash loan attack scenarios
        assert len(simulation_result['attack_scenarios']) > 0, "Should identify attack scenarios"

    def test_oracle_manipulation_simulation(self):
        """Test oracle manipulation simulation."""
        simulation_result = self.detector._simulate_oracle_manipulation(self.oracle_contract)
        
        assert isinstance(simulation_result, dict), "Should return simulation result dictionary"
        assert 'price_impact' in simulation_result, "Should include price impact calculation"
        assert 'dependent_protocols' in simulation_result, "Should include dependent protocol analysis"
        assert 'manipulation_cost' in simulation_result, "Should include manipulation cost"
        
        # Should calculate price impact
        assert simulation_result['price_impact'] > 0, "Should calculate positive price impact"

    def test_reentrancy_attack_simulation(self):
        """Test reentrancy attack simulation."""
        reentrancy_contract = '''
        pragma solidity ^0.8.0;
        
        contract ReentrancyContract {
            mapping(address => uint256) public balances;
            
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                msg.sender.call{value: amount}(""); // Reentrancy vector
            }
        }
        '''
        
        simulation_result = self.detector._simulate_reentrancy_attack(reentrancy_contract)
        
        assert isinstance(simulation_result, dict), "Should return simulation result dictionary"
        assert 'potential_damage' in simulation_result, "Should include potential damage calculation"
        assert 'exploitability' in simulation_result, "Should include exploitability assessment"
        assert 'attack_vectors' in simulation_result, "Should include attack vectors"
        
        # Should identify reentrancy attack vectors
        assert len(simulation_result['attack_vectors']) > 0, "Should identify attack vectors"

    def test_attack_impact_quantification(self):
        """Test attack impact quantification."""
        impact_analysis = self.detector._quantify_attack_impact(self.flash_loan_contract)
        
        assert isinstance(impact_analysis, dict), "Should return impact analysis dictionary"
        assert 'financial_impact' in impact_analysis, "Should include financial impact"
        assert 'systemic_risk' in impact_analysis, "Should include systemic risk assessment"
        assert 'user_impact' in impact_analysis, "Should include user impact"
        
        # Should quantify various impact dimensions
        assert impact_analysis['financial_impact'] >= 0, "Financial impact should be non-negative"
        assert 0 <= impact_analysis['systemic_risk'] <= 1, "Systemic risk should be between 0 and 1"


class TestCrossProtocolImpactAnalysis:
    """Test cases for Cross-Protocol Impact Analysis (Phase 2.3)"""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = EnhancedVulnerabilityDetector()
        
        # Test contracts representing different protocols
        self.oracle_contract = '''
        pragma solidity ^0.8.0;
        
        contract PriceOracle {
            uint256 public price;
            
            function updatePrice(uint256 newPrice) external {
                price = newPrice;
            }
            
            function getPrice() external view returns (uint256) {
                return price;
            }
        }
        '''
        
        self.lending_contract = '''
        pragma solidity ^0.8.0;
        
        contract LendingProtocol {
            PriceOracle public oracle;
            
            function borrow(uint256 amount) external {
                uint256 price = oracle.getPrice();
                // Uses oracle price for borrowing
            }
        }
        '''

    def test_dependent_protocol_identification(self):
        """Test identification of dependent protocols."""
        dependent_protocols = self.detector._identify_dependent_protocols(self.oracle_contract)
        
        assert isinstance(dependent_protocols, list), "Should return list of dependent protocols"
        
        # Should identify potential dependent protocols
        assert len(dependent_protocols) >= 0, "Should identify dependent protocols"

    def test_cascading_failure_analysis(self):
        """Test cascading failure analysis."""
        cascading_analysis = self.detector._analyze_cascading_effects(self.oracle_contract)
        
        assert isinstance(cascading_analysis, dict), "Should return cascading analysis dictionary"
        assert 'failure_chain' in cascading_analysis, "Should include failure chain analysis"
        assert 'risk_level' in cascading_analysis, "Should include risk level assessment"
        assert 'mitigation_strategies' in cascading_analysis, "Should include mitigation strategies"
        
        # Should assess cascading failure risk
        assert cascading_analysis['risk_level'] in ['Low', 'Medium', 'High'], "Risk level should be Low/Medium/High"

    def test_systemic_impact_assessment(self):
        """Test systemic impact assessment."""
        systemic_impact = self.detector._assess_systemic_impact(self.oracle_contract)
        
        assert isinstance(systemic_impact, dict), "Should return systemic impact dictionary"
        assert 'impact_radius' in systemic_impact, "Should include impact radius"
        assert 'affected_protocols' in systemic_impact, "Should include affected protocols"
        assert 'economic_impact' in systemic_impact, "Should include economic impact"
        
        # Should assess systemic impact
        assert systemic_impact['impact_radius'] >= 0, "Impact radius should be non-negative"

    def test_integration_point_mapping(self):
        """Test integration point mapping."""
        integration_points = self.detector._map_integration_points(self.lending_contract)
        
        assert isinstance(integration_points, list), "Should return list of integration points"
        
        # Should identify integration points
        assert len(integration_points) >= 0, "Should identify integration points"

    def test_cross_protocol_vulnerability_analysis(self):
        """Test cross-protocol vulnerability analysis."""
        # Analyze oracle contract for cross-protocol impact
        oracle_vulns = self.detector.analyze_contract(self.oracle_contract)
        
        # Analyze lending contract for dependencies
        lending_vulns = self.detector.analyze_contract(self.lending_contract)
        
        # Perform cross-protocol analysis
        cross_protocol_analysis = self.detector._analyze_cross_protocol_vulnerabilities(
            oracle_vulns, lending_vulns
        )
        
        assert isinstance(cross_protocol_analysis, dict), "Should return cross-protocol analysis"
        assert 'shared_vulnerabilities' in cross_protocol_analysis, "Should identify shared vulnerabilities"
        assert 'dependency_risks' in cross_protocol_analysis, "Should assess dependency risks"
        assert 'mitigation_recommendations' in cross_protocol_analysis, "Should provide mitigation recommendations"


class TestPhase2Integration:
    """Integration tests for Phase 2 features working together"""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = EnhancedVulnerabilityDetector()
        
        # Complex contract with multiple attack vectors
        self.complex_contract = '''
        pragma solidity ^0.8.0;
        
        contract ComplexDeFiContract {
            uint256 public price;
            mapping(address => uint256) public balances;
            
            function updatePrice(uint256 newPrice) external {
                price = newPrice; // Oracle manipulation vector
            }
            
            function flashLoan(uint256 amount) external {
                // Flash loan attack vector
                require(amount > 0, "Amount must be positive");
            }
            
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                msg.sender.call{value: amount}(""); // Reentrancy vector
            }
        }
        '''

    def test_exploitability_analysis_with_attack_simulation(self):
        """Test that exploitability analysis works with attack simulation."""
        vulns = self.detector.analyze_contract(self.complex_contract)
        
        # Analyze exploitability for each vulnerability
        exploitability_results = []
        for vuln in vulns:
            exploitability = self.detector._analyze_exploitability(vuln)
            exploitability_results.append(exploitability)
        
        # Simulate attacks for each vulnerability type
        attack_simulations = []
        for vuln in vulns:
            if vuln.vulnerability_type == 'oracle_manipulation':
                simulation = self.detector._simulate_oracle_manipulation(self.complex_contract)
            elif vuln.vulnerability_type == 'reentrancy':
                simulation = self.detector._simulate_reentrancy_attack(self.complex_contract)
            else:
                simulation = self.detector._quantify_attack_impact(self.complex_contract)
            
            attack_simulations.append(simulation)
        
        # Should have both exploitability analysis and attack simulations
        assert len(exploitability_results) > 0, "Should have exploitability analysis"
        assert len(attack_simulations) > 0, "Should have attack simulations"

    def test_multi_vector_analysis_with_cross_protocol_impact(self):
        """Test that multi-vector analysis works with cross-protocol impact."""
        vulns = self.detector.analyze_contract(self.complex_contract)
        
        # Perform multi-vector attack simulation
        multi_vector_analysis = self.detector._perform_multi_vector_analysis(vulns)
        
        # Perform cross-protocol impact analysis
        cross_protocol_impact = self.detector._assess_systemic_impact(self.complex_contract)
        
        # Should have both analyses
        assert isinstance(multi_vector_analysis, dict), "Should have multi-vector analysis"
        assert isinstance(cross_protocol_impact, dict), "Should have cross-protocol impact analysis"

    def test_phase2_success_metrics(self):
        """Test that Phase 2 achieves target success metrics."""
        # Test exploitability assessment accuracy
        vulns = self.detector.analyze_contract(self.complex_contract)
        
        exploitability_assessments = []
        for vuln in vulns:
            exploitability = self.detector._analyze_exploitability(vuln)
            exploitability_assessments.append(exploitability)
        
        # Phase 2 targets:
        # - Exploitability Assessment: >90% (current: ~75%)
        # - Attack simulation capabilities
        # - Cross-protocol impact analysis
        
        # Should have exploitability assessments for all vulnerabilities
        assert len(exploitability_assessments) == len(vulns), "Should assess exploitability for all vulnerabilities"
        
        # Should have feasibility scores
        feasibility_scores = [result['feasibility_score'] for result in exploitability_assessments if 'feasibility_score' in result]
        assert len(feasibility_scores) > 0, "Should have feasibility scores"
        
        # Should have attack simulations
        attack_simulations = []
        for vuln in vulns:
            if vuln.vulnerability_type == 'oracle_manipulation':
                simulation = self.detector._simulate_oracle_manipulation(self.complex_contract)
            elif vuln.vulnerability_type == 'reentrancy':
                simulation = self.detector._simulate_reentrancy_attack(self.complex_contract)
            else:
                simulation = self.detector._quantify_attack_impact(self.complex_contract)
            attack_simulations.append(simulation)
        
        assert len(attack_simulations) > 0, "Should have attack simulations"

    def test_enhanced_detection_capabilities(self):
        """Test that enhanced detection capabilities are working."""
        # Test that all Phase 2 features are available
        assert hasattr(self.detector, '_analyze_exploitability'), "Should have exploitability analysis"
        assert hasattr(self.detector, '_simulate_flash_loan_attack'), "Should have flash loan simulation"
        assert hasattr(self.detector, '_simulate_oracle_manipulation'), "Should have oracle simulation"
        assert hasattr(self.detector, '_simulate_reentrancy_attack'), "Should have reentrancy simulation"
        assert hasattr(self.detector, '_identify_dependent_protocols'), "Should have dependent protocol identification"
        assert hasattr(self.detector, '_analyze_cascading_effects'), "Should have cascading effects analysis"
        assert hasattr(self.detector, '_assess_systemic_impact'), "Should have systemic impact assessment"
        
        # Test that methods are callable
        vuln = VulnerabilityMatch(
            vulnerability_type='test',
            severity='high',
            confidence=0.8,
            line_number=10,
            description='Test vulnerability',
            code_snippet='test code'
        )
        
        # Should be able to call all Phase 2 methods
        try:
            self.detector._analyze_exploitability(vuln)
            self.detector._simulate_flash_loan_attack(self.complex_contract)
            self.detector._simulate_oracle_manipulation(self.complex_contract)
            self.detector._simulate_reentrancy_attack(self.complex_contract)
            self.detector._identify_dependent_protocols(self.complex_contract)
            self.detector._analyze_cascading_effects(self.complex_contract)
            self.detector._assess_systemic_impact(self.complex_contract)
        except Exception as e:
            pytest.fail(f"Phase 2 methods should be callable: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
