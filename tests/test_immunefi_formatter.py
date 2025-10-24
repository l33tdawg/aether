#!/usr/bin/env python3
"""
Tests for Immunefi Formatter Module

Tests bug bounty report generation for Immunefi submissions.
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

from core.immunefi_formatter import ImmunefFormatter, ImmunefiBugReport


class TestImmunefiBugReport:
    """Test ImmunefiBugReport dataclass."""
    
    def test_report_creation(self):
        """Test creating ImmunefiBugReport."""
        report = ImmunefiBugReport(
            title="Reentrancy in Vault Allows Fund Drainage",
            severity="Critical",
            affected_asset="0x1234567890123456789012345678901234567890",
            chain="Ethereum",
            vulnerability_type="reentrancy",
            description="The withdraw function is vulnerable to reentrancy",
            impact="Direct theft of any user funds",
            poc_code="contract Exploit { ... }",
            reproduction_steps=["Step 1", "Step 2"],
            recommended_fix="Use ReentrancyGuard",
            references=["https://swcregistry.io/docs/SWC-107"],
            submission_date="2025-10-24"
        )
        
        assert report.title == "Reentrancy in Vault Allows Fund Drainage"
        assert report.severity == "Critical"
        assert report.affected_asset.startswith("0x")
        assert report.chain == "Ethereum"
        assert report.poc_code is not None
        assert len(report.reproduction_steps) == 2


class TestImmunefFormatter:
    """Test ImmunefFormatter functionality."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_initialization(self):
        """Test formatter initialization."""
        assert self.formatter is not None
        assert len(self.formatter.IMPACT_MAPPING) > 0
    
    def test_generate_report_basic(self):
        """Test generating basic report."""
        vulnerability = {
            'vulnerability_type': 'reentrancy',
            'severity': 'critical',
            'description': 'Reentrancy vulnerability in withdraw function',
            'contract_name': 'Vault',
            'line_number': 42
        }
        
        deployment_info = {
            'contract_address': '0x1234567890123456789012345678901234567890',
            'chain': 'Ethereum'
        }
        
        report = self.formatter.generate_report(vulnerability, deployment_info)
        
        assert isinstance(report, ImmunefiBugReport)
        assert report.severity == 'Critical'
        assert report.chain == 'Ethereum'
        assert report.affected_asset == deployment_info['contract_address']
    
    def test_generate_report_without_deployment_info(self):
        """Test generating report without deployment info."""
        vulnerability = {
            'vulnerability_type': 'access_control',
            'severity': 'high',
            'description': 'Missing access control'
        }
        
        report = self.formatter.generate_report(vulnerability)
        
        assert isinstance(report, ImmunefiBugReport)
        assert report.affected_asset == 'TBD'
        assert report.chain == 'Ethereum'  # Default


class TestSeverityMapping:
    """Test severity mapping."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_map_critical_severity(self):
        """Test mapping critical severity."""
        vuln = {'severity': 'critical'}
        assert self.formatter._map_severity(vuln) == 'Critical'
    
    def test_map_high_severity(self):
        """Test mapping high severity."""
        vuln = {'severity': 'high'}
        assert self.formatter._map_severity(vuln) == 'High'
    
    def test_map_medium_severity(self):
        """Test mapping medium severity."""
        vuln = {'severity': 'medium'}
        assert self.formatter._map_severity(vuln) == 'Medium'
    
    def test_map_low_severity(self):
        """Test mapping low severity."""
        vuln = {'severity': 'low'}
        assert self.formatter._map_severity(vuln) == 'Low'
    
    def test_map_informational_severity(self):
        """Test mapping informational severity."""
        vuln = {'severity': 'informational'}
        assert self.formatter._map_severity(vuln) == 'Low'


class TestImpactDetermination:
    """Test impact determination."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_reentrancy_impact(self):
        """Test reentrancy impact classification."""
        vuln = {'vulnerability_type': 'reentrancy'}
        impact = self.formatter._determine_impact(vuln)
        
        assert impact == 'Direct theft of any user funds'
    
    def test_arithmetic_underflow_impact(self):
        """Test arithmetic underflow impact classification."""
        vuln = {'vulnerability_type': 'arithmetic_underflow'}
        impact = self.formatter._determine_impact(vuln)
        
        assert impact == 'Temporary freezing of funds'
    
    def test_oracle_manipulation_impact(self):
        """Test oracle manipulation impact classification."""
        vuln = {'vulnerability_type': 'oracle_manipulation'}
        impact = self.formatter._determine_impact(vuln)
        
        assert 'Oracle manipulation' in impact or 'pricing' in impact
    
    def test_unknown_type_fallback(self):
        """Test fallback for unknown vulnerability type."""
        vuln = {'vulnerability_type': 'unknown', 'severity': 'high'}
        impact = self.formatter._determine_impact(vuln)
        
        assert isinstance(impact, str)
        assert len(impact) > 0


class TestTitleGeneration:
    """Test title generation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_generate_title_basic(self):
        """Test basic title generation."""
        vuln = {
            'vulnerability_type': 'reentrancy',
            'contract_name': 'RocketVault'
        }
        
        title = self.formatter._generate_title(vuln)
        
        assert 'Reentrancy' in title
        assert 'RocketVault' in title
    
    def test_generate_title_with_impact(self):
        """Test title generation with impact keywords."""
        vuln = {
            'vulnerability_type': 'access_control',
            'contract_name': 'Vault',
            'description': 'Governance can drain all funds from the vault'
        }
        
        title = self.formatter._generate_title(vuln)
        
        assert 'Vault' in title
        assert 'Drainage' in title or 'Access Control' in title


class TestMarkdownGeneration:
    """Test markdown report generation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_to_markdown_complete(self):
        """Test complete markdown generation."""
        report = ImmunefiBugReport(
            title="Test Vulnerability",
            severity="High",
            affected_asset="0x1234567890123456789012345678901234567890",
            chain="Ethereum",
            vulnerability_type="test_vuln",
            description="Test description",
            impact="Temporary freezing of funds",
            poc_code="contract Exploit {}",
            reproduction_steps=["Step 1", "Step 2"],
            recommended_fix="Apply fix",
            references=["https://example.com"],
            submission_date="2025-10-24"
        )
        
        md = self.formatter.to_markdown(report)
        
        assert '# Test Vulnerability' in md
        assert '**Severity**: High' in md
        assert '0x1234567890123456789012345678901234567890' in md
        assert 'Ethereum' in md
        assert 'Proof of Concept' in md
        assert '```solidity' in md
        assert 'Reproduction Steps' in md
        assert 'Recommended Fix' in md
        assert 'References' in md
    
    def test_to_markdown_minimal(self):
        """Test markdown generation with minimal data."""
        report = ImmunefiBugReport(
            title="Minimal Vulnerability",
            severity="Medium",
            affected_asset="TBD",
            chain="Ethereum",
            vulnerability_type="test",
            description="Test",
            impact="Test impact"
        )
        
        md = self.formatter.to_markdown(report)
        
        assert '# Minimal Vulnerability' in md
        assert '**Severity**: Medium' in md
        # Should handle None values gracefully
        assert 'None' not in md or md.count('None') < 3


class TestJSONConversion:
    """Test JSON conversion."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_to_json(self):
        """Test converting report to JSON."""
        report = ImmunefiBugReport(
            title="Test",
            severity="High",
            affected_asset="0x1234",
            chain="Ethereum",
            vulnerability_type="test",
            description="Description",
            impact="Impact"
        )
        
        json_data = self.formatter.to_json(report)
        
        assert isinstance(json_data, dict)
        assert json_data['title'] == "Test"
        assert json_data['severity'] == "High"
        assert json_data['chain'] == "Ethereum"


class TestFileOperations:
    """Test file save operations."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    def test_save_report_markdown(self, temp_dir):
        """Test saving report as markdown."""
        report = ImmunefiBugReport(
            title="Test Vulnerability",
            severity="High",
            affected_asset="0x1234",
            chain="Ethereum",
            vulnerability_type="test",
            description="Test",
            impact="Test impact"
        )
        
        output_path = temp_dir / 'report.md'
        self.formatter.save_report(report, output_path)
        
        assert output_path.exists()
        content = output_path.read_text()
        assert '# Test Vulnerability' in content
    
    def test_save_report_json(self, temp_dir):
        """Test saving report as JSON."""
        report = ImmunefiBugReport(
            title="Test Vulnerability",
            severity="High",
            affected_asset="0x1234",
            chain="Ethereum",
            vulnerability_type="test",
            description="Test",
            impact="Test impact"
        )
        
        output_path = temp_dir / 'report.json'
        self.formatter.save_report(report, output_path)
        
        assert output_path.exists()
        with open(output_path) as f:
            data = json.load(f)
        assert data['title'] == "Test Vulnerability"


class TestBatchOperations:
    """Test batch report generation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_batch_generate_reports(self):
        """Test generating multiple reports."""
        vulnerabilities = [
            {
                'vulnerability_type': 'reentrancy',
                'severity': 'critical',
                'description': 'Reentrancy in withdraw',
                'validation_confidence': 0.9
            },
            {
                'vulnerability_type': 'access_control',
                'severity': 'high',
                'description': 'Missing access control',
                'validation_confidence': 0.8
            }
        ]
        
        reports = self.formatter.batch_generate_reports(vulnerabilities)
        
        assert len(reports) == 2
        assert all(isinstance(r, ImmunefiBugReport) for r in reports)
    
    def test_batch_filters_low_confidence(self):
        """Test that batch generation filters low confidence findings."""
        vulnerabilities = [
            {
                'vulnerability_type': 'test1',
                'severity': 'high',
                'description': 'Test',
                'validation_confidence': 0.9  # High confidence
            },
            {
                'vulnerability_type': 'test2',
                'severity': 'high',
                'description': 'Test',
                'validation_confidence': 0.3  # Low confidence
            }
        ]
        
        reports = self.formatter.batch_generate_reports(vulnerabilities)
        
        # Should only include high confidence finding
        assert len(reports) == 1
    
    def test_batch_filters_informational(self):
        """Test that batch generation filters informational findings."""
        vulnerabilities = [
            {
                'vulnerability_type': 'test1',
                'severity': 'high',
                'description': 'Test'
            },
            {
                'vulnerability_type': 'test2',
                'severity': 'informational',
                'description': 'Test'
            }
        ]
        
        reports = self.formatter.batch_generate_reports(vulnerabilities)
        
        # Should filter informational
        assert len(reports) == 1
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    def test_save_batch_reports(self, temp_dir):
        """Test saving batch reports."""
        vulnerabilities = [
            {
                'vulnerability_type': 'reentrancy',
                'severity': 'critical',
                'description': 'Test 1',
                'validation_confidence': 0.9
            },
            {
                'vulnerability_type': 'access_control',
                'severity': 'high',
                'description': 'Test 2',
                'validation_confidence': 0.85
            }
        ]
        
        output_dir = temp_dir / 'reports'
        self.formatter.save_batch_reports(vulnerabilities, output_dir)
        
        # Should create directory
        assert output_dir.exists()
        
        # Should create individual reports
        report_files = list(output_dir.glob('*.md'))
        assert len(report_files) == 2
        
        # Should create summary JSON
        summary_file = output_dir / 'submission_summary.json'
        assert summary_file.exists()
        
        with open(summary_file) as f:
            summary = json.load(f)
        
        assert summary['total_reports'] == 2
        assert 'severity_breakdown' in summary
        assert 'reports' in summary


class TestRealWorldReports:
    """Test with real-world vulnerability scenarios."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_gains_network_report(self):
        """Test generating report for Gains Network vulnerability."""
        vulnerability = {
            'vulnerability_type': 'arithmetic_underflow',
            'severity': 'high',
            'description': 'Arithmetic underflow in yFee[i-1] at line 304 when i=0',
            'contract_name': 'GNSTradingCallbacksV6_4',
            'line_number': 304,
            'code_snippet': 'require(yFee[i] >= yFee[i-1], "FEES_NOT_MONOTONIC");',
            'validation_confidence': 0.95,
            'validation_reasoning': 'Real vulnerability - array underflow possible'
        }
        
        deployment_info = {
            'contract_address': '0xGainsNetworkAddress',
            'chain': 'Polygon'
        }
        
        report = self.formatter.generate_report(vulnerability, deployment_info)
        
        assert 'Underflow' in report.title or 'Arithmetic' in report.title
        assert report.chain == 'Polygon'
        assert report.severity == 'High'
        assert 'Line 304' in report.description
    
    def test_rocket_pool_report(self):
        """Test generating report for RocketPool vulnerability."""
        vulnerability = {
            'vulnerability_type': 'access_control',
            'severity': 'critical',
            'description': 'Governance can replace network contracts allowing immediate vault drainage',
            'contract_name': 'RocketVault',
            'line_number': 42,
            'poc_code': '''
// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

contract RocketVaultExploit {
    function exploit(address vault) external {
        // Exploit logic
    }
}
''',
            'recommendation': 'Implement timelock for contract replacements',
            'validation_confidence': 0.9
        }
        
        deployment_info = {
            'contract_address': '0xRocketPoolVaultAddress',
            'chain': 'Ethereum'
        }
        
        report = self.formatter.generate_report(vulnerability, deployment_info)
        
        assert 'RocketVault' in report.title
        assert report.severity == 'Critical'
        assert report.poc_code is not None
        assert 'pragma solidity 0.7.6' in report.poc_code


class TestMarkdownFormatting:
    """Test markdown formatting quality."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_markdown_structure(self):
        """Test that markdown has proper structure."""
        vulnerability = {
            'vulnerability_type': 'reentrancy',
            'severity': 'critical',
            'description': 'Reentrancy allows fund theft',
            'contract_name': 'Vault',
            'poc_code': 'contract Exploit {}',
            'reproduction_steps': ['Deploy', 'Execute', 'Verify'],
            'recommendation': 'Use ReentrancyGuard',
            'references': ['https://example.com']
        }
        
        report = self.formatter.generate_report(vulnerability)
        md = self.formatter.to_markdown(report)
        
        # Check for required sections
        required_sections = [
            '# ',  # Title
            '## Summary',
            '## Vulnerability Details',
            '## Impact Analysis',
            '## Proof of Concept',
            '## Recommended Fix',
            '## References'
        ]
        
        for section in required_sections:
            assert section in md, f"Missing section: {section}"
    
    def test_markdown_code_blocks(self):
        """Test that code blocks are properly formatted."""
        vulnerability = {
            'vulnerability_type': 'test',
            'severity': 'medium',
            'description': 'Test',
            'poc_code': 'contract Test { function test() public {} }'
        }
        
        report = self.formatter.generate_report(vulnerability)
        md = self.formatter.to_markdown(report)
        
        # Should have proper code fences
        assert '```solidity' in md
        assert '```' in md
        assert md.count('```') % 2 == 0  # Balanced code fences


class TestReproductionSteps:
    """Test reproduction steps extraction."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_extract_steps_from_poc(self):
        """Test extracting steps when POC exists."""
        vuln = {
            'vulnerability_type': 'test',
            'poc_code': 'contract Exploit {}'
        }
        
        steps = self.formatter._extract_reproduction_steps(vuln)
        
        assert steps is not None
        assert len(steps) > 0
        assert any('Deploy' in step for step in steps)
    
    def test_extract_steps_from_snippet(self):
        """Test extracting steps from code snippet."""
        vuln = {
            'vulnerability_type': 'test',
            'code_snippet': 'vulnerable code',
            'line_number': 42
        }
        
        steps = self.formatter._extract_reproduction_steps(vuln)
        
        assert steps is not None
        assert any('42' in step for step in steps)
    
    def test_custom_steps(self):
        """Test custom reproduction steps."""
        vuln = {
            'vulnerability_type': 'test',
            'reproduction_steps': ['Custom step 1', 'Custom step 2']
        }
        
        steps = self.formatter._extract_reproduction_steps(vuln)
        
        assert 'Custom step 1' in steps
        assert 'Custom step 2' in steps


class TestReferences:
    """Test reference gathering."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_gather_references_with_swc(self):
        """Test gathering references with SWC ID."""
        vuln = {
            'vulnerability_type': 'reentrancy',
            'swc_id': 'SWC-107',
            'category': 'Reentrancy'
        }
        
        refs = self.formatter._gather_references(vuln)
        
        assert refs is not None
        assert any('SWC-107' in ref for ref in refs)
        assert any('swcregistry.io' in ref for ref in refs)
    
    def test_gather_custom_references(self):
        """Test gathering custom references."""
        vuln = {
            'vulnerability_type': 'test',
            'references': ['https://example.com/vuln1', 'https://example.com/vuln2']
        }
        
        refs = self.formatter._gather_references(vuln)
        
        assert refs is not None
        assert 'https://example.com/vuln1' in refs
        assert 'https://example.com/vuln2' in refs


class TestSeverityBreakdown:
    """Test severity breakdown."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.formatter = ImmunefFormatter()
    
    def test_severity_breakdown(self):
        """Test getting severity breakdown."""
        reports = [
            ImmunefiBugReport("T1", "Critical", "0x", "Eth", "test", "d", "i"),
            ImmunefiBugReport("T2", "High", "0x", "Eth", "test", "d", "i"),
            ImmunefiBugReport("T3", "High", "0x", "Eth", "test", "d", "i"),
            ImmunefiBugReport("T4", "Medium", "0x", "Eth", "test", "d", "i"),
        ]
        
        breakdown = self.formatter._get_severity_breakdown(reports)
        
        assert breakdown['Critical'] == 1
        assert breakdown['High'] == 2
        assert breakdown['Medium'] == 1
        assert breakdown['Low'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

