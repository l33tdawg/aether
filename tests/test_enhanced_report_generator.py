#!/usr/bin/env python3
"""
Unit tests for enhanced report generator.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

from core.enhanced_report_generator import (
    EnhancedReportGenerator,
    RiskScorer,
    ComplianceReporter,
    AdvancedVisualizer
)


class TestRiskScorer:
    """Test cases for RiskScorer."""

    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        scorer = RiskScorer()

        # Test different severity levels
        low_vuln = {"severity": "low", "type": "access_control"}
        medium_vuln = {"severity": "medium", "type": "reentrancy"}
        high_vuln = {"severity": "high", "type": "oracle_manipulation"}
        critical_vuln = {"severity": "critical", "type": "flash_loan"}

        assert scorer.calculate_risk_score(low_vuln) < scorer.calculate_risk_score(medium_vuln)
        assert scorer.calculate_risk_score(medium_vuln) < scorer.calculate_risk_score(high_vuln)
        assert scorer.calculate_risk_score(high_vuln) < scorer.calculate_risk_score(critical_vuln)

        # Test category multipliers
        access_vuln = {"severity": "medium", "type": "access_control"}
        defi_vuln = {"severity": "medium", "type": "flash_loan"}

        assert scorer.calculate_risk_score(access_vuln) < scorer.calculate_risk_score(defi_vuln)

    def test_prioritize_vulnerabilities(self):
        """Test vulnerability prioritization."""
        scorer = RiskScorer()

        vulnerabilities = [
            {"severity": "low", "type": "access_control", "confidence": 0.8},
            {"severity": "high", "type": "reentrancy", "confidence": 0.9},
            {"severity": "medium", "type": "gas_optimization", "confidence": 0.7},
            {"severity": "critical", "type": "oracle_manipulation", "confidence": 0.95}
        ]

        prioritized = scorer.prioritize_vulnerabilities(vulnerabilities)

        # Should be sorted by risk score (highest first)
        # Critical should be first, then high, then medium, then low
        assert prioritized[0]["severity"] == "critical"
        assert prioritized[1]["severity"] == "high"
        assert prioritized[2]["severity"] == "medium"
        assert prioritized[3]["severity"] == "low"

        # Each should have a risk_score
        for vuln in prioritized:
            assert "risk_score" in vuln
            assert vuln["risk_score"] > 0

        # Risk scores should be in descending order
        for i in range(len(prioritized) - 1):
            assert prioritized[i]["risk_score"] >= prioritized[i + 1]["risk_score"]


class TestComplianceReporter:
    """Test cases for ComplianceReporter."""

    def test_soc2_report_generation(self):
        """Test SOC2 compliance report generation."""
        reporter = ComplianceReporter()

        results = {
            "vulnerabilities": [
                {"severity": "high", "type": "access_control"},
                {"severity": "medium", "type": "reentrancy"}
            ],
            "fixes": [{"title": "Fix access control"}]
        }

        report = reporter._generate_soc2_report(results)

        assert "SOC2 Compliance Report" in report
        assert "Executive Summary" in report
        assert "Security Controls Assessment" in report
        assert "Compliance Status" in report

    def test_pci_dss_report_generation(self):
        """Test PCI-DSS compliance report generation."""
        reporter = ComplianceReporter()

        results = {
            "vulnerabilities": [
                {"severity": "critical", "type": "access_control"}
            ],
            "fixes": []
        }

        report = reporter._generate_pci_dss_report(results)

        assert "PCI-DSS Compliance Report" in report
        assert "Requirement 6" in report
        assert "Compliance Status" in report

    def test_compliance_report_generation(self):
        """Test compliance report generation for different standards."""
        reporter = ComplianceReporter()

        results = {
            "vulnerabilities": [{"severity": "medium", "type": "test"}],
            "fixes": [{"title": "Test fix"}]
        }

        # Test all supported standards
        standards = ['SOC2', 'PCI-DSS', 'GDPR', 'ISO27001', 'NIST']

        for standard in standards:
            report = reporter.generate_compliance_report(results, standard, f"/tmp/test_{standard}.md")

            # Should not raise an exception
            assert report is None  # generate_compliance_report doesn't return content, it writes to file

    def test_unsupported_standard(self):
        """Test error handling for unsupported compliance standards."""
        reporter = ComplianceReporter()

        results = {"vulnerabilities": []}

        with pytest.raises(ValueError, match="Unsupported compliance standard"):
            reporter.generate_compliance_report(results, "UNSUPPORTED_STANDARD", "/tmp/test.md")


class TestAdvancedVisualizer:
    """Test cases for AdvancedVisualizer."""

    def test_html_dashboard_generation_without_plotly(self):
        """Test HTML dashboard generation when plotly is not available."""
        # Mock plotly as unavailable
        with patch('core.enhanced_report_generator.PLOTLY_AVAILABLE', False):
            visualizer = AdvancedVisualizer()

            results = {
                "vulnerabilities": [
                    {"severity": "high", "type": "reentrancy", "description": "Test vuln"}
                ],
                "fixes": [{"title": "Test fix"}]
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                dashboard_path = f.name

            try:
                visualizer.generate_html_dashboard(results, dashboard_path)

                # Should generate a fallback dashboard
                assert os.path.exists(dashboard_path)

                with open(dashboard_path, 'r') as f:
                    content = f.read()

                assert "AetherAudit Security Dashboard" in content
                assert "Total Vulnerabilities" in content

            finally:
                if os.path.exists(dashboard_path):
                    os.unlink(dashboard_path)

    def test_excel_report_generation(self):
        """Test Excel report generation."""
        # Now that dependencies are available, test actual Excel generation
        try:
            import pandas as pd
            from openpyxl import Workbook

            generator = EnhancedReportGenerator()

            results = {
                "vulnerabilities": [
                    {"type": "reentrancy", "severity": "high", "confidence": 0.9, "description": "Test vuln"},
                    {"type": "access_control", "severity": "medium", "confidence": 0.8, "description": "Test vuln 2"}
                ],
                "execution_time": 5.5,
                "fixes": [{"title": "Fix reentrancy"}]
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.xlsx', delete=False) as f:
                excel_path = f.name

            try:
                generator.visualizer.generate_excel_report(results, excel_path)

                # Verify Excel file was created and is valid
                assert os.path.exists(excel_path)

                # Try to read the Excel file to verify it's valid
                df = pd.read_excel(excel_path, sheet_name='Summary')
                assert len(df) > 0  # Should have at least summary row

                # Check that vulnerabilities sheet exists
                df_vulns = pd.read_excel(excel_path, sheet_name='Vulnerabilities')
                assert len(df_vulns) == 2  # Should have 2 vulnerabilities

            finally:
                if os.path.exists(excel_path):
                    os.unlink(excel_path)

        except ImportError:
            pytest.skip("Pandas/openpyxl not available for Excel export testing")

    def test_pdf_report_generation(self):
        """Test PDF report generation."""
        # Now that dependencies are available, test actual PDF generation
        try:
            from reportlab.platypus import SimpleDocTemplate
            from reportlab.lib.pagesizes import letter

            generator = EnhancedReportGenerator()

            results = {
                "vulnerabilities": [
                    {"type": "reentrancy", "severity": "high", "confidence": 0.9, "description": "Test vuln"}
                ],
                "execution_time": 5.5,
                "fixes": [{"title": "Fix reentrancy"}]
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.pdf', delete=False) as f:
                pdf_path = f.name

            try:
                generator.visualizer.generate_pdf_report(results, pdf_path)

                # Verify PDF file was created
                assert os.path.exists(pdf_path)

                # Check that file has some content (PDF files have specific structure)
                with open(pdf_path, 'rb') as f:
                    content = f.read()
                    # PDF files start with %PDF-
                    assert content.startswith(b'%PDF-')

            finally:
                if os.path.exists(pdf_path):
                    os.unlink(pdf_path)

        except ImportError:
            pytest.skip("ReportLab not available for PDF export testing")

    def test_export_to_json(self):
        """Test JSON export functionality."""
        generator = EnhancedReportGenerator()

        results = {
            "vulnerabilities": [{"type": "test", "severity": "medium"}],
            "execution_time": 5.0
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json_path = f.name

        try:
            generator.export_to_json(results, json_path)

            # Should create valid JSON file
            assert os.path.exists(json_path)

            with open(json_path, 'r') as f:
                data = json.load(f)

            assert "metadata" in data
            assert "vulnerabilities" in data
            assert len(data["vulnerabilities"]) == 1

        finally:
            if os.path.exists(json_path):
                os.unlink(json_path)

    def test_export_to_xml(self):
        """Test XML export functionality."""
        generator = EnhancedReportGenerator()

        results = {
            "vulnerabilities": [{"type": "test", "severity": "medium"}],
            "execution_time": 5.0
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_path = f.name

        try:
            generator.export_to_xml(results, xml_path)

            # Should create XML file
            assert os.path.exists(xml_path)

            with open(xml_path, 'r') as f:
                content = f.read()

            assert "<aetheraudit_report>" in content
            assert "<item>" in content  # XML structure uses <item> tags for vulnerabilities

        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

class TestEnhancedReportGenerator:
    """Test cases for EnhancedReportGenerator."""

    def test_initialization(self):
        """Test EnhancedReportGenerator initialization."""
        generator = EnhancedReportGenerator()

        assert generator.risk_scorer is not None
        assert generator.compliance_reporter is not None
        assert generator.visualizer is not None

    def test_comprehensive_report_generation(self):
        """Test comprehensive report generation."""
        generator = EnhancedReportGenerator()

        results = {
            "vulnerabilities": [
                {"type": "reentrancy", "severity": "high", "confidence": 0.9, "description": "Test vuln"},
                {"type": "access_control", "severity": "medium", "confidence": 0.8, "description": "Test vuln 2"}
            ],
            "execution_time": 10.5,
            "fixes": [{"title": "Fix reentrancy"}]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            report_files = generator.generate_comprehensive_report(results, temp_dir, include_compliance=False)

            # Should return a dictionary structure
            assert isinstance(report_files, dict)

            # Should have basic report types
            expected_keys = ['markdown', 'dashboard', 'excel', 'pdf']
            for key in expected_keys:
                assert key in report_files

            # Check that files were actually created (where possible)
            for file_type, file_path in report_files.items():
                if file_path and file_path != 'N/A' and file_path != temp_dir + '/test.json' and file_path != temp_dir + '/test.xml':
                    assert os.path.exists(file_path), f"File {file_path} was not created"

    def test_risk_assessment_generation(self):
        """Test risk assessment generation."""
        generator = EnhancedReportGenerator()

        vulnerabilities = [
            {"severity": "critical", "type": "oracle_manipulation", "confidence": 0.95},
            {"severity": "high", "type": "reentrancy", "confidence": 0.9},
            {"severity": "medium", "type": "access_control", "confidence": 0.8},
            {"severity": "low", "type": "gas_optimization", "confidence": 0.7}
        ]

        assessment = generator.generate_risk_assessment(vulnerabilities)

        assert "prioritized_vulnerabilities" in assessment
        assert "risk_distribution" in assessment
        assert "overall_risk_level" in assessment
        assert "recommendations" in assessment

        # Should have 4 risk levels
        assert len(assessment["risk_distribution"]) == 4

        # Should be sorted by risk score
        prioritized = assessment["prioritized_vulnerabilities"]
        assert len(prioritized) == 4
        assert prioritized[0]["severity"] == "critical"  # Highest risk first

    def test_export_results_functionality(self):
        """Test export results functionality."""
        generator = EnhancedReportGenerator()

        results = {
            "vulnerabilities": [{"type": "test", "severity": "medium"}],
            "execution_time": 5.0
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            exported_files = generator.export_results(results, temp_dir, ['json', 'xml'])

            # Should export in requested formats
            assert 'json' in exported_files
            assert 'xml' in exported_files

            # Files should exist and be valid
            for format_type, file_path in exported_files.items():
                assert os.path.exists(file_path), f"{format_type} file was not created"

                if format_type == 'json':
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        assert "metadata" in data
                        assert "vulnerabilities" in data
                elif format_type == 'xml':
                    with open(file_path, 'r') as f:
                        content = f.read()
                        assert "<aetheraudit_report>" in content


if __name__ == '__main__':
    pytest.main([__file__])
