#!/usr/bin/env python3
"""
Integration tests for Protocol-Level Protection Detector

Tests the complete integration with ValidationPipeline and LLMFalsePositiveFilter
to ensure no breaking changes.
"""

import pytest
import tempfile
from pathlib import Path

from core.validation_pipeline import ValidationPipeline
from core.protocol_protection_detector import ProtocolProtectionDetector


class TestProtocolProtectionIntegration:
    """Integration tests for protocol protection detector."""
    
    def test_validation_pipeline_with_protocol_protection(self):
        """Test that ValidationPipeline works with protocol protection enabled."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract ZetaConnectorEth {
            event ZetaSent(uint256 destinationChainId, bytes destinationAddress);
            
            function send(uint256 destinationChainId, bytes memory destinationAddress) external {
                emit ZetaSent(destinationChainId, destinationAddress);
            }
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'missing_input_validation',
            'description': 'Missing destinationChainId validation',
            'severity': 'high',
            'contract_name': 'ZetaConnectorEth',
            'line': 6
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            
            # Create observer file
            observer_dir = project_dir / 'zetaclient' / 'observer'
            observer_dir.mkdir(parents=True)
            observer_file = observer_dir / 'inbound.go'
            observer_file.write_text("""
            package observer
            
            func buildInboundVoteMsgForZetaSentEvent(event ZetaSentEvent) *VoteMsg {
                if event.DestinationChainId == 0 {
                    return nil
                }
                return &VoteMsg{}
            }
            """)
            
            pipeline = ValidationPipeline(project_dir, contract_code)
            stages = pipeline.validate(vulnerability)
            
            # Should complete without errors
            assert isinstance(stages, list)
            assert len(stages) > 0
    
    def test_protocol_protection_disabled(self):
        """Test that system works when protocol protection is disabled."""
        contract_code = "contract Test {}"
        vulnerability = {
            'vulnerability_type': 'test',
            'severity': 'low'
        }
        
        # Disable via detector
        detector = ProtocolProtectionDetector(enabled=False)
        result = detector.validate_finding(vulnerability, contract_code)
        assert result is None
        
        # Pipeline should still work
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        assert isinstance(stages, list)
    
    def test_no_project_root_handling(self):
        """Test that system handles missing project root gracefully."""
        contract_code = "contract Test {}"
        vulnerability = {
            'vulnerability_type': 'test',
            'severity': 'low'
        }
        
        pipeline = ValidationPipeline(None, contract_code)
        stages = pipeline.validate(vulnerability)
        
        # Should work without project root
        assert isinstance(stages, list)
        assert len(stages) > 0
    
    def test_legacy_contract_detection_integration(self):
        """Test legacy contract detection in full pipeline."""
        contract_code = """
        /// @deprecated Use V2 instead
        contract ZetaConnectorEthV1 {
            function send() external {}
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'missing_input_validation',
            'description': 'Missing validation',
            'severity': 'high',
            'contract_name': 'ZetaConnectorEthV1'
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pipeline = ValidationPipeline(project_dir, contract_code)
            stages = pipeline.validate(vulnerability)
            
            # Should complete
            assert isinstance(stages, list)
    
    def test_observer_detection_integration(self):
        """Test observer detection in full pipeline."""
        contract_code = """
        contract Bridge {
            event CrossChainSent(uint256 chainId);
        }
        """
        
        vulnerability = {
            'vulnerability_type': 'missing_input_validation',
            'description': 'Missing chainId validation',
            'severity': 'high'
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            
            # Create observer
            observer_file = project_dir / 'observer.go'
            observer_file.write_text("func validate(chainId uint256) bool { return chainId != 0 }")
            
            pipeline = ValidationPipeline(project_dir, contract_code)
            stages = pipeline.validate(vulnerability)
            
            # Should complete
            assert isinstance(stages, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

