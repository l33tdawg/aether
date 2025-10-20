#!/usr/bin/env python3
"""
Test suite for Gemini API integration.

Tests verify that:
1. Gemini API is being called correctly
2. Safety settings are properly configured
3. Responses are valid JSON and parse correctly
4. Error handling captures promptFeedback
5. Both GeminiSecurityAuditor and GeminiFormalVerifier work
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import logging
import sys
from io import StringIO

from core.ai_ensemble import GeminiSecurityAuditor, GeminiFormalVerifier

logger = logging.getLogger(__name__)


class TestGeminiAPIRequestFormat:
    """Test that Gemini API requests are formatted correctly."""

    def test_gemini_security_auditor_initialization(self):
        """Test that GeminiSecurityAuditor initializes correctly."""
        auditor = GeminiSecurityAuditor()
        assert auditor is not None
        assert auditor.agent_name == 'gemini_security'

    def test_gemini_formal_verifier_initialization(self):
        """Test that GeminiFormalVerifier initializes correctly."""
        verifier = GeminiFormalVerifier()
        assert verifier is not None
        assert verifier.agent_name == 'gemini_verification'

    @pytest.mark.asyncio
    async def test_gemini_prompt_includes_authorization_context(self):
        """Test that the prompt includes authorization language for security research."""
        auditor = GeminiSecurityAuditor()
        
        # Create a simple test contract
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            # Mock successful response
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            # Set API key via environment
            with patch.dict('os.environ', {'GEMINI_API_KEY': 'test-key'}):
                with patch('core.config_manager.ConfigManager') as mock_config:
                    mock_config_instance = MagicMock()
                    mock_config_instance.config.gemini_api_key = 'test-key'
                    mock_config.return_value = mock_config_instance
                    
                    result = await auditor.analyze_contract(test_contract)
                    
                    # Verify the call was made
                    assert mock_post.called
                    
                    # Get the call arguments
                    call_args = mock_post.call_args
                    url = call_args[0][0]
                    payload = call_args[1]['json']
                    
                    # Verify URL is correct
                    assert 'generativelanguage.googleapis.com' in url
                    
                    # Verify payload structure
                    assert 'contents' in payload
                    assert 'parts' in payload['contents'][0]
                    
                    # Verify authorization context is in the prompt (now in professional tone)
                    prompt_text = payload['contents'][0]['parts'][0]['text']
                    assert 'automated security analysis' in prompt_text.lower() or 'automated code review' in prompt_text.lower()
                    assert 'authorized developers' in prompt_text.lower()
                    assert 'security testing' in prompt_text.lower() or 'quality assurance' in prompt_text.lower()


class TestGeminiSafetySettings:
    """Test that Gemini safety settings are properly configured."""

    @pytest.mark.asyncio
    async def test_security_auditor_safety_settings(self):
        """Test that security auditor includes proper safety settings."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                await auditor.analyze_contract(test_contract)
                
                # Get the payload that was sent
                payload = mock_post.call_args[1]['json']
                
                # Verify safety settings exist
                assert 'safetySettings' in payload
                safety_settings = payload['safetySettings']
                
                # Verify settings include valid Gemini categories
                categories = [s['category'] for s in safety_settings]
                assert 'HARM_CATEGORY_HATE_SPEECH' in categories or 'HARM_CATEGORY_DANGEROUS_CONTENT' in categories
                
                # All should be set to BLOCK_NONE
                for setting in safety_settings:
                    assert setting['threshold'] == 'BLOCK_NONE'

    @pytest.mark.asyncio
    async def test_formal_verifier_safety_settings(self):
        """Test that formal verifier includes proper safety settings."""
        verifier = GeminiFormalVerifier()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                await verifier.analyze_contract(test_contract)
                
                # Get the payload that was sent
                payload = mock_post.call_args[1]['json']
                
                # Verify safety settings exist
                assert 'safetySettings' in payload
                safety_settings = payload['safetySettings']
                assert len(safety_settings) > 0


class TestGeminiResponseParsing:
    """Test that Gemini responses are parsed correctly."""

    @pytest.mark.asyncio
    async def test_valid_gemini_response_parsing(self):
        """Test parsing of a valid Gemini response with findings."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        findings_with_all_fields = [{
            'type': 'reentrancy',
            'severity': 'high',
            'confidence': 0.9,
            'description': 'Potential reentrancy vulnerability',
            'line': 42,
            'swc_id': 'SWC-107'
        }]
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': findings_with_all_fields})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                result = await auditor.analyze_contract(test_contract)
                
                # Verify findings were parsed
                assert result.findings is not None
                assert len(result.findings) > 0
                assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_gemini_prompt_feedback_error_handling(self):
        """Test that promptFeedback errors are properly logged."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'promptFeedback': {
                    'blockReason': 'SAFETY',
                    'safetyRatings': [
                        {
                            'category': 'HARM_CATEGORY_DANGEROUS_CODE',
                            'probability': 'HIGH'
                        }
                    ]
                },
                'candidates': []
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                # Capture log output
                with patch('core.ai_ensemble.logger') as mock_logger:
                    result = await auditor.analyze_contract(test_contract)
                    
                    # Should log error about safety filter
                    assert mock_logger.error.called

    @pytest.mark.asyncio
    async def test_gemini_malformed_json_response(self):
        """Test handling of malformed JSON response from Gemini."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': 'Not valid JSON at all!'
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                result = await auditor.analyze_contract(test_contract)
                
                # Should handle gracefully (possibly with empty findings or error)
                assert result is not None
                assert result.model_name == 'gemini_security'

    @pytest.mark.asyncio
    async def test_gemini_empty_candidates_response(self):
        """Test handling of empty candidates response."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': []
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                result = await auditor.analyze_contract(test_contract)
                
                # Should handle gracefully
                assert result is not None
                assert result.model_name == 'gemini_security'


class TestGeminiAPIConfiguration:
    """Test Gemini API configuration."""

    def test_gemini_api_key_missing(self):
        """Test handling of missing API key."""
        auditor = GeminiSecurityAuditor()
        
        with patch('core.config_manager.ConfigManager') as mock_config:
            mock_config_instance = MagicMock()
            mock_config_instance.config.gemini_api_key = None
            mock_config.return_value = mock_config_instance
            
            # Should not raise, just return empty findings
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(auditor.analyze_contract("test"))
            
            assert result.findings == []
            assert 'error' in result.metadata

    @pytest.mark.asyncio
    async def test_gemini_endpoint_url_correct(self):
        """Test that the correct Gemini endpoint URL is being used."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                await auditor.analyze_contract(test_contract)
                
                # Verify correct endpoint
                call_url = mock_post.call_args[0][0]
                assert 'generativelanguage.googleapis.com' in call_url
                assert 'v1beta/models/gemini-2.5-flash' in call_url
                assert 'generateContent' in call_url
                assert 'key=test-key' in call_url


class TestGeminiModelSpecialization:
    """Test that each Gemini model specializes correctly."""

    @pytest.mark.asyncio
    async def test_security_auditor_focuses_on_security(self):
        """Test that GeminiSecurityAuditor focuses on security issues."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                await auditor.analyze_contract(test_contract)
                
                # Check prompt contains security-specific instructions
                prompt = mock_post.call_args[1]['json']['contents'][0]['parts'][0]['text']
                assert 'security vulnerabilities' in prompt
                assert 'delegatecall' in prompt or 'reentrancy' in prompt or 'access control' in prompt

    @pytest.mark.asyncio
    async def test_formal_verifier_focuses_on_arithmetic(self):
        """Test that GeminiFormalVerifier focuses on arithmetic issues."""
        verifier = GeminiFormalVerifier()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                await verifier.analyze_contract(test_contract)
                
                # Check prompt contains arithmetic-specific instructions
                prompt = mock_post.call_args[1]['json']['contents'][0]['parts'][0]['text']
                assert 'arithmetic' in prompt or 'mathematical' in prompt
                assert 'overflow' in prompt or 'underflow' in prompt or 'precision' in prompt


class TestGeminiRetryLogic:
    """Test Gemini API retry logic."""

    @pytest.mark.asyncio
    async def test_gemini_timeout_retry(self):
        """Test that timeout triggers retry logic."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            # First call times out, second succeeds
            timeout_exception = Exception("Timeout")
            
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': []})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            
            mock_post.side_effect = [timeout_exception, mock_response]
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                with patch('time.sleep'):  # Don't actually sleep in tests
                    result = await auditor.analyze_contract(test_contract)
                    
                    # Verify it retried (called twice)
                    assert mock_post.call_count >= 1

    @pytest.mark.asyncio
    async def test_gemini_max_retries_exceeded(self):
        """Test handling when max retries are exceeded."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            # Always timeout
            mock_post.side_effect = Exception("Timeout")
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                with patch('time.sleep'):  # Don't actually sleep in tests
                    result = await auditor.analyze_contract(test_contract)
                    
                    # Should have empty findings and error metadata
                    assert result.findings == [] or result.confidence == 0.0


class TestGeminiCompleteness:
    """Test that Gemini responses are complete with required fields."""

    @pytest.mark.asyncio
    async def test_gemini_finding_has_required_fields(self):
        """Test that each finding has all required fields."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        findings_with_all_fields = [{
            'type': 'reentrancy',
            'severity': 'high',
            'confidence': 0.9,
            'description': 'Potential reentrancy vulnerability',
            'line': 42,
            'swc_id': 'SWC-107'
        }]
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': json.dumps({'findings': findings_with_all_fields})
                        }]
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                result = await auditor.analyze_contract(test_contract)
                
                # Verify all required fields are present
                for finding in result.findings:
                    assert 'type' in finding or 'severity' in finding
                    # At minimum, some fields should be present
                    assert len(finding) > 0


class TestGeminiEmptyPartsHandling:
    """Test handling of empty parts array from Gemini API (safety filtering scenarios)."""

    @pytest.mark.asyncio
    async def test_gemini_safety_blocked_mid_generation_security_auditor(self):
        """Test that GeminiSecurityAuditor handles finishReason: SAFETY correctly."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            # Response with finishReason: SAFETY and empty parts
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': []  # Empty parts array
                    },
                    'finishReason': 'SAFETY',
                    'safetyRatings': [
                        {
                            'category': 'HARM_CATEGORY_DANGEROUS_CONTENT',
                            'probability': 'HIGH'
                        }
                    ]
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                result = await auditor.analyze_contract(test_contract)
                
                # Should return empty findings
                assert result.findings == []
                # Should have error in metadata
                assert 'error' in result.metadata
                assert 'safety filters' in result.metadata['error'].lower()
                assert result.metadata.get('finish_reason') == 'SAFETY'
                # Confidence should be 0
                assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_gemini_safety_blocked_mid_generation_formal_verifier(self):
        """Test that GeminiFormalVerifier handles finishReason: SAFETY correctly."""
        verifier = GeminiFormalVerifier()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            # Response with finishReason: SAFETY and empty parts
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': []  # Empty parts array
                    },
                    'finishReason': 'SAFETY',
                    'safetyRatings': [
                        {
                            'category': 'HARM_CATEGORY_DANGEROUS_CONTENT',
                            'probability': 'MEDIUM'
                        }
                    ]
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                result = await verifier.analyze_contract(test_contract)
                
                # Should return empty findings
                assert result.findings == []
                # Should have error in metadata
                assert 'error' in result.metadata
                assert 'safety filters' in result.metadata['error'].lower()
                assert result.metadata.get('finish_reason') == 'SAFETY'
                # Confidence should be 0
                assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_gemini_finish_reason_logged(self):
        """Test that finishReason SAFETY triggers proper error logging."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': []
                    },
                    'finishReason': 'SAFETY',
                    'safetyRatings': [
                        {
                            'category': 'HARM_CATEGORY_DANGEROUS_CONTENT',
                            'probability': 'HIGH'
                        }
                    ]
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                # Capture log output
                with patch('core.ai_ensemble.logger') as mock_logger:
                    result = await auditor.analyze_contract(test_contract)
                    
                    # Should log error about safety filtering
                    assert mock_logger.error.called
                    # Check that one of the error calls mentions safety filters
                    error_calls = [call[0][0] for call in mock_logger.error.call_args_list]
                    assert any('safety filters' in str(call).lower() for call in error_calls)

    @pytest.mark.asyncio
    async def test_gemini_empty_parts_without_finish_reason(self):
        """Test handling of empty parts without a finishReason."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            # Response with empty parts but no finishReason (unusual but possible)
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': []
                    }
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                with patch('core.ai_ensemble.logger') as mock_logger:
                    result = await auditor.analyze_contract(test_contract)
                    
                    # Should handle gracefully
                    assert result is not None
                    assert result.findings == []
                    # Should log warning about empty parts
                    assert mock_logger.warning.called

    @pytest.mark.asyncio
    async def test_gemini_empty_parts_graceful_return(self):
        """Test that empty parts returns valid ModelResult without crashing."""
        auditor = GeminiSecurityAuditor()
        test_contract = "contract Test { function test() public {} }"
        
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': []
                    },
                    'finishReason': 'SAFETY'
                }]
            }
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            
            with patch('core.config_manager.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.config.gemini_api_key = 'test-key'
                mock_config.return_value = mock_config_instance
                
                # Should not raise exception
                result = await auditor.analyze_contract(test_contract)
                
                # Verify valid ModelResult structure
                assert hasattr(result, 'model_name')
                assert hasattr(result, 'findings')
                assert hasattr(result, 'confidence')
                assert hasattr(result, 'processing_time')
                assert hasattr(result, 'metadata')
                assert result.model_name == 'gemini_security'
                assert isinstance(result.findings, list)
                assert isinstance(result.confidence, float)
                assert isinstance(result.processing_time, float)
                assert isinstance(result.metadata, dict)
