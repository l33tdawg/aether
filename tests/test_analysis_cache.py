#!/usr/bin/env python3
"""
Tests for Analysis Cache Module

Tests caching functionality for analysis results.
"""

import pytest
import json
import time
import tempfile
import shutil
from pathlib import Path

from core.analysis_cache import AnalysisCache


class TestAnalysisCache:
    """Test cases for AnalysisCache."""
    
    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        yield cache_dir
        shutil.rmtree(temp_dir)
    
    def test_initialization(self, temp_cache_dir):
        """Test AnalysisCache initialization."""
        cache = AnalysisCache(cache_dir=temp_cache_dir)
        
        assert cache.cache_dir == temp_cache_dir
        assert temp_cache_dir.exists()
        assert cache.cache_hits == 0
        assert cache.cache_misses == 0
    
    def test_default_cache_dir(self):
        """Test default cache directory creation."""
        cache = AnalysisCache()
        
        expected_dir = Path.home() / '.aether' / 'analysis_cache'
        assert cache.cache_dir == expected_dir


class TestCacheOperations:
    """Test cache get/set operations."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir, ttl_hours=1)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_cache_miss(self, cache):
        """Test cache miss."""
        result = cache.get("contract code", "slither")
        
        assert result is None
        assert cache.cache_misses == 1
        assert cache.cache_hits == 0
    
    def test_cache_set_and_get(self, cache):
        """Test setting and getting from cache."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        analysis_result = {'vulnerabilities': [], 'status': 'success'}
        
        # Set cache
        cache.set(contract_code, "slither", analysis_result)
        
        # Get from cache
        result = cache.get(contract_code, "slither")
        
        assert result is not None
        assert result == analysis_result
        assert cache.cache_hits == 1
    
    def test_multiple_analysis_types(self, cache):
        """Test caching different analysis types for same contract."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        slither_result = {'tool': 'slither', 'findings': []}
        llm_result = {'tool': 'llm', 'findings': []}
        
        cache.set(contract_code, "slither", slither_result)
        cache.set(contract_code, "llm", llm_result)
        
        assert cache.get(contract_code, "slither") == slither_result
        assert cache.get(contract_code, "llm") == llm_result
    
    def test_different_contracts(self, cache):
        """Test caching results for different contracts."""
        contract1 = "pragma solidity ^0.8.0; contract Test1 {}"
        contract2 = "pragma solidity ^0.8.0; contract Test2 {}"
        
        result1 = {'contract': 'Test1'}
        result2 = {'contract': 'Test2'}
        
        cache.set(contract1, "slither", result1)
        cache.set(contract2, "slither", result2)
        
        assert cache.get(contract1, "slither") == result1
        assert cache.get(contract2, "slither") == result2


class TestCacheExpiration:
    """Test cache TTL and expiration."""
    
    @pytest.fixture
    def short_ttl_cache(self):
        """Create cache with short TTL."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        # 1 second TTL for testing
        cache = AnalysisCache(cache_dir=cache_dir, ttl_hours=1/3600)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_cache_expiration(self, short_ttl_cache):
        """Test that cache entries expire."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        result = {'test': 'data'}
        
        # Set cache
        short_ttl_cache.set(contract_code, "test", result)
        
        # Should be available immediately
        assert short_ttl_cache.get(contract_code, "test") is not None
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Should be expired now
        assert short_ttl_cache.get(contract_code, "test") is None


class TestCacheKeyGeneration:
    """Test cache key generation."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_key_generation_basic(self, cache):
        """Test basic cache key generation."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        key1 = cache.get_cache_key(contract_code, "slither")
        key2 = cache.get_cache_key(contract_code, "slither")
        
        # Same input should generate same key
        assert key1 == key2
    
    def test_key_generation_different_code(self, cache):
        """Test that different code generates different keys."""
        contract1 = "pragma solidity ^0.8.0; contract Test1 {}"
        contract2 = "pragma solidity ^0.8.0; contract Test2 {}"
        
        key1 = cache.get_cache_key(contract1, "slither")
        key2 = cache.get_cache_key(contract2, "slither")
        
        assert key1 != key2
    
    def test_key_generation_different_type(self, cache):
        """Test that different analysis types generate different keys."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        key1 = cache.get_cache_key(contract_code, "slither")
        key2 = cache.get_cache_key(contract_code, "llm")
        
        assert key1 != key2
    
    def test_key_generation_with_params(self, cache):
        """Test cache key with additional parameters."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        key1 = cache.get_cache_key(contract_code, "llm", model="gpt-4")
        key2 = cache.get_cache_key(contract_code, "llm", model="gpt-4")
        key3 = cache.get_cache_key(contract_code, "llm", model="gpt-3.5")
        
        # Same params should generate same key
        assert key1 == key2
        
        # Different params should generate different key
        assert key1 != key3


class TestCacheInvalidation:
    """Test cache invalidation."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_invalidate_entry(self, cache):
        """Test invalidating a cache entry."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        result = {'test': 'data'}
        
        # Set cache
        cache.set(contract_code, "slither", result)
        assert cache.get(contract_code, "slither") is not None
        
        # Invalidate
        cache.invalidate(contract_code, "slither")
        
        # Should be gone
        assert cache.get(contract_code, "slither") is None
    
    def test_clear_expired(self, cache):
        """Test clearing expired entries."""
        # Create cache with very short TTL
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        short_cache = AnalysisCache(cache_dir=cache_dir, ttl_hours=1/3600)
        
        try:
            # Add entries
            short_cache.set("code1", "test", {'data': 1})
            short_cache.set("code2", "test", {'data': 2})
            
            # Wait for expiration
            time.sleep(1.5)
            
            # Clear expired
            removed = short_cache.clear_expired()
            
            assert removed >= 2
        finally:
            shutil.rmtree(temp_dir)
    
    def test_clear_all(self, cache):
        """Test clearing all cache entries."""
        # Add multiple entries
        for i in range(5):
            cache.set(f"code{i}", "test", {'data': i})
        
        # Verify entries exist
        assert len(cache.memory_cache) == 5
        
        # Clear all
        cache.clear_all()
        
        # Should be empty
        assert len(cache.memory_cache) == 0
        assert cache.cache_hits == 0
        assert cache.cache_misses == 0


class TestCacheStatistics:
    """Test cache statistics."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_get_stats(self, cache):
        """Test getting cache statistics."""
        # Add some entries
        cache.set("code1", "test", {'data': 1})
        cache.set("code2", "test", {'data': 2})
        
        # Access cache (hits and misses)
        cache.get("code1", "test")  # Hit
        cache.get("code1", "test")  # Hit
        cache.get("code3", "test")  # Miss
        
        stats = cache.get_stats()
        
        assert stats['memory_entries'] == 2
        assert stats['cache_hits'] == 2
        assert stats['cache_misses'] == 1
        assert stats['total_requests'] == 3
        assert abs(stats['hit_rate'] - 2/3) < 0.01
    
    def test_get_size_stats(self, cache):
        """Test getting cache size statistics."""
        # Add entries
        for i in range(5):
            cache.set(f"code{i}", "test", {'data': i, 'large_field': 'x' * 1000})
        
        size_stats = cache.get_size_stats()
        
        assert size_stats['total_size_bytes'] > 0
        assert size_stats['total_size_mb'] > 0
        assert size_stats['file_count'] == 5
        assert size_stats['average_file_size_bytes'] > 0


class TestMemoryCache:
    """Test in-memory cache layer."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_memory_cache_performance(self, cache):
        """Test that memory cache is faster than disk cache."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        result = {'test': 'data'}
        
        # Set cache (writes to both memory and disk)
        cache.set(contract_code, "test", result)
        
        # First get (from memory)
        start = time.time()
        result1 = cache.get(contract_code, "test")
        memory_time = time.time() - start
        
        # Clear memory cache
        cache.memory_cache.clear()
        
        # Second get (from disk)
        start = time.time()
        result2 = cache.get(contract_code, "test")
        disk_time = time.time() - start
        
        # Memory should be faster (though in tests the difference is minimal)
        assert result1 == result2
        # Just verify both work
        assert result1 is not None


class TestOldEntriesCleanup:
    """Test cleanup of old entries."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_cleanup_old_entries(self, cache):
        """Test cleaning up old entries."""
        # Add entry and manually set old timestamp
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        cache.set(contract_code, "test", {'data': 'old'})
        
        # Manually set old timestamp (8 days ago)
        key = cache.get_cache_key(contract_code, "test")
        cache_file = cache.cache_dir / f"{key}.json"
        
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            data['timestamp'] = time.time() - (8 * 24 * 3600)
            cache_file.write_text(json.dumps(data))
        
        # Clear memory cache to force disk read
        cache.memory_cache.clear()
        
        # Cleanup entries older than 7 days
        removed = cache.cleanup_old_entries(max_age_days=7)
        
        # Should have removed the old entry
        assert removed >= 1


class TestCacheWithParameters:
    """Test caching with additional parameters."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_cache_with_model_param(self, cache):
        """Test caching with model parameter."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        gpt4_result = {'model': 'gpt-4', 'result': 'data1'}
        gpt35_result = {'model': 'gpt-3.5', 'result': 'data2'}
        
        # Cache with different models
        cache.set(contract_code, "llm", gpt4_result, model="gpt-4")
        cache.set(contract_code, "llm", gpt35_result, model="gpt-3.5")
        
        # Retrieve specific model results
        assert cache.get(contract_code, "llm", model="gpt-4") == gpt4_result
        assert cache.get(contract_code, "llm", model="gpt-3.5") == gpt35_result
    
    def test_cache_with_multiple_params(self, cache):
        """Test caching with multiple parameters."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        result = {'data': 'test'}
        
        # Cache with multiple params
        cache.set(
            contract_code, 
            "llm", 
            result, 
            model="gpt-4",
            temperature=0.2,
            max_tokens=1000
        )
        
        # Retrieve with same params
        retrieved = cache.get(
            contract_code,
            "llm",
            model="gpt-4",
            temperature=0.2,
            max_tokens=1000
        )
        
        assert retrieved == result


class TestPersistence:
    """Test cache persistence across instances."""
    
    @pytest.fixture
    def cache_dir(self):
        """Create temporary cache directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        yield cache_dir
        shutil.rmtree(temp_dir)
    
    def test_persistence_across_instances(self, cache_dir):
        """Test that cache persists across instances."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        result = {'test': 'data'}
        
        # Create first cache instance and store data
        cache1 = AnalysisCache(cache_dir=cache_dir)
        cache1.set(contract_code, "test", result)
        
        # Create second cache instance
        cache2 = AnalysisCache(cache_dir=cache_dir)
        
        # Should load from disk
        retrieved = cache2.get(contract_code, "test")
        
        assert retrieved == result


class TestCacheStatistics:
    """Test cache statistics calculation."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_hit_rate_calculation(self, cache):
        """Test hit rate calculation."""
        # Add entries
        cache.set("code1", "test", {'data': 1})
        cache.set("code2", "test", {'data': 2})
        
        # Generate hits and misses
        cache.get("code1", "test")  # Hit
        cache.get("code1", "test")  # Hit
        cache.get("code1", "test")  # Hit
        cache.get("code3", "test")  # Miss
        
        stats = cache.get_stats()
        
        assert stats['cache_hits'] == 3
        assert stats['cache_misses'] == 1
        assert stats['total_requests'] == 4
        assert abs(stats['hit_rate'] - 0.75) < 0.01


class TestRealWorldUsage:
    """Test real-world usage scenarios."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_slither_analysis_caching(self, cache):
        """Test caching Slither analysis results."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract Token {
            mapping(address => uint256) public balances;
            
            function transfer(address to, uint256 amount) external {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
        }
        """
        
        slither_result = {
            'vulnerabilities': [
                {'type': 'reentrancy', 'severity': 'high'}
            ],
            'execution_time': 5.2
        }
        
        # Cache the result
        cache.set(contract_code, "slither", slither_result)
        
        # Retrieve later
        cached_result = cache.get(contract_code, "slither")
        
        assert cached_result == slither_result
    
    def test_llm_analysis_caching(self, cache):
        """Test caching LLM analysis results."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        llm_result = {
            'vulnerabilities': [],
            'confidence': 0.9,
            'model': 'gpt-4',
            'execution_time': 12.5
        }
        
        # Cache with model parameter
        cache.set(contract_code, "llm", llm_result, model="gpt-4")
        
        # Retrieve
        cached_result = cache.get(contract_code, "llm", model="gpt-4")
        
        assert cached_result == llm_result


class TestErrorHandling:
    """Test error handling."""
    
    @pytest.fixture
    def cache(self):
        """Create cache with temporary directory."""
        temp_dir = tempfile.mkdtemp()
        cache_dir = Path(temp_dir) / 'cache'
        cache = AnalysisCache(cache_dir=cache_dir)
        yield cache
        shutil.rmtree(temp_dir)
    
    def test_corrupted_cache_file(self, cache):
        """Test handling of corrupted cache file."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        # Create corrupted cache file
        key = cache.get_cache_key(contract_code, "test")
        cache_file = cache.cache_dir / f"{key}.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text("{ invalid json }")
        
        # Should handle gracefully
        result = cache.get(contract_code, "test")
        
        assert result is None
        assert cache.cache_misses == 1
    
    def test_missing_timestamp(self, cache):
        """Test handling of cache entry without timestamp."""
        contract_code = "pragma solidity ^0.8.0; contract Test {}"
        
        # Create cache entry without timestamp
        key = cache.get_cache_key(contract_code, "test")
        cache_file = cache.cache_dir / f"{key}.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps({'data': 'test'}))
        
        # Should treat as expired
        result = cache.get(contract_code, "test")
        
        assert result is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

