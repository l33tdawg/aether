#!/usr/bin/env python3
"""
Unit tests for enhanced performance optimizer.
"""

import pytest
import time
import gc
from unittest.mock import patch, MagicMock

from core.performance_optimizer import (
    PerformanceOptimizer,
    AsyncPerformanceOptimizer,
    OptimizationLevel,
    PerformanceMetrics,
    CacheEntry
)


class TestPerformanceOptimizer:
    """Test cases for PerformanceOptimizer."""

    def test_initialization_minimal(self):
        """Test initialization with minimal optimization level."""
        optimizer = PerformanceOptimizer(OptimizationLevel.MINIMAL)

        assert optimizer.optimization_level == OptimizationLevel.MINIMAL
        assert optimizer.max_workers == 2  # Should be min(2, cpu_count)

    def test_initialization_standard(self):
        """Test initialization with standard optimization level."""
        optimizer = PerformanceOptimizer(OptimizationLevel.STANDARD)

        assert optimizer.optimization_level == OptimizationLevel.STANDARD
        assert optimizer.max_workers >= 2

    def test_initialization_aggressive(self):
        """Test initialization with aggressive optimization level."""
        optimizer = PerformanceOptimizer(OptimizationLevel.AGGRESSIVE)

        assert optimizer.optimization_level == OptimizationLevel.AGGRESSIVE
        assert optimizer.max_workers >= 4

    def test_initialization_maximum(self):
        """Test initialization with maximum optimization level."""
        optimizer = PerformanceOptimizer(OptimizationLevel.MAXIMUM)

        assert optimizer.optimization_level == OptimizationLevel.MAXIMUM
        assert optimizer.max_workers >= 8

    def test_cache_operations(self):
        """Test cache get/put operations."""
        optimizer = PerformanceOptimizer()

        # Test cache miss
        result = optimizer.get_from_cache("test_key")
        assert result is None
        assert optimizer.cache_stats["misses"] == 1

        # Test cache put
        test_data = {"test": "data"}
        optimizer.put_to_cache("test_key", test_data)

        # Test cache hit
        result = optimizer.get_from_cache("test_key")
        assert result == test_data
        assert optimizer.cache_stats["hits"] == 1

    def test_cache_ttl_expiry(self):
        """Test cache TTL expiry."""
        optimizer = PerformanceOptimizer()

        # Put data with very short TTL
        test_data = {"test": "data"}
        optimizer.put_to_cache("test_key", test_data, ttl=0.1)  # 0.1 second TTL

        # Should get data immediately
        result = optimizer.get_from_cache("test_key")
        assert result == test_data

        # Wait for expiry
        time.sleep(0.2)

        # Should be expired now
        result = optimizer.get_from_cache("test_key")
        assert result is None

    def test_performance_monitoring(self):
        """Test performance monitoring functionality."""
        optimizer = PerformanceOptimizer()

        # Start monitoring
        metrics = optimizer.start_monitoring("test_operation")

        assert metrics.operation_name == "test_operation"
        assert metrics.start_time > 0
        assert metrics.end_time == 0
        assert metrics.duration == 0

        # Simulate some work
        time.sleep(0.01)

        # End monitoring
        optimizer.end_monitoring(metrics)

        assert metrics.end_time > metrics.start_time
        assert metrics.duration > 0

    def test_optimize_small_contract(self):
        """Test optimization for small contracts."""
        optimizer = PerformanceOptimizer()

        small_contract = "pragma solidity ^0.8.0;\ncontract Test {\n    function test() public {}\n}"

        result = optimizer.optimize_large_contract(small_contract)

        # Should return original content for small contracts
        assert result == small_contract

    def test_optimize_medium_contract(self):
        """Test optimization for medium contracts."""
        optimizer = PerformanceOptimizer()

        # Create medium-sized contract (around 5K lines)
        lines = []
        for i in range(5000):
            lines.append(f"    uint256 public var{i};")
        medium_contract = "pragma solidity ^0.8.0;\ncontract Test {\n" + "\n".join(lines) + "\n}"

        result = optimizer.optimize_large_contract(medium_contract)

        # Should process in chunks and return optimized content
        assert isinstance(result, str)
        assert len(result) > 0

    def test_optimize_large_contract(self):
        """Test optimization for large contracts."""
        optimizer = PerformanceOptimizer()

        # Create large contract (around 50K lines)
        lines = []
        for i in range(50000):
            lines.append(f"    uint256 public var{i};")
        large_contract = "pragma solidity ^0.8.0;\ncontract Test {\n" + "\n".join(lines) + "\n}"

        result = optimizer.optimize_large_contract(large_contract)

        # Should process in smaller chunks
        assert isinstance(result, str)
        assert len(result) > 0

    def test_optimize_mega_contract(self):
        """Test optimization for mega contracts (>100K lines)."""
        optimizer = PerformanceOptimizer()

        # Create mega contract (around 150K lines)
        lines = []
        for i in range(150000):
            lines.append(f"    uint256 public var{i};")
        mega_contract = "pragma solidity ^0.8.0;\ncontract Test {\n" + "\n".join(lines) + "\n}"

        result = optimizer.optimize_mega_contract(mega_contract)

        # Should use streaming approach for mega contracts
        assert isinstance(result, str)
        assert len(result) > 0

    def test_optimize_mega_contract_memory_limit(self):
        """Test mega contract optimization with memory limit."""
        optimizer = PerformanceOptimizer()

        # Create large contract
        lines = []
        for i in range(200000):
            lines.append(f"    uint256 public var{i};")
        mega_contract = "pragma solidity ^0.8.0;\ncontract Test {\n" + "\n".join(lines) + "\n}"

        # Test with low memory limit
        result = optimizer.optimize_mega_contract(mega_contract, max_memory_mb=100)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_analyze_contract_streaming(self):
        """Test streaming contract analysis."""
        optimizer = PerformanceOptimizer()

        # Create medium contract
        lines = []
        for i in range(5000):
            lines.append(f"    uint256 public var{i};")
        contract = "pragma solidity ^0.8.0;\ncontract Test {\n" + "\n".join(lines) + "\n}"

        # Mock analyzer function
        def mock_analyzer(content, chunk_id):
            return [f"result_{chunk_id}"]

        results = optimizer.analyze_contract_streaming(contract, mock_analyzer, chunk_size=1000)

        assert isinstance(results, list)
        assert len(results) > 0

    def test_memory_optimization(self):
        """Test memory optimization functionality."""
        optimizer = PerformanceOptimizer()

        # Create some cache entries to trigger cleanup
        for i in range(100):
            optimizer.put_to_cache(f"key_{i}", f"data_{i}")

        initial_cache_size = len(optimizer.cache)

        # Trigger memory optimization
        optimizer.optimize_memory_usage()

        # Cache should still exist but may be cleaned up
        assert len(optimizer.cache) <= initial_cache_size

    def test_aggressive_cleanup(self):
        """Test aggressive cleanup functionality."""
        optimizer = PerformanceOptimizer()

        # Fill cache
        for i in range(100):
            optimizer.put_to_cache(f"key_{i}", f"data_{i}")

        initial_cache_size = len(optimizer.cache)

        # Trigger aggressive cleanup
        optimizer._aggressive_cleanup()

        # Cache should be cleared
        assert len(optimizer.cache) == 0

    @pytest.mark.asyncio
    async def test_batch_processing(self):
        """Test batch processing functionality."""
        optimizer = PerformanceOptimizer()

        # Create test items
        items = [f"item_{i}" for i in range(50)]

        # Mock async processing function
        async def mock_process(item):
            return f"processed_{item}"

        results = await optimizer.batch_process(items, mock_process, batch_size=10)

        assert len(results) == 50
        assert all("processed_" in result for result in results)

    def test_performance_summary(self):
        """Test performance summary generation."""
        optimizer = PerformanceOptimizer()

        # Create some mock metrics
        metrics1 = PerformanceMetrics("test1", 0, 1, 1.0, 1000, 50.0)
        metrics2 = PerformanceMetrics("test2", 1, 2, 1.0, 2000, 60.0)

        optimizer.performance_metrics = [metrics1, metrics2]

        summary = optimizer.get_performance_summary()

        assert "summary" in summary
        assert "memory" in summary
        assert "cpu" in summary
        assert "cache" in summary
        assert "optimization" in summary

        assert summary["summary"]["total_operations"] == 2
        assert summary["summary"]["total_duration"] == 2.0

    def test_cache_stats(self):
        """Test cache statistics."""
        optimizer = PerformanceOptimizer()

        # Perform some cache operations
        optimizer.put_to_cache("key1", "data1")
        optimizer.get_from_cache("key1")  # Hit
        optimizer.get_from_cache("key2")  # Miss

        stats = optimizer.get_cache_stats()

        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["entries"] == 1  # Only key1 should remain

    def test_clear_cache(self):
        """Test cache clearing."""
        optimizer = PerformanceOptimizer()

        # Fill cache
        for i in range(10):
            optimizer.put_to_cache(f"key_{i}", f"data_{i}")

        assert len(optimizer.cache) == 10

        # Clear cache
        optimizer.clear_cache()

        assert len(optimizer.cache) == 0
        assert optimizer.cache_stats["hits"] == 0
        assert optimizer.cache_stats["misses"] == 0
        assert optimizer.cache_stats["evictions"] == 0

    def test_optimization_level_changes(self):
        """Test optimization level changes."""
        optimizer = PerformanceOptimizer(OptimizationLevel.MINIMAL)

        # Change to maximum
        optimizer.set_optimization_level(OptimizationLevel.MAXIMUM)

        assert optimizer.optimization_level == OptimizationLevel.MAXIMUM
        assert optimizer.max_workers >= 8


class TestAsyncPerformanceOptimizer:
    """Test cases for AsyncPerformanceOptimizer."""

    @pytest.mark.asyncio
    async def test_async_contract_analysis(self):
        """Test async contract analysis."""
        optimizer = AsyncPerformanceOptimizer()

        # Create test contracts
        contracts = [
            {"path": "test1.sol", "content": "contract Test1 {}"},
            {"path": "test2.sol", "content": "contract Test2 {}"}
        ]

        # Mock analyzer function
        async def mock_analyzer(path, content):
            return f"analyzed_{path}"

        results = await optimizer.analyze_contracts_async(contracts, mock_analyzer)

        assert len(results) == 2
        assert "analyzed_test1.sol" in results
        assert "analyzed_test2.sol" in results

    @pytest.mark.asyncio
    async def test_async_batch_processing(self):
        """Test async batch processing."""
        optimizer = AsyncPerformanceOptimizer()

        # Create test items
        items = [f"item_{i}" for i in range(20)]

        # Mock async processing function
        async def mock_process(item):
            return f"processed_{item}"

        results = await optimizer.batch_process_async(items, mock_process, batch_size=5)

        assert len(results) == 20
        assert all("processed_" in result for result in results)

    def test_performance_summary_delegation(self):
        """Test that performance summary is delegated to underlying optimizer."""
        optimizer = AsyncPerformanceOptimizer()

        # Mock the underlying optimizer's method
        optimizer.optimizer.get_performance_summary = MagicMock(return_value={"test": "summary"})

        summary = optimizer.get_performance_summary()
        assert summary == {"test": "summary"}

    def test_cache_stats_delegation(self):
        """Test that cache stats are delegated to underlying optimizer."""
        optimizer = AsyncPerformanceOptimizer()

        # Mock the underlying optimizer's method
        optimizer.optimizer.get_cache_stats = MagicMock(return_value={"test": "stats"})

        stats = optimizer.get_cache_stats()
        assert stats == {"test": "stats"}

    def test_clear_cache_delegation(self):
        """Test that cache clearing is delegated to underlying optimizer."""
        optimizer = AsyncPerformanceOptimizer()

        # Mock the underlying optimizer's method
        optimizer.optimizer.clear_cache = MagicMock()

        optimizer.clear_cache()
        optimizer.optimizer.clear_cache.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__])
