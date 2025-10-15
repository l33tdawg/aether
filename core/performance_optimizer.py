#!/usr/bin/env python3
"""
Performance Optimizer for AetherAudit

Implements performance optimizations including:
- Parallel analysis execution
- Result caching
- Large contract optimization
- Memory management
- Async processing
- Resource pooling
"""

import asyncio
import json
import pickle
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import threading
import queue
import gc
import psutil
import os


class OptimizationLevel(Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis operations."""
    operation_name: str
    start_time: float
    end_time: float
    duration: float
    memory_usage: int
    cpu_usage: float
    cache_hits: int = 0
    cache_misses: int = 0
    parallel_tasks: int = 0
    optimization_level: OptimizationLevel = OptimizationLevel.STANDARD


@dataclass
class CacheEntry:
    """Cache entry for analysis results."""
    key: str
    data: Any
    timestamp: float
    access_count: int
    size_bytes: int
    ttl: float = 3600  # 1 hour default TTL


class PerformanceOptimizer:
    """Performance optimizer for AetherAudit operations."""

    def __init__(self, optimization_level: OptimizationLevel = OptimizationLevel.STANDARD):
        self.optimization_level = optimization_level
        self.cache = {}
        self.cache_stats = {"hits": 0, "misses": 0, "evictions": 0}
        self.performance_metrics = []
        self.max_workers = self._calculate_optimal_workers()
        self.memory_limit = self._calculate_memory_limit()
        self.cache_size_limit = self._calculate_cache_size_limit()
        
        # Threading and async management
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self.process_pool = ProcessPoolExecutor(max_workers=min(4, self.max_workers))
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Performance monitoring
        self.monitoring_enabled = True
        self.metrics_lock = threading.Lock()
        
        # Cache management
        self.cache_lock = threading.Lock()
        self.cache_cleanup_interval = 300  # 5 minutes
        self.last_cache_cleanup = time.time()

    def _calculate_optimal_workers(self) -> int:
        """Calculate optimal number of workers based on system resources."""
        cpu_count = mp.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        if self.optimization_level == OptimizationLevel.MINIMAL:
            return min(2, cpu_count)
        elif self.optimization_level == OptimizationLevel.STANDARD:
            return min(4, cpu_count)
        elif self.optimization_level == OptimizationLevel.AGGRESSIVE:
            return min(8, cpu_count)
        else:  # MAXIMUM
            return min(16, cpu_count)

    def _calculate_memory_limit(self) -> int:
        """Calculate memory limit based on system resources."""
        total_memory = psutil.virtual_memory().total
        available_memory = psutil.virtual_memory().available
        
        if self.optimization_level == OptimizationLevel.MINIMAL:
            return min(1024**3, available_memory // 4)  # 1GB or 25% of available
        elif self.optimization_level == OptimizationLevel.STANDARD:
            return min(2 * 1024**3, available_memory // 2)  # 2GB or 50% of available
        elif self.optimization_level == OptimizationLevel.AGGRESSIVE:
            return min(4 * 1024**3, available_memory * 3 // 4)  # 4GB or 75% of available
        else:  # MAXIMUM
            return min(8 * 1024**3, available_memory)  # 8GB or all available

    def _calculate_cache_size_limit(self) -> int:
        """Calculate cache size limit based on memory limit."""
        return self.memory_limit // 4  # Use 25% of memory limit for cache

    def generate_cache_key(self, operation: str, inputs: Dict[str, Any]) -> str:
        """Generate cache key for operation and inputs."""
        # Create deterministic string from inputs
        input_str = json.dumps(inputs, sort_keys=True)
        
        # Generate hash
        hash_obj = hashlib.md5()
        hash_obj.update(f"{operation}:{input_str}".encode())
        
        return hash_obj.hexdigest()

    def get_from_cache(self, key: str) -> Optional[Any]:
        """Get data from cache."""
        with self.cache_lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check TTL
                if time.time() - entry.timestamp > entry.ttl:
                    del self.cache[key]
                    self.cache_stats["evictions"] += 1
                    self.cache_stats["misses"] += 1
                    return None
                
                # Update access count and timestamp
                entry.access_count += 1
                entry.timestamp = time.time()
                
                self.cache_stats["hits"] += 1
                return entry.data
            else:
                self.cache_stats["misses"] += 1
                return None

    def put_to_cache(self, key: str, data: Any, ttl: float = 3600) -> None:
        """Put data to cache."""
        with self.cache_lock:
            # Check cache size limit
            if self._get_cache_size() > self.cache_size_limit:
                self._evict_oldest_entries()
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                data=data,
                timestamp=time.time(),
                access_count=1,
                size_bytes=self._estimate_size(data),
                ttl=ttl
            )
            
            self.cache[key] = entry

    def _get_cache_size(self) -> int:
        """Get total cache size in bytes."""
        return sum(entry.size_bytes for entry in self.cache.values())

    def _estimate_size(self, data: Any) -> int:
        """Estimate size of data in bytes."""
        try:
            return len(pickle.dumps(data))
        except:
            return len(str(data).encode())

    def _evict_oldest_entries(self) -> None:
        """Evict oldest cache entries."""
        # Sort by access count and timestamp
        sorted_entries = sorted(
            self.cache.items(),
            key=lambda x: (x[1].access_count, x[1].timestamp)
        )
        
        # Remove oldest 25% of entries
        evict_count = len(sorted_entries) // 4
        for i in range(evict_count):
            key, _ = sorted_entries[i]
            del self.cache[key]
            self.cache_stats["evictions"] += 1

    def cleanup_cache(self) -> None:
        """Clean up expired cache entries."""
        current_time = time.time()
        
        if current_time - self.last_cache_cleanup < self.cache_cleanup_interval:
            return
        
        with self.cache_lock:
            expired_keys = []
            for key, entry in self.cache.items():
                if current_time - entry.timestamp > entry.ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
                self.cache_stats["evictions"] += 1
        
        self.last_cache_cleanup = current_time

    def start_monitoring(self, operation_name: str) -> PerformanceMetrics:
        """Start monitoring an operation."""
        metrics = PerformanceMetrics(
            operation_name=operation_name,
            start_time=time.time(),
            end_time=0,
            duration=0,
            memory_usage=psutil.Process().memory_info().rss,
            cpu_usage=psutil.Process().cpu_percent(),
            optimization_level=self.optimization_level
        )
        
        return metrics

    def end_monitoring(self, metrics: PerformanceMetrics) -> None:
        """End monitoring an operation."""
        metrics.end_time = time.time()
        metrics.duration = metrics.end_time - metrics.start_time
        metrics.memory_usage = psutil.Process().memory_info().rss
        metrics.cpu_usage = psutil.Process().cpu_percent()
        
        with self.metrics_lock:
            self.performance_metrics.append(metrics)

    async def parallel_analyze_contracts(self, contracts: List[Dict[str, Any]], analyzer_func) -> List[Any]:
        """Analyze multiple contracts in parallel."""
        metrics = self.start_monitoring("parallel_contract_analysis")
        
        try:
            # Create tasks for parallel execution
            tasks = []
            for contract in contracts:
                task = asyncio.create_task(
                    self._analyze_single_contract(contract, analyzer_func)
                )
                tasks.append(task)
            
            # Execute tasks in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            valid_results = [r for r in results if not isinstance(r, Exception)]
            
            metrics.parallel_tasks = len(tasks)
            return valid_results
            
        finally:
            self.end_monitoring(metrics)

    async def _analyze_single_contract(self, contract: Dict[str, Any], analyzer_func) -> Any:
        """Analyze a single contract with caching."""
        contract_path = contract.get("path", "")
        content = contract.get("content", "")
        
        # Generate cache key
        cache_key = self.generate_cache_key("contract_analysis", {
            "path": contract_path,
            "content_hash": hashlib.md5(content.encode()).hexdigest()
        })
        
        # Check cache first
        cached_result = self.get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
        
        # Perform analysis
        result = await analyzer_func(contract_path, content)
        
        # Cache result
        self.put_to_cache(cache_key, result)
        
        return result

    def optimize_large_contract(self, content: str) -> str:
        """Optimize analysis for large contracts."""
        metrics = self.start_monitoring("large_contract_optimization")

        try:
            # Split large contract into smaller chunks
            lines = content.split('\n')
            total_lines = len(lines)

            # Dynamic chunk sizing based on contract size
            if total_lines <= 1000:
                return content
            elif total_lines <= 10000:
                chunk_size = 500  # Smaller chunks for medium contracts
            elif total_lines <= 100000:
                chunk_size = 200  # Even smaller chunks for large contracts
            else:
                chunk_size = 100  # Very small chunks for massive contracts

            # Process chunks and merge results
            optimized_content = ""
            chunk_count = 0

            for i in range(0, total_lines, chunk_size):
                chunk = lines[i:i + chunk_size]
                optimized_content += '\n'.join(chunk) + '\n'

                chunk_count += 1

                # Progressive garbage collection based on contract size
                if total_lines <= 10000:
                    # GC every 5 chunks for medium contracts
                    if chunk_count % 5 == 0:
                        gc.collect()
                elif total_lines <= 100000:
                    # GC every 2 chunks for large contracts
                    if chunk_count % 2 == 0:
                        gc.collect()
                else:
                    # GC every chunk for massive contracts
                    gc.collect()

                # Force more aggressive cleanup for very large contracts
                if total_lines > 100000 and chunk_count % 10 == 0:
                    self._aggressive_cleanup()

            return optimized_content

        finally:
            self.end_monitoring(metrics)

    def optimize_mega_contract(self, content: str, max_memory_mb: int = 1024) -> str:
        """Specialized optimization for contracts >1M lines."""
        metrics = self.start_monitoring("mega_contract_optimization")

        try:
            lines = content.split('\n')
            total_lines = len(lines)

            if total_lines <= 100000:  # Use standard optimization for smaller contracts
                return self.optimize_large_contract(content)

            # For mega contracts, use streaming approach
            chunk_size = 50  # Very small chunks for memory efficiency
            optimized_content = ""
            chunk_count = 0

            # Monitor memory usage more aggressively
            memory_threshold = max_memory_mb * 1024 * 1024  # Convert to bytes

            for i in range(0, total_lines, chunk_size):
                chunk = lines[i:i + chunk_size]
                optimized_content += '\n'.join(chunk) + '\n'

                chunk_count += 1

                # Check memory usage and cleanup if needed
                current_memory = psutil.Process().memory_info().rss
                if current_memory > memory_threshold:
                    self._aggressive_cleanup()
                    # Wait a bit for memory to be freed
                    time.sleep(0.1)

                # GC every chunk for mega contracts
                gc.collect()

            return optimized_content

        finally:
            self.end_monitoring(metrics)

    def analyze_contract_streaming(self, content: str, analyzer_func, chunk_size: int = 1000) -> List[Any]:
        """Analyze contract in streaming fashion for memory efficiency."""
        metrics = self.start_monitoring("streaming_contract_analysis")

        try:
            lines = content.split('\n')
            total_lines = len(lines)
            results = []

            for i in range(0, total_lines, chunk_size):
                chunk = '\n'.join(lines[i:i + chunk_size])
                chunk_results = analyzer_func(chunk, f"chunk_{i//chunk_size}")

                # Filter out None results and extend main results
                if chunk_results:
                    if isinstance(chunk_results, list):
                        results.extend(chunk_results)
                    else:
                        results.append(chunk_results)

                # Memory management between chunks
                if i // chunk_size % 5 == 0:
                    gc.collect()

            return results

        finally:
            self.end_monitoring(metrics)

    def optimize_memory_usage(self) -> None:
        """Optimize memory usage."""
        metrics = self.start_monitoring("memory_optimization")
        
        try:
            # Force garbage collection
            gc.collect()
            
            # Clean up cache
            self.cleanup_cache()
            
            # Monitor memory usage
            memory_info = psutil.virtual_memory()
            if memory_info.percent > 80:  # If memory usage > 80%
                # Aggressive cleanup
                self._aggressive_cleanup()
            
        finally:
            self.end_monitoring(metrics)

    def _aggressive_cleanup(self) -> None:
        """Perform aggressive memory cleanup."""
        # Clear cache
        with self.cache_lock:
            self.cache.clear()
        
        # Force garbage collection multiple times
        for _ in range(3):
            gc.collect()
        
        # Clear performance metrics (keep only recent ones)
        with self.metrics_lock:
            if len(self.performance_metrics) > 1000:
                self.performance_metrics = self.performance_metrics[-500:]

    async def batch_process(self, items: List[Any], process_func, batch_size: int = 10) -> List[Any]:
        """Process items in batches to optimize performance."""
        metrics = self.start_monitoring("batch_processing")
        
        try:
            results = []
            
            # Process items in batches
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                
                # Process batch
                batch_results = await asyncio.gather(
                    *[process_func(item) for item in batch],
                    return_exceptions=True
                )
                
                # Filter out exceptions
                valid_results = [r for r in batch_results if not isinstance(r, Exception)]
                results.extend(valid_results)
                
                # Memory optimization between batches
                if i % (batch_size * 5) == 0:
                    self.optimize_memory_usage()
            
            return results
            
        finally:
            self.end_monitoring(metrics)

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        with self.metrics_lock:
            if not self.performance_metrics:
                return {"error": "No performance metrics available"}
            
            # Calculate summary statistics
            total_duration = sum(m.duration for m in self.performance_metrics)
            avg_duration = total_duration / len(self.performance_metrics)
            max_duration = max(m.duration for m in self.performance_metrics)
            min_duration = min(m.duration for m in self.performance_metrics)
            
            total_memory = sum(m.memory_usage for m in self.performance_metrics)
            avg_memory = total_memory / len(self.performance_metrics)
            max_memory = max(m.memory_usage for m in self.performance_metrics)
            
            total_cpu = sum(m.cpu_usage for m in self.performance_metrics)
            avg_cpu = total_cpu / len(self.performance_metrics)
            max_cpu = max(m.cpu_usage for m in self.performance_metrics)
            
            # Cache statistics
            total_cache_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
            cache_hit_rate = (self.cache_stats["hits"] / total_cache_requests * 100) if total_cache_requests > 0 else 0
            
            return {
                "summary": {
                    "total_operations": len(self.performance_metrics),
                    "total_duration": total_duration,
                    "avg_duration": avg_duration,
                    "max_duration": max_duration,
                    "min_duration": min_duration
                },
                "memory": {
                    "avg_memory_usage": avg_memory,
                    "max_memory_usage": max_memory,
                    "memory_limit": self.memory_limit
                },
                "cpu": {
                    "avg_cpu_usage": avg_cpu,
                    "max_cpu_usage": max_cpu
                },
                "cache": {
                    "hits": self.cache_stats["hits"],
                    "misses": self.cache_stats["misses"],
                    "evictions": self.cache_stats["evictions"],
                    "hit_rate": cache_hit_rate,
                    "cache_size": self._get_cache_size(),
                    "cache_limit": self.cache_size_limit
                },
                "optimization": {
                    "level": self.optimization_level.value,
                    "max_workers": self.max_workers,
                    "memory_limit": self.memory_limit
                }
            }

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "hits": self.cache_stats["hits"],
            "misses": self.cache_stats["misses"],
            "evictions": self.cache_stats["evictions"],
            "size": self._get_cache_size(),
            "limit": self.cache_size_limit,
            "entries": len(self.cache)
        }

    def clear_cache(self) -> None:
        """Clear all cache entries."""
        with self.cache_lock:
            self.cache.clear()
            self.cache_stats = {"hits": 0, "misses": 0, "evictions": 0}

    def set_optimization_level(self, level: OptimizationLevel) -> None:
        """Set optimization level."""
        self.optimization_level = level
        self.max_workers = self._calculate_optimal_workers()
        self.memory_limit = self._calculate_memory_limit()
        self.cache_size_limit = self._calculate_cache_size_limit()

    def shutdown(self) -> None:
        """Shutdown optimizer and cleanup resources."""
        # Shutdown thread pools
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)
        
        # Clear cache
        self.clear_cache()
        
        # Clear performance metrics
        with self.metrics_lock:
            self.performance_metrics.clear()

    def __del__(self):
        """Destructor to ensure cleanup."""
        self.shutdown()


class AsyncPerformanceOptimizer:
    """Async version of performance optimizer for better async integration."""

    def __init__(self, optimization_level: OptimizationLevel = OptimizationLevel.STANDARD):
        self.optimizer = PerformanceOptimizer(optimization_level)
        self.semaphore = asyncio.Semaphore(self.optimizer.max_workers)

    async def analyze_contracts_async(self, contracts: List[Dict[str, Any]], analyzer_func) -> List[Any]:
        """Analyze contracts asynchronously with rate limiting."""
        async def analyze_with_semaphore(contract):
            async with self.semaphore:
                return await self.optimizer._analyze_single_contract(contract, analyzer_func)
        
        tasks = [analyze_with_semaphore(contract) for contract in contracts]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def batch_process_async(self, items: List[Any], process_func, batch_size: int = 10) -> List[Any]:
        """Process items asynchronously in batches."""
        return await self.optimizer.batch_process(items, process_func, batch_size)

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        return self.optimizer.get_performance_summary()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.optimizer.get_cache_stats()

    def clear_cache(self) -> None:
        """Clear cache."""
        self.optimizer.clear_cache()

    def shutdown(self) -> None:
        """Shutdown optimizer."""
        self.optimizer.shutdown()


# Global optimizer instance
_global_optimizer: Optional[PerformanceOptimizer] = None


def get_global_optimizer() -> PerformanceOptimizer:
    """Get global optimizer instance."""
    global _global_optimizer
    if _global_optimizer is None:
        _global_optimizer = PerformanceOptimizer()
    return _global_optimizer


def set_global_optimizer(optimizer: PerformanceOptimizer) -> None:
    """Set global optimizer instance."""
    global _global_optimizer
    _global_optimizer = optimizer


def cleanup_global_optimizer() -> None:
    """Cleanup global optimizer."""
    global _global_optimizer
    if _global_optimizer is not None:
        _global_optimizer.shutdown()
        _global_optimizer = None
