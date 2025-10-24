#!/usr/bin/env python3
"""
Smart Caching for Analysis Results

Caches analysis results to avoid redundant work and improve performance.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta


class AnalysisCache:
    """Cache analysis results to avoid redundant work."""
    
    def __init__(self, cache_dir: Optional[Path] = None, ttl_hours: int = 24):
        """
        Initialize analysis cache.
        
        Args:
            cache_dir: Directory to store cache files
            ttl_hours: Time-to-live for cache entries in hours
        """
        self.cache_dir = cache_dir or (Path.home() / '.aether' / 'analysis_cache')
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        
        # In-memory cache for frequently accessed items
        self.memory_cache: Dict[str, Any] = {}
        self.cache_hits = 0
        self.cache_misses = 0
    
    def get_cache_key(self, contract_code: str, analysis_type: str, **kwargs) -> str:
        """
        Generate cache key from contract code + analysis type + additional params.
        
        Args:
            contract_code: Contract source code
            analysis_type: Type of analysis (e.g., 'slither', 'llm', 'arithmetic')
            **kwargs: Additional parameters to include in cache key
        
        Returns:
            Unique cache key string
        """
        # Create hash from contract code
        content_hash = hashlib.sha256(contract_code.encode('utf-8')).hexdigest()[:16]
        
        # Include additional parameters in hash if provided
        if kwargs:
            params_str = json.dumps(kwargs, sort_keys=True)
            params_hash = hashlib.md5(params_str.encode('utf-8')).hexdigest()[:8]
            return f"{analysis_type}_{content_hash}_{params_hash}"
        
        return f"{analysis_type}_{content_hash}"
    
    def get(self, contract_code: str, analysis_type: str, **kwargs) -> Optional[Dict[Any, Any]]:
        """
        Retrieve cached analysis result.
        
        Args:
            contract_code: Contract source code
            analysis_type: Type of analysis
            **kwargs: Additional parameters used in cache key
        
        Returns:
            Cached result dict or None if not found/expired
        """
        key = self.get_cache_key(contract_code, analysis_type, **kwargs)
        
        # Check memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if not self._is_expired(entry):
                self.cache_hits += 1
                return entry['data']
            else:
                # Remove expired entry
                del self.memory_cache[key]
        
        # Check disk cache
        cache_file = self.cache_dir / f"{key}.json"
        
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding='utf-8'))
                
                # Check if expired
                if self._is_expired(data):
                    cache_file.unlink()
                    self.cache_misses += 1
                    return None
                
                # Add to memory cache
                self.memory_cache[key] = data
                self.cache_hits += 1
                return data['data']
                
            except Exception:
                self.cache_misses += 1
                return None
        
        self.cache_misses += 1
        return None
    
    def set(
        self, 
        contract_code: str, 
        analysis_type: str, 
        result: Dict[Any, Any],
        **kwargs
    ):
        """
        Store analysis result in cache.
        
        Args:
            contract_code: Contract source code
            analysis_type: Type of analysis
            result: Analysis result to cache
            **kwargs: Additional parameters used in cache key
        """
        key = self.get_cache_key(contract_code, analysis_type, **kwargs)
        
        cache_entry = {
            'data': result,
            'timestamp': time.time(),
            'analysis_type': analysis_type,
            'cached_at': datetime.now().isoformat()
        }
        
        # Store in memory cache
        self.memory_cache[key] = cache_entry
        
        # Store in disk cache
        cache_file = self.cache_dir / f"{key}.json"
        try:
            cache_file.write_text(
                json.dumps(cache_entry, indent=2),
                encoding='utf-8'
            )
        except Exception as e:
            print(f"Warning: Failed to write cache file: {e}")
    
    def _is_expired(self, cache_entry: Dict) -> bool:
        """Check if cache entry is expired."""
        if 'timestamp' not in cache_entry:
            return True
        
        age = time.time() - cache_entry['timestamp']
        return age > self.ttl_seconds
    
    def invalidate(self, contract_code: str, analysis_type: str, **kwargs):
        """
        Invalidate a specific cache entry.
        
        Args:
            contract_code: Contract source code
            analysis_type: Type of analysis
            **kwargs: Additional parameters
        """
        key = self.get_cache_key(contract_code, analysis_type, **kwargs)
        
        # Remove from memory cache
        if key in self.memory_cache:
            del self.memory_cache[key]
        
        # Remove from disk cache
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            cache_file.unlink()
    
    def clear_expired(self):
        """Clear all expired cache entries."""
        expired_count = 0
        
        # Clear expired from memory cache
        expired_keys = [
            key for key, entry in self.memory_cache.items()
            if self._is_expired(entry)
        ]
        for key in expired_keys:
            del self.memory_cache[key]
            expired_count += 1
        
        # Clear expired from disk cache
        for cache_file in self.cache_dir.glob('*.json'):
            try:
                data = json.loads(cache_file.read_text(encoding='utf-8'))
                if self._is_expired(data):
                    cache_file.unlink()
                    expired_count += 1
            except Exception:
                continue
        
        return expired_count
    
    def clear_all(self):
        """Clear all cache entries."""
        # Clear memory cache
        self.memory_cache.clear()
        
        # Clear disk cache
        for cache_file in self.cache_dir.glob('*.json'):
            try:
                cache_file.unlink()
            except Exception:
                continue
        
        # Reset stats
        self.cache_hits = 0
        self.cache_misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        disk_entries = len(list(self.cache_dir.glob('*.json')))
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = self.cache_hits / total_requests if total_requests > 0 else 0.0
        
        return {
            'memory_entries': len(self.memory_cache),
            'disk_entries': disk_entries,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'hit_rate': hit_rate,
            'hit_rate_percentage': f"{hit_rate * 100:.1f}%",
            'total_requests': total_requests
        }
    
    def get_size_stats(self) -> Dict[str, Any]:
        """Get cache size statistics."""
        total_size = 0
        file_count = 0
        
        for cache_file in self.cache_dir.glob('*.json'):
            try:
                total_size += cache_file.stat().st_size
                file_count += 1
            except Exception:
                continue
        
        return {
            'total_size_bytes': total_size,
            'total_size_mb': total_size / (1024 * 1024),
            'file_count': file_count,
            'average_file_size_bytes': total_size / file_count if file_count > 0 else 0
        }
    
    def cleanup_old_entries(self, max_age_days: int = 7):
        """
        Clean up entries older than specified days.
        
        Args:
            max_age_days: Maximum age in days
        
        Returns:
            Number of entries removed
        """
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        removed_count = 0
        
        # Clean memory cache
        old_keys = [
            key for key, entry in self.memory_cache.items()
            if entry.get('timestamp', 0) < cutoff_time
        ]
        for key in old_keys:
            del self.memory_cache[key]
            removed_count += 1
        
        # Clean disk cache
        for cache_file in self.cache_dir.glob('*.json'):
            try:
                data = json.loads(cache_file.read_text(encoding='utf-8'))
                if data.get('timestamp', 0) < cutoff_time:
                    cache_file.unlink()
                    removed_count += 1
            except Exception:
                continue
        
        return removed_count

