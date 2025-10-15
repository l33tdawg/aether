#!/usr/bin/env python3
"""
Test runner for AetherAudit roadmap implementation.
Runs all tests to verify improvements without breaking existing functionality.
"""

import pytest
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def run_baseline_tests():
    """Run baseline functionality tests."""
    print("🔍 Running baseline functionality tests...")
    result = pytest.main([
        "tests/test_baseline_functionality.py",
        "-v",
        "--tb=short"
    ])
    return result == 0

def run_phase1_tests():
    """Run Phase 1 roadmap tests."""
    print("🚀 Running Phase 1 tests (Foundation Improvements)...")
    result = pytest.main([
        "tests/test_roadmap_phase1.py",
        "-v",
        "--tb=short"
    ])
    return result == 0

def run_phase2_tests():
    """Run Phase 2 roadmap tests."""
    print("⚡ Running Phase 2 tests (Enhanced Detection)...")
    result = pytest.main([
        "tests/test_roadmap_phase2.py",
        "-v",
        "--tb=short"
    ])
    return result == 0

def run_all_tests():
    """Run all tests."""
    print("🧪 Running all roadmap tests...")
    result = pytest.main([
        "tests/test_baseline_functionality.py",
        "tests/test_roadmap_phase1.py",
        "tests/test_roadmap_phase2.py",
        "-v",
        "--tb=short"
    ])
    return result == 0

def main():
    """Main test runner."""
    print("=" * 60)
    print("AetherAudit Roadmap Test Runner")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("tests").exists():
        print("❌ Error: tests directory not found. Please run from project root.")
        return 1
    
    # Run tests in phases
    baseline_passed = run_baseline_tests()
    if not baseline_passed:
        print("❌ Baseline tests failed. Stopping.")
        return 1
    
    phase1_passed = run_phase1_tests()
    if not phase1_passed:
        print("❌ Phase 1 tests failed. Stopping.")
        return 1
    
    phase2_passed = run_phase2_tests()
    if not phase2_passed:
        print("❌ Phase 2 tests failed. Stopping.")
        return 1
    
    print("=" * 60)
    print("✅ All tests passed!")
    print("🎯 Roadmap implementation is working correctly.")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
