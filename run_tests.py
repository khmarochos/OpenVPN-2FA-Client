#!/usr/bin/env python3

"""
Test runner for OpenVPN 2FA script.

This script runs all tests and provides a summary of the results.
"""

import unittest
import sys
import os
from pathlib import Path

def main():
    """Run all tests with coverage information."""
    
    # Ensure we can import the test module
    test_dir = Path(__file__).parent
    sys.path.insert(0, str(test_dir))
    
    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern='test_*.py')
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True,
        failfast=False
    )
    
    print("=" * 70)
    print("OpenVPN 2FA - Test Suite")
    print("=" * 70)
    print()
    
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())