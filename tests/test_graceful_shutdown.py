#!/usr/bin/env python3
"""
Test graceful shutdown handler functionality.

This test demonstrates:
1. Signal handling for Ctrl+C (SIGINT)
2. Database registration and cleanup
3. Custom callback registration
4. Force stop on double Ctrl+C
"""

import unittest
import signal
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.graceful_shutdown import GracefulShutdownHandler, get_shutdown_handler


class TestGracefulShutdownHandler(unittest.TestCase):
    """Test cases for GracefulShutdownHandler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = GracefulShutdownHandler()
    
    def test_initialization(self):
        """Test handler initializes correctly."""
        self.assertEqual(len(self.handler.database_managers), 0)
        self.assertEqual(len(self.handler.cleanup_callbacks), 0)
        self.assertFalse(self.handler.is_shutting_down)
    
    def test_register_database(self):
        """Test database registration."""
        mock_db = Mock()
        self.handler.register_database(mock_db)
        
        self.assertEqual(len(self.handler.database_managers), 1)
        self.assertIn(mock_db, self.handler.database_managers)
        
        # Test duplicate prevention
        self.handler.register_database(mock_db)
        self.assertEqual(len(self.handler.database_managers), 1)
    
    def test_register_cleanup_callback(self):
        """Test cleanup callback registration."""
        mock_callback = Mock()
        self.handler.register_cleanup_callback(mock_callback)
        
        self.assertEqual(len(self.handler.cleanup_callbacks), 1)
        self.assertIn(mock_callback, self.handler.cleanup_callbacks)
        
        # Test duplicate prevention
        self.handler.register_cleanup_callback(mock_callback)
        self.assertEqual(len(self.handler.cleanup_callbacks), 1)
    
    def test_cleanup_closes_databases(self):
        """Test that cleanup closes all registered databases."""
        # Test with close() method
        mock_db_1 = Mock()
        mock_db_1.close = Mock()
        self.handler.register_database(mock_db_1)
        
        # Test with _close() method
        mock_db_2 = Mock()
        mock_db_2._close = Mock()
        delattr(mock_db_2, 'close')  # Remove close method
        self.handler.register_database(mock_db_2)
        
        # Test with conn attribute
        mock_db_3 = Mock()
        mock_db_3.conn = Mock()
        delattr(mock_db_3, 'close')  # Remove close method
        delattr(mock_db_3, '_close')  # Remove _close method
        self.handler.register_database(mock_db_3)
        
        # Run cleanup
        self.handler._cleanup()
        
        # Verify databases were closed
        mock_db_1.close.assert_called_once()
        mock_db_2._close.assert_called_once()
        mock_db_3.conn.close.assert_called_once()
    
    def test_cleanup_runs_callbacks(self):
        """Test that cleanup runs registered callbacks."""
        mock_callback_1 = Mock()
        mock_callback_2 = Mock()
        
        self.handler.register_cleanup_callback(mock_callback_1)
        self.handler.register_cleanup_callback(mock_callback_2)
        
        self.handler._cleanup()
        
        mock_callback_1.assert_called_once()
        mock_callback_2.assert_called_once()
    
    def test_cleanup_prevents_reentry(self):
        """Test that cleanup prevents re-entry."""
        mock_callback = Mock()
        self.handler.register_cleanup_callback(mock_callback)
        
        # First cleanup
        self.handler._cleanup()
        first_call_count = mock_callback.call_count
        
        # Second cleanup attempt (should be prevented)
        self.handler._cleanup()
        
        # Callback should only have been called once
        self.assertEqual(mock_callback.call_count, first_call_count)
    
    def test_signal_handler_first_signal(self):
        """Test signal handler on first signal."""
        initial_shutdown_state = self.handler.is_shutting_down
        
        # Simulate first signal
        with patch('core.graceful_shutdown.sys.exit') as mock_exit:
            self.handler._handle_signal(signal.SIGINT, None)
            
            # Should be marked as shutting down
            self.assertTrue(self.handler.is_shutting_down)
            # Should exit with code 0
            mock_exit.assert_called_once_with(0)
    
    def test_signal_handler_double_signal(self):
        """Test signal handler on second signal (force stop)."""
        # First signal - set is_shutting_down to True to simulate already started shutdown
        self.handler.is_shutting_down = True
        
        # Second signal should exit with code 1 (force stop, not 0)
        with patch('core.graceful_shutdown.sys.exit') as mock_exit:
            self.handler._handle_signal(signal.SIGINT, None)
            
            # Verify exit was called with 1 (force stop), not 0 (graceful)
            # It may be called multiple times due to atexit, but at least once should be with 1
            self.assertTrue(any(call[0][0] == 1 for call in mock_exit.call_args_list),
                          f"Expected exit(1) to be called, but got: {mock_exit.call_args_list}")
    
    def test_setup_signal_handlers(self):
        """Test that signal handlers are set up correctly."""
        with patch('signal.signal') as mock_signal:
            handler = GracefulShutdownHandler()
            handler.setup_signal_handlers()
            
            # Should register handlers for SIGINT and SIGTERM
            calls = mock_signal.call_args_list
            self.assertEqual(len(calls), 2)
    
    def test_get_shutdown_handler_singleton(self):
        """Test that get_shutdown_handler returns singleton."""
        handler1 = get_shutdown_handler()
        handler2 = get_shutdown_handler()
        
        # Should be the same instance
        self.assertIs(handler1, handler2)


class TestGracefulShutdownIntegration(unittest.TestCase):
    """Integration tests for graceful shutdown."""
    
    def test_multiple_database_cleanup(self):
        """Test cleanup of multiple databases."""
        handler = GracefulShutdownHandler()
        
        # Register multiple mock databases
        dbs = [Mock() for _ in range(3)]
        for db in dbs:
            handler.register_database(db)
        
        # Run cleanup
        handler._cleanup()
        
        # All databases should be closed
        for db in dbs:
            db.close.assert_called_once()
    
    def test_callback_error_handling(self):
        """Test that errors in callbacks don't prevent cleanup."""
        handler = GracefulShutdownHandler()
        
        # Register callback that raises exception
        def bad_callback():
            raise ValueError("Test error")
        
        handler.register_cleanup_callback(bad_callback)
        
        # Mock database
        mock_db = Mock()
        handler.register_database(mock_db)
        
        # Cleanup should not raise exception
        handler._cleanup()
        
        # Database should still be closed
        mock_db.close.assert_called_once()
    
    def test_database_error_handling(self):
        """Test that errors closing databases don't prevent other cleanups."""
        handler = GracefulShutdownHandler()
        
        # Register database that raises exception on close
        mock_db_bad = Mock()
        mock_db_bad.close.side_effect = Exception("Close failed")
        handler.register_database(mock_db_bad)
        
        # Register good database
        mock_db_good = Mock()
        handler.register_database(mock_db_good)
        
        # Register callback
        mock_callback = Mock()
        handler.register_cleanup_callback(mock_callback)
        
        # Cleanup should not raise exception
        handler._cleanup()
        
        # Good database should still be closed
        mock_db_good.close.assert_called_once()
        
        # Callback should still be called
        mock_callback.assert_called_once()


def run_manual_test():
    """Manual test to observe graceful shutdown behavior."""
    import time
    
    print("\n" + "="*70)
    print("MANUAL GRACEFUL SHUTDOWN TEST")
    print("="*70)
    print("\nThis test demonstrates how the graceful shutdown handler works.")
    print("\nInstructions:")
    print("  1. Wait for 'Ready to receive Ctrl+C' message")
    print("  2. Press Ctrl+C once to trigger graceful shutdown")
    print("  3. Observe the cleanup messages")
    print("  4. The process should exit cleanly with 'Cleanup complete'")
    print("\nStarting in 2 seconds...\n")
    
    time.sleep(2)
    
    # Set up handler
    handler = get_shutdown_handler()
    
    # Register a test database
    class FakeDB:
        def close(self):
            print("   [FakeDB] Connection closed")
    
    handler.register_database(FakeDB())
    
    # Register a cleanup callback
    def custom_cleanup():
        print("   [CustomCleanup] Running custom cleanup...")
        time.sleep(0.5)
        print("   [CustomCleanup] Done!")
    
    handler.register_cleanup_callback(custom_cleanup)
    
    print("✅ Ready to receive Ctrl+C...")
    print("   (Press Ctrl+C now)\n")
    
    try:
        # Just wait for signal
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n⏹️  Keyboard interrupt received!")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Test graceful shutdown handler")
    parser.add_argument('--manual', action='store_true', help='Run manual test')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    if args.manual:
        run_manual_test()
    else:
        # Run unit tests
        if args.verbose:
            unittest.main(verbosity=2)
        else:
            unittest.main(verbosity=1)
