"""
Graceful shutdown handler for Aether CLI.

Handles Ctrl+C (SIGINT) and other termination signals gracefully,
ensuring database connections are properly closed before exit.
"""

import signal
import sys
import atexit
from typing import Optional, Callable, List
from pathlib import Path


class GracefulShutdownHandler:
    """Handles graceful shutdown on signals like Ctrl+C."""
    
    def __init__(self):
        self.cleanup_callbacks: List[Callable] = []
        self.is_shutting_down = False
        self.database_managers: List = []
        
    def register_database(self, db_manager):
        """Register a database manager to be closed on shutdown."""
        if db_manager not in self.database_managers:
            self.database_managers.append(db_manager)
    
    def register_cleanup_callback(self, callback: Callable):
        """Register a cleanup callback to be called on shutdown."""
        if callback not in self.cleanup_callbacks:
            self.cleanup_callbacks.append(callback)
    
    def setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        
        # Register cleanup on normal exit
        atexit.register(self._cleanup)
    
    def _handle_signal(self, signum, frame):
        """Handle termination signals."""
        if self.is_shutting_down:
            print("\n⚠️  Force stopping (signal received again)...")
            sys.exit(1)
        
        self.is_shutting_down = True
        print("\n⏹️  Received interrupt signal. Shutting down gracefully...")
        print("   (Press Ctrl+C again to force stop)")
        
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self):
        """Perform cleanup operations."""
        if self.is_shutting_down:
            return  # Already cleaning up
        
        self.is_shutting_down = True
        
        print("\n🔄 Cleaning up...")
        
        # Close all registered databases
        for db in self.database_managers:
            try:
                if hasattr(db, 'close'):
                    print("   💾 Closing database connection...")
                    db.close()
                elif hasattr(db, '_close'):
                    print("   💾 Closing database connection...")
                    db._close()
                elif hasattr(db, 'conn') and db.conn:
                    print("   💾 Closing database connection...")
                    db.conn.close()
            except Exception as e:
                print(f"   ⚠️  Error closing database: {e}")
        
        # Run registered cleanup callbacks
        for callback in self.cleanup_callbacks:
            try:
                if callable(callback):
                    print("   🔧 Running cleanup callback...")
                    callback()
            except Exception as e:
                print(f"   ⚠️  Error in cleanup callback: {e}")
        
        print("✅ Cleanup complete. Exiting.")
    
    def save_checkpoint(self, checkpoint_file: Optional[str] = None):
        """Save current audit state to checkpoint file."""
        if checkpoint_file:
            try:
                checkpoint_path = Path(checkpoint_file)
                checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
                
                checkpoint_data = {
                    'timestamp': __import__('time').time(),
                    'status': 'interrupted',
                    'databases_registered': len(self.database_managers)
                }
                
                import json
                with open(checkpoint_path, 'w') as f:
                    json.dump(checkpoint_data, f, indent=2)
                
                print(f"   💾 Checkpoint saved to: {checkpoint_path}")
            except Exception as e:
                print(f"   ⚠️  Failed to save checkpoint: {e}")


# Global shutdown handler instance
_global_shutdown_handler: Optional[GracefulShutdownHandler] = None


def get_shutdown_handler() -> GracefulShutdownHandler:
    """Get or create the global shutdown handler."""
    global _global_shutdown_handler
    if _global_shutdown_handler is None:
        _global_shutdown_handler = GracefulShutdownHandler()
        _global_shutdown_handler.setup_signal_handlers()
    return _global_shutdown_handler


def register_database(db_manager):
    """Register a database manager for graceful shutdown."""
    handler = get_shutdown_handler()
    handler.register_database(db_manager)


def register_cleanup_callback(callback: Callable):
    """Register a cleanup callback for graceful shutdown."""
    handler = get_shutdown_handler()
    handler.register_cleanup_callback(callback)
