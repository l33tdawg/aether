# Graceful Shutdown Handler

## Overview

The AetherAudit CLI now implements a **graceful shutdown handler** that properly closes database connections and cleans up resources when you press `Ctrl+C` or when the process receives termination signals.

## Features

### ✅ What Graceful Shutdown Does

1. **Catches Interrupt Signals**: Handles `Ctrl+C` (SIGINT) and termination signals (SIGTERM)
2. **Closes Database Connections**: Properly closes all registered database connections
3. **Prevents Data Corruption**: Ensures incomplete transactions are rolled back safely
4. **Provides User Feedback**: Shows clear messages about shutdown progress
5. **Allows Force Stop**: Users can press `Ctrl+C` twice to force-exit if needed

### ✅ How It Works

```
User presses Ctrl+C
         ↓
Graceful shutdown handler catches SIGINT signal
         ↓
Displays: "⏹️  Received interrupt signal. Shutting down gracefully..."
         ↓
Closes all registered databases:
    🔄 Cleaning up...
    💾 Closing database connection...
         ↓
Runs any registered cleanup callbacks
         ↓
Displays: "✅ Cleanup complete. Exiting."
         ↓
Exit with code 0 (success)
```

## Usage

### Normal Usage (Graceful Shutdown Enabled)

```bash
# Start an audit
python main.py audit https://github.com/rocket-pool/rocketpool

# While auditing, press Ctrl+C to stop gracefully:
# Output:
# ⏹️  Received interrupt signal. Shutting down gracefully...
#    (Press Ctrl+C again to force stop)
# 
# 🔄 Cleaning up...
#    💾 Closing database connection...
# ✅ Cleanup complete. Exiting.
```

### Force Stop (If Needed)

If graceful shutdown seems stuck, you can force-stop:

```bash
# Press Ctrl+C twice rapidly
# Output:
# ⏹️  Received interrupt signal. Shutting down gracefully...
#    (Press Ctrl+C again to force stop)
# 
# ⚠️  Force stopping (signal received again)...
# [Process terminates immediately]
```

## Technical Implementation

### Files Modified

1. **`core/graceful_shutdown.py`** (NEW)
   - `GracefulShutdownHandler` class
   - Signal handlers for SIGINT and SIGTERM
   - Database connection cleanup

2. **`core/database_manager.py`**
   - Added `close()` and `_close()` methods to `AetherDatabase`
   - Properly handles shutdown cleanup

3. **`main.py`**
   - Imports and initializes `get_shutdown_handler()`
   - Sets up signal handlers at CLI startup

4. **`cli/main.py`**
   - Registers auditor database with shutdown handler
   - Ensures cleanup during GitHub audits

### How to Register Additional Resources

If you add new resources that need cleanup:

```python
from core.graceful_shutdown import register_database, register_cleanup_callback

# Register a database
register_database(my_database_manager)

# Register a custom cleanup function
def cleanup_resources():
    """Clean up external resources."""
    print("Cleaning up resources...")
    # ... cleanup code ...

register_cleanup_callback(cleanup_resources)
```

## Database Safety

### What Happens During Shutdown

1. **WAL Mode**: The database uses WAL (Write-Ahead Logging) mode for safer concurrent access
2. **Foreign Keys**: Foreign key constraints are enabled to ensure data integrity
3. **Connection Closure**: Connections are properly closed to prevent orphaned processes
4. **Transaction Rollback**: Any pending transactions are automatically rolled back by SQLite

### What This Prevents

- ✅ Corrupted database files
- ✅ Orphaned database connections
- ✅ Lost audit progress (progress is saved incrementally)
- ✅ Incomplete contract analysis records
- ✅ Partial findings saved in inconsistent state

## Workflow with Resume

The graceful shutdown works perfectly with the **Resume/Smart Resume** workflow:

1. **Start Audit**: `python main.py audit https://github.com/rocket-pool/rocketpool`
2. **Audit Progress**: Contracts are marked as `status='success'` or `status='skipped'` as they complete
3. **Press Ctrl+C**: Shutdown handler gracefully closes the database
4. **Resume Audit**: The next run detects the incomplete scope and offers resume options
5. **Continue**: Resume from the next unaudited contract

```
Initial Run:
  ✅ Contract 1: success
  ✅ Contract 2: success
  ✅ Contract 3: in_progress
  [Ctrl+C pressed - graceful shutdown]
  ✅ Database safely closed

Resume Run:
  📋 Found incomplete scope with 10 contracts selected
  ⏹️ 3 contracts completed, 7 remaining
  
  Resume Menu:
  1. Continue from contract 4/10
  2. Add more contracts to scope
  3. Remove contracts from scope
  4. Re-audit specific contracts
  5. View findings report
  [User selects "1: Continue"]
  
  ✅ Contract 4: success
  ✅ Contract 5: success
  ✅ Contract 6: success
  [Audit continues...]
```

## Troubleshooting

### Database Already Locked Error

If you see "database is locked" errors:

1. Make sure the previous process was fully terminated
2. Wait 2-3 seconds for SQLite to release locks
3. Try again: `python main.py audit ...`

### Force Delete Database (Last Resort)

If the database becomes corrupted:

```bash
# Remove corrupted database
rm ~/.aether/aether_github_audit.db

# Next run will create a fresh database
python main.py audit https://github.com/rocket-pool/rocketpool
```

## Best Practices

1. **Always Use Graceful Shutdown**: Don't kill processes with `-9`, let them shut down gracefully
2. **Watch the Cleanup**: The cleanup messages show what's being closed
3. **Check Resume Options**: After graceful shutdown, use resume to continue work
4. **Monitor DB Size**: Large audits create large databases, monitor disk space
5. **Use Checkpoint Saves**: The system auto-saves audit progress incrementally

## Example: Interrupted Audit Session

```bash
# Terminal 1: Start audit
$ python main.py audit https://github.com/rocket-pool/rocketpool
Aether GitHub Auditor v1.0.0
Discovering contracts in https://github.com/rocket-pool/rocketpool...
Found 145 total contracts (65 interfaces, 80 implementations)

AETHER CONTRACT SELECTOR
Selected: 10 contracts

Analyzing contracts...
✅ Contract 1/10: RocketPool.sol (2s)
✅ Contract 2/10: RocketStorage.sol (3s)
✅ Contract 3/10: RocketBase.sol (2s)
[User presses Ctrl+C here]

# Output:
⏹️  Received interrupt signal. Shutting down gracefully...
   (Press Ctrl+C again to force stop)

🔄 Cleaning up...
   💾 Closing database connection...
✅ Cleanup complete. Exiting.

# Safely exited!
```

```bash
# Terminal 2: Resume same audit (30 seconds later)
$ python main.py audit https://github.com/rocket-pool/rocketpool
Aether GitHub Auditor v1.0.0

📋 Found saved scope for rocket-pool/rocketpool
   ⏹️ 3 contracts completed, 7 remaining

Resume Menu:
  1) Continue from contract 4/10
  2) Add more contracts to scope
  3) Remove contracts from scope
  4) Re-audit specific contracts
  5) View findings report
  6) Start new scope

Select option (1-6): 1

Resuming from contract 4/10...
✅ Contract 4/10: RocketDAOProtocol.sol (3s)
✅ Contract 5/10: RocketMerkleDistributor.sol (2s)
✅ Contract 6/10: RocketTokenRETH.sol (4s)
[Audit continues...]
```

## Related Documentation

- See [SCOPE_MANAGER.md](./SCOPE_MANAGER.md) for resume/smart resume details
- See [README.md](../README.md) for general CLI usage
- See [INTERACTIVE_SELECTOR.md](./INTERACTIVE_SELECTOR.md) for contract selection UI

