# Graceful Shutdown - Quick Start Guide

## What's New?

When you press **Ctrl+C** during an audit, the system now:
- ✅ Safely closes database connections
- ✅ Prevents database corruption
- ✅ Preserves your audit progress
- ✅ Shows clear feedback messages
- ✅ Allows force-stop with double Ctrl+C

## Usage

### Starting an Audit

```bash
python main.py audit https://github.com/rocket-pool/rocketpool --interactive-scope
```

### Stopping Gracefully

**Press Ctrl+C once:**
```
⏹️  Received interrupt signal. Shutting down gracefully...
   (Press Ctrl+C again to force stop)

🔄 Cleaning up...
   💾 Closing database connection...
✅ Cleanup complete. Exiting.
```

**Database is safely closed!**

### Resuming Later

```bash
python main.py audit https://github.com/rocket-pool/rocketpool
```

The system will detect your incomplete audit and show:
```
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
```

Select **"1"** to continue from where you left off!

## Force Stop (If Needed)

If graceful shutdown seems stuck, press **Ctrl+C again**:
```
⚠️  Force stopping (signal received again)...
[Process terminates immediately]
```

## Key Benefits

| Scenario | Before | Now |
|----------|--------|-----|
| Ctrl+C during audit | ❌ Possible DB corruption | ✅ Safe shutdown |
| Interrupted mid-analysis | ❌ Lost progress | ✅ Resume from checkpoint |
| Network timeout | ❌ Incomplete data | ✅ Safely rollback |
| Power outage | ❌ Corrupted DB | ✅ Atomic writes with WAL |

## Common Scenarios

### Scenario 1: Quick Stop for Lunch
```bash
$ python main.py audit https://github.com/rocket-pool/rocketpool
# ... auditing ...
[Ctrl+C]
✅ Database safely closed

# Later
$ python main.py audit https://github.com/rocket-pool/rocketpool
📋 Found 3 completed, 7 remaining
Continue? [1] → audit resumes
```

### Scenario 2: Reaudit Specific Contracts
```bash
$ python main.py audit https://github.com/rocket-pool/rocketpool
📋 3 completed, 7 remaining
Menu: 4) Re-audit specific contracts
[Select contracts]
✅ Re-analysis starts
```

### Scenario 3: Change Scope Mid-Audit
```bash
$ python main.py audit https://github.com/rocket-pool/rocketpool
[Ctrl+C]
✅ Safely closed

$ python main.py audit https://github.com/rocket-pool/rocketpool
📋 3 completed, 7 remaining
Menu: 2) Add more contracts to scope
[Add new contracts]
✅ Audit resumes with expanded scope
```

## Technical Details

- **Signal Handling**: Uses Python's `signal` module for SIGINT/SIGTERM
- **Database**: SQLite with WAL mode for atomic writes
- **Transactions**: Automatic rollback on interrupt
- **Checkpoint**: Progress saved incrementally
- **Recovery**: Resume mechanism remembers your selections

## Troubleshooting

**Database locked error?**
- Wait 2-3 seconds for SQLite to release locks
- Try again

**Wants to delete and restart?**
```bash
rm ~/.aether/aether_github_audit.db
python main.py audit https://github.com/rocket-pool/rocketpool
```

**More info?**
See [docs/GRACEFUL_SHUTDOWN.md](docs/GRACEFUL_SHUTDOWN.md) for complete documentation.

---

**That's it!** Just press Ctrl+C and your audit is safely preserved. 🎉
