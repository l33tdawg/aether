# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aether v3.0 is a Python-based smart contract security analysis framework for EVM chains. It combines pattern-based detection, LLM-driven analysis (GPT/Gemini/Claude), AI-ensemble reasoning, and Foundry-based PoC generation to find vulnerabilities in Solidity contracts and produce bug-bounty-ready exploit proofs.

The entire application runs as a **persistent full-screen Textual TUI** — zero `app.suspend()` calls. Every operation (audits, PoC generation, reports, GitHub scope selection, settings) runs inline within the TUI as background daemon threads.

## Commands

### Setup
```bash
python setup.py                    # Interactive installer (recommended)
python setup.py --non-interactive  # CI/CD mode
```

### Running the Tool
```bash
python aether.py                   # Persistent full-screen dashboard (sole entry point)
```

The dashboard is a persistent full-screen Textual TUI with keyboard shortcuts:
`n` New Audit, `r` Resume, `h` History, `p` PoCs, `o` Reports, `f` Fetch, `s` Settings, `q` Quit.
Press `Enter` on a job row to view live output, `Escape` to go back.

### Tests
```bash
python -m pytest tests/                                    # All tests (~13s, 770 tests)
python -m pytest tests/test_enhanced_detectors.py -v       # Single file
python -m pytest tests/test_enhanced_detectors.py::TestArithmeticAnalyzer -v          # Single class
python -m pytest tests/test_enhanced_detectors.py::TestArithmeticAnalyzer::test_overflow_detection -v  # Single test
python -m pytest tests/ -k "governance" -v                 # Pattern match
python -m pytest tests/ --cov=core --cov-report=html       # With coverage
```

Tests use `unittest.TestCase` with pytest as the runner. pytest-timeout is NOT installed; don't use `--timeout` flag.

### Code Quality
```bash
black core/ tests/       # Formatting
isort core/ tests/       # Import sorting
flake8 core/ tests/      # Linting
mypy core/               # Type checking
```

## Architecture

### Entry Points
- `aether.py` — Sole entry point. Launches the Textual TUI dashboard
- `cli/interactive_menu.py` — Thin shim that creates JobManager + AetherApp and calls run()
- `cli/tui/app.py` — `AetherApp(App)` — main Textual app with key bindings and 1s refresh timer

### TUI Layer (`cli/tui/`)
- `cli/tui/screens/` — Screen classes: MainScreen, JobDetailScreen, NewAuditScreen, HistoryScreen, ResumeScreen, PoCScreen, ReportsScreen, FetchScreen, SettingsScreen
- `cli/tui/widgets/` — Live widgets: JobsTable (DataTable), CostBar, LogViewer (RichLog), PhaseBar
- `cli/tui/dialogs/` — Modal dialogs: ConfirmDialog, TextInputDialog, SelectDialog, CheckboxDialog, PathDialog, ContractSelectorDialog — all ModalScreen subclasses
- `cli/tui/github_audit_helper.py` — Decomposed GitHub audit operations (clone_and_discover, get_scope_state, save_new_scope, get_pending_contracts, handle_reaudit) for TUI integration
- `cli/tui/theme.tcss` — Textual CSS theme (cyan color scheme)

### Background Execution
- `cli/audit_runner.py` — `AuditRunner` class — runs audits, PoCs, reports, and GitHub audits in background daemon threads. Four job types: `local`, `github`, `poc`, `report`
- `core/job_manager.py` — `JobManager` singleton — session job registry (QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED)
- `core/audit_progress.py` — `ContractAuditStatus` with per-job log buffers, `ThreadDemuxWriter` for output capture
- `core/llm_usage_tracker.py` — Thread-safe singleton with `snapshot()` for per-job cost deltas

### Core Orchestration
- `cli/main.py` — `AetherCLI` class (~2600 lines) — internal audit orchestrator (used by AuditRunner)
- `cli/console.py` — Interactive console mode
- `core/enhanced_audit_engine.py` — Main orchestrator (Phase 1-3 execution)
- `core/post_audit_summary.py` — Post-audit panel with cost-by-provider breakdown

### Core Layer Organization (`core/`)

**Detection Layer** — Vulnerability pattern matching:
- `enhanced_vulnerability_detector.py` — Primary detector with 60+ patterns
- `business_logic_detector.py`, `state_management_detector.py`, `data_inconsistency_detector.py`, `centralization_detector.py`, `looping_detector.py` — Move-inspired detectors adapted from Move Vulnerability Database
- `defi_vulnerability_detector.py`, `mev_detector.py`, `oracle_manipulation_detector.py` — DeFi-specific detectors
- Specialized analyzers: `arithmetic_analyzer.py`, `precision_analyzer.py`, `gas_analyzer.py`, `input_validation_detector.py`, `data_decoding_analyzer.py`

**Validation Layer** — Multi-stage false positive reduction (66% → ~30-35%):
- `validation_pipeline.py` — 4-stage pipeline: built-in protection check → governance control detection → deployment verification → local validation detection
- `governance_detector.py` — Identifies onlyOwner/onlyGovernor protected parameters
- `deployment_analyzer.py` — Verifies code paths are actually used in production
- `llm_false_positive_filter.py` — LLM-based validation with governance-aware prompts
- `control_flow_guard_detector.py`, `inheritance_verifier.py` — Additional validation

**LLM & AI Layer**:
- `enhanced_llm_analyzer.py` — Structured LLM analysis (GPT/Gemini/Claude) with JSON output
- `ai_ensemble.py` — Multi-agent coordination with consensus-based reasoning (6 agents: 2 OpenAI, 2 Gemini, 2 Anthropic)
- `enhanced_prompts.py` — Production prompt templates

**PoC Generation Layer**:
- `foundry_poc_generator.py` (~8000 lines) — AST-based contract analysis, iterative compilation feedback loop, Foundry test generation
- `llm_foundry_generator.py` — LLM-based test generation
- `enhanced_foundry_integration.py` — Foundry validation and formatting

**Persistence Layer**:
- `database_manager.py` — SQLite persistence: `DatabaseManager` for local audits (`~/.aether/aetheraudit.db`), `AetherDatabase` for GitHub audits (`~/.aether/aether_github_audit.db`)
- `analysis_cache.py` — Smart caching for 2x faster repeated analysis
- `accuracy_tracker.py` — Tracks submission outcomes and bounty earnings

**Integrations**:
- `github_auditor.py` — Clones repos, detects frameworks (Foundry/Hardhat/Truffle), discovers contracts, coordinates analysis
- `etherscan_fetcher.py`, `basescan_fetcher.py` — Fetch verified contracts from block explorers
- `exploit_tester.py`, `fork_verifier.py` — Validate exploits against Anvil forks

### Flow-Based Execution
Audit flows are defined in YAML configs (`configs/`). The enhanced audit uses a node pipeline:
`FileReaderNode → StaticAnalysisNode → LLMAnalysisNode → EnhancedExploitabilityNode → [FixGeneratorNode → ValidationNode] → ReportNode`

Flow nodes live in `core/nodes/`, validators in `core/validators/`, config in `core/config/`.

## Key Patterns

- **No app.suspend() in TUI** — All operations run inline via Textual dialogs or as background jobs
- **Background job pattern** — AuditRunner workers: snapshot tracker → register demuxers → start_job → try/except with complete_job or fail_job → finally unregister
- **Output capture** — ThreadDemuxWriter (stdout+stderr) + JobLogHandler (logging) → per-job log buffers in ContractAuditStatus
- **Per-job cost tracking** — `LLMUsageTracker.snapshot()` before/after to compute cost_delta without resetting global tracker
- **Async** — `asyncio.run()` wraps async methods from sync context; `run_worker()` for Textual async tasks
- **Lazy loading** — Heavy imports like `AetherCLI` deferred for fast startup
- **Textual CSS** — Separate `color` and `text-style` properties — `color: cyan bold` is INVALID, must be `color: cyan; text-style: bold;`
- **Textual tests** — Use `App.run_test()` + Pilot API with `IsolatedAsyncioTestCase`. Use `app.screen.query_one()` not `app.query_one()`. Always `await pilot.pause()` after entering `run_test()` context.

## Key Requirements
- Python 3.11+ (tested with 3.12.8)
- Node.js 22+ (for Hardhat-based projects)
- Foundry (forge/anvil) on PATH
- solc-select for multiple Solidity compiler versions
- API keys: `OPENAI_API_KEY`, `GEMINI_API_KEY`, and/or `ANTHROPIC_API_KEY` for LLM features, `ETHERSCAN_API_KEY` optional
- Textual >= 1.0.0 for the TUI; questionary retained only for `setup.py` installer

## Foundry Configuration
- Default solc: 0.8.20, optimizer enabled (200 runs), `via_ir: true`
- PoC tests in `poc-tests/`, build output in `out/`
- Supports mainnet, polygon, arbitrum RPC endpoints
- Profile `rocketpool` uses solc 0.7.6 with istanbul EVM

## Known Constraints
- `setuptools <81` required due to `pkg_resources` deprecation warnings (suppressed in `aether.py`)
- Heavy use of asyncio throughout — async tests use `pytest-asyncio`
- The AI ensemble feature is experimental
- Slither fully removed in v2.1; pattern-based detectors + Foundry ABI + regex are the only analysis tools
- **NEVER call `LLMUsageTracker.reset()` from inside audit/worker code** — the singleton pattern means external code (AuditRunner) holds references to the instance; `reset()` replaces it, orphaning those references and causing all snapshot deltas to read 0. Use snapshot-based deltas (before/after) instead.
- **Always capture return values from `run_audit()`** — it returns a results dict with `summary.total_vulnerabilities`; discarding it forces reliance on fragile stdout regex parsing
- **Per-job LLM stats** — compute from `tracker.snapshot()` deltas (total_calls, total_cost), not from `sync_llm_stats()` which reads global totals

## Deleted Files (v3.0)
- `main.py` — CLI entry point (replaced by `aether.py` TUI)
- `core/audit_dashboard.py` — Single-audit Rich Live dashboard (replaced by JobDetailScreen)
- `core/parallel_audit_manager.py` — Parallel audit orchestrator (replaced by AuditRunner + JobManager)
- `cli/dashboard.py` — Rich+questionary hybrid dashboard (replaced by `cli/tui/`)
- `cli/input_helpers.py` — questionary wrappers (replaced by Textual dialogs)
- `cli/subflows.py` — action handlers (logic ported to Textual screens)
