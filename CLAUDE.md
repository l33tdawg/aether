# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aether v6.0 is a Python-based smart contract security analysis framework for EVM chains. It features a **collaborative multi-agent LLM pipeline** where 5 specialized AI agents share structured knowledge through **[SAGE](https://github.com/l33tdawg/sage) institutional memory** — findings, dismissals, and verified protections flow between agents via per-audit session domains. Combined with Solidity AST parsing, taint analysis, cross-contract analysis, 14 protocol archetypes, 75+ exploit knowledge base, 180+ pattern-based static detectors, token quirks detection, invariant extraction, and Foundry-based PoC generation. Ships with 228 pre-trained exploit patterns. SAGE is required — every audit builds institutional knowledge for the next.

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
python -m pytest tests/                                    # All tests (~23s, 1839 tests)
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
- `core/enhanced_audit_engine.py` — Main orchestrator with deep analysis integration
- `core/post_audit_summary.py` — Post-audit panel with cost-by-provider breakdown

### Core Layer Organization (`core/`)

**Deep Analysis Layer** (v4.0) — Multi-pass LLM pipeline:
- `deep_analysis_engine.py` — 6-pass pipeline plus Pass 3.5 (cross-contract): Protocol Understanding → Attack Surface → Invariant Violations → Cross-Contract → Cross-Function → Adversarial Modeling → Edge Cases. Passes 1-2 cached by content hash. Few-shot examples in Passes 3-5, chain-of-thought enforcement.
- `protocol_archetypes.py` — 14 protocol archetypes (DEX_AMM, LENDING_POOL, VAULT_ERC4626, BRIDGE, STAKING, GOVERNANCE, LIQUID_STAKING, PERPETUAL_DEX, CDP_STABLECOIN, YIELD_AGGREGATOR, etc.) with regex signal detection and per-archetype vulnerability checklists
- `exploit_knowledge_base.py` — 75+ categorized real-world exploit patterns across 14 categories (including CROSS_CONTRACT, SIGNATURE_AUTH, TOKEN_INTEGRATION, PROXY_UPGRADE, TYPE_SAFETY), filterable by archetype/focus area
- `invariant_engine.py` — Invariant extraction (NatSpec + LLM + pattern) and Foundry invariant test generation
- `solidity_ast.py` — Solidity AST parsing via py-solc-x for inheritance resolution, function visibility, storage layout, state read/write tracking; graceful regex fallback
- `taint_analyzer.py` — Data flow / taint analysis with 8 source types, 12 sink types, sanitizer detection, cross-contract tracking
- `cross_contract_analyzer.py` — Inter-contract relationship analysis with trust boundary detection and union-find grouping
- `token_quirks.py` — Token quirks database (12 categories of non-standard ERC-20 behaviors)

**Detection Layer** — Vulnerability pattern matching:
- `enhanced_vulnerability_detector.py` — Primary detector with 60+ patterns
- `business_logic_detector.py`, `state_management_detector.py`, `data_inconsistency_detector.py`, `centralization_detector.py`, `looping_detector.py` — Move-inspired detectors adapted from Move Vulnerability Database
- `defi_vulnerability_detector.py`, `mev_detector.py`, `oracle_manipulation_detector.py` — DeFi-specific detectors (DeFi detector integrated into enhanced engine in v3.5)
- Specialized analyzers: `arithmetic_analyzer.py`, `precision_analyzer.py` (enhanced: share inflation, rounding direction, division truncation, dust exploitation, accumulator overflow), `gas_analyzer.py`, `input_validation_detector.py`, `data_decoding_analyzer.py`
- Token quirks detection integrated into static pipeline via `token_quirks.py`

**Validation Layer** — Multi-stage false positive reduction with context-aware calibration:
- `validation_pipeline.py` — Multi-stage pipeline: built-in protection check → governance control detection → taint-aware validation (Stage 1.85) → deployment verification → local validation detection
- `governance_detector.py` — Identifies onlyOwner/onlyGovernor protected parameters
- `deployment_analyzer.py` — Verifies code paths are actually used in production
- `llm_false_positive_filter.py` — LLM-based validation with governance-aware prompts
- `control_flow_guard_detector.py`, `inheritance_verifier.py` — Additional validation

**SAGE Institutional Memory Layer** (v5.0) — Persistent learning across audits:
- `sage_client.py` — Thread-safe singleton REST client for SAGE (remember, recall, reflect, health_check)
- `sage_seeder.py` — Pre-trained knowledge seeder: 170 memories from exploit KB, archetypes, token quirks, historical exploits. Ships as JSON fixtures in `data/sage_seeds/`
- `sage_feedback.py` — Feedback loop manager: records finding outcomes (confirmed/rejected), syncs detector accuracy, recalls historical FP patterns
- `docker-compose.yml` — SAGE Docker container (ghcr.io/l33tdawg/sage:latest, port 8080)
- Pipeline integration: SAGE recall in deep analysis pre-pipeline, Pass 3, Pass 5; SAGE remember post-pipeline; SAGE FP check in validation pipeline (Stage -1)

**LLM & AI Layer**:
- `enhanced_llm_analyzer.py` — Structured LLM analysis (GPT/Gemini/Claude) with JSON output and multi-provider rotation
- `ai_ensemble.py` — Multi-agent coordination (retained for backward compatibility; retired from production pipeline in v3.8, replaced by multi-provider rotation)
- `enhanced_prompts.py` — Production prompt templates with dynamic exploit pattern loading from knowledge base, few-shot examples, severity calibration, and chain-of-thought enforcement

**PoC Generation Layer**:
- `foundry_poc_generator.py` (~8000 lines) — AST-based contract analysis, iterative compilation feedback loop (up to 5 attempts), Foundry test generation
- `llm_foundry_generator.py` — LLM-based test generation with mock API documentation and recommended setUp patterns
- `enhanced_foundry_integration.py` — Foundry validation and formatting
- `poc_templates.py` — Mock contract templates (MockERC20, MockOracle, MockWETH, MockFlashLoanProvider)
- `poc_setup_generator.py` — Intelligent setUp() generation: constructor param extraction, mock deployment, upgradeable contract handling

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

- **SAGE institutional memory** — Auto-seeds on first launch (170 pre-trained memories), recalls historical findings in Pass 3/5, stores learnings post-audit, feedback loop via AccuracyTracker → sage_feedback → sage_remember/reflect. Config: `sage_enabled`, `sage_url` in `~/.aether/config.yaml`. Docker: `docker compose up -d`
- **Deep analysis pipeline** — `AETHER_DEEP_ANALYSIS=1` (default ON) enables 6-pass LLM pipeline; set to `0` for one-shot fallback
- **Protocol archetype detection** — Runs automatically before deep analysis; archetype + checklist fed into Passes 1, 3, 5
- **Context-aware severity** — `_has_risk_indicators()` checks unchecked blocks, value transfers, price calculations before downgrading severity
- **Multi-provider rotation** — Gemini Flash for cheap passes, Anthropic Claude for reasoning, OpenAI GPT for diversity (replaced AI ensemble in v3.8)
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
- py-solc-x (optional) for Solidity AST parsing — falls back to regex analysis if unavailable
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
- AI ensemble retained for backward compatibility but retired from production pipeline (replaced by multi-provider rotation in v3.8)
- Slither fully removed in v2.1; pattern-based detectors + Foundry ABI + regex + Solidity AST (via py-solc-x) are the analysis tools

## Deleted Files (v3.0)
- `main.py` — CLI entry point (replaced by `aether.py` TUI)
- `core/audit_dashboard.py` — Single-audit Rich Live dashboard (replaced by JobDetailScreen)
- `core/parallel_audit_manager.py` — Parallel audit orchestrator (replaced by AuditRunner + JobManager)
- `cli/dashboard.py` — Rich+questionary hybrid dashboard (replaced by `cli/tui/`)
- `cli/input_helpers.py` — questionary wrappers (replaced by Textual dialogs)
- `cli/subflows.py` — action handlers (logic ported to Textual screens)

## SAGE — Persistent Memory

Your brain is powered by SAGE MCP. You have persistent institutional memory.

### Boot Sequence (MANDATORY)
1. Call `sage_inception` as your VERY FIRST action in every new conversation
2. Do NOT respond to the user before booting — your memories must load first
3. Follow the instructions returned by inception (they adapt to the user's settings)

### If SAGE MCP is not connected
Start the node: `sage-gui serve`
MCP config is in `.mcp.json` at project root. Restart your session after starting.
