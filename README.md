# Aether v3.0 — Smart Contract Security Analysis Framework

**Version 3.0** | [What's New in v3.0](#whats-new-in-v30) | [Changelog](#changelog)

Aether is a Python-based framework for analyzing Solidity smart contracts, generating vulnerability findings, producing Foundry-based proof-of-concept (PoC) tests, and validating exploits on mainnet forks. It combines 60+ pattern-based static detectors, prompt-driven LLM analysis (GPT/Gemini/Claude), AI-ensemble reasoning, and advanced false-positive filtering into a single persistent full-screen TUI.

## What's New in v3.0

**Fully Inline Textual TUI** — Aether v3.0 is a persistent full-screen application that never drops to a raw terminal. Every operation — audits, PoC generation, report generation, GitHub scope selection, settings configuration — runs entirely within the TUI:

- **Zero `app.suspend()` calls** — the TUI never disappears, no jarring terminal switches
- **Background jobs for everything** — local audits, GitHub audits, PoC generation, and report generation all run as daemon threads with live output streaming
- **Live jobs table** — htop-style view of all running/completed jobs with real-time status, phase progress, findings count, cost, and elapsed time
- **Per-job drill-down** — press `Enter` on any job to see live scrolling output, phase progress bar, and metadata
- **Concurrent operations** — start multiple audits, PoC generations, and reports simultaneously; all visible and trackable
- **Contract selector dialog** — filterable, near-fullscreen multi-select replacing the old curses-based selector. Space to toggle, `a`/`n` for all/none, type to filter, color-coded previously-audited contracts
- **Inline GitHub audit flow** — clone, discover, select contracts, and launch audits without leaving the TUI. Scope management (continue, re-audit, new scope) via native Textual dialogs
- **Inline settings** — API key configuration and model selection via TextInputDialog and SelectDialog, no external setup wizard needed
- **Session cost bar** — real-time LLM cost tracking by provider (OpenAI, Gemini, Anthropic)
- **Keyboard-driven** — `n` New Audit, `r` Resume, `h` History, `p` PoCs, `o` Reports, `f` Fetch, `s` Settings, `q` Quit

**Four Background Job Types**: All heavy operations run as background daemon threads via `AuditRunner`, with output captured by `ThreadDemuxWriter` and visible in `JobDetailScreen`:

| Job Type | Description |
|----------|-------------|
| `local` | Single or parallel contract audits |
| `github` | GitHub repository audits with pre-selected scope |
| `poc` | Foundry proof-of-concept generation |
| `report` | Audit report generation (markdown/json/html) |

**Three-Provider LLM Support**: OpenAI (GPT-5/5.3), Google Gemini (2.5/3.0), and Anthropic Claude (Sonnet 4.5/Opus 4.6) for maximum flexibility and redundancy.

**Enhanced PoC Generation**: AST-based contract analysis, iterative compilation fixes, and production-ready LLM prompts generating exploits suitable for bug bounty submissions.

**Advanced False Positive Filtering**: Multi-stage validation reduces false positives from 66% to ~30-35%, improving accuracy from 33% to 65-70%:
- Governance detection (onlyOwner/onlyGovernor protected parameters)
- Deployment analysis (verifies code paths are actually used in production)
- Built-in protection checks (Solidity 0.8+ auto-protection, SafeMath)
- Governance-aware LLM validation with 4-stage checklist
- Accuracy tracking with submission outcomes and bounty earnings
- Smart caching for 2x faster repeated analysis

**Move Vulnerability Database Integration**: Patterns from 128 Critical/High findings across 77 audits, adapted for Solidity/EVM:
- Business logic, state management, data inconsistency, centralization, looping issues, and enhanced input validation

---

## Quick Start

### 1. Setup

```bash
python setup.py          # Interactive installer (recommended)
```

### 2. Launch Aether

```bash
python aether.py         # Launches the full-screen Textual TUI
```

That's it. The TUI guides you through everything via keyboard shortcuts and modal dialogs.

---

## Requirements

- **Python 3.11+** (tested with 3.12.8)
- **Node.js 22+** (for Hardhat/npm-based projects)
- **Foundry (forge/anvil)** on PATH for PoC generation and validation
- **solc-select** for multiple Solidity compiler versions
- **API keys for LLM features:**
  - `OPENAI_API_KEY` (for GPT models)
  - `GEMINI_API_KEY` (for Gemini models)
  - `ANTHROPIC_API_KEY` (for Claude models)
  - `ETHERSCAN_API_KEY` (optional, for fetching verified contracts)

## Manual Setup

If you prefer manual installation:

```bash
# Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup
export PATH="$PATH:$HOME/.foundry/bin"

# solc-select
pip install solc-select
solc-select install 0.4.26 0.8.0 0.8.19 0.8.20 latest

# Python dependencies
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The setup wizard (`python setup.py`) handles everything. You can also configure from within the TUI via `s` (Settings):

- **Configure API Keys** — sequential prompts for OpenAI, Gemini, Anthropic, Etherscan keys with masked current values
- **Configure Models** — select models per provider from available options
- **Full Wizard** — runs API keys followed by model selection
- **Triage Settings** — adjust severity thresholds, confidence levels, max findings

Or set environment variables directly:

```bash
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=...
export ANTHROPIC_API_KEY=...
```

Configuration is stored in `~/.aether/config.yaml`.

Database locations:
- Engine results: `~/.aether/aetheraudit.db`
- GitHub audit workflow: `~/.aether/aether_github_audit.db`

---

## TUI Guide

All interaction happens via keyboard shortcuts from the main screen:

### `n` — New Audit

Multi-step wizard with three source types:

**Local file or directory:**
1. Select path via PathDialog
2. If directory, select contracts via CheckboxDialog
3. Choose features (Enhanced, AI Ensemble, LLM Validation, Foundry PoC, Enhanced Reports)
4. Set output directory
5. Confirm and launch as background job(s)

**GitHub URL:**
1. Enter repository URL
2. Aether clones the repo and discovers contracts (progress shown inline)
3. If previous scopes exist, choose: continue, re-audit, or create new scope
4. Select contracts via ContractSelectorDialog (filterable, space to toggle, `a`/`n` for all/none)
5. Audit launches as a background job — visible in the jobs table

**Block explorer URL / address:**
1. Enter address or explorer URL
2. Aether fetches verified source code
3. Continue through features and output selection

### `r` — Resume Audit

Table of all in-progress GitHub audits with project name, scope, progress (N/M contracts), and last update time. Select one to verify pending contracts and launch as a background job.

### `h` — Audit History

Unified view of all past audits from both databases (local + GitHub). Select any entry for a submenu:
- **View Details** — scope breakdown with progress and status
- **Generate PoCs** — redirect to PoC wizard with project pre-selected
- **Re-audit** — select contracts via ContractSelectorDialog, launch as background job

### `p` — Generate PoCs

Select a project, configure max items, minimum severity, and consensus-only filtering. PoC generation runs as a background job — watch progress in the jobs table.

### `o` — Reports

Select project, scope, and format (markdown/json/html/all). Report generation runs as a background job.

### `f` — Fetch Contract

Pick a network from 10+ supported chains, enter an address or paste an explorer URL, fetch the verified source code, and optionally audit it immediately.

### `s` — Settings

- **Run full setup wizard** — API keys then model selection, all inline
- **View current configuration** — formatted display of all settings
- **Reconfigure API keys** — TextInputDialog prompts with masked current values
- **Reconfigure model selections** — SelectDialog per provider
- **Triage settings** — severity, confidence threshold, max findings

### `Enter` — Job Detail

Press Enter on any row in the jobs table to see:
- Live scrolling log output (updated every second)
- Phase progress bar
- Job metadata (type, target, status, cost, elapsed time)

### `q` — Quit

Exits the TUI. If jobs are running, prompts for confirmation.

---

## Scope and Capabilities

- **Static analysis** — 60+ pattern-based detectors (reentrancy, access control, arithmetic, oracle manipulation, flash loans, MEV, governance, DeFi-specific, and more)
- **LLM analysis** — Structured, validation-oriented analysis with OpenAI, Gemini, and Claude; automatic provider fallback
- **AI ensemble** — Multi-agent coordination with consensus-based reasoning (6 agents: 2 OpenAI, 2 Gemini, 2 Anthropic)
- **Parallel auditing** — Concurrent multi-contract analysis with live progress in the jobs table
- **False positive filtering** — 4-stage validation pipeline with governance, deployment, and LLM-based filtering
- **GitHub audit workflow** — Clone repos, detect frameworks, discover contracts, inline scope selection, persistent state
- **Foundry PoC generation** — AST-based analysis, iterative compilation feedback, production-ready exploit prompts
- **Multi-chain contract fetching** — 10+ EVM networks + Solana support
- **Reporting** — Markdown, JSON, HTML report generation from audit data
- **LLM usage tracking** — Token usage, cost tracking, and post-audit summary across all providers
- **Persistence** — Two SQLite databases for engine results and GitHub audit workflow

## Output Directories

- `./output/` — General output root
- `./output/reports/` — Generated reports
- `./output/pocs/` — Generated Foundry PoC suites
- `./output/exploit_tests/` — Results from exploit testing

---

## Architecture

### Entry Points
- `aether.py` — Sole entry point; launches the Textual TUI
- `cli/interactive_menu.py` — Thin shim creating JobManager + AetherApp
- `cli/tui/app.py` — `AetherApp(App)` — main Textual app with key bindings and 1-second refresh timer

### TUI Layer (`cli/tui/`)
- **Screens**: `MainScreen` (jobs table + cost bar), `JobDetailScreen` (live log + phase + metadata), `NewAuditScreen`, `HistoryScreen`, `ResumeScreen`, `PoCScreen`, `ReportsScreen`, `FetchScreen`, `SettingsScreen`
- **Widgets**: `JobsTable` (DataTable polling JobManager), `CostBar` (session cost by provider), `LogViewer` (RichLog with incremental refresh), `PhaseBar` (Unicode block progress)
- **Dialogs**: `ConfirmDialog`, `TextInputDialog`, `SelectDialog`, `CheckboxDialog`, `PathDialog`, `ContractSelectorDialog` — all ModalScreen subclasses
- **Helpers**: `GitHubAuditHelper` — decomposed GitHub audit operations for TUI integration
- **Theme**: `theme.tcss` — cyan-themed Textual CSS

### Background Execution
- `cli/audit_runner.py` — `AuditRunner` class running audits, PoCs, reports, and GitHub audits in daemon threads
- `core/job_manager.py` — `JobManager` singleton: session job registry (QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED)
- `core/audit_progress.py` — `ContractAuditStatus` with per-job log buffers, `ThreadDemuxWriter` for stdout/stderr capture
- `core/llm_usage_tracker.py` — Thread-safe singleton with `snapshot()` for per-job cost deltas

### Core Orchestration
- `cli/main.py` — `AetherCLI` class (~2600 lines) — internal audit orchestrator used by AuditRunner
- `core/enhanced_audit_engine.py` — Main audit engine (Phase 1-3 execution)
- `core/post_audit_summary.py` — Post-audit panel with cost-by-provider breakdown

### Detection Layer
- `core/enhanced_vulnerability_detector.py` — Primary detector with 60+ patterns
- `core/business_logic_detector.py`, `core/state_management_detector.py`, `core/data_inconsistency_detector.py`, `core/centralization_detector.py`, `core/looping_detector.py` — Move-inspired detectors
- `core/defi_vulnerability_detector.py`, `core/mev_detector.py`, `core/oracle_manipulation_detector.py` — DeFi-specific detectors
- `core/arithmetic_analyzer.py`, `core/precision_analyzer.py`, `core/gas_analyzer.py`, `core/input_validation_detector.py`, `core/data_decoding_analyzer.py` — Specialized analyzers

### Validation Layer
- `core/validation_pipeline.py` — 4-stage pipeline: built-in protection check, governance detection, deployment verification, local validation
- `core/governance_detector.py`, `core/deployment_analyzer.py`, `core/llm_false_positive_filter.py`
- `core/control_flow_guard_detector.py`, `core/inheritance_verifier.py`

### LLM & AI Layer
- `core/enhanced_llm_analyzer.py` — Structured LLM analysis (GPT/Gemini/Claude) with JSON output
- `core/ai_ensemble.py` — Multi-agent coordination with consensus-based reasoning
- `core/enhanced_prompts.py` — Production prompt templates

### PoC Generation Layer
- `core/foundry_poc_generator.py` (~8000 lines) — AST-based analysis, iterative compilation feedback
- `core/llm_foundry_generator.py` — LLM-based test generation
- `core/enhanced_foundry_integration.py` — Foundry validation and formatting

### Persistence Layer
- `core/database_manager.py` — `DatabaseManager` (local audits) + `AetherDatabase` (GitHub audits)
- `core/analysis_cache.py` — Smart caching for 2x faster repeated analysis
- `core/accuracy_tracker.py` — Submission outcomes and bounty earnings

### Integrations
- `core/github_auditor.py` — Clone repos, detect frameworks, discover contracts, coordinate analysis
- `core/etherscan_fetcher.py`, `core/basescan_fetcher.py` — Fetch verified contracts from block explorers
- `core/exploit_tester.py`, `core/fork_verifier.py` — Validate exploits against Anvil forks

### Flow-Based Execution
Audit flows defined in YAML configs (`configs/`). Enhanced audit pipeline:
`FileReaderNode -> StaticAnalysisNode -> LLMAnalysisNode -> EnhancedExploitabilityNode -> [FixGeneratorNode -> ValidationNode] -> ReportNode`

---

## Tests

770 tests across 50 test files, running in ~13 seconds:

```bash
python -m pytest tests/                                    # All tests (~13s)
python -m pytest tests/test_enhanced_detectors.py -v       # Single file
python -m pytest tests/test_enhanced_detectors.py::TestArithmeticAnalyzer -v  # Single class
python -m pytest tests/ -k "governance" -v                 # Pattern match
python -m pytest tests/ --cov=core --cov-report=html       # With coverage
```

## Troubleshooting

- **Foundry not found** — Ensure `forge`/`anvil` are installed and on `PATH` (`foundryup` and `export PATH="$PATH:$HOME/.foundry/bin"`)
- **solc not found** — Install `solc-select` and required versions: `solc-select install 0.8.20 latest`
- **LLM features not working** — Verify API keys are set. Some models may be unavailable in your account/region; the system falls back automatically
- **Database not found** — For GitHub reports, ensure the audit workflow has been run first
- **Textual not loading** — Run `pip install textual>=1.0.0` if missing

---

## Changelog

### v3.0 — Fully Inline Textual TUI
- **Zero `app.suspend()` calls** — the TUI never drops to a raw terminal; every operation runs inline
- **Background PoC generation** — runs as a daemon thread via `AuditRunner.start_poc_generation()` with live output in JobDetailScreen
- **Background report generation** — runs as a daemon thread via `AuditRunner.start_report_generation()` with live output
- **Background GitHub audits** — scope selection via Textual dialogs, audit runs as a daemon thread via `AuditRunner.start_github_audit()`
- **ContractSelectorDialog** — near-fullscreen filterable multi-select modal replacing curses-based `ScopeManager.interactive_select()`. Space to toggle, `a`/`n` for all/none, type to filter, color-coded previously-audited contracts
- **GitHubAuditHelper** — decomposed wrapper around `GitHubAuditor`/`AetherDatabase` providing atomic operations (`clone_and_discover`, `get_scope_state`, `save_new_scope`, `get_pending_contracts`, `handle_reaudit`) callable from Textual screens
- **Inline settings** — API key and model configuration via native TextInputDialog/SelectDialog, no external setup wizard needed
- **Inline GitHub scope management** — continue, re-audit, or create new scope via SelectDialog; contract selection via ContractSelectorDialog
- **6 screens rewritten** — PoCScreen, ReportsScreen, SettingsScreen, NewAuditScreen, HistoryScreen, ResumeScreen — all fully inline
- **770 tests** passing across 50 test files in ~13 seconds

### v2.2 — Textual TUI Dashboard
- Full-screen Textual TUI with persistent app, key bindings, and 1-second refresh timer
- MainScreen with live jobs table and session cost bar
- JobDetailScreen with live log viewer, phase progress bar, and metadata
- Modal dialogs (confirm, text input, select, checkbox, path picker) replacing questionary prompts
- Background audit execution via AuditRunner with ThreadDemuxWriter output capture
- JobManager singleton for session job registry
- Per-job cost tracking via LLMUsageTracker snapshots

### v2.1 — Parallel Audits, Slither Removal & Test Cleanup
- Parallel audit engine — run multiple contracts concurrently with `ThreadPoolExecutor`, configurable up to 8 parallel workers
- Thread-safe progress tracking — `ContractAuditStatus` with locking, `ThreadDemuxWriter` for stdout multiplexing
- Post-audit summary — consolidated results view after parallel audits complete
- LLM usage tracking — track token usage, costs, and API calls across all three providers
- Slither fully removed — all dependencies, integration code, and tests deleted (~1200 lines); pattern-based detectors + Foundry ABI + regex are the sole analysis tools
- Test suite cleanup — removed 40+ old/slow/integration test files

### v2.0 — Interactive Menu TUI
- Interactive menu-driven TUI as the primary interface
- Guided audit wizard with source selection, feature checkboxes, and confirmation
- Resume audit capability for in-progress GitHub audits
- Unified audit history browser across local and GitHub databases
- Integrated PoC generation and report workflows from menu
- Multi-chain contract fetching with optional immediate audit
- Settings management from menu
- Console launch/return from menu

### v1.5 — Three-Provider LLM Support & Enhanced Analysis
- Anthropic Claude integration (Sonnet 4.5, Opus 4.6, Haiku 4.5) as third LLM provider
- 6-agent AI ensemble: 2 OpenAI + 2 Gemini + 2 Anthropic specialist agents
- Automatic cross-provider fallback for maximum availability
- Updated OpenAI models (GPT-5.3) and Google Gemini models (3.0 Flash/Pro)
- Setup wizard updated with Anthropic API key configuration and model selection
- Fixed broken generate-foundry CLI command

---

## License

Aether is distributed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

**Dhillon Andrew Kannabhiran** (@l33tdawg)
- Email: l33tdawg@hitb.org
- Twitter: [@l33tdawg](https://twitter.com/l33tdawg)
- GitHub: [@l33tdawg](https://github.com/l33tdawg)

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.
