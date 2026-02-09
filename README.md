# Aether v2.0 — Smart Contract Security Analysis Framework

**Version 2.0** | [What's New in v2.0](#whats-new-in-v20) | [Changelog](#changelog)

Aether is a Python-based framework for analyzing Solidity smart contracts, generating vulnerability findings, producing Foundry-based proof-of-concept (PoC) tests, and validating exploits on mainnet forks. It combines static analysis (Slither), prompt-driven LLM analysis, AI-ensemble reasoning, and advanced false-positive filtering into a single guided workflow.

## What's New in v2.0

**Interactive Menu-Driven TUI** — Aether v2.0 replaces the command-memorization workflow with a guided interactive experience. Just run `python aether.py` (or `python main.py` with no arguments) and you get:

```
╔══════════════════════════════════════════════════════════════╗
║               A E T H E R   v 2 . 0                          ║
║      Smart Contract Security Analysis Framework              ║
╚══════════════════════════════════════════════════════════════╝

  [1]  New Audit            Start a new security audit
  [2]  Resume Audit         Continue an in-progress audit
  [3]  Audit History        Browse past audits & results
  [4]  Generate PoCs        Create Foundry exploit proofs
  [5]  Reports              Generate/view audit reports
  [6]  Fetch Contract       Fetch from blockchain explorers
  [7]  Settings             Configure API keys, models, tools
  [8]  Console              Launch advanced Metasploit-style console
  [0]  Exit

  Select: _
```

- **Guided audit wizard** — walks you through source selection, feature toggles, and output config
- **Resume audits** — pick up exactly where you left off on any in-progress GitHub audit
- **Audit history** — browse all past audits across local and GitHub sources, with details and re-audit options
- **Integrated PoC generation** — select project, scope, severity, and generate Foundry exploits in one flow
- **Report generation** — choose project, scope, format (markdown/json/html/all) from a menu
- **Multi-chain contract fetching** — select network, paste address or URL, optionally audit immediately
- **Settings management** — full setup wizard, API key config, model selection, triage tuning
- **Power-user CLI preserved** — all `python main.py <command>` workflows still work for scripting and CI/CD

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
python aether.py         # Interactive menu (recommended)
python main.py           # Same thing — launches menu when no args given
```

That's it. The menu guides you through everything.

### Non-interactive / CI mode

```bash
python setup.py --non-interactive
python main.py audit ./contracts --enhanced --ai-ensemble --llm-validation -o ./output
```

---

## Requirements

- **Python 3.11+** (tested with 3.12.8)
- **Node.js 22+** (for Hardhat/npm-based projects)
- **Foundry (forge/anvil)** on PATH for PoC generation and validation
- **solc-select** for multiple Solidity compiler versions
- **Optional: Slither** for static analysis integration (v0.10.0 recommended)
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

# Slither (optional)
pip install slither-analyzer==0.10.0

# solc-select
pip install solc-select
solc-select install 0.4.26 0.8.0 0.8.19 0.8.20 latest

# Python dependencies
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The setup wizard (`python setup.py`) handles everything, or configure manually:

```bash
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=...
export ANTHROPIC_API_KEY=...
```

Or copy and edit the example env file:

```bash
cp env.example .env
```

Configuration is stored in `~/.aether/config.yaml`. Use **[7] Settings** in the interactive menu to manage it.

Database locations:
- Engine results: `~/.aether/aetheraudit.db`
- GitHub audit workflow: `~/.aether/aether_github_audit.db`

---

## Interactive Menu Guide

### [1] New Audit

The guided wizard walks you through:
1. **Source selection** — Local file/directory, GitHub URL, or block explorer URL/address
2. **Target input** — path, URL, or address with validation
3. **Feature selection** — checkboxes for Enhanced mode, AI Ensemble, LLM Validation, Foundry PoC, Enhanced Reports (sensible defaults pre-checked)
4. **Output directory** — with sensible default
5. **Confirm & run**

### [2] Resume Audit

Shows a table of all in-progress GitHub audits with project name, scope, progress (N/M contracts), and last update time. Select one to resume exactly where you left off.

### [3] Audit History

Unified view of all past audits from both databases (local + GitHub). Select any entry for a submenu: view scopes & details, generate PoCs, or re-audit.

### [4] Generate PoCs

Select a project, configure max items, minimum severity, and consensus-only filtering, then generate Foundry exploit proofs.

### [5] Reports

Select project, scope, and format (markdown/json/html/all) to generate audit reports.

### [6] Fetch Contract

Pick a network from 10+ supported chains, enter an address or paste an explorer URL, fetch the verified source code, and optionally audit it immediately.

### [7] Settings

- Run full setup wizard
- View current configuration
- Reconfigure API keys only
- Reconfigure model selections only
- Edit triage settings (severity, confidence, max findings)

### [8] Console

Launches the advanced Metasploit-style interactive console. Type `exit` to return to the main menu.

---

## CLI Reference (Power-User Mode)

All subcommands remain available for scripting, CI/CD, and power users:

```bash
# Audit local contracts
python main.py audit ./contracts --enhanced --ai-ensemble --llm-validation -o ./output

# Audit a GitHub repository
python main.py audit https://github.com/owner/repo --interactive-scope --github-token <token>

# Generate Foundry PoCs
python main.py generate-foundry --from-results ./output/results.json --out ./output/pocs
python main.py generate-foundry --project-id 1 --scope-id 2 --only-consensus

# Generate reports
python main.py report --format markdown --project-id 1 -o ./output/reports
python main.py report --list-projects
python main.py report --list-scopes 1

# Foundry validation
python main.py foundry ./contracts -o ./output --verbose

# Fork verification
python main.py fork-verify ./output --rpc-url <url>

# Exploit testing
python main.py exploit-test <project_name>

# Fetch contracts from block explorers
python main.py fetch 0x1234... --network polygon -o ./contracts

# Console
python main.py console

# Configuration
python main.py config --show
python main.py config --set-etherscan-key YOUR_KEY
python main.py config --list-networks

# Database management
python main.py db --stats
python main.py db --list-audits

# Version
python main.py version
```

Use `python main.py <command> --help` for full options on any subcommand.

---

## Scope and Capabilities

- **Static analysis** — Slither integration + 60+ pattern-based detectors
- **LLM analysis** — Structured, validation-oriented analysis with OpenAI, Gemini, and Claude; automatic provider fallback
- **AI ensemble** — Multi-agent coordination with consensus-based reasoning (6 agents: 2 OpenAI, 2 Gemini, 2 Anthropic)
- **False positive filtering** — 4-stage validation pipeline with governance, deployment, and LLM-based filtering
- **GitHub audit workflow** — Clone repos, detect frameworks, discover contracts, interactive scope selection, persistent state
- **Foundry PoC generation** — AST-based analysis, iterative compilation feedback, production-ready exploit prompts
- **Multi-chain contract fetching** — 10+ EVM networks + Solana support
- **Reporting** — Markdown, JSON, HTML report generation from audit data
- **Persistence** — Two SQLite databases for engine results and GitHub audit workflow

## Output Directories

- `./output/` — General output root
- `./output/reports/` — Generated reports
- `./output/pocs/` — Generated Foundry PoC suites
- `./output/exploit_tests/` — Results from exploit testing


## Troubleshooting

- **Foundry not found** — Ensure `forge`/`anvil` are installed and on `PATH` (`foundryup` and `export PATH="$PATH:$HOME/.foundry/bin"`)
- **Slither not found** — Install with `pip install slither-analyzer==0.10.0`. If unavailable, the pipeline skips Slither
- **solc not found** — Install `solc-select` and required versions: `solc-select install 0.8.20 latest`
- **LLM features not working** — Verify API keys are set. Some models may be unavailable in your account/region; the system falls back automatically
- **Database not found** — For GitHub reports, ensure the audit workflow has been run first
- **Menu not appearing** — Run `pip install questionary rich` if missing


## Tests

```bash
python -m pytest tests/                                    # All tests
python -m pytest tests/test_enhanced_detectors.py -v       # Single file
python -m pytest tests/ -k "governance" -v                 # Pattern match
python -m pytest tests/ --cov=core --cov-report=html       # With coverage
```


## Architecture

### Entry Points
- `aether.py` — Primary entry point, launches interactive menu TUI
- `main.py` — CLI dispatcher; no args launches menu, subcommands for direct access
- `cli/interactive_menu.py` — Interactive menu engine (AetherInteractiveMenu class)
- `cli/main.py` — AetherCLI class (~2600 lines) orchestrating all command implementations
- `cli/console.py` — Metasploit-style interactive console

### Core Layers
- **Detection** — `core/enhanced_vulnerability_detector.py` + specialized detectors (DeFi, MEV, oracle, arithmetic, gas, business logic, state management, centralization, looping, data inconsistency)
- **Validation** — `core/validation_pipeline.py` (4-stage pipeline), `core/governance_detector.py`, `core/deployment_analyzer.py`, `core/llm_false_positive_filter.py`
- **LLM & AI** — `core/enhanced_llm_analyzer.py`, `core/ai_ensemble.py`, `core/enhanced_prompts.py`
- **PoC Generation** — `core/foundry_poc_generator.py` (AST-based, ~8000 lines), `core/llm_foundry_generator.py`, `core/enhanced_foundry_integration.py`
- **Persistence** — `core/database_manager.py` (DatabaseManager + AetherDatabase), `core/analysis_cache.py`, `core/accuracy_tracker.py`
- **Integrations** — `core/github_auditor.py`, `core/etherscan_fetcher.py`, `core/basescan_fetcher.py`, `core/exploit_tester.py`, `core/fork_verifier.py`

### Flow-Based Execution
Audit flows defined in YAML configs (`configs/`). Enhanced audit pipeline:
`FileReaderNode → StaticAnalysisNode → LLMAnalysisNode → EnhancedExploitabilityNode → [FixGeneratorNode → ValidationNode] → ReportNode`


## Changelog

### v2.0 — Interactive Menu TUI
- Interactive menu-driven TUI as the primary interface (`python aether.py`)
- `python main.py` without arguments now launches the interactive menu
- Guided audit wizard with source selection, feature checkboxes, and confirmation
- Resume audit capability for in-progress GitHub audits
- Unified audit history browser across local and GitHub databases
- Integrated PoC generation and report workflows from menu
- Multi-chain contract fetching with optional immediate audit
- Settings management (setup wizard, API keys, models, triage) from menu
- Console launch/return from menu
- Version bumped to 2.0.0

### v1.5 — Three-Provider LLM Support & Enhanced Analysis
- Anthropic Claude integration (Sonnet 4.5, Opus 4.6, Haiku 4.5) as third LLM provider
- 6-agent AI ensemble: 2 OpenAI + 2 Gemini + 2 Anthropic specialist agents
- Automatic cross-provider fallback for maximum availability
- Updated OpenAI models (GPT-5.3) and Google Gemini models (3.0 Flash/Pro)
- Anthropic Security Auditor agent for deep access control and reentrancy analysis
- Anthropic Reasoning Specialist agent leveraging extended thinking for complex vulnerabilities
- Setup wizard updated with Anthropic API key configuration and model selection
- Fixed broken generate-foundry CLI command (restored LLMFoundryGenerator module)
- Fixed indentation bug in output directory handling for generate-foundry
- All 22 previously-broken foundry generator tests now passing


## License

Aether is distributed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

**Dhillon Andrew Kannabhiran** (@l33tdawg)
- Email: l33tdawg@hitb.org
- Twitter: [@l33tdawg](https://twitter.com/l33tdawg)
- GitHub: [@l33tdawg](https://github.com/l33tdawg)

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.
