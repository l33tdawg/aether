# Aether - Adaptive Exploit & Threat Hunting Engine for EVM-based Repositories 
## A Smart Contract Security Analysis and PoC Generation Framework 

Aether is a Python-based framework for analyzing Solidity smart contracts, generating vulnerability findings, producing Foundry-based proof-of-concept (PoC) tests, and optionally validating those tests on mainnet forks. It combines static analysis, prompt-driven LLM analysis, and AI-ensemble reasoning with reporting and persistence.

**Enhanced PoC Generation**: Aether now features advanced AST-based contract analysis, iterative compilation fixes, and production-ready LLM prompts that generate exploits suitable for bug bounty submissions.

## Scope and Capabilities

- Static analysis
  - Slither integration when available
  - Enhanced pattern-based detectors in `core/enhanced_vulnerability_detector.py`

- LLM analysis
  - `core/enhanced_llm_analyzer.py` performs structured, validation-oriented analysis
  - Requires `OPENAI_API_KEY` and/or `GEMINI_API_KEY`
  - Strict JSON output and post-processing to reduce false positives

- AI ensemble
  - `core/ai_ensemble.py` coordinates multiple specialized agents, aggregates results, and attempts consensus
  - Requires API keys and model availability

- GitHub audit workflow
  - `core/github_auditor.py` clones repositories, detects frameworks, discovers contracts, and coordinates analysis
  - Interactive scope selection via `core/scope_manager.py`
  - Audit results persisted via `core/database_manager.AetherDatabase` to `~/.aether/aether_github_audit.db`

- Foundry integration and PoC generation
  - **AST-based contract analysis** for 100% accurate function and modifier extraction
  - **Enhanced LLM prompts** with production-ready exploit generation for $100k+ bounties
  - **Iterative compilation feedback loop** that fixes errors automatically using LLM
  - **Vulnerability-aware contract context** extraction based on vulnerability type
  - LLM-based Foundry tests via `core/llm_foundry_generator.py`
  - Enhanced Foundry validation and submission formatting via `core/enhanced_foundry_integration.py`
  - Optional exploit testing and fork verification via `core/exploit_tester.py` and the `fork-verify` command (implemented by `core/fork_verifier.py`)

- Reporting
  - Markdown/JSON/HTML report generation from audit data
  - GitHub audit reporting via `core/github_audit_report_generator.py`

- Persistence
  - Two SQLite databases are used:
    - `~/.aether/aetheraudit.db` for engine-driven results
    - `~/.aether/aether_github_audit.db` for GitHub audit workflow


## Quick Setup (Recommended)

**New users:** Run the automated installer for a guided setup experience:

```bash
python setup.py
```

This interactive installer will:
- ✓ Check system requirements (Python 3.11+)
- ✓ Install Foundry (forge/anvil) if needed
- ✓ Set up Python virtual environment
- ✓ Install all Python dependencies
- ✓ Configure API keys with validation
- ✓ Create configuration files
- ✓ Verify everything works

**Non-interactive mode** (for CI/CD):
```bash
python setup.py --non-interactive
```

## Requirements

- **Python 3.11+** (currently tested with Python 3.12.8)
- **Foundry (forge/anvil)** installed and on PATH for Foundry-related features
- **solc-select** for multiple Solidity compiler versions (supports 0.4.x through 0.8.x)
- **Optional: Slither** for static analysis integration (v0.10.0 recommended)
- **API keys for LLM features:**
  - `OPENAI_API_KEY` (for GPT models)
  - `GEMINI_API_KEY` (for Gemini models)
  - `ETHERSCAN_API_KEY` (optional, for fetching verified contracts)

## Manual Setup

If you prefer manual installation or the automated setup fails:

### Install system tools:

```bash
# Foundry (required for PoC generation)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Add Foundry to PATH if needed
export PATH="$PATH:$HOME/.foundry/bin"

# Slither (optional but recommended for static analysis)
pip install slither-analyzer==0.10.0

# solc-select (required for multiple Solidity versions)
pip install solc-select

# Install common Solidity compiler versions
solc-select install 0.4.26 0.8.0 0.8.19 0.8.20 latest
```

### Install Python dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## Configuration

### Automated Configuration

The `setup.py` installer will guide you through configuring all API keys.

### Manual Configuration

Set environment variables:

```bash
# Required for LLM features
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=gsk-...

# Optional
export AETHER_LOG_LEVEL=INFO
```

Or copy the example environment file and fill in your keys:

```bash
cp env.example .env
# Edit .env with your API keys
```

Database locations:

- Engine results: `~/.aether/aetheraudit.db`
- GitHub audit workflow: `~/.aether/aether_github_audit.db`

To reset the GitHub audit database:

```bash
rm ~/.aether/aether_github_audit.db
```


## CLI Overview

The primary entrypoint is `python main.py`. Key subcommands implemented in `main.py` and `cli/main.py`:

- `audit` — Analyze a local contract path or a GitHub repository URL
- `report` — Generate reports from the GitHub audit database
- `generate-foundry` — Generate Foundry PoCs from a structured results file or report
- `foundry` — Run Foundry validation with PoC generation for bug bounty submissions
- `fork-verify` — Run generated Foundry tests against an Anvil fork
- `exploit-test` — Test generated exploit code against audited contracts (database-backed)
- `console` — Interactive console
- `config` — Manage configuration settings
- `fetch`, `db`, `version` — Utilities

Use `python main.py <command> --help` for full options.


## Usage Examples

### 1) Audit a local contract directory

```bash
python main.py audit ./contracts --enhanced --ai-ensemble --llm-validation -o ./output
```

Notes:
- `--enhanced` enables the enhanced audit engine.
- `--ai-ensemble` activates experimental multi-agent analysis if API keys are configured.
- `--llm-validation` adds LLM-based validation and triage.

### 2) Audit a GitHub repository with interactive scoping

```bash
python main.py audit https://github.com/owner/repo --interactive-scope --github-token <token>
```

Notes:
- Contracts are discovered and presented for interactive selection.
- Results are persisted to `~/.aether/aether_github_audit.db`.

### 3) Generate reports from the GitHub audit database

```bash
python main.py report --format markdown --output ./output/reports --list-projects
python main.py report --format json --project-id 1 -o ./output/reports
```

You can list projects or scopes before generating a report:

```bash
python main.py report --list-projects
python main.py report --list-scopes 1
```

### 4) Generate Foundry PoCs from results

```bash
# Preferred: from a structured results.json produced by prior analysis
python main.py generate-foundry --from-results ./output/results.json --out ./output/pocs --max-items 20 --only-consensus

# Fallback: from a markdown report (limited parsing)
python main.py generate-foundry --from-report ./output/report.md --out ./output/pocs
```

LLM-based PoC generation is the default. Ensure `OPENAI_API_KEY` (and/or `GEMINI_API_KEY`) is set for best results. Template-only mode (no LLM) is available but not recommended except for offline/CI smoke runs:

```bash
python scripts/generate_foundry_pocs.py \
  --results ./output/results.json \
  --contract ./contracts/MyContract.sol \
  --output ./output/pocs \
  --template-only
```

**Enhanced PoC Generation Features:**
- **AST-based analysis** provides 100% accurate contract function extraction
- **Production-ready prompts** generate exploits suitable for $100k+ bug bounty submissions
- **Iterative compilation fixes** automatically resolve compilation errors using LLM feedback
- **Vulnerability-specific attack chains** for different vulnerability types (access control, reentrancy, oracle manipulation, etc.)
- **Enhanced contract context** provides vulnerability-focused analysis around vulnerable code locations

### 5) Run Foundry validation directly

```bash
python main.py foundry ./contracts/MyContract.sol -o ./output/foundry
```

### 6) Verify PoCs on a mainnet fork

```bash
# Start Anvil locally (in another terminal) or provide an RPC URL to fork-verify
anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/<key>

# Verify generated tests against a fork
python main.py fork-verify ./output/pocs --rpc-url https://eth-mainnet.g.alchemy.com/v2/<key> --block 19000000
```

### 7) Exploit testing across audited findings (database-backed)

```bash
python main.py exploit-test <project_name>
```

This uses findings persisted by the GitHub audit workflow and attempts PoC generation and execution.


## Output and Directories

- `./output/` — General output root
- `./output/reports/` — Generated reports
- `./output/pocs/` — Generated Foundry PoC suites
- `./output/exploit_tests/` — Results from exploit testing


## Troubleshooting

- Foundry not found
  - Ensure `forge`/`anvil` are installed and on `PATH` (`foundryup` and `export PATH="$PATH:$HOME/.foundry/bin"`).

- Slither not found
  - Install with `pip install slither-analyzer==0.10.0`. If unavailable, the pipeline skips Slither.
  - Note: Slither may not be detected by the dependency checker if installed outside PATH, but should still work.

- solc not found or wrong version
  - Install solc-select: `pip install solc-select`
  - Install required versions: `solc-select install 0.4.26 0.8.0 0.8.19 0.8.20 latest`
  - Switch versions as needed: `solc-select use 0.8.19`

- LLM features not working
  - Verify `OPENAI_API_KEY` and/or `GEMINI_API_KEY` are set.
  - Some ensemble models may be unavailable in your account/region. The system falls back where possible.

- Database not found
  - For GitHub reports, ensure the audit workflow has been run and `~/.aether/aether_github_audit.db` exists.


## Development Notes

- Code paths used by the CLI:
  - Main entrypoint: `main.py`
  - CLI coordinator: `cli/main.py`
  - Enhanced audit engine: `core/enhanced_audit_engine.py`
  - LLM analyzer: `core/enhanced_llm_analyzer.py`
  - AI ensemble: `core/ai_ensemble.py` (experimental)
  - GitHub auditor: `core/github_auditor.py`
  - **Enhanced Foundry generation**: `core/foundry_poc_generator.py` (AST analysis, iterative fixes, production-ready prompts)
  - Foundry generation and validation: `core/llm_foundry_generator.py`, `core/enhanced_foundry_integration.py`
  - Exploit testing: `core/exploit_tester.py`
  - Reporting: `core/report_generator.py`, `core/github_audit_report_generator.py`
  - Persistence: `core/database_manager.py`

- **Comprehensive test suite** for enhanced features:
  - `tests/test_poc_generator_enhancements.py` - AST analysis and enhanced prompts
  - `tests/test_iterative_compilation_fixes.py` - Compilation feedback loop
  - `tests/test_enhanced_llm_integration.py` - LLM integration improvements
  - `tests/test_poc_generator_improvements.py` - Integration testing

- Known inconsistencies and caveats:
  - AI ensemble is experimental and subject to change.
  - Some modules print colored output or symbols; functionality does not depend on them.


## License

AetherAudit is distributed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

**Dhillon Andrew Kannabhiran** (@l33tdawg)
- Email: l33tdawg@hitb.org
- Twitter: [@l33tdawg](https://twitter.com/l33tdawg)
- GitHub: [@l33tdawg](https://github.com/l33tdawg)

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.
