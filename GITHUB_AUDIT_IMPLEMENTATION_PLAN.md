# AetherAudit GitHub Audit Implementation Plan

**Version**: 1.0  
**Date**: October 16, 2025  
**Status**: Ready for Implementation  
**Priority**: High - Core Feature for Bug Bounty Hunting

---

## Executive Summary

This plan outlines the implementation of a **production-grade GitHub audit workflow** that enables bug bounty hunters to analyze entire smart contract projects with a single command. The system will clone repositories, detect frameworks, build projects, analyze contracts sequentially, cache results intelligently, and learn from failures.

**Key Feature**: `aether audit https://github.com/enzyme-finance/protocol-onyx`

---

## Architecture Overview

### Two-Layer Design

```
┌─────────────────────────────────────────────────────────┐
│  NEW LAYER: GitHub Audit Orchestrator                  │
│  - Repository management (clone/cache/pull)             │
│  - Framework detection (Foundry/Hardhat/Truffle)        │
│  - Build orchestration & artifact caching               │
│  - Contract discovery (sequential processing)           │
│  - Result aggregation & organization                    │
│  - Error tracking & learning                            │
└─────────────────────────────────────────────────────────┘
              ↓ (Uses existing engines)
┌─────────────────────────────────────────────────────────┐
│  EXISTING LAYER: Core Analysis Engine (Unchanged)       │
│  - Pattern detection                                    │
│  - DeFi-specific analysis                               │
│  - Slither integration with fallback                    │
│  - LLM analysis                                         │
│  - Vulnerability aggregation                           │
└─────────────────────────────────────────────────────────┘
```

**Design Principle**: New code orchestrates; existing code analyzes. Zero changes to core analysis logic.

---

## Database Schema (SQLite)

### Projects Table
```sql
CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    repo_name TEXT NOT NULL,
    owner TEXT,
    framework TEXT,  -- 'foundry', 'hardhat', 'truffle'
    cloned_at DATETIME,
    last_updated DATETIME,
    last_analyzed DATETIME,
    cache_path TEXT,
    build_status TEXT,  -- 'success', 'failed', 'partial'
    build_log TEXT,
    solc_version TEXT,
    is_private BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, repo_name)
);
```

### Contracts Table
```sql
CREATE TABLE contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,  -- src/handlers/FeeHandler.sol
    contract_name TEXT,
    solc_version TEXT,
    discovered_at DATETIME,
    line_count INTEGER,
    dependencies TEXT,  -- JSON list of imports
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, file_path)
);
```

### Analysis Results Table
```sql
CREATE TABLE analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL,
    analysis_type TEXT NOT NULL,  -- 'pattern', 'defi', 'slither', 'llm'
    findings JSON,  -- Complete findings JSON
    analyzed_at DATETIME,
    status TEXT,  -- 'success', 'failed', 'fallback'
    error_log TEXT,
    analysis_duration_ms INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(contract_id) REFERENCES contracts(id) ON DELETE CASCADE,
    UNIQUE(contract_id, analysis_type)
);
```

### Build Artifacts Cache Table
```sql
CREATE TABLE build_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    artifact_path TEXT,  -- Location of compiled artifacts
    artifact_hash TEXT,  -- Hash of foundry.toml + remappings for invalidation
    solc_version TEXT,
    dependencies_hash TEXT,
    created_at DATETIME,
    last_accessed DATETIME,
    size_mb REAL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id)
);
```

### Analysis Errors Table (For Learning)
```sql
CREATE TABLE analysis_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    contract_id INTEGER,
    error_type TEXT,  -- 'build_failed', 'slither_error', 'import_error', etc.
    error_message TEXT,
    tool_that_failed TEXT,  -- 'foundry', 'slither', 'pattern_analyzer', 'llm'
    contract_path TEXT,
    full_error_log TEXT,
    occurred_at DATETIME,
    status TEXT,  -- 'logged_for_review', 'fixed', 'known_limitation'
    resolution_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id),
    FOREIGN KEY(contract_id) REFERENCES contracts(id)
);
```

### Summary Statistics Table
```sql
CREATE TABLE project_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL UNIQUE,
    total_contracts INTEGER,
    total_findings INTEGER,
    critical_findings INTEGER,
    high_findings INTEGER,
    medium_findings INTEGER,
    low_findings INTEGER,
    fallback_analyses INTEGER,
    failed_analyses INTEGER,
    analysis_time_seconds REAL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);
```

---

## New Modules Required

### 1. **`core/github_auditor.py`** (Main Orchestrator)

**Purpose**: High-level orchestration of GitHub audit workflow

**Key Classes**:
```python
class GitHubAuditor:
    - __init__(cache_dir, db_path, engine)
    - audit(github_url, options) -> AuditResult
    - _clone_or_update_repo(url) -> str
    - _detect_framework(repo_path) -> str
    - _build_project(repo_path) -> BuildResult
    - _discover_contracts(repo_path) -> List[ContractInfo]
    - _analyze_contract_sequential(contract_path) -> ContractAnalysis
    - _aggregate_results(findings) -> AuditReport
    - _track_error(error) -> None
```

**Responsibilities**:
- Coordinate overall audit workflow
- Manage repository lifecycle
- Call existing analysis engine for each contract
- Handle caching and cache validation
- Aggregate and format final results

---

### 2. **`core/repository_manager.py`** (Git Operations)

**Purpose**: Handle all git/repository operations

**Key Classes**:
```python
class RepositoryManager:
    - __init__(cache_dir, db)
    - clone_or_get(github_url, force_fresh=False) -> str
    - pull_updates(repo_path) -> bool
    - is_cache_valid(repo_path, github_url) -> bool
    - get_cache_size(repo_path) -> int
    - clear_cache(repo_path) -> None
    - validate_repo_structure(repo_path) -> bool
```

**Responsibilities**:
- Clone new repositories to cache
- Update existing cached repos
- Validate cache integrity
- Handle private repos (with token support)
- Clean up old caches

---

### 3. **`core/framework_detector.py`** (Framework Detection)

**Purpose**: Auto-detect and handle different frameworks

**Key Classes**:
```python
class FrameworkDetector:
    - detect(repo_path) -> FrameworkType
    - read_config(repo_path) -> FrameworkConfig
    - get_solc_version(repo_path) -> str
    - get_remappings(repo_path) -> Dict[str, str]
    - get_lib_paths(repo_path) -> List[str]
    - supports_framework(repo_path) -> bool
```

**Supported Frameworks**:
- Foundry (foundry.toml)
- Hardhat (hardhat.config.js)
- Truffle (truffle-config.js)

---

### 4. **`core/project_builder.py`** (Build Orchestration)

**Purpose**: Handle project compilation and artifact management

**Key Classes**:
```python
class ProjectBuilder:
    - __init__(db, cache_manager)
    - build(repo_path, framework) -> BuildResult
    - get_cached_artifacts(project_id) -> Optional[ArtifactCache]
    - is_cache_valid(project_id, repo_path) -> bool
    - cache_artifacts(project_id, repo_path, artifacts)
    - install_dependencies(repo_path, framework) -> bool
    - compute_config_hash(repo_path) -> str
```

**Responsibilities**:
- Execute build commands (forge build, npm run build, etc.)
- Validate build success
- Cache compiled artifacts
- Invalidate cache when config changes
- Log build errors for learning

---

### 5. **`core/contract_discoverer.py`** (Contract Discovery)

**Purpose**: Find and catalog all contracts in a project

**Key Classes**:
```python
class ContractDiscoverer:
    - __init__(db)
    - discover_all(repo_path, project_id) -> List[ContractInfo]
    - filter_contracts(contracts, patterns) -> List[ContractInfo]
    - parse_dependencies(contract_path) -> List[str]
    - classify_contract(contract_path, content) -> ContractType
    - get_contract_info(contract_path) -> ContractInfo
```

**Responsibilities**:
- Find all .sol files (skip test/)
- Extract contract names
- Parse imports/dependencies
- Skip test contracts
- Generate ContractInfo objects

**ContractInfo Structure**:
```python
@dataclass
class ContractInfo:
    file_path: str
    contract_name: str
    solc_version: str
    dependencies: List[str]
    line_count: int
    is_test: bool
    is_library: bool
```

---

### 6. **`core/sequential_analyzer.py`** (Sequential Analysis Orchestrator)

**Purpose**: Manage sequential analysis of contracts with caching

**Key Classes**:
```python
class SequentialAnalyzer:
    - __init__(db, audit_engine)
    - analyze_contract(contract_path, contract_id, force=False) -> ContractAnalysis
    - analyze_all_contracts(contracts, options) -> List[ContractAnalysis]
    - should_reanalyze(contract_id, force=False) -> bool
    - get_cached_analysis(contract_id) -> Optional[ContractAnalysis]
    - save_analysis_result(contract_id, findings, status) -> None
    - try_fallback_analysis(contract_path, error) -> Optional[ContractAnalysis]
```

**Responsibilities**:
- Check cache before analyzing
- Call existing audit engine
- Handle analysis failures
- Attempt fallback analysis
- Save results to database
- Track errors for learning

---

### 7. **`core/database_manager.py`** (SQLite Management)

**Purpose**: Database operations and caching logic

**Key Classes**:
```python
class AetherDatabase:
    - __init__(db_path)
    - init_schema() -> None
    - get_project(github_url) -> Optional[Project]
    - create_project(url, repo_name, framework) -> Project
    - get_contracts(project_id) -> List[Contract]
    - save_contract(project_id, file_path, info) -> Contract
    - get_analysis_results(contract_id) -> Optional[AnalysisResults]
    - save_analysis_result(contract_id, findings, status, error_log)
    - get_build_artifacts(project_id) -> Optional[BuildArtifact]
    - save_build_artifacts(project_id, artifact_path, hash)
    - log_error(error_info) -> None
    - get_error_patterns() -> List[ErrorPattern]
    - get_project_statistics(project_id) -> ProjectStats
    - is_analysis_complete(project_id) -> bool
```

**Responsibilities**:
- Manage SQLite connections
- Execute CRUD operations
- Cache validation logic
- Error tracking
- Statistics aggregation

---

### 8. **`core/audit_result_formatter.py`** (Results Formatting)

**Purpose**: Format and organize analysis results

**Key Classes**:
```python
class AuditResultFormatter:
    - format_for_display(findings) -> str
    - format_for_immunefi(findings, project_info) -> str
    - format_for_json(findings) -> Dict
    - generate_summary(findings) -> Summary
    - estimate_bounty_range(findings) -> BountyRange
    - organize_by_severity(findings) -> SeverityGrouped
    - organize_by_contract(findings) -> ContractGrouped
```

**Output Formats**:
- Console display (human-readable)
- Immunefi markdown (submission-ready)
- JSON (programmatic)
- CSV (data analysis)

---

## Integration Points

### With Existing Code

```
GitHubAuditor
    ↓
SequentialAnalyzer  →  AetherAuditEngine.run_static_analysis()
    ↓                   (existing engine, unchanged)
    ↓                   Returns: Pattern + DeFi + Slither + LLM findings
    ↓
AuditResultFormatter
    ↓
Output (Display/JSON/Immunefi)
```

**Existing Modules Used (No Changes)**:
- `core.audit_engine.AetherAuditEngine`
- `core.nodes.audit_nodes.StaticAnalysisNode`
- `core.llm_analyzer.LLMAnalyzer`
- `core.file_handler.FileHandler`

---

## CLI Interface

### Command Structure

```bash
aether audit <github-url> [options]

OPTIONS:
  --scope <contracts>          Filter to specific contracts (comma-separated)
  --min-severity <level>       Only show critical,high,medium,low
  --format <output>            display (default), json, immunefi, csv
  --output <file>              Save results to file
  --fresh                      Ignore cache, full re-analysis
  --reanalyze                  Re-run analysis on cached contracts
  --retry-failed               Only analyze contracts that failed last time
  --clear-cache                Remove cached project before analysis
  --parallel                   Analyze multiple contracts simultaneously [future]
  --skip-build                 Use existing build artifacts
  --no-cache                   Don't cache results
  --verbose                    Detailed logging
  --dry-run                    Show what would be analyzed, don't analyze
  --github-token <token>       For private repos
```

### Examples

```bash
# Basic audit
aether audit https://github.com/enzyme-finance/protocol-onyx

# With Immunefi output
aether audit https://github.com/enzyme-finance/protocol-onyx \
  --format immunefi \
  --output immunefi_report.md

# Only analyze in-scope contracts
aether audit https://github.com/enzyme-finance/protocol-onyx \
  --scope "FeeHandler,ValuationHandler"

# Resume interrupted analysis
aether audit https://github.com/enzyme-finance/protocol-onyx
# (Automatically skips cached contracts)

# Find what needs fixing
aether audit https://github.com/enzyme-finance/protocol-onyx --retry-failed

# Dry run to see what would be analyzed
aether audit https://github.com/enzyme-finance/protocol-onyx --dry-run
```

---

## Workflow Diagram

```
┌─────────────────────────────┐
│  User Input: GitHub URL     │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│  Check if project cached    │
│  (SQLite lookup)            │
└──────┬──────────────┬───────┘
       │              │
    YES              NO
       ↓              ↓
    ┌─────────────────────────────────┐
    │  git pull (update)              │  OR  │  git clone (new)  │
    └────────────┬────────────────────┘      └────────┬──────────┘
                 └────────────────┬────────────────────┘
                                  ↓
                    ┌─────────────────────────────┐
                    │  Detect Framework           │
                    │  (foundry.toml detected)    │
                    └────────────┬────────────────┘
                                 ↓
                    ┌─────────────────────────────┐
                    │  Check Build Cache          │
                    │  (valid artifact?)          │
                    └──────┬──────────────┬───────┘
                        YES              NO
                           ↓              ↓
                    ┌──────────────────────────────────┐
                    │  Use cached artifacts  OR  Build │
                    │  (forge build)                   │
                    └──────┬───────────────────────────┘
                           ↓
         ┌─────────────────────────────────────┐
         │  Discover Contracts (skip test/)    │
         │  Found: 12 contracts                │
         └──────┬──────────────────────────────┘
                ↓
        ┌───────────────────────┐
        │  For Each Contract:   │
        │  (Sequential)         │
        └────┬─────────────┬────┘
             ↓             ↓
    ┌─────────────────────────────────┐
    │  Check Analysis Cache           │
    │  (Contract analyzed before?)    │
    └──────┬──────────────┬───────────┘
        YES              NO
           ↓              ↓
    ┌─────────────────────────────────┐
    │  Use cached OR Run Analysis     │
    │  - Pattern detection            │
    │  - DeFi analysis                │
    │  - Slither                      │
    │  - LLM analysis                 │
    └──────┬──────────────────────────┘
           ↓
    [If analysis fails]
           ↓
    ┌─────────────────────────────────┐
    │  Try Fallback Analysis          │
    │  (Direct Slither)               │
    └──────┬──────────────────────────┘
           ↓
    ┌─────────────────────────────────┐
    │  Log Error to DB                │
    │  (For tool improvement)         │
    └──────┬──────────────────────────┘
           ↓
    ┌─────────────────────────────────┐
    │  Cache Results (SQLite)         │
    └──────┬──────────────────────────┘
           ↓
    ┌──────────────────────────────────────────────┐
    │  Continue to next contract (if any)          │
    └──────┬───────────────────────────────────────┘
           ↓
       More?  → YES → Back to "For Each Contract"
       NO
           ↓
    ┌──────────────────────────────────┐
    │  Aggregate Results               │
    │  - Sort by severity              │
    │  - Group by contract             │
    │  - Calculate statistics          │
    │  - Estimate bounty range         │
    └──────┬───────────────────────────┘
           ↓
    ┌──────────────────────────────────┐
    │  Format Output                   │
    │  (Display/JSON/Immunefi/CSV)     │
    └──────┬───────────────────────────┘
           ↓
    ┌──────────────────────────────────┐
    │  Display/Save Results            │
    │  Return AuditReport              │
    └──────────────────────────────────┘
```

---

## Error Handling & Learning

### Error Categories

```python
ErrorType = Enum([
    'CLONE_FAILED',           # Cannot clone repo
    'BUILD_FAILED',           # Foundry build error
    'DISCOVERY_FAILED',       # Cannot find contracts
    'ANALYSIS_FAILED',        # Analysis engine error
    'IMPORT_ERROR',           # Unresolved import
    'SOLC_VERSION_MISMATCH',  # Compiler version issue
    'NETWORK_ERROR',          # GitHub access issue
    'CACHE_INVALID',          # Corrupted cache
])
```

### Error Response

```python
class AnalysisError(Exception):
    def __init__(self, error_type, message, contract_path, tool_that_failed):
        self.error_type = error_type
        self.message = message
        self.contract_path = contract_path
        self.tool_that_failed = tool_that_failed

# Handled by:
try:
    results = await analyzer.analyze_contract(contract_path)
except AnalysisError as e:
    # 1. Log to database
    db.log_error(e)
    
    # 2. Try fallback
    fallback = await try_fallback(contract_path)
    
    # 3. Save state for learning
    db.save_analysis_result(
        contract_id,
        {},
        status='failed',
        error_log=str(e)
    )
```

### Learning from Errors

```sql
-- Query 1: Most common errors
SELECT error_type, COUNT(*) as frequency
FROM analysis_errors
GROUP BY error_type
ORDER BY frequency DESC
LIMIT 10;

-- Query 2: Tools that fail most
SELECT tool_that_failed, COUNT(*) as frequency
FROM analysis_errors
GROUP BY tool_that_failed
ORDER BY frequency DESC;

-- Query 3: Contracts with consistent issues
SELECT contract_path, COUNT(*) as occurrences
FROM analysis_errors
GROUP BY contract_path
HAVING COUNT(*) > 1
ORDER BY occurrences DESC;
```

---

## Implementation Phase

### Phase 1: Foundation (Week 1)
- [ ] Create SQLite schema and database manager
- [ ] Implement RepositoryManager (clone/cache/pull)
- [ ] Implement FrameworkDetector
- [ ] Create basic GitHubAuditor orchestrator

### Phase 2: Build & Discovery (Week 2)
- [ ] Implement ProjectBuilder (build orchestration)
- [ ] Implement ContractDiscoverer
- [ ] Create SequentialAnalyzer
- [ ] Add fallback analysis

### Phase 3: Integration (Week 3)
- [ ] Integrate with existing AetherAuditEngine
- [ ] Create AuditResultFormatter
- [ ] Implement caching logic
- [ ] Add error tracking

### Phase 4: CLI & Testing (Week 4)
- [ ] Create CLI commands
- [ ] End-to-end testing
- [ ] Performance optimization
- [ ] Documentation

---

## File Structure

```
core/
├── github_auditor.py              # Main orchestrator [NEW]
├── repository_manager.py           # Git operations [NEW]
├── framework_detector.py           # Framework detection [NEW]
├── project_builder.py              # Build orchestration [NEW]
├── contract_discoverer.py          # Contract discovery [NEW]
├── sequential_analyzer.py          # Sequential analysis [NEW]
├── database_manager.py             # SQLite operations [NEW]
├── audit_result_formatter.py       # Results formatting [NEW]
│
├── audit_engine.py                 # Existing (unchanged)
├── llm_analyzer.py                 # Existing (unchanged)
├── vulnerability_detector.py       # Existing (unchanged)
├── nodes/
│   └── audit_nodes.py              # Existing (unchanged)
│
└── ... (other existing modules)

cli/
├── __init__.py
├── main.py                          # Update to add new commands
└── commands/
    └── audit_command.py            # New GitHub audit command
```

---

## Success Criteria

✅ User can run `aether audit <github-url>` and get results
✅ Sequential analysis: One contract at a time
✅ SQLite caching: Results reused across runs
✅ Build artifacts cached: No unnecessary recompilation
✅ Error tracking: All failures logged for learning
✅ Fallback analysis: Direct Slither on build failure
✅ Results formatted: Display, JSON, Immunefi, CSV
✅ Performance: <30s for 12 contracts on second run (cached)

---

## Next Steps

1. **Review this plan** with team
2. **Create database schema** in SQLite
3. **Implement modules** in order (foundation → integration)
4. **Test with real repos** (Enzyme, Uniswap, etc.)
5. **Optimize caching** based on performance metrics
6. **Document** CLI and best practices

---

**Document Created**: October 16, 2025  
**Ready for Implementation**: YES  
**Estimated Timeline**: 4 weeks  
**Priority**: HIGH - Core feature for production launch
