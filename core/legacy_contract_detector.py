#!/usr/bin/env python3
"""
Legacy Contract Detector

Detects deprecated/legacy contracts that may not be actively maintained.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeprecationNotice:
    """Represents a deprecation notice found in documentation."""
    source: str  # File path
    notice_type: str  # 'comment', 'readme', 'changelog', 'migration'
    content: str
    confidence: float


@dataclass
class LegacyStatus:
    """Status of legacy/deprecated contract."""
    is_legacy: bool
    confidence: float
    indicators: List[str] = field(default_factory=list)
    deprecation_notices: List[DeprecationNotice] = field(default_factory=list)
    replacement_contracts: List[str] = field(default_factory=list)
    reasoning: Optional[str] = None


class LegacyContractDetector:
    """Detects legacy/deprecated contracts."""
    
    def __init__(self):
        self.status_cache: Dict[str, LegacyStatus] = {}
    
    def detect_legacy_status(
        self,
        contract_code: str,
        contract_path: Optional[Path] = None,
        project_root: Optional[Path] = None
    ) -> LegacyStatus:
        """
        Detect if contract is legacy/deprecated.
        
        Args:
            contract_code: Contract source code
            contract_path: Path to contract file
            project_root: Root directory of project
            
        Returns:
            LegacyStatus with detection results
        """
        cache_key = contract_path if contract_path else hash(contract_code)
        if cache_key in self.status_cache:
            return self.status_cache[cache_key]
        
        status = LegacyStatus(is_legacy=False, confidence=0.0)
        indicators = []
        
        # Check contract name patterns
        contract_name = self._extract_contract_name(contract_code)
        if contract_name:
            legacy_name_patterns = [
                r'V1\b', r'Legacy\b', r'Old\b', r'Deprecated\b',
                r'_v1\b', r'_legacy\b', r'_old\b', r'_deprecated\b'
            ]
            
            for pattern in legacy_name_patterns:
                if re.search(pattern, contract_name, re.IGNORECASE):
                    indicators.append(f"Contract name contains legacy pattern: {pattern}")
                    status.is_legacy = True
                    status.confidence = max(status.confidence, 0.7)
        
        # Check file path patterns
        if contract_path:
            path_str = str(contract_path)
            legacy_path_patterns = [
                r'/legacy/', r'/deprecated/', r'/v1/', r'/old/',
                r'\\legacy\\', r'\\deprecated\\', r'\\v1\\', r'\\old\\'
            ]
            
            for pattern in legacy_path_patterns:
                if re.search(pattern, path_str, re.IGNORECASE):
                    indicators.append(f"File path contains legacy pattern: {pattern}")
                    status.is_legacy = True
                    status.confidence = max(status.confidence, 0.8)
        
        # Check comments in contract
        comment_notices = self._check_contract_comments(contract_code)
        if comment_notices:
            status.deprecation_notices.extend(comment_notices)
            status.is_legacy = True
            status.confidence = max(status.confidence, 0.9)
            indicators.append("Deprecation notice found in contract comments")
        
        # Check documentation files
        if project_root and project_root.exists():
            doc_notices = self.check_deprecation_notices(project_root, contract_name)
            if doc_notices:
                status.deprecation_notices.extend(doc_notices)
                status.is_legacy = True
                status.confidence = max(status.confidence, 0.85)
                indicators.append(f"Deprecation notices found in {len(doc_notices)} documentation files")
            
            # Find replacement contracts
            replacements = self.identify_replacement_contracts(contract_name, project_root)
            if replacements:
                status.replacement_contracts = replacements
                indicators.append(f"Found {len(replacements)} potential replacement contract(s)")
        
        status.indicators = indicators
        
        if status.is_legacy:
            status.reasoning = self._build_reasoning(status)
        
        # Cache result
        self.status_cache[cache_key] = status
        
        return status
    
    def _extract_contract_name(self, contract_code: str) -> Optional[str]:
        """Extract contract name from code."""
        match = re.search(r'contract\s+(\w+)', contract_code)
        return match.group(1) if match else None
    
    def _check_contract_comments(self, contract_code: str) -> List[DeprecationNotice]:
        """Check contract comments for deprecation notices."""
        notices = []
        
        # Single-line comments
        single_line_pattern = r'//\s*(.*)'
        for match in re.finditer(single_line_pattern, contract_code):
            comment = match.group(1).lower()
            if any(keyword in comment for keyword in ['deprecated', 'legacy', 'phased out', 'use .* instead']):
                notices.append(DeprecationNotice(
                    source='contract_comments',
                    notice_type='comment',
                    content=match.group(1),
                    confidence=0.9
                ))
        
        # Multi-line comments / NatSpec
        multi_line_pattern = r'/\*\*?(.*?)\*/'
        for match in re.finditer(multi_line_pattern, contract_code, re.DOTALL):
            comment = match.group(1).lower()
            if any(keyword in comment for keyword in ['deprecated', 'legacy', 'phased out', '@notice.*use']):
                notices.append(DeprecationNotice(
                    source='contract_comments',
                    notice_type='comment',
                    content=match.group(1)[:200],  # First 200 chars
                    confidence=0.9
                ))
        
        return notices
    
    def check_deprecation_notices(
        self,
        project_root: Path,
        contract_name: Optional[str] = None
    ) -> List[DeprecationNotice]:
        """
        Check for deprecation notices in documentation files.
        
        Args:
            project_root: Root directory of project
            contract_name: Optional contract name to search for
            
        Returns:
            List of DeprecationNotice objects
        """
        notices = []
        
        # Files to check
        doc_files = [
            'README.md', 'CHANGELOG.md', 'MIGRATION.md', 'SECURITY.md',
            'docs/README.md', 'docs/MIGRATION.md', 'docs/CHANGELOG.md'
        ]
        
        deprecation_keywords = [
            'deprecated', 'legacy', 'phased out', 'no longer maintained',
            'use .* instead', 'replaced by', 'superseded by'
        ]
        
        for doc_file in doc_files:
            doc_path = project_root / doc_file
            if doc_path.exists() and doc_path.is_file():
                try:
                    content = doc_path.read_text(encoding='utf-8', errors='ignore')
                    content_lower = content.lower()
                    
                    # Check if document mentions deprecation
                    if any(keyword in content_lower for keyword in deprecation_keywords):
                        # If contract name provided, check if it's mentioned
                        if contract_name:
                            if contract_name.lower() in content_lower:
                                # Extract relevant section
                                lines = content.split('\n')
                                relevant_lines = []
                                for i, line in enumerate(lines):
                                    if contract_name.lower() in line.lower() or any(kw in line.lower() for kw in deprecation_keywords):
                                        # Include context (2 lines before/after)
                                        start = max(0, i - 2)
                                        end = min(len(lines), i + 3)
                                        relevant_lines.extend(lines[start:end])
                                
                                if relevant_lines:
                                    notices.append(DeprecationNotice(
                                        source=str(doc_path),
                                        notice_type='readme' if 'README' in doc_file else 'changelog',
                                        content='\n'.join(relevant_lines[:10]),  # First 10 lines
                                        confidence=0.85
                                    ))
                        else:
                            # No contract name, but deprecation mentioned
                            notices.append(DeprecationNotice(
                                source=str(doc_path),
                                notice_type='readme' if 'README' in doc_file else 'changelog',
                                content=content[:500],  # First 500 chars
                                confidence=0.6
                            ))
                except Exception:
                    continue
        
        return notices
    
    def identify_replacement_contracts(
        self,
        legacy_contract: Optional[str],
        project_root: Path
    ) -> List[str]:
        """
        Find newer versions/replacements of legacy contracts.
        
        Args:
            legacy_contract: Name of legacy contract
            project_root: Root directory of project
            
        Returns:
            List of replacement contract names
        """
        replacements = []
        
        if not legacy_contract:
            return replacements
        
        # Patterns to look for
        base_name = re.sub(r'V1|Legacy|Old|Deprecated', '', legacy_contract, flags=re.IGNORECASE).strip()
        
        # Search for contracts with similar names but version numbers
        version_patterns = [r'V2', r'V3', r'V4', r'V2_', r'V3_']
        
        # Search Solidity files
        for sol_file in project_root.rglob('*.sol'):
            try:
                content = sol_file.read_text(encoding='utf-8', errors='ignore')
                
                # Find contract declarations
                contract_matches = re.findall(r'contract\s+(\w+)', content)
                
                for contract_name in contract_matches:
                    # Check if it's a versioned version of the base name
                    if base_name.lower() in contract_name.lower():
                        # Check if it has a version number
                        if any(pattern in contract_name for pattern in version_patterns):
                            if contract_name not in replacements:
                                replacements.append(contract_name)
            except Exception:
                continue
        
        return replacements
    
    def _build_reasoning(self, status: LegacyStatus) -> str:
        """Build reasoning string from status."""
        reasons = []
        
        if status.indicators:
            reasons.append(f"Indicators found: {len(status.indicators)}")
        
        if status.deprecation_notices:
            reasons.append(f"Deprecation notices: {len(status.deprecation_notices)}")
        
        if status.replacement_contracts:
            reasons.append(f"Replacement contracts: {', '.join(status.replacement_contracts)}")
        
        return "; ".join(reasons) if reasons else "Legacy status detected"

