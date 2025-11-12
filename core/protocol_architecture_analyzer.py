#!/usr/bin/env python3
"""
Protocol Architecture Analyzer

Analyzes complete protocol architecture to understand multi-component systems,
including on-chain contracts and off-chain services.
"""

import re
import os
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Component:
    """Represents a component in the protocol architecture."""
    name: str
    component_type: str  # 'contract', 'observer', 'validator', 'service'
    path: Optional[Path] = None
    language: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ComponentRelationship:
    """Represents a relationship between components."""
    source: str
    target: str
    relationship_type: str  # 'validates', 'listens_to', 'calls', 'depends_on'
    description: Optional[str] = None


@dataclass
class SecurityBoundary:
    """Represents a security boundary in the system."""
    boundary_name: str
    location: str  # 'on-chain', 'off-chain', 'boundary'
    validation_type: str  # 'input_validation', 'access_control', 'state_validation'
    components: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class ProtocolArchitecture:
    """Complete protocol architecture representation."""
    components: List[Component] = field(default_factory=list)
    relationships: List[ComponentRelationship] = field(default_factory=list)
    security_boundaries: List[SecurityBoundary] = field(default_factory=list)
    data_flow: List[Dict[str, Any]] = field(default_factory=list)


class ProtocolArchitectureAnalyzer:
    """Analyzes protocol architecture to understand multi-component systems."""
    
    def __init__(self):
        self.architecture_cache: Dict[str, ProtocolArchitecture] = {}
    
    def analyze_architecture(
        self,
        contract_code: str,
        contract_path: Optional[Path] = None,
        project_root: Optional[Path] = None,
        github_url: Optional[str] = None
    ) -> ProtocolArchitecture:
        """
        Analyze complete protocol architecture.
        
        Args:
            contract_code: The contract source code
            contract_path: Path to the contract file
            project_root: Root directory of the project
            github_url: Optional GitHub URL for repository analysis
            
        Returns:
            ProtocolArchitecture with components, relationships, and boundaries
        """
        # Check cache
        cache_key = self._get_cache_key(contract_path, project_root)
        if cache_key in self.architecture_cache:
            return self.architecture_cache[cache_key]
        
        architecture = ProtocolArchitecture()
        
        # Find project root if not provided
        if not project_root and contract_path:
            project_root = self._find_project_root(contract_path)
        
        # Analyze contract for component information
        contract_components = self._analyze_contract_components(contract_code, contract_path)
        architecture.components.extend(contract_components)
        
        # Detect events that suggest off-chain processing
        events = self._extract_events(contract_code)
        
        # Analyze project structure if available
        if project_root and project_root.exists():
            off_chain_components = self._detect_off_chain_components(project_root, events)
            architecture.components.extend(off_chain_components)
            
            # Build relationships
            relationships = self._build_relationships(contract_components, off_chain_components, events)
            architecture.relationships.extend(relationships)
            
            # Map security boundaries
            boundaries = self._map_security_boundaries(architecture)
            architecture.security_boundaries.extend(boundaries)
        
        # Cache result
        if cache_key:
            self.architecture_cache[cache_key] = architecture
        
        return architecture
    
    def _get_cache_key(self, contract_path: Optional[Path], project_root: Optional[Path]) -> Optional[str]:
        """Generate cache key for architecture."""
        if contract_path:
            return str(contract_path)
        if project_root:
            return str(project_root)
        return None
    
    def _find_project_root(self, file_path: Path) -> Optional[Path]:
        """Find project root by looking for common markers."""
        current = Path(file_path).parent if file_path.is_file() else Path(file_path)
        
        markers = [
            'package.json', 'foundry.toml', 'hardhat.config.js', 'hardhat.config.ts',
            'truffle-config.js', '.git', 'go.mod', 'Cargo.toml', 'pyproject.toml'
        ]
        
        max_levels = 5
        for _ in range(max_levels):
            for marker in markers:
                if (current / marker).exists():
                    return current
            parent = current.parent
            if parent == current:
                break
            current = parent
        
        return None
    
    def _analyze_contract_components(self, contract_code: str, contract_path: Optional[Path]) -> List[Component]:
        """Analyze contract code for component information."""
        components = []
        
        # Extract contract name
        contract_match = re.search(r'contract\s+(\w+)', contract_code)
        if contract_match:
            contract_name = contract_match.group(1)
            components.append(Component(
                name=contract_name,
                component_type='contract',
                path=contract_path,
                language='solidity',
                description=f"Smart contract: {contract_name}"
            ))
        
        # Detect bridge/connector patterns
        if re.search(r'(bridge|connector|gateway)', contract_code, re.IGNORECASE):
            components.append(Component(
                name=f"{contract_name}_bridge",
                component_type='bridge',
                path=contract_path,
                language='solidity',
                description="Bridge/connector contract"
            ))
        
        return components
    
    def _extract_events(self, contract_code: str) -> List[Dict[str, Any]]:
        """Extract events from contract that suggest off-chain processing."""
        events = []
        
        # Pattern: event EventName(...) emits(...)
        event_pattern = r'event\s+(\w+)\s*\([^)]*\)'
        for match in re.finditer(event_pattern, contract_code):
            event_name = match.group(1)
            
            # Check if event suggests cross-chain or off-chain processing
            cross_chain_indicators = [
                'sent', 'received', 'transfer', 'cross', 'bridge', 'zeta',
                'chain', 'destination', 'message'
            ]
            
            if any(indicator in event_name.lower() for indicator in cross_chain_indicators):
                # Extract parameters
                event_sig = match.group(0)
                params_match = re.search(r'\(([^)]*)\)', event_sig)
                params = []
                if params_match:
                    params = [p.strip() for p in params_match.group(1).split(',') if p.strip()]
                
                events.append({
                    'name': event_name,
                    'signature': event_sig,
                    'parameters': params,
                    'suggests_off_chain': True
                })
        
        return events
    
    def _detect_off_chain_components(
        self,
        project_root: Path,
        events: List[Dict[str, Any]]
    ) -> List[Component]:
        """Detect off-chain components in project."""
        components = []
        
        # Patterns to search for
        patterns = {
            'go': {
                'files': ['**/*observer*.go', '**/*validator*.go', '**/*watcher*.go'],
                'keywords': ['observer', 'validator', 'watcher', 'indexer']
            },
            'rust': {
                'files': ['**/*observer*.rs', '**/*validator*.rs'],
                'keywords': ['observer', 'validator']
            },
            'typescript': {
                'files': ['**/*observer*.ts', '**/*validator*.ts'],
                'keywords': ['observer', 'validator']
            },
            'python': {
                'files': ['**/*observer*.py', '**/*validator*.py'],
                'keywords': ['observer', 'validator']
            }
        }
        
        for lang, config in patterns.items():
            for file_pattern in config['files']:
                try:
                    for file_path in project_root.glob(file_pattern):
                        if file_path.is_file():
                            # Check if file contains relevant keywords
                            try:
                                content = file_path.read_text(encoding='utf-8', errors='ignore')
                                if any(keyword in content.lower() for keyword in config['keywords']):
                                    # Check if it references any events
                                    references_event = False
                                    for event in events:
                                        if event['name'].lower() in content.lower():
                                            references_event = True
                                            break
                                    
                                    component_name = file_path.stem
                                    components.append(Component(
                                        name=component_name,
                                        component_type='observer' if 'observer' in component_name.lower() else 'validator',
                                        path=file_path,
                                        language=lang,
                                        description=f"{lang.title()} {component_name} component"
                                    ))
                            except Exception:
                                continue
                except Exception:
                    continue
        
        # Also search for common directory patterns
        common_dirs = ['observer', 'validator', 'watcher', 'indexer', 'zetaclient', 'node']
        for dir_name in common_dirs:
            dir_path = project_root / dir_name
            if dir_path.exists() and dir_path.is_dir():
                # Look for main files
                for main_file in ['main.go', 'main.rs', 'index.ts', 'main.py']:
                    main_path = dir_path / main_file
                    if main_path.exists():
                        components.append(Component(
                            name=dir_name,
                            component_type='service',
                            path=main_path,
                            language=self._detect_language(main_path),
                            description=f"{dir_name} service"
                        ))
                        break
        
        return components
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension."""
        ext = file_path.suffix.lower()
        lang_map = {
            '.go': 'go',
            '.rs': 'rust',
            '.ts': 'typescript',
            '.js': 'javascript',
            '.py': 'python'
        }
        return lang_map.get(ext, 'unknown')
    
    def _build_relationships(
        self,
        contract_components: List[Component],
        off_chain_components: List[Component],
        events: List[Dict[str, Any]]
    ) -> List[ComponentRelationship]:
        """Build relationships between components."""
        relationships = []
        
        # Map events to contract components
        for contract in contract_components:
            for event in events:
                # Check if off-chain components reference this event
                for off_chain in off_chain_components:
                    if off_chain.path and off_chain.path.exists():
                        try:
                            content = off_chain.path.read_text(encoding='utf-8', errors='ignore')
                            if event['name'] in content:
                                relationships.append(ComponentRelationship(
                                    source=contract.name,
                                    target=off_chain.name,
                                    relationship_type='listens_to',
                                    description=f"{off_chain.name} listens to {event['name']} event from {contract.name}"
                                ))
                        except Exception:
                            continue
        
        return relationships
    
    def _map_security_boundaries(self, architecture: ProtocolArchitecture) -> List[SecurityBoundary]:
        """Map security boundaries in the architecture."""
        boundaries = []
        
        # Check for off-chain validation boundaries
        for relationship in architecture.relationships:
            if relationship.relationship_type == 'listens_to':
                # This suggests off-chain validation
                boundaries.append(SecurityBoundary(
                    boundary_name=f"{relationship.target}_validation",
                    location='off-chain',
                    validation_type='input_validation',
                    components=[relationship.source, relationship.target],
                    description=f"Off-chain validation by {relationship.target} for {relationship.source}"
                ))
        
        return boundaries

