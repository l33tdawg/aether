#!/usr/bin/env python3
"""
Off-Chain Component Finder

Finds and analyzes off-chain observer/validator services that interact with contracts.
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ObserverComponent:
    """Represents an off-chain observer/validator component."""
    name: str
    path: Path
    language: str
    validation_functions: List[str] = field(default_factory=list)
    validates_parameters: List[str] = field(default_factory=list)
    event_listeners: List[str] = field(default_factory=list)
    code_snippet: Optional[str] = None


@dataclass
class ValidationAnalysis:
    """Analysis of validation logic in observer code."""
    function_name: str
    validates_parameter: str
    validation_logic: str
    prevents_exploit: bool
    confidence: float
    reasoning: str


@dataclass
class ObserverMapping:
    """Mapping between contract function and observer validation."""
    contract_function: str
    event_name: str
    observer_function: str
    validation_parameter: str
    prevents_exploit: bool
    confidence: float


class OffChainComponentFinder:
    """Finds and analyzes off-chain components."""
    
    def __init__(self):
        self.component_cache: Dict[str, List[ObserverComponent]] = {}
    
    def find_observers(
        self,
        project_root: Path,
        contract_address: Optional[str] = None
    ) -> List[ObserverComponent]:
        """
        Find observer/validator services in project.
        
        Args:
            project_root: Root directory of the project
            contract_address: Optional contract address to filter by
            
        Returns:
            List of ObserverComponent objects
        """
        cache_key = str(project_root)
        if cache_key in self.component_cache:
            return self.component_cache[cache_key]
        
        observers = []
        
        if not project_root or not project_root.exists():
            return observers
        
        # Search patterns for different languages
        search_patterns = {
            'go': {
                'file_patterns': ['**/*observer*.go', '**/*validator*.go', '**/*watcher*.go'],
                'function_patterns': [
                    r'func\s+(\w+.*?)\s*\([^)]*\)\s*\{',
                    r'func\s+(\w+.*?)\s*\([^)]*\)\s*\([^)]*\)\s*\{'
                ],
                'validation_keywords': ['validate', 'check', 'reject', 'return nil', 'return null']
            },
            'rust': {
                'file_patterns': ['**/*observer*.rs', '**/*validator*.rs'],
                'function_patterns': [
                    r'fn\s+(\w+)\s*\([^)]*\)\s*->',
                    r'pub\s+fn\s+(\w+)\s*\([^)]*\)\s*->'
                ],
                'validation_keywords': ['validate', 'check', 'reject', 'return None', 'return Err']
            },
            'typescript': {
                'file_patterns': ['**/*observer*.ts', '**/*validator*.ts'],
                'function_patterns': [
                    r'(?:function|const)\s+(\w+)\s*=\s*\([^)]*\)\s*=>',
                    r'function\s+(\w+)\s*\([^)]*\)\s*\{'
                ],
                'validation_keywords': ['validate', 'check', 'reject', 'return null', 'return undefined']
            },
            'python': {
                'file_patterns': ['**/*observer*.py', '**/*validator*.py'],
                'function_patterns': [
                    r'def\s+(\w+)\s*\([^)]*\)\s*:'
                ],
                'validation_keywords': ['validate', 'check', 'reject', 'return None']
            }
        }
        
        for lang, config in search_patterns.items():
            for file_pattern in config['file_patterns']:
                try:
                    for file_path in project_root.glob(file_pattern):
                        if file_path.is_file():
                            observer = self._analyze_observer_file(
                                file_path,
                                lang,
                                config['function_patterns'],
                                config['validation_keywords']
                            )
                            if observer:
                                observers.append(observer)
                except Exception:
                    continue
        
        # Cache results
        self.component_cache[cache_key] = observers
        
        return observers
    
    def _analyze_observer_file(
        self,
        file_path: Path,
        language: str,
        function_patterns: List[str],
        validation_keywords: List[str]
    ) -> Optional[ObserverComponent]:
        """Analyze a single observer file."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check if file contains observer/validator patterns
            if not any(keyword in content.lower() for keyword in ['observer', 'validator', 'watch', 'validate']):
                return None
            
            # Extract functions
            functions = []
            for pattern in function_patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    func_name = match.group(1).split('(')[0].strip()
                    if func_name and func_name not in functions:
                        functions.append(func_name)
            
            # Find validation functions
            validation_functions = []
            validates_parameters = []
            
            for func in functions:
                # Extract function body
                func_pattern = rf'(?:func|fn|function|def)\s+{re.escape(func)}\s*\([^)]*\)[^{{]*\{{([^}}]+)}}'
                func_match = re.search(func_pattern, content, re.DOTALL)
                
                if func_match:
                    func_body = func_match.group(1)
                    
                    # Check if function contains validation logic
                    if any(keyword in func_body.lower() for keyword in validation_keywords):
                        validation_functions.append(func)
                        
                        # Extract validated parameters
                        # Look for patterns like: if param == 0, if param == nil, etc.
                        param_patterns = [
                            r'if\s+(\w+)\s*==\s*0',
                            r'if\s+(\w+)\s*==\s*nil',
                            r'if\s+(\w+)\s*==\s*null',
                            r'if\s+!(\w+)',
                            r'if\s+(\w+)\s*==\s*""',
                            r'if\s+len\((\w+)\)\s*==\s*0',
                        ]
                        
                        for param_pattern in param_patterns:
                            for param_match in re.finditer(param_pattern, func_body, re.IGNORECASE):
                                param = param_match.group(1)
                                if param not in validates_parameters:
                                    validates_parameters.append(param)
            
            # Extract event listeners
            event_listeners = []
            event_patterns = [
                r'(\w+Sent)',
                r'(\w+Received)',
                r'(\w+Transfer)',
                r'(\w+Event)',
                r'buildInbound.*?Event',
                r'handle.*?Event'
            ]
            
            for pattern in event_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    event = match.group(1) if match.lastindex else match.group(0)
                    if event and event not in event_listeners:
                        event_listeners.append(event)
            
            if validation_functions or event_listeners:
                return ObserverComponent(
                    name=file_path.stem,
                    path=file_path,
                    language=language,
                    validation_functions=validation_functions,
                    validates_parameters=validates_parameters,
                    event_listeners=event_listeners,
                    code_snippet=content[:2000]  # First 2000 chars
                )
        
        except Exception:
            pass
        
        return None
    
    def analyze_validation_logic(
        self,
        observer_code: str,
        contract_function: str
    ) -> Optional[ValidationAnalysis]:
        """
        Analyze validation logic in observer code.
        
        Args:
            observer_code: Source code of observer component
            contract_function: Name of contract function being analyzed
            
        Returns:
            ValidationAnalysis if validation found, None otherwise
        """
        # Look for validation patterns related to common vulnerability parameters
        validation_patterns = {
            'destinationChainId': [
                r'destinationChainId\s*==\s*0',
                r'destinationChainId\s*==\s*nil',
                r'destinationChainId\s*==\s*null',
                r'destinationChainId\s*<=\s*0',
            ],
            'destinationAddress': [
                r'len\(destinationAddress\)\s*==\s*0',
                r'destinationAddress\s*==\s*""',
                r'destinationAddress\s*==\s*nil',
                r'destinationAddress\s*==\s*null',
            ],
            'destinationGasLimit': [
                r'destinationGasLimit\s*==\s*0',
                r'destinationGasLimit\s*<=\s*0',
            ],
        }
        
        # Check for rejection patterns
        rejection_patterns = [
            r'return\s+nil',
            r'return\s+null',
            r'return\s+None',
            r'return\s+Err',
            r'return\s+error',
            r'reject',
            r'invalid',
        ]
        
        for param, patterns in validation_patterns.items():
            for pattern in patterns:
                if re.search(pattern, observer_code, re.IGNORECASE):
                    # Check if rejection follows
                    # Find the validation context
                    context_pattern = rf'({pattern}[^{{}}]*?)(?:return|reject|invalid)'
                    context_match = re.search(context_pattern, observer_code, re.IGNORECASE | re.DOTALL)
                    
                    if context_match or any(re.search(reject_pattern, observer_code, re.IGNORECASE) for reject_pattern in rejection_patterns):
                        return ValidationAnalysis(
                            function_name=contract_function,
                            validates_parameter=param,
                            validation_logic=context_match.group(1) if context_match else pattern,
                            prevents_exploit=True,
                            confidence=0.8,
                            reasoning=f"Observer validates {param} and rejects invalid values"
                        )
        
        return None
    
    def map_contract_to_observer(
        self,
        contract_function: str,
        observers: List[ObserverComponent]
    ) -> Optional[ObserverMapping]:
        """
        Map contract function to observer validation.
        
        Args:
            contract_function: Name of contract function
            observers: List of observer components
            
        Returns:
            ObserverMapping if found, None otherwise
        """
        # Extract function name and event name
        # Common patterns: send(), transfer(), bridge()
        function_lower = contract_function.lower()
        
        # Look for matching observers
        for observer in observers:
            # Check validation functions
            for val_func in observer.validation_functions:
                val_func_lower = val_func.lower()
                
                # Check if observer function relates to contract function
                if any(keyword in val_func_lower for keyword in ['send', 'transfer', 'bridge', 'cross']):
                    # Check if it validates common parameters
                    for param in observer.validates_parameters:
                        if param in ['destinationChainId', 'destinationAddress', 'destinationGasLimit', 'chainId']:
                            return ObserverMapping(
                                contract_function=contract_function,
                                event_name=observer.event_listeners[0] if observer.event_listeners else 'Unknown',
                                observer_function=val_func,
                                validation_parameter=param,
                                prevents_exploit=True,
                                confidence=0.75
                            )
        
        return None

