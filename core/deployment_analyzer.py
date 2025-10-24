#!/usr/bin/env python3
"""
Deployment Analysis Module

Checks if features/code paths are actually used in production.
Prevents false positives from flagging unused or commented-out code.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class DeploymentAnalyzer:
    """Analyzes deployment scripts to detect unused features."""
    
    def __init__(self, project_path: Path):
        self.project_path = Path(project_path)
        self.deployment_scripts = self._find_deployment_scripts()
        self.config_files = self._find_config_files()
    
    def _find_deployment_scripts(self) -> List[Path]:
        """Find deployment/migration scripts."""
        patterns = [
            'deploy/**/*.ts',
            'deploy/**/*.js',
            'scripts/deploy*.ts',
            'scripts/deploy*.js',
            'migrations/**/*.js',
            'script/**/*.sol',  # Foundry deployment scripts
            'script/**/*.s.sol',
        ]
        
        scripts = []
        for pattern in patterns:
            scripts.extend(self.project_path.glob(pattern))
        return scripts
    
    def _find_config_files(self) -> List[Path]:
        """Find configuration JSON files."""
        patterns = [
            'deploy/config/**/*.json',
            'config/**/*.json',
            'deployments/**/*.json',
            '**/deployed-addresses.json',
        ]
        
        configs = []
        for pattern in patterns:
            configs.extend(self.project_path.glob(pattern))
        return configs
    
    def is_feature_deployed(self, feature_name: str, contract_name: str) -> Dict:
        """
        Check if a specific feature is actually deployed.
        
        Example: is_feature_deployed("EXTERNAL", "Oracle")
        
        Returns:
            Dict with 'deployed' (bool), 'found_in' (str), 'confidence' (float)
        """
        
        # Check deployment scripts
        for script in self.deployment_scripts:
            try:
                content = script.read_text(encoding='utf-8')
                
                # Look for feature usage
                if feature_name in content:
                    # Check if it's actually being set/used
                    deployment_pattern = rf'{contract_name}.*{feature_name}|{feature_name}.*{contract_name}'
                    if re.search(deployment_pattern, content, re.IGNORECASE):
                        return {
                            'deployed': True,
                            'found_in': str(script),
                            'confidence': 0.8
                        }
            except Exception:
                continue
        
        # Check config files
        for config_file in self.config_files:
            try:
                data = json.loads(config_file.read_text(encoding='utf-8'))
                if self._search_json_for_feature(data, feature_name):
                    return {
                        'deployed': True,
                        'found_in': str(config_file),
                        'confidence': 0.9
                    }
            except Exception:
                continue
        
        return {
            'deployed': False,
            'reason': 'Feature not found in deployment scripts or configs',
            'confidence': 0.7
        }
    
    def _search_json_for_feature(self, data: any, feature_name: str) -> bool:
        """Recursively search JSON for feature."""
        if isinstance(data, dict):
            for key, value in data.items():
                if feature_name.lower() in str(key).lower():
                    return True
                if isinstance(value, (dict, list)):
                    if self._search_json_for_feature(value, feature_name):
                        return True
        elif isinstance(data, list):
            for item in data:
                if self._search_json_for_feature(item, feature_name):
                    return True
        return False
    
    def check_oracle_type_usage(self, oracle_type: str) -> Dict:
        """
        Specific check for oracle types (like EXTERNAL).
        
        Args:
            oracle_type: Oracle type to check (e.g., "EXTERNAL", "CHAINLINK")
            
        Returns:
            Dict with 'used' (bool) and 'confidence' (float)
        """
        
        # Check if oracle type appears in configs
        for config_file in self.config_files:
            try:
                content = config_file.read_text(encoding='utf-8')
                if f'"oracleType": "{oracle_type}"' in content:
                    return {'used': True, 'confidence': 0.95}
                if f'oracleType.*{oracle_type}' in content:
                    return {'used': True, 'confidence': 0.8}
            except Exception:
                continue
        
        # Check deployment scripts
        for script in self.deployment_scripts:
            try:
                content = script.read_text(encoding='utf-8')
                # Look for enum usage like OracleReadType.EXTERNAL
                if f'OracleReadType.{oracle_type}' in content or f'OracleType.{oracle_type}' in content:
                    # But also check if it's in comments or actual code
                    if not self._is_in_comment(content, oracle_type):
                        return {'used': True, 'confidence': 0.85}
            except Exception:
                continue
        
        return {'used': False, 'confidence': 0.9}
    
    def _is_in_comment(self, code: str, feature: str) -> bool:
        """Check if feature reference is only in comments."""
        lines = code.split('\n')
        for line in lines:
            if feature in line:
                stripped = line.strip()
                if not (stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*')):
                    return False
        return True
    
    def check_function_usage(self, function_name: str, contract_name: str) -> Dict:
        """
        Check if a function is actually called in deployment/test scripts.
        
        Args:
            function_name: Function to check
            contract_name: Contract containing the function
            
        Returns:
            Dict with 'used' (bool), 'usage_count' (int), 'confidence' (float)
        """
        usage_count = 0
        found_in = []
        
        # Check deployment scripts
        for script in self.deployment_scripts:
            try:
                content = script.read_text(encoding='utf-8')
                # Look for function calls: contract.functionName() or functionName()
                patterns = [
                    rf'{contract_name}\.{function_name}\s*\(',
                    rf'\.{function_name}\s*\(',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        usage_count += len(matches)
                        found_in.append(str(script))
            except Exception:
                continue
        
        if usage_count > 0:
            return {
                'used': True,
                'usage_count': usage_count,
                'found_in': found_in,
                'confidence': min(0.95, 0.6 + (usage_count * 0.1))
            }
        else:
            return {
                'used': False,
                'usage_count': 0,
                'reason': 'Function not called in deployment scripts',
                'confidence': 0.5  # Lower confidence - might be called in production
            }
    
    def is_code_path_reachable(self, code_snippet: str, contract_name: str) -> Dict:
        """
        Check if a code path is reachable based on deployment configuration.
        
        Args:
            code_snippet: Code to check (e.g., "if (managerType == ManagerType.EXTERNAL)")
            contract_name: Contract containing the code
            
        Returns:
            Dict with 'reachable' (bool) and 'confidence' (float)
        """
        
        # Extract condition from code snippet
        condition_match = re.search(r'if\s*\(([^)]+)\)', code_snippet)
        if not condition_match:
            return {'reachable': True, 'confidence': 0.5, 'reason': 'Cannot determine reachability'}
        
        condition = condition_match.group(1)
        
        # Check if condition values are used in deployment
        for config_file in self.config_files:
            try:
                content = config_file.read_text(encoding='utf-8')
                # Look for enum values or constants in condition
                enum_matches = re.findall(r'\w+\.\w+', condition)
                for enum_value in enum_matches:
                    if enum_value in content and not self._is_in_comment(content, enum_value):
                        return {'reachable': True, 'confidence': 0.8}
            except Exception:
                continue
        
        # If no evidence of usage found, likely unreachable
        return {
            'reachable': False,
            'reason': 'Code path values not found in deployment configuration',
            'confidence': 0.7
        }
    
    def get_deployment_summary(self) -> Dict:
        """
        Get summary of deployment analysis.
        
        Returns:
            Dict with deployment information
        """
        return {
            'project_path': str(self.project_path),
            'deployment_scripts_found': len(self.deployment_scripts),
            'config_files_found': len(self.config_files),
            'deployment_scripts': [str(s) for s in self.deployment_scripts],
            'config_files': [str(c) for c in self.config_files],
        }

