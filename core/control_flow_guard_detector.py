"""
Control Flow Guard Detector

Detects guards, checks, and conditions that prevent vulnerable code paths from being reached.
This helps reduce false positives by understanding when "vulnerable" patterns are actually protected.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class Guard:
    """Represents a guard/check that protects code."""
    guard_type: str  # 'require', 'if_revert', 'modifier', 'timing', 'access_control'
    line_number: int
    condition: str
    protects_lines: List[int]  # Line numbers this guard protects
    description: str


class ControlFlowGuardDetector:
    """
    Detects control flow guards that prevent vulnerabilities.
    
    Examples:
    - Timing guards: if (block.timestamp < deadline) revert();
    - Access guards: require(msg.sender == owner);
    - State guards: require(!paused);
    - Value guards: require(amount > 0);
    """
    
    def __init__(self):
        self.guards: List[Guard] = []
        
    def analyze_function(self, function_code: str, start_line: int) -> List[Guard]:
        """Analyze a function to find all guards."""
        self.guards = []
        lines = function_code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = start_line + i
            
            # Detect require statements
            if 'require(' in line:
                guard = self._parse_require_guard(line, line_num, lines, i)
                if guard:
                    self.guards.append(guard)
            
            # Detect revert conditions
            if 'revert' in line and ('if' in lines[max(0, i-1)] or 'if' in line):
                guard = self._parse_revert_guard(line, line_num, lines, i)
                if guard:
                    self.guards.append(guard)
            
            # Detect custom error reverts
            if 'revert ' in line and not 'revert(' in line:
                guard = self._parse_custom_revert_guard(line, line_num, lines, i)
                if guard:
                    self.guards.append(guard)
        
        return self.guards
    
    def _parse_require_guard(self, line: str, line_num: int, lines: List[str], idx: int) -> Optional[Guard]:
        """Parse a require statement to extract guard information."""
        # Extract condition from require(condition, "message")
        match = re.search(r'require\s*\((.+?)(?:,|;|\))', line)
        if not match:
            return None
        
        condition = match.group(1).strip()
        
        # Determine guard type
        guard_type = 'require'
        if 'block.timestamp' in condition or 'block.number' in condition:
            guard_type = 'timing'
        elif 'msg.sender' in condition or 'owner' in condition.lower() or 'authorized' in condition.lower():
            guard_type = 'access_control'
        elif '>' in condition or '<' in condition or '!=' in condition:
            guard_type = 'value_check'
        
        # Lines protected: everything after this line in the function
        protected_lines = list(range(line_num + 1, line_num + len(lines) - idx))
        
        return Guard(
            guard_type=guard_type,
            line_number=line_num,
            condition=condition,
            protects_lines=protected_lines,
            description=f"Require guard: {condition}"
        )
    
    def _parse_revert_guard(self, line: str, line_num: int, lines: List[str], idx: int) -> Optional[Guard]:
        """Parse an if-revert pattern."""
        # Look for if (condition) revert pattern
        if_line = lines[max(0, idx-1)] if 'if' not in line else line
        
        match = re.search(r'if\s*\((.+?)\)', if_line)
        if not match:
            return None
        
        condition = match.group(1).strip()
        
        # Determine guard type
        guard_type = 'if_revert'
        if 'block.timestamp' in condition or 'lastNotify' in condition or 'lockDuration' in condition:
            guard_type = 'timing'
        elif 'msg.sender' in condition:
            guard_type = 'access_control'
        
        # Lines protected: everything after the revert
        protected_lines = list(range(line_num + 1, line_num + len(lines) - idx))
        
        return Guard(
            guard_type=guard_type,
            line_number=line_num,
            condition=condition,
            protects_lines=protected_lines,
            description=f"If-revert guard: {condition}"
        )
    
    def _parse_custom_revert_guard(self, line: str, line_num: int, lines: List[str], idx: int) -> Optional[Guard]:
        """Parse custom error revert (Solidity 0.8.4+)."""
        # revert CustomError();
        match = re.search(r'revert\s+(\w+)\s*\(', line)
        if not match:
            return None
        
        error_name = match.group(1)
        
        # Check previous line for condition
        if idx > 0:
            prev_line = lines[idx - 1]
            cond_match = re.search(r'if\s*\((.+?)\)', prev_line)
            if cond_match:
                condition = cond_match.group(1).strip()
            else:
                condition = error_name
        else:
            condition = error_name
        
        # Classify by error name
        guard_type = 'custom_error'
        if 'time' in error_name.lower() or 'vesting' in error_name.lower() or 'lock' in error_name.lower():
            guard_type = 'timing'
        elif 'unauthorized' in error_name.lower() or 'access' in error_name.lower():
            guard_type = 'access_control'
        
        protected_lines = list(range(line_num + 1, line_num + len(lines) - idx))
        
        return Guard(
            guard_type=guard_type,
            line_number=line_num,
            condition=condition,
            protects_lines=protected_lines,
            description=f"Custom error guard: {error_name}"
        )
    
    def is_line_protected(self, line_num: int, guard_types: List[str] = None) -> Tuple[bool, List[Guard]]:
        """
        Check if a line is protected by guards.
        
        Args:
            line_num: Line number to check
            guard_types: Optional filter for specific guard types
        
        Returns:
            (is_protected, protecting_guards)
        """
        protecting_guards = []
        
        for guard in self.guards:
            # Check if this guard protects the line
            if line_num in guard.protects_lines:
                # Apply type filter if specified
                if guard_types is None or guard.guard_type in guard_types:
                    protecting_guards.append(guard)
        
        return len(protecting_guards) > 0, protecting_guards
    
    def get_timing_guards(self) -> List[Guard]:
        """Get all timing-based guards (for vesting, lock duration, etc.)."""
        return [g for g in self.guards if g.guard_type == 'timing']
    
    def analyze_vesting_pattern(self, contract_code: str) -> Optional[Dict[str, Any]]:
        """
        Detect and analyze vesting/unlock patterns.
        
        Returns info about vesting mechanism if found.
        """
        # Look for vesting indicators
        has_lock_duration = 'lockDuration' in contract_code
        has_last_notify = 'lastNotify' in contract_code or 'lastUpdate' in contract_code
        has_locked_amount = 'totalLocked' in contract_code or 'lockedAmount' in contract_code
        has_vesting_calc = 'lockedProfit' in contract_code or 'vestedAmount' in contract_code
        
        if not (has_lock_duration and has_locked_amount):
            return None
        
        # Find the vesting guard
        vesting_guards = []
        for guard in self.guards:
            if guard.guard_type == 'timing' and ('lockDuration' in guard.condition or 'vesting' in guard.condition.lower()):
                vesting_guards.append(guard)
        
        if not vesting_guards:
            return None
        
        return {
            'pattern_type': 'linear_vesting',
            'has_time_lock': has_lock_duration,
            'has_last_update': has_last_notify,
            'has_locked_tracking': has_locked_amount,
            'has_vesting_calculation': has_vesting_calc,
            'guards': vesting_guards,
            'description': 'Linear vesting pattern with time-lock protection'
        }
    
    def explain_protection(self, line_num: int) -> str:
        """Generate human-readable explanation of why a line is protected."""
        is_protected, guards = self.is_line_protected(line_num)
        
        if not is_protected:
            return "No protection detected"
        
        explanations = []
        for guard in guards:
            if guard.guard_type == 'timing':
                explanations.append(f"Protected by timing constraint at line {guard.line_number}: {guard.condition}")
            elif guard.guard_type == 'access_control':
                explanations.append(f"Protected by access control at line {guard.line_number}: {guard.condition}")
            else:
                explanations.append(f"Protected by {guard.guard_type} at line {guard.line_number}: {guard.condition}")
        
        return "; ".join(explanations)


def test_guard_detector():
    """Test the guard detector with Cap contracts example."""
    sample_code = '''
    function notify() external {
        StakedCapStorage storage $ = getStakedCapStorage();
        if ($.lastNotify + $.lockDuration > block.timestamp) revert StillVesting();
        
        uint256 total = IERC20(asset()).balanceOf(address(this));
        if (total > $.storedTotal) {
            uint256 diff = total - $.storedTotal;
            
            $.totalLocked = diff;  // Line 57 - flagged as vulnerable
            $.storedTotal = total;
            $.lastNotify = block.timestamp;
        }
    }
    '''
    
    detector = ControlFlowGuardDetector()
    guards = detector.analyze_function(sample_code, start_line=49)
    
    print("Detected guards:")
    for guard in guards:
        print(f"  Line {guard.line_number}: {guard.description}")
    
    # Check if line 57 is protected
    is_protected, protecting_guards = detector.is_line_protected(57)
    print(f"\nLine 57 protected: {is_protected}")
    if is_protected:
        print(detector.explain_protection(57))
    
    # Check for vesting pattern
    vesting_info = detector.analyze_vesting_pattern(sample_code)
    if vesting_info:
        print(f"\nVesting pattern detected: {vesting_info['description']}")


if __name__ == "__main__":
    test_guard_detector()

