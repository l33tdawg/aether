"""
Mathematical Expression Parser for Smart Contract Analysis

This module provides parsing and analysis of Solidity mathematical expressions
to detect potential vulnerabilities in complex arithmetic operations.
"""

import re
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum


class NodeType(Enum):
    """Types of expression tree nodes"""
    OPERATOR = "operator"
    OPERAND = "operand"
    VARIABLE = "variable"
    CONSTANT = "constant"
    FUNCTION_CALL = "function_call"
    PARENTHESIS = "parenthesis"


@dataclass
class ExpressionNode:
    """Represents a node in the expression tree"""
    node_type: NodeType
    value: str
    children: List['ExpressionNode']
    line_number: int
    position: int


@dataclass
class ExpressionTree:
    """Represents a parsed mathematical expression"""
    root: ExpressionNode
    variables: List[str]
    constants: List[str]
    operators: List[str]
    complexity_score: float


class MathExpressionParser:
    """Parses and analyzes mathematical expressions in Solidity code"""
    
    def __init__(self):
        self.expression_patterns = self._initialize_expression_patterns()
        self.operators = ['+', '-', '*', '/', '%', '**', '<<', '>>']
        self.precedence = {
            '**': 4,
            '*': 3, '/': 3, '%': 3,
            '+': 2, '-': 2,
            '<<': 1, '>>': 1
        }
        
    def _initialize_expression_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for expression analysis"""
        return [
            {
                'pattern': r'(\w+)\s*[\+\-\*\/\%\*\*]\s*(\w+)',
                'description': 'Binary arithmetic operation',
                'risk_level': 'medium'
            },
            {
                'pattern': r'\([^)]+\)\s*[\+\-\*\/\%\*\*]\s*\([^)]+\)',
                'description': 'Complex arithmetic expression with parentheses',
                'risk_level': 'high'
            },
            {
                'pattern': r'(\w+)\s*\*\*\s*(\d+)',
                'description': 'Exponentiation operation',
                'risk_level': 'high'
            },
            {
                'pattern': r'(\w+)\s*<<\s*(\w+)',
                'description': 'Left shift operation',
                'risk_level': 'medium'
            },
            {
                'pattern': r'(\w+)\s*>>\s*(\w+)',
                'description': 'Right shift operation',
                'risk_level': 'medium'
            }
        ]
    
    def parse_expression(self, expression: str, line_number: int = 1) -> ExpressionTree:
        """Parse mathematical expression into tree structure"""
        # Clean the expression
        cleaned_expression = self._clean_expression(expression)
        
        # Extract variables, constants, and operators
        variables = self._extract_variables(cleaned_expression)
        constants = self._extract_constants(cleaned_expression)
        operators = self._extract_operators(cleaned_expression)
        
        # Build expression tree
        root = self._build_expression_tree(cleaned_expression, line_number)
        
        # Calculate complexity score
        complexity_score = self._calculate_complexity_score(root, variables, constants, operators)
        
        return ExpressionTree(
            root=root,
            variables=variables,
            constants=constants,
            operators=operators,
            complexity_score=complexity_score
        )
    
    def _clean_expression(self, expression: str) -> str:
        """Clean and normalize expression"""
        # Remove comments
        expression = re.sub(r'//.*$', '', expression, flags=re.MULTILINE)
        expression = re.sub(r'/\*.*?\*/', '', expression, flags=re.DOTALL)
        
        # Remove extra whitespace
        expression = re.sub(r'\s+', ' ', expression.strip())
        
        return expression
    
    def _extract_variables(self, expression: str) -> List[str]:
        """Extract variable names from expression"""
        # Pattern for Solidity identifiers
        variable_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        matches = re.findall(variable_pattern, expression)
        
        # Filter out keywords and function names
        keywords = {'uint', 'int', 'bool', 'address', 'string', 'bytes', 'mapping', 'struct', 'enum', 'function', 'return', 'if', 'else', 'for', 'while', 'do', 'break', 'continue', 'true', 'false', 'this', 'super', 'msg', 'tx', 'block', 'now', 'gasleft', 'revert', 'require', 'assert', 'modifier', 'event', 'emit', 'payable', 'view', 'pure', 'external', 'public', 'internal', 'private', 'memory', 'storage', 'calldata'}
        
        variables = []
        for match in matches:
            if match not in keywords and not match.isdigit():
                variables.append(match)
        
        return list(set(variables))  # Remove duplicates
    
    def _extract_constants(self, expression: str) -> List[str]:
        """Extract constant values from expression"""
        # Pattern for numeric constants
        constant_pattern = r'\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b'
        matches = re.findall(constant_pattern, expression)
        
        # Also extract hex constants
        hex_pattern = r'0x[a-fA-F0-9]+'
        hex_matches = re.findall(hex_pattern, expression)
        
        return matches + hex_matches
    
    def _extract_operators(self, expression: str) -> List[str]:
        """Extract operators from expression"""
        operators = []
        for op in self.operators:
            if op in expression:
                operators.append(op)
        return operators
    
    def _build_expression_tree(self, expression: str, line_number: int) -> ExpressionNode:
        """Build expression tree from infix notation"""
        # Convert to postfix notation using Shunting Yard algorithm
        postfix = self._infix_to_postfix(expression)
        
        # Build tree from postfix notation
        stack = []
        position = 0
        
        for token in postfix:
            if self._is_operator(token):
                if len(stack) < 2:
                    raise ValueError(f"Insufficient operands for operator {token}")
                
                right = stack.pop()
                left = stack.pop()
                
                node = ExpressionNode(
                    node_type=NodeType.OPERATOR,
                    value=token,
                    children=[left, right],
                    line_number=line_number,
                    position=position
                )
                stack.append(node)
            else:
                node_type = NodeType.CONSTANT if token.isdigit() or token.startswith('0x') else NodeType.VARIABLE
                node = ExpressionNode(
                    node_type=node_type,
                    value=token,
                    children=[],
                    line_number=line_number,
                    position=position
                )
                stack.append(node)
            
            position += 1
        
        if len(stack) != 1:
            raise ValueError("Invalid expression")
        
        return stack[0]
    
    def _infix_to_postfix(self, expression: str) -> List[str]:
        """Convert infix notation to postfix using Shunting Yard algorithm"""
        # Tokenize the expression
        tokens = self._tokenize(expression)
        
        output = []
        operator_stack = []
        
        for token in tokens:
            if self._is_operand(token):
                output.append(token)
            elif token == '(':
                operator_stack.append(token)
            elif token == ')':
                while operator_stack and operator_stack[-1] != '(':
                    output.append(operator_stack.pop())
                if operator_stack:
                    operator_stack.pop()  # Remove '('
            elif self._is_operator(token):
                while (operator_stack and 
                       operator_stack[-1] != '(' and
                       self.precedence.get(operator_stack[-1], 0) >= self.precedence.get(token, 0)):
                    output.append(operator_stack.pop())
                operator_stack.append(token)
        
        while operator_stack:
            output.append(operator_stack.pop())
        
        return output
    
    def _tokenize(self, expression: str) -> List[str]:
        """Tokenize expression into operators, operands, and parentheses"""
        tokens = []
        current_token = ""
        
        i = 0
        while i < len(expression):
            char = expression[i]
            
            if char.isspace():
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            elif char in '()':
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
                tokens.append(char)
            elif char in self.operators:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
                # Handle multi-character operators
                if i + 1 < len(expression) and expression[i:i+2] in ['**', '<<', '>>']:
                    tokens.append(expression[i:i+2])
                    i += 1
                else:
                    tokens.append(char)
            else:
                current_token += char
            
            i += 1
        
        if current_token:
            tokens.append(current_token)
        
        return tokens
    
    def _is_operator(self, token: str) -> bool:
        """Check if token is an operator"""
        return token in self.operators
    
    def _is_operand(self, token: str) -> bool:
        """Check if token is an operand"""
        return (token.isdigit() or 
                token.startswith('0x') or 
                (token.isalpha() and token not in ['true', 'false']))
    
    def _calculate_complexity_score(self, root: ExpressionNode, variables: List[str], 
                                  constants: List[str], operators: List[str]) -> float:
        """Calculate complexity score for the expression"""
        score = 0.0
        
        # Base score from number of operators
        score += len(operators) * 0.1
        
        # Increase score for high-risk operators
        high_risk_ops = ['**', '*', '/', '%', '<<', '>>']
        for op in operators:
            if op in high_risk_ops:
                score += 0.2
        
        # Increase score for number of variables
        score += len(variables) * 0.05
        
        # Increase score for nested expressions
        score += self._count_nested_expressions(root) * 0.15
        
        return min(score, 1.0)
    
    def _count_nested_expressions(self, node: ExpressionNode) -> int:
        """Count nested expressions in the tree"""
        count = 0
        if node.node_type == NodeType.OPERATOR:
            count += 1
            for child in node.children:
                count += self._count_nested_expressions(child)
        return count
    
    def analyze_expression_vulnerabilities(self, tree: ExpressionTree) -> List[Dict[str, Any]]:
        """Analyze expression tree for vulnerabilities"""
        vulnerabilities = []
        
        # Analyze for overflow/underflow risks
        vulnerabilities.extend(self._analyze_overflow_risks(tree))
        
        # Analyze for division by zero risks
        vulnerabilities.extend(self._analyze_division_risks(tree))
        
        # Analyze for precision loss risks
        vulnerabilities.extend(self._analyze_precision_risks(tree))
        
        # Analyze for gas consumption risks
        vulnerabilities.extend(self._analyze_gas_risks(tree))
        
        return vulnerabilities
    
    def _analyze_overflow_risks(self, tree: ExpressionTree) -> List[Dict[str, Any]]:
        """Analyze expression for overflow risks"""
        vulnerabilities = []
        
        # Check for multiplication operations
        if '*' in tree.operators:
            vulnerabilities.append({
                'type': 'overflow_risk',
                'severity': 'high',
                'description': 'Multiplication operation detected - potential overflow risk',
                'line_number': tree.root.line_number,
                'confidence': 0.7
            })
        
        # Check for exponentiation
        if '**' in tree.operators:
            vulnerabilities.append({
                'type': 'overflow_risk',
                'severity': 'critical',
                'description': 'Exponentiation operation detected - high overflow risk',
                'line_number': tree.root.line_number,
                'confidence': 0.9
            })
        
        # Check for left shift
        if '<<' in tree.operators:
            vulnerabilities.append({
                'type': 'overflow_risk',
                'severity': 'medium',
                'description': 'Left shift operation detected - potential overflow risk',
                'line_number': tree.root.line_number,
                'confidence': 0.6
            })
        
        return vulnerabilities
    
    def _analyze_division_risks(self, tree: ExpressionTree) -> List[Dict[str, Any]]:
        """Analyze expression for division by zero risks"""
        vulnerabilities = []
        
        # Check for division operations
        if '/' in tree.operators or '%' in tree.operators:
            vulnerabilities.append({
                'type': 'division_by_zero_risk',
                'severity': 'high',
                'description': 'Division/modulo operation detected - potential division by zero risk',
                'line_number': tree.root.line_number,
                'confidence': 0.8
            })
        
        return vulnerabilities
    
    def _analyze_precision_risks(self, tree: ExpressionTree) -> List[Dict[str, Any]]:
        """Analyze expression for precision loss risks"""
        vulnerabilities = []
        
        # Check for division operations that could cause precision loss
        if '/' in tree.operators:
            vulnerabilities.append({
                'type': 'precision_loss_risk',
                'severity': 'medium',
                'description': 'Division operation detected - potential precision loss',
                'line_number': tree.root.line_number,
                'confidence': 0.5
            })
        
        return vulnerabilities
    
    def _analyze_gas_risks(self, tree: ExpressionTree) -> List[Dict[str, Any]]:
        """Analyze expression for gas consumption risks"""
        vulnerabilities = []
        
        # High complexity expressions consume more gas
        if tree.complexity_score > 0.7:
            vulnerabilities.append({
                'type': 'gas_consumption_risk',
                'severity': 'medium',
                'description': 'Complex arithmetic expression - high gas consumption risk',
                'line_number': tree.root.line_number,
                'confidence': 0.6
            })
        
        return vulnerabilities
    
    def find_arithmetic_expressions(self, contract_content: str) -> List[Dict[str, Any]]:
        """Find all arithmetic expressions in contract content"""
        expressions = []
        lines = contract_content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for assignment statements with arithmetic
            assignment_pattern = r'(\w+)\s*=\s*([^;]+);'
            matches = re.finditer(assignment_pattern, line)
            
            for match in matches:
                variable = match.group(1)
                expression = match.group(2)
                
                # Check if expression contains arithmetic operators
                if any(op in expression for op in self.operators):
                    try:
                        tree = self.parse_expression(expression, i)
                        vulnerabilities = self.analyze_expression_vulnerabilities(tree)
                        
                        expressions.append({
                            'line_number': i,
                            'variable': variable,
                            'expression': expression,
                            'tree': tree,
                            'vulnerabilities': vulnerabilities
                        })
                    except Exception as e:
                        # Skip malformed expressions
                        continue
        
        return expressions
