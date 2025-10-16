#!/usr/bin/env python3
"""
LearningSystem (Phase 3)

Maintains feedback-driven learning metrics and adapted patterns.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LearningMetrics:
	total_feedback_entries: int = 0
	false_positive_corrections: int = 0
	severity_corrections: int = 0
	pattern_updates: int = 0


@dataclass
class FeedbackEntry:
	vulnerability_id: str
	contract_path: str
	finding_type: str
	user_feedback: str
	severity_correction: Optional[str] = None
	user_notes: Optional[str] = None


@dataclass
class PatternUpdate:
	type: str
	pattern: str
	description: str
	severity: str
	confidence: float


class LearningSystem:
	def __init__(self, data_dir: Optional[str] = None):
		self.data_dir = data_dir
		self.min_feedback_threshold = 3
		self.confidence_threshold = 0.7
		self.learning_rate = 0.1
		self.max_pattern_history = 1000
		self._metrics = LearningMetrics()
		self._adapted_patterns: Dict[str, Dict[str, Any]] = {}
		self._pattern_confidence: Dict[str, float] = {}
		self._false_positive_rate: Dict[str, float] = {}

	def get_learning_metrics(self) -> LearningMetrics:
		return self._metrics

	async def learn_from_feedback(
		self,
		vulnerability_id: str,
		contract_path: str,
		finding_type: str,
		user_feedback: str,
		severity_correction: Optional[str] = None,
		user_notes: Optional[str] = None,
	) -> bool:
		self._metrics.total_feedback_entries += 1
		if user_feedback == 'false_positive':
			self._metrics.false_positive_corrections += 1
			self._false_positive_rate[finding_type] = min(1.0, self._false_positive_rate.get(finding_type, 0.0) + 0.1)
		elif severity_correction:
			self._metrics.severity_corrections += 1
		self._pattern_confidence[finding_type] = min(1.0, self._pattern_confidence.get(finding_type, 0.5) + 0.05)
		return True

	async def update_patterns(self, new_pattern: Dict[str, Any]) -> bool:
		ptype = new_pattern.get('type', 'unknown')
		self._adapted_patterns[ptype] = new_pattern
		self._metrics.pattern_updates += 1
		return True

	async def adapt_to_protocol(self, protocol_type: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
		finding_types = [f.get('type', 'unknown') for f in findings]
		severity_distribution: Dict[str, int] = {}
		for f in findings:
			sev = f.get('severity', 'unknown').lower()
			severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
		pattern_key = f'protocol_{protocol_type}'
		self._adapted_patterns[pattern_key] = {'finding_types': finding_types, 'severity_distribution': severity_distribution}
		return {
			'protocol_type': protocol_type,
			'finding_types': finding_types,
			'severity_distribution': severity_distribution,
			'common_patterns': list(set(finding_types)),
		}

	def get_adapted_patterns(self) -> Dict[str, Any]:
		return self._adapted_patterns

	def get_pattern_confidence(self, pattern_type: str) -> float:
		return float(self._pattern_confidence.get(pattern_type, 0.5))

	def get_false_positive_rate(self, pattern_type: str) -> float:
		return float(self._false_positive_rate.get(pattern_type, 0.0))

	def get_learning_summary(self) -> Dict[str, Any]:
		return {
			'metrics': self._metrics,
			'total_patterns': len(self._adapted_patterns),
			'pattern_confidence': self._pattern_confidence,
			'false_positive_patterns': self._false_positive_rate,
			'learning_parameters': {
				'min_feedback_threshold': self.min_feedback_threshold,
				'confidence_threshold': self.confidence_threshold,
				'learning_rate': self.learning_rate,
			},
		}
