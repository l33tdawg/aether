#!/usr/bin/env python3
"""
Accuracy Tracker

Track accuracy of vulnerability detection over time.
Monitors true/false positive rates and submission outcomes.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional


@dataclass
class DetectorStats:
    """Per-detector accuracy statistics computed from submission outcomes."""
    detector_name: str
    total_findings: int = 0
    total: int = 0  # alias kept for backward compat
    accepted: int = 0
    rejected: int = 0
    duplicate: int = 0
    out_of_scope: int = 0
    precision: float = 0.0  # accepted / (accepted + rejected), 0.0 if no data
    accuracy: float = 0.0
    weight: float = 1.0


class AccuracyTracker:
    """Track true/false positive rates."""
    
    def __init__(self, metrics_file: Optional[Path] = None):
        self.metrics_file = metrics_file or (Path.home() / '.aether' / 'accuracy_metrics.json')
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        self.load_metrics()
    
    def load_metrics(self):
        """Load metrics from file."""
        if self.metrics_file.exists():
            try:
                self.metrics = json.loads(self.metrics_file.read_text(encoding='utf-8'))
            except Exception:
                self._initialize_metrics()
        else:
            self._initialize_metrics()
    
    def _initialize_metrics(self):
        """Initialize empty metrics structure."""
        self.metrics = {
            'submissions': [],
            'false_positives_filtered': [],
            'true_positives': [],
            'version': '1.0',
            'initialized_at': datetime.now().isoformat()
        }
    
    def record_submission(
        self, 
        vulnerability: Dict, 
        outcome: str,
        bounty_amount: Optional[float] = None,
        platform: str = 'immunefi'
    ):
        """
        Record bug bounty submission outcome.
        
        Args:
            vulnerability: Vulnerability that was submitted
            outcome: 'accepted', 'rejected', 'duplicate', 'out_of_scope', 'pending'
            bounty_amount: Optional bounty amount received (if accepted)
            platform: Bug bounty platform (default: immunefi)
        """
        submission = {
            'timestamp': datetime.now().isoformat(),
            'vulnerability_type': vulnerability.get('vulnerability_type', 'unknown'),
            'severity': vulnerability.get('severity', 'unknown'),
            'outcome': outcome,
            'confidence': vulnerability.get('validation_confidence', vulnerability.get('confidence', 0.0)),
            'platform': platform,
            'contract_name': vulnerability.get('contract_name', 'unknown'),
            'project': vulnerability.get('project', 'unknown'),
            'detector': vulnerability.get('detector', vulnerability.get('vulnerability_type', 'unknown')),
        }
        
        if bounty_amount is not None:
            submission['bounty_amount'] = bounty_amount
        
        if outcome == 'accepted':
            submission['description'] = vulnerability.get('description', '')[:200]  # Store snippet
        
        self.metrics['submissions'].append(submission)
        self.save_metrics()
    
    def record_filtered(self, vulnerability: Dict, reason: str, stage: str = 'unknown'):
        """
        Record false positive that was filtered.
        
        Args:
            vulnerability: Vulnerability that was filtered
            reason: Reason for filtering
            stage: Validation stage that filtered it
        """
        filtered = {
            'timestamp': datetime.now().isoformat(),
            'vulnerability_type': vulnerability.get('vulnerability_type', 'unknown'),
            'severity': vulnerability.get('severity', 'unknown'),
            'filter_reason': reason,
            'filter_stage': stage,
            'confidence': vulnerability.get('confidence', 0.0),
            'contract_name': vulnerability.get('contract_name', 'unknown')
        }
        
        self.metrics['false_positives_filtered'].append(filtered)
        self.save_metrics()
    
    def record_true_positive(self, vulnerability: Dict):
        """
        Record confirmed true positive.
        
        Args:
            vulnerability: Confirmed vulnerability
        """
        true_positive = {
            'timestamp': datetime.now().isoformat(),
            'vulnerability_type': vulnerability.get('vulnerability_type', 'unknown'),
            'severity': vulnerability.get('severity', 'unknown'),
            'confidence': vulnerability.get('validation_confidence', vulnerability.get('confidence', 0.0)),
            'contract_name': vulnerability.get('contract_name', 'unknown')
        }
        
        self.metrics['true_positives'].append(true_positive)
        self.save_metrics()
    
    def get_accuracy_stats(self) -> Dict:
        """Calculate accuracy statistics."""
        total_submissions = len(self.metrics['submissions'])
        accepted = sum(1 for s in self.metrics['submissions'] if s['outcome'] == 'accepted')
        rejected = sum(1 for s in self.metrics['submissions'] if s['outcome'] == 'rejected')
        duplicate = sum(1 for s in self.metrics['submissions'] if s['outcome'] == 'duplicate')
        out_of_scope = sum(1 for s in self.metrics['submissions'] if s['outcome'] == 'out_of_scope')
        
        if total_submissions == 0:
            return {
                'accuracy': 0.0,
                'total_submissions': 0,
                'accepted': 0,
                'rejected': 0,
                'false_positives_filtered': len(self.metrics['false_positives_filtered']),
                'message': 'No submissions recorded yet'
            }
        
        accuracy = accepted / total_submissions if total_submissions > 0 else 0.0
        
        return {
            'accuracy': accuracy,
            'accuracy_percentage': f"{accuracy * 100:.1f}%",
            'total_submissions': total_submissions,
            'accepted': accepted,
            'rejected': rejected,
            'duplicate': duplicate,
            'out_of_scope': out_of_scope,
            'false_positives_filtered': len(self.metrics['false_positives_filtered']),
            'filter_effectiveness': self._calculate_filter_effectiveness()
        }
    
    def _calculate_filter_effectiveness(self) -> Dict:
        """Calculate how effective the filtering is."""
        total_filtered = len(self.metrics['false_positives_filtered'])
        total_submitted = len(self.metrics['submissions'])
        total_rejected = sum(1 for s in self.metrics['submissions'] if s['outcome'] == 'rejected')
        
        # Filter effectiveness = filtered / (filtered + rejected)
        # This shows how many false positives we caught before submission
        total_false_positives = total_filtered + total_rejected
        
        if total_false_positives == 0:
            return {
                'catch_rate': 1.0,
                'total_false_positives': 0,
                'caught_before_submission': total_filtered,
                'submitted_anyway': total_rejected
            }
        
        catch_rate = total_filtered / total_false_positives
        
        return {
            'catch_rate': catch_rate,
            'catch_rate_percentage': f"{catch_rate * 100:.1f}%",
            'total_false_positives': total_false_positives,
            'caught_before_submission': total_filtered,
            'submitted_anyway': total_rejected
        }
    
    def get_severity_breakdown(self) -> Dict:
        """Get breakdown by severity."""
        severity_stats = {}
        
        for submission in self.metrics['submissions']:
            severity = submission.get('severity', 'unknown')
            if severity not in severity_stats:
                severity_stats[severity] = {
                    'total': 0,
                    'accepted': 0,
                    'rejected': 0
                }
            
            severity_stats[severity]['total'] += 1
            if submission['outcome'] == 'accepted':
                severity_stats[severity]['accepted'] += 1
            elif submission['outcome'] == 'rejected':
                severity_stats[severity]['rejected'] += 1
        
        # Calculate accuracy per severity
        for severity, stats in severity_stats.items():
            if stats['total'] > 0:
                stats['accuracy'] = stats['accepted'] / stats['total']
                stats['accuracy_percentage'] = f"{stats['accuracy'] * 100:.1f}%"
        
        return severity_stats
    
    def get_vulnerability_type_breakdown(self) -> Dict:
        """Get breakdown by vulnerability type."""
        type_stats = {}
        
        for submission in self.metrics['submissions']:
            vuln_type = submission.get('vulnerability_type', 'unknown')
            if vuln_type not in type_stats:
                type_stats[vuln_type] = {
                    'total': 0,
                    'accepted': 0,
                    'rejected': 0
                }
            
            type_stats[vuln_type]['total'] += 1
            if submission['outcome'] == 'accepted':
                type_stats[vuln_type]['accepted'] += 1
            elif submission['outcome'] == 'rejected':
                type_stats[vuln_type]['rejected'] += 1
        
        # Calculate accuracy per type
        for vuln_type, stats in type_stats.items():
            if stats['total'] > 0:
                stats['accuracy'] = stats['accepted'] / stats['total']
                stats['accuracy_percentage'] = f"{stats['accuracy'] * 100:.1f}%"
        
        return type_stats
    
    def get_bounty_stats(self) -> Dict:
        """Get bounty earnings statistics."""
        total_bounties = 0.0
        bounty_count = 0
        
        for submission in self.metrics['submissions']:
            if submission.get('outcome') == 'accepted' and 'bounty_amount' in submission:
                total_bounties += submission['bounty_amount']
                bounty_count += 1
        
        return {
            'total_earned': total_bounties,
            'average_bounty': total_bounties / bounty_count if bounty_count > 0 else 0,
            'bounty_count': bounty_count,
            'submissions_with_bounty': bounty_count
        }
    
    def get_time_series_data(self, days: int = 30) -> Dict:
        """Get time series data for the last N days."""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_submissions = [
            s for s in self.metrics['submissions']
            if datetime.fromisoformat(s['timestamp']) >= cutoff_date
        ]
        
        recent_filtered = [
            f for f in self.metrics['false_positives_filtered']
            if datetime.fromisoformat(f['timestamp']) >= cutoff_date
        ]
        
        return {
            'period_days': days,
            'submissions': len(recent_submissions),
            'filtered': len(recent_filtered),
            'accepted': sum(1 for s in recent_submissions if s['outcome'] == 'accepted'),
            'rejected': sum(1 for s in recent_submissions if s['outcome'] == 'rejected'),
        }
    
    def record_outcome(
        self,
        vulnerability: Dict,
        outcome: str,
        detector: str = "unknown",
        bounty_amount: Optional[float] = None,
        platform: str = "immunefi",
    ):
        """Record a submission outcome and attribute it to a detector.

        This is a convenience wrapper around ``record_submission`` that also
        stores the originating detector name so per-detector weights can be
        computed later.

        Args:
            vulnerability: Vulnerability dict with at least ``vulnerability_type`` and ``severity``.
            outcome: 'accepted', 'rejected', 'duplicate', 'out_of_scope', 'pending'.
            detector: Name/category of the detector that produced the finding
                      (e.g. 'reentrancy', 'precision_analyzer', 'deep_analysis_Pass 3').
            bounty_amount: Optional bounty received.
            platform: Bug bounty platform.
        """
        # Ensure the vulnerability dict carries the detector tag before recording
        vuln_copy = dict(vulnerability)
        vuln_copy['detector'] = detector
        self.record_submission(vuln_copy, outcome, bounty_amount=bounty_amount, platform=platform)

    def record_finding_outcome(self, finding_id: str, detector_name: str,
                               outcome: str, bounty_amount: float = 0.0):
        """Record outcome of a submitted finding.

        Args:
            finding_id: Unique identifier for the finding.
            detector_name: Name/category of the detector that produced the finding.
            outcome: 'accepted', 'rejected', 'duplicate', 'out_of_scope'.
            bounty_amount: Bounty received (if accepted).
        """
        vuln = {
            'finding_id': finding_id,
            'vulnerability_type': detector_name,
            'severity': 'unknown',
            'detector': detector_name,
        }
        self.record_submission(
            vuln, outcome,
            bounty_amount=bounty_amount if bounty_amount else None,
        )

    # -- Per-detector accuracy & weight computation --------------------------

    def get_detector_accuracy(self) -> Dict[str, DetectorStats]:
        """Compute per-detector accuracy from recorded submissions.

        Returns:
            Mapping of detector name -> DetectorStats.
        """
        stats_map: Dict[str, DetectorStats] = {}

        for sub in self.metrics.get('submissions', []):
            det = sub.get('detector', sub.get('vulnerability_type', 'unknown'))
            if det not in stats_map:
                stats_map[det] = DetectorStats(detector_name=det)
            ds = stats_map[det]
            ds.total += 1
            ds.total_findings += 1
            if sub['outcome'] == 'accepted':
                ds.accepted += 1
            elif sub['outcome'] == 'rejected':
                ds.rejected += 1
            elif sub['outcome'] == 'duplicate':
                ds.duplicate += 1
            elif sub['outcome'] == 'out_of_scope':
                ds.out_of_scope += 1

        for ds in stats_map.values():
            if ds.total > 0:
                ds.accuracy = ds.accepted / ds.total
            # precision = accepted / (accepted + rejected), ignoring duplicate/oos
            denom = ds.accepted + ds.rejected
            ds.precision = ds.accepted / denom if denom > 0 else 0.0
            ds.weight = self._compute_weight(ds)

        return stats_map

    def get_detector_weights(self) -> Dict[str, float]:
        """Return a mapping of detector name -> confidence weight multiplier.

        Weights are derived from historical precision (accepted / (accepted + rejected)):
          - Higher precision -> higher weight (range 0.5 to 1.5).
          - New detectors or those with fewer than 20 outcomes stay at 1.0 (neutral).
          - Minimum 20 outcomes before calibration activates.
        """
        stats = self.get_detector_accuracy()
        return {name: ds.weight for name, ds in stats.items()}

    def get_severity_accuracy(self) -> Dict[str, Dict[str, int]]:
        """Return per-severity acceptance/rejection counts.

        Returns:
            e.g. {"critical": {"accepted": 5, "rejected": 15, "total": 20}, ...}
        """
        severity_counts: Dict[str, Dict[str, int]] = {}
        for sub in self.metrics.get('submissions', []):
            sev = sub.get('severity', 'unknown').lower()
            if sev not in severity_counts:
                severity_counts[sev] = {'accepted': 0, 'rejected': 0, 'duplicate': 0,
                                        'out_of_scope': 0, 'total': 0}
            severity_counts[sev]['total'] += 1
            outcome = sub.get('outcome', '')
            if outcome in severity_counts[sev]:
                severity_counts[sev][outcome] += 1
        return severity_counts

    def get_severity_calibration(self) -> Dict[str, float]:
        """Return per-severity acceptance rates for calibrating LLM severity.

        Returns:
            Mapping of severity level -> acceptance rate (0.0-1.0).
            Only severities with at least 1 submission are included.
        """
        severity_counts: Dict[str, Dict[str, int]] = {}
        for sub in self.metrics.get('submissions', []):
            sev = sub.get('severity', 'unknown').lower()
            if sev not in severity_counts:
                severity_counts[sev] = {'total': 0, 'accepted': 0}
            severity_counts[sev]['total'] += 1
            if sub['outcome'] == 'accepted':
                severity_counts[sev]['accepted'] += 1

        return {
            sev: counts['accepted'] / counts['total']
            for sev, counts in severity_counts.items()
            if counts['total'] > 0
        }

    @staticmethod
    def _compute_weight(ds: 'DetectorStats') -> float:
        """Compute confidence weight multiplier for a detector.

        Requires at least 20 outcomes before calibration activates.
        Uses precision (accepted / (accepted + rejected)) for weight calculation.
        Range: 0.5 (low precision) to 1.5 (high precision).
        """
        if ds.total < 20:
            return 1.0
        prec = ds.precision
        if prec >= 0.66:
            # Linear scale from 1.0 at 0.66 to 1.5 at 1.0
            return 1.0 + 0.5 * ((prec - 0.66) / 0.34)
        if prec <= 0.33:
            # Linear scale from 1.0 at 0.33 to 0.5 at 0.0
            return 0.5 + 0.5 * (prec / 0.33)
        return 1.0

    def save_metrics(self):
        """Save metrics to file."""
        try:
            self.metrics['last_updated'] = datetime.now().isoformat()
            self.metrics_file.write_text(
                json.dumps(self.metrics, indent=2),
                encoding='utf-8'
            )
        except Exception as e:
            print(f"Warning: Failed to save metrics: {e}")
    
    def print_summary(self):
        """Print formatted summary of metrics."""
        stats = self.get_accuracy_stats()
        severity_breakdown = self.get_severity_breakdown()
        type_breakdown = self.get_vulnerability_type_breakdown()
        bounty_stats = self.get_bounty_stats()
        
        print("\n" + "="*60)
        print("AETHER ACCURACY METRICS")
        print("="*60)
        
        print(f"\n📊 Overall Performance:")
        print(f"   Accuracy: {stats['accuracy_percentage']}")
        print(f"   Total Submissions: {stats['total_submissions']}")
        print(f"   ✅ Accepted: {stats['accepted']}")
        print(f"   ❌ Rejected: {stats['rejected']}")
        print(f"   🔄 Duplicates: {stats.get('duplicate', 0)}")
        print(f"   ⚠️  Out of Scope: {stats.get('out_of_scope', 0)}")
        
        print(f"\n🛡️  False Positive Filtering:")
        filter_eff = stats['filter_effectiveness']
        print(f"   Catch Rate: {filter_eff['catch_rate_percentage']}")
        print(f"   Caught Before Submission: {filter_eff['caught_before_submission']}")
        print(f"   Submitted Anyway (Rejected): {filter_eff['submitted_anyway']}")
        
        if bounty_stats['bounty_count'] > 0:
            print(f"\n💰 Bounty Earnings:")
            print(f"   Total Earned: ${bounty_stats['total_earned']:,.2f}")
            print(f"   Average Bounty: ${bounty_stats['average_bounty']:,.2f}")
            print(f"   Successful Submissions: {bounty_stats['bounty_count']}")
        
        if severity_breakdown:
            print(f"\n📈 Severity Breakdown:")
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_breakdown:
                    s = severity_breakdown[severity]
                    print(f"   {severity.upper()}: {s['total']} total, {s['accepted']} accepted ({s.get('accuracy_percentage', 'N/A')})")
        
        print("\n" + "="*60 + "\n")
    
    def export_report(self, output_path: Path):
        """Export detailed report to file."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'overall_stats': self.get_accuracy_stats(),
            'severity_breakdown': self.get_severity_breakdown(),
            'type_breakdown': self.get_vulnerability_type_breakdown(),
            'bounty_stats': self.get_bounty_stats(),
            'recent_activity_30_days': self.get_time_series_data(30),
            'recent_activity_7_days': self.get_time_series_data(7),
        }
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

