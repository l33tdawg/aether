#!/usr/bin/env python3
"""
Accuracy Tracker

Track accuracy of vulnerability detection over time.
Monitors true/false positive rates and submission outcomes.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional


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

