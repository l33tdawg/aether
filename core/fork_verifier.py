#!/usr/bin/env python3
"""
Fork Verifier: Runs Foundry test suites against a live-chain fork (anvil) to
validate LLM-generated PoCs against real state.
"""

import os
import json
import time
import signal
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ForkVerifier:
    """Orchestrates an anvil fork + forge test runs for generated suites."""

    def __init__(self, rpc_url: str, block_number: Optional[int] = None, anvil_port: int = 8545):
        self.rpc_url = rpc_url
        self.block_number = block_number
        self.anvil_port = anvil_port
        self.anvil_proc: Optional[subprocess.Popen] = None

    def _foundry_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        bins = [
            os.path.expanduser('~/.foundry/bin'),
            '/opt/homebrew/bin',
            '/usr/local/bin',
            '/usr/bin'
        ]
        env['PATH'] = f"{':'.join(bins)}:{env.get('PATH', '')}"
        return env

    def start_fork(self, timeout: int = 10) -> None:
        """Start anvil fork pointing at self.rpc_url (and optional block)."""
        if self.anvil_proc is not None:
            return
        cmd = [
            'anvil',
            '--fork-url', self.rpc_url,
            '--port', str(self.anvil_port),
        ]
        if self.block_number is not None:
            cmd += ['--fork-block-number', str(self.block_number)]
        try:
            self.anvil_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=self._foundry_env()
            )
        except Exception as e:
            logger.warning(f"Failed to start anvil: {e}")
            self.anvil_proc = None
            return

        # Give anvil time to come up
        start = time.time()
        while time.time() - start < timeout:
            if self.anvil_proc.poll() is not None:
                break
            time.sleep(0.25)

    def stop_fork(self) -> None:
        if self.anvil_proc is None:
            return
        try:
            self.anvil_proc.terminate()
            try:
                self.anvil_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.anvil_proc.kill()
        except Exception:
            pass
        finally:
            self.anvil_proc = None

    def _run_forge_tests(self, suite_dir: Path) -> Dict[str, Any]:
        """Run forge tests in suite_dir against local fork RPC."""
        env = self._foundry_env()
        rpc = f"http://127.0.0.1:{self.anvil_port}"
        try:
            proc = subprocess.run(
                ["forge", "test", "--rpc-url", rpc, "--json"],
                cwd=str(suite_dir),
                capture_output=True,
                text=True,
                timeout=600,
                env=env
            )
            output = (proc.stdout or '') + '\n' + (proc.stderr or '')
            # Try to parse Foundry JSON summary
            try:
                from .json_utils import extract_json_from_response, safe_json_parse
                blob = extract_json_from_response(output)
                data = safe_json_parse(blob, fallback={})
                if not data:
                    # Fallback to raw stdout JSON
                    import json as _json
                    data = _json.loads(proc.stdout or '{}')
            except Exception:
                data = {}
            summary = {
                'status_code': proc.returncode,
                'passed': 0,
                'failed': 0,
                'tests': []
            }
            def _accumulate(from_data: dict):
                _tests = []
                if 'test_results' in from_data and isinstance(from_data['test_results'], dict):
                    _tests = from_data['test_results'].get('tests', []) or []
                elif 'tests' in from_data and isinstance(from_data.get('tests'), list):
                    _tests = from_data.get('tests', []) or []
                for t in _tests:
                    ok = bool((isinstance(t, dict) and (t.get('success') or t.get('ok'))) or False)
                    summary['passed'] += 1 if ok else 0
                    summary['failed'] += 0 if ok else 1
                    name = t.get('name') if isinstance(t, dict) else 'unknown'
                    if not name:
                        name = t.get('test') if isinstance(t, dict) else 'unknown'
                    summary['tests'].append({'name': name or 'unknown', 'success': ok})

            if isinstance(data, dict):
                _accumulate(data)
            if summary['passed'] == 0 and summary['failed'] == 0:
                try:
                    import json as _json
                    raw = _json.loads(proc.stdout or '{}')
                    if isinstance(raw, dict):
                        _accumulate(raw)
                except Exception:
                    pass
            return {'raw': data, 'summary': summary}
        except Exception as e:
            logger.warning(f"forge test failed in {suite_dir}: {e}")
            return {'raw': {}, 'summary': {'status_code': -1, 'passed': 0, 'failed': 0, 'tests': []}}

    def verify_suites_under(self, output_dir: str) -> Dict[str, Any]:
        """Discover vulnerability_* subdirs and run tests against fork."""
        base = Path(output_dir)
        if not base.exists():
            return {'error': f'Output dir not found: {output_dir}'}
        suites = sorted([p for p in base.glob('vulnerability_*') if p.is_dir()])
        results: List[Dict[str, Any]] = []
        for s in suites:
            results.append(self._run_forge_tests(s))
        aggregate = {
            'total_suites': len(suites),
            'total_passed': sum(r.get('summary', {}).get('failed', 0) == 0 and r.get('summary', {}).get('status_code', 1) == 0 for r in results),
            'total_failed': sum(1 for r in results if r.get('summary', {}).get('failed', 0) > 0 or r.get('summary', {}).get('status_code', 1) != 0)
        }
        return {'aggregate': aggregate, 'runs': results}


def run_fork_verification(output_dir: str, rpc_url: str, block_number: Optional[int] = None) -> Dict[str, Any]:
    verifier = ForkVerifier(rpc_url=rpc_url, block_number=block_number)
    try:
        verifier.start_fork()
        results = verifier.verify_suites_under(output_dir)
        # Save to file
        try:
            out = Path(output_dir) / 'fork_verification.json'
            with open(out, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception:
            pass
        return results
    finally:
        verifier.stop_fork()


