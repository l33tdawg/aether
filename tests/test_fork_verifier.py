import json
from pathlib import Path

import pytest

from core.fork_verifier import ForkVerifier, run_fork_verification


def test_verify_suites_under_aggregates(tmp_path: Path, monkeypatch):
    base = tmp_path / "out"
    base.mkdir()
    (base / "vulnerability_1").mkdir()
    (base / "vulnerability_2").mkdir()

    fv = ForkVerifier(rpc_url="http://localhost:8545")

    def fake_run(suite_dir):
        # First suite passes, second fails
        if str(suite_dir).endswith("vulnerability_1"):
            return {"raw": {}, "summary": {"status_code": 0, "passed": 1, "failed": 0, "tests": [{"name": "t1", "success": True}]}}
        else:
            return {"raw": {}, "summary": {"status_code": 1, "passed": 0, "failed": 1, "tests": [{"name": "t2", "success": False}]}}

    monkeypatch.setattr(fv, "_run_forge_tests", fake_run)

    res = fv.verify_suites_under(str(base))
    agg = res.get("aggregate", {})
    assert agg.get("total_suites") == 2
    assert agg.get("total_passed") == 1
    assert agg.get("total_failed") == 1


def test__run_forge_tests_parses_output(tmp_path: Path, monkeypatch):
    suite = tmp_path / "suite"
    suite.mkdir()

    class DummyCP:
        def __init__(self, stdout, stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=600, env=None):
        payload = {
            "test_results": {
                "tests": [
                    {"name": "testA", "success": True},
                    {"name": "testB", "success": False}
                ]
            }
        }
        return DummyCP(stdout=json.dumps(payload), returncode=0)

    monkeypatch.setattr("core.fork_verifier.subprocess.run", fake_run)

    fv = ForkVerifier(rpc_url="http://localhost:8545")
    res = fv._run_forge_tests(suite)
    summ = res.get("summary", {})
    assert summ.get("passed") == 1
    assert summ.get("failed") == 1
    assert len(summ.get("tests", [])) == 2


def test_run_fork_verification_writes_file(tmp_path: Path, monkeypatch):
    outdir = tmp_path / "out"
    (outdir / "vulnerability_1").mkdir(parents=True)

    class DummyFV:
        def __init__(self, *args, **kwargs):
            pass
        def start_fork(self, *a, **k):
            return None
        def verify_suites_under(self, path):
            return {"aggregate": {"total_suites": 1, "total_passed": 1, "total_failed": 0}, "runs": []}
        def stop_fork(self, *a, **k):
            return None

    # Patch the class used inside run_fork_verification
    monkeypatch.setattr("core.fork_verifier.ForkVerifier", DummyFV)

    res = run_fork_verification(str(outdir), rpc_url="http://localhost:8545")
    assert res.get("aggregate", {}).get("total_suites") == 1
    saved = outdir / "fork_verification.json"
    assert saved.exists()
    data = json.loads(saved.read_text())
    assert data.get("aggregate", {}).get("total_passed") == 1


