import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


def wrapper():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'run_atomistic_a03_ci.py'
    spec = importlib.util.spec_from_file_location('native_a03_ci', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample(start, finish):
    return {'phase': 'baseline', 'path': '/', 'status': 200, 'expected_status': 200,
            'wall_seconds': finish - start, 'error': None,
            'timing': {'started_monotonic': start, 'finished_monotonic': finish}}


@pytest.mark.parametrize(('case_window', 'engine_exit', 'during_finish', 'complete', 'passed'), [
    (True, 0, 14.0, True, True),
    (True, 0, 14.001, True, False),
    (True, 2, 14.0, True, False),
    (True, 0, 14.0, False, False),
    (False, 0, 14.0, True, False),
])
def test_independent_observer_applies_same_wall_limit_and_requires_case_evidence(
        tmp_path, monkeypatch, case_window, engine_exit, during_finish, complete, passed):
    module = wrapper()
    monkeypatch.syspath_prepend(str(Path(module.__file__).parent))
    timing = {'case_started_monotonic': 10.0, 'cleanup_finished_monotonic': 20.0}
    cases = [{'timing': timing}] if case_window else []
    report = {'cases': cases, 'passed_execution_gates': True}
    web = {'samples': [sample(9.0, 9.1), sample(12.0, during_finish), sample(21.0, 21.1)]}
    module.apply_independent_web(report, web, engine_exit=engine_exit, observer_complete=complete, output=tmp_path)

    assert report['passed_execution_gates'] is passed
    assert 'web_gate_error' not in report if passed else True
    raw = (tmp_path / 'web-samples.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == report['web_responsiveness']['raw_samples_sha256']
    phases = [item['phase'] for item in json.loads(raw)]
    assert phases == (['baseline', 'during', 'after'] if case_window else ['unclassified'] * 3)
