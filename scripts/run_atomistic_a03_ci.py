#!/usr/bin/env python3
"""Run the standalone A03 probe beside a temporary, independent Quanta service."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request


WEB_ORIGIN = 'http://127.0.0.1:8765'


def case_window(cases):
    """Return the monotonic window measured by the child, including CUBE parsing."""
    if not isinstance(cases, list) or not cases:
        return None
    first = last = None
    for case in cases:
        timing = case.get('timing') if isinstance(case, dict) else None
        if not isinstance(timing, dict):
            return None
        start = timing.get('case_started_monotonic')
        end = timing.get('cleanup_finished_monotonic')
        if (type(start) not in (int, float) or type(end) not in (int, float)
                or not math.isfinite(start) or not math.isfinite(end)
                or start >= end or last is not None and start < last):
            return None
        if first is None:
            first = start
        last = end
    return first, last


def apply_independent_web(report, web, *, engine_exit, observer_complete, output):
    from verify_atomistic_a03 import WebSampler

    window = case_window(report.get('cases'))

    def phase(timestamp):
        if window is None:
            return 'unclassified'
        start, end = window
        if timestamp < start:
            return 'baseline'
        if timestamp <= end:
            return 'during'
        return 'after'

    samples = web['samples']
    for sample in samples:
        timing = sample['timing']
        sample['phase'] = phase(timing['finished_monotonic'])
        timing['phase_at_start'] = phase(timing['started_monotonic'])
    # The disabled sampler reuses the phase summary without making new requests.
    summary = WebSampler(None)
    summary.samples = samples
    web['summary'] = summary.finish()['summary']
    outliers = [sample for sample in samples if sample['status'] != sample['expected_status']
                or sample['wall_seconds'] > 2 or sample['error'] is not None]
    web_passed = bool(observer_complete and window is not None and not outliers
                      and all(row['samples'] for row in web['summary'].values()))
    report['engine_execution_gates_passed'] = engine_exit == 0 and report.get('passed_execution_gates') is True
    report['passed_execution_gates'] = report['engine_execution_gates_passed'] and web_passed
    if not web_passed:
        report['web_gate_error'] = 'Unexpected web status/timeout or incomplete independent observation window'

    raw = (json.dumps(samples, indent=2) + '\n').encode()
    (output / 'web-samples.json').write_bytes(raw)
    web.update({'observer_scope': 'independent_native_ci_parent', 'observer_complete': observer_complete,
                'case_window_monotonic': window, 'raw_samples_file': 'web-samples.json',
                'raw_samples_sha256': hashlib.sha256(raw).hexdigest(), 'timing_outliers': outliers[:8],
                'samples': samples[:4] + samples[-4:] if len(samples) > 8 else samples,
                'report_samples_are_excerpt': True})
    report['web_responsiveness'] = web


def run_independent_web(command, output):
    from verify_atomistic_a03 import WebSampler

    observer = WebSampler(WEB_ORIGIN)
    observer.start()
    try:
        # Only the wrapper can report the final combined execution result.
        engine_exit = subprocess.call(command, stdout=subprocess.DEVNULL)
    except OSError:
        engine_exit = 2
    finally:
        web = observer.finish()
    observer_complete = observer.thread is not None and not observer.thread.is_alive()
    if not observer_complete:
        # A late sample must not change the partial observation being preserved.
        web['samples'] = list(web['samples'])

    report_path = output / 'report.json'
    try:
        report = json.loads(report_path.read_text())
        if not isinstance(report, dict):
            raise ValueError('invalid engine report')
    except (OSError, ValueError):
        output.mkdir(exist_ok=True)
        report = {'schema_version': 1, 'source_sha': os.environ.get('QUANTA_A03_SOURCE_SHA'),
                  'error': 'Engine probe did not produce a valid report', 'cases': [],
                  'passed_execution_gates': False}
    apply_independent_web(report, web, engine_exit=engine_exit, observer_complete=observer_complete, output=output)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(report_path), 'passed_execution_gates': report['passed_execution_gates'],
                      'error': report.get('error') or report.get('web_gate_error')}))
    return 0 if report['passed_execution_gates'] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--candidate-dir', type=Path)
    parser.add_argument('--independent-web-observer', action='store_true')
    args = parser.parse_args()
    if args.independent_web_observer and platform.machine() != 'x86_64':
        parser.error('The independent observer is limited to the x86 native CI control')
    output = args.output_dir.resolve()
    if output.exists():
        parser.error('output directory must be new')
    output.parent.mkdir(parents=True, exist_ok=True)
    # This temporary API has no production data, account or mail configuration.
    with tempfile.TemporaryDirectory(prefix='quanta-a03-web-') as private:
        env = {**os.environ, 'QUANTA_API_TOKEN': secrets.token_urlsafe(32)}
        log_path = Path(private) / 'service.log'
        with log_path.open('wb') as log:
            service = subprocess.Popen(
                [sys.executable, '-m', 'quanta', 'serve', '--store', str(Path(private) / 'store'), '--port', '8765'],
                env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
            try:
                ready = False
                for _ in range(100):
                    if service.poll() is not None:
                        raise RuntimeError('independent Quanta service exited before probe')
                    try:
                        with urllib.request.urlopen(WEB_ORIGIN + '/', timeout=1) as response:
                            ready = response.status == 200
                        if ready:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                if not ready:
                    raise RuntimeError('independent Quanta service did not become ready')
                command = [
                    sys.executable, 'scripts/verify_atomistic_a03.py',
                    '--output-dir', str(output), '--case-timeout', '180',
                ]
                if args.candidate_dir is not None:
                    command.extend(['--candidate-dir', str(args.candidate_dir)])
                if args.independent_web_observer:
                    if args.candidate_dir is not None:
                        command.append('--amd64-candidate')
                    return run_independent_web(command, output)
                command.extend(['--web-origin', WEB_ORIGIN])
                return subprocess.call(command)
            finally:
                if service.poll() is None:
                    os.killpg(service.pid, signal.SIGTERM)
                try:
                    service.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(service.pid, signal.SIGKILL)
                    service.wait(timeout=5)
                if output.exists():
                    (output / 'independent-web-scope.json').write_text(json.dumps({
                        'scope': 'temporary native CI Quanta API; no OCI or production data',
                        'service_exit_code': service.returncode,
                        'production_service_verified': False,
                    }, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
