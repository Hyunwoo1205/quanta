#!/usr/bin/env python3
"""One idempotent, authenticated pair replay after a separately verified OS reboot.

The reviewed controller injects quanta_fixed_backup. Only a new replay run is
intentionally persisted through the existing API; source data and secrets are
never returned. Run the exact pre/post-reboot database comparison BEFORE this
operation because this calculation adds legitimate run/event/artifact records.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys
import time
import uuid

import quanta_fixed_backup as helper

SOURCE_SHA = '1738107301ef873bfe5e01f930866c2a74e4ec3f'
REBOOT_BASELINE = Path('/etc/quanta/recovery-reboot.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
MAX_HTTP_BYTES = 2 * 1024**2
MAX_REPORT_BYTES = 16 * 1024**2
MAX_SOURCE_ROWS = 1000
POLL_SECONDS = 60
MAX_OUTPUT_BYTES = 8192
BOOLEANS = ('boot_changed', 'source_run_selected', 'replay_submitted', 'new_run_completed',
            'same_revision', 'replay_link_verified', 'source_values_matched',
            'independent_reference_matched', 'physical_validation_unchanged', 'new_calculation_verified')
STAGES = frozenset({'configuration', 'postboot', 'source', 'submit', 'poll', 'compare', 'complete'})
FAILURES = frozenset({'none', 'invalid_configuration', 'postboot_precondition_failed',
                     'source_run_unavailable', 'replay_submission_failed', 'replay_not_completed',
                     'result_mismatch'})
FAILURE_BY_STAGE = {'configuration': 'invalid_configuration', 'postboot': 'postboot_precondition_failed',
                    'source': 'source_run_unavailable', 'submit': 'replay_submission_failed',
                    'poll': 'replay_not_completed', 'compare': 'result_mismatch'}
FIELDS = frozenset(('scope', 'status', 'stage', 'failure_reason', 'run_id', 'energy_j', 'forces_n',
                    'physical_validation_status', *BOOLEANS))


class SmokeError(Exception):
    pass


def validate_config(config):
    return helper.validate_config(config)


def _uuid(value):
    return (isinstance(value, str) and bool(re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', value)))


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except (OverflowError, ValueError):
        return False


def _values(result):
    if (not isinstance(result, dict) or result.get('execution_status') != 'SUCCEEDED'
            or result.get('physical_validation_status') != 'unvalidated'
            or not isinstance(result.get('steps'), list) or len(result['steps']) != 1):
        raise SmokeError()
    step = result['steps'][0]
    if (not isinstance(step, dict) or step.get('module_id') != 'quanta.pair_static'
            or step.get('module_version') != '0.1.0' or step.get('outcome') != 'SUCCEEDED'
            or step.get('partial') is not False or not isinstance(step.get('payload'), dict)):
        raise SmokeError()
    payload = step['payload']
    energy, forces = payload.get('energy_j'), payload.get('forces_n')
    if (payload.get('operation') != 'energy_forces' or not _finite(energy)
            or not isinstance(forces, list) or len(forces) != 2
            or any(not isinstance(row, list) or len(row) != 3 or any(not _finite(v) for v in row)
                   for row in forces)):
        raise SmokeError()
    return energy, forces


def _reference_matches(values):
    energy, forces = values
    expected = [[4e-11, 0.0, 0.0], [-4e-11, 0.0, 0.0]]
    return (math.isclose(energy, 4e-21, rel_tol=1e-12, abs_tol=1e-30)
            and all(math.isclose(value, target, rel_tol=1e-12, abs_tol=1e-20)
                    for row, targets in zip(forces, expected) for value, target in zip(row, targets)))


@contextmanager
def _database_identity():
    """Keep real UID 0 for restoration; SQLite-created WAL/SHM belong to 10001."""
    if os.getuid() != 0 or os.geteuid() != 0:
        raise SmokeError()
    original_uid, original_gid = os.geteuid(), os.getegid()

    @contextmanager
    def transition():
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    try:
        with transition():
            os.setegid(10001)
            os.seteuid(10001)
        yield
    finally:
        # Also execute when entering the second identity change fails, or when
        # the SQLite deadline interrupts connect/query/close.
        with transition():
            try:
                os.seteuid(original_uid)
            finally:
                os.setegid(original_gid)


def _source_run():
    path = helper.DATA / 'jobs.sqlite3'
    device = os.lstat(helper.DATA).st_dev
    before = helper._private_file(path, device)
    selected = None
    with _database_identity():
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2, isolation_level=None)
        try:
            expires = time.monotonic() + 10
            connection.set_progress_handler(lambda: int(time.monotonic() > expires), 1000)
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('BEGIN')
            rows = connection.execute("SELECT run_id,revision_id,report FROM runs "
                "WHERE owner='local' AND status='SUCCEEDED' ORDER BY seq LIMIT ?", (MAX_SOURCE_ROWS,))
            for run_id, revision_id, raw in rows:
                if not _uuid(run_id) or not _uuid(revision_id) or not isinstance(raw, str) or len(raw) > MAX_REPORT_BYTES:
                    continue
                report = helper._json(raw.encode('utf-8'))
                if not isinstance(report, dict) or report.get('valid') is not True or not isinstance(report.get('result'), dict):
                    continue
                try:
                    values = _values(report['result'])
                except SmokeError:
                    continue
                if (report['result'].get('run_id') != run_id or report['result'].get('revision_id') != revision_id
                        or not _reference_matches(values)):
                    raise SmokeError()
                selected = run_id, revision_id, values
                break
        finally:
            connection.close()
    # File identity checks run only after effective root identity is restored.
    after = helper._private_file(path, device)
    if selected is None or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise SmokeError()
    return selected


def _preflight(config):
    if os.geteuid() != 0 or helper._json(helper._read_root(helper.ETC / 'installed.json', private=True)) != config:
        raise SmokeError()
    baseline = helper._json(helper._read_root(REBOOT_BASELINE, private=True, limit=1024**2))
    if (not isinstance(baseline, dict) or type(baseline.get('schema_version')) is not int
            or baseline['schema_version'] not in {1, 2} or baseline.get('source_sha') != SOURCE_SHA
            or not isinstance(baseline.get('old_boot_id'), str)
            or str(uuid.UUID(baseline['old_boot_id'])) != baseline['old_boot_id']
            or not isinstance(baseline.get('created_at'), str)):
        raise SmokeError()
    if baseline['schema_version'] == 2:
        fields = {'schema_version', 'source_sha', 'created_at', 'operation_id', 'old_boot_id',
                  'database', 'peers', 'settings', 'database_basis', 'backup_policy_basis',
                  'backup_policy_console_verified'}
        if (set(baseline) != fields
                or baseline['database_basis'] != 'quiescent_live_store_before_os_reboot'
                or baseline['backup_policy_basis'] != 'user_reported_oci_daily'
                or baseline['backup_policy_console_verified'] is not False
                or not isinstance(baseline['operation_id'], str)
                or str(uuid.UUID(baseline['operation_id'])) != baseline['operation_id']
                or any(not isinstance(baseline[field], dict) for field in ('database', 'peers', 'settings'))):
            raise SmokeError()
    created = datetime.strptime(baseline['created_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if not 0 <= (datetime.now(timezone.utc) - created).total_seconds() <= 86400:
        raise SmokeError()
    raw = helper._read_root(BOOT_ID, limit=64)
    boot_id = raw.decode('ascii').removesuffix('\n')
    if raw != (boot_id + '\n').encode() or str(uuid.UUID(boot_id)) != boot_id or boot_id == baseline['old_boot_id']:
        raise SmokeError()
    environment = helper._read_root(helper.ETC / 'app.env', private=True)
    prefix = ('QUANTA_PUBLIC_ORIGIN=' + config['public_origin'] + '\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=').encode()
    if not environment.startswith(prefix) or not re.fullmatch(rb'[0-9a-f]{64}\n', environment[len(prefix):]):
        raise SmokeError()
    return boot_id, environment[len(prefix):-1].decode('ascii')


def _request(config, token, method, path, *, key=None):
    if (method not in {'GET', 'POST'} or not re.fullmatch(
            r'/v1/runs/[0-9a-f-]{36}(?:/(?:replay|result))?', path)
            or method == 'POST' and not path.endswith('/replay')):
        raise SmokeError()
    headers = {'Host': config['public_origin'][8:], 'Origin': config['public_origin'],
               'Authorization': 'Bearer ' + token, 'Connection': 'close'}
    body = None
    if method == 'POST':
        body = b'{}'
        headers.update({'Content-Type': 'application/json', 'Content-Length': '2', 'Idempotency-Key': key})
    connection = http.client.HTTPConnection('127.0.0.1', 8765, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != (202 if method == 'POST' else 200):
            raise SmokeError()
        raw = response.read(MAX_HTTP_BYTES + 1)
        if len(raw) > MAX_HTTP_BYTES:
            raise SmokeError()
        value = helper._json(raw)
        if not isinstance(value, dict):
            raise SmokeError()
        return value
    finally:
        connection.close()


def _initial_report():
    return {'scope': 'post_reboot_authenticated_calculation', 'status': 'failed', 'stage': 'configuration',
            'failure_reason': 'invalid_configuration', 'run_id': None, 'energy_j': None, 'forces_n': None,
            'physical_validation_status': 'unvalidated', **dict.fromkeys(BOOLEANS, False)}


def _perform(config, report):
    report['stage'] = 'postboot'
    boot_id, token = _preflight(config)
    report['boot_changed'] = True
    report['stage'] = 'source'
    source, revision, original = _source_run()
    report['source_run_selected'] = True
    report['stage'] = 'submit'
    key = str(uuid.uuid5(uuid.NAMESPACE_URL, 'quanta:post-reboot-compute:' + boot_id + ':' + source))
    submitted = _request(config, token, 'POST', '/v1/runs/' + source + '/replay', key=key)
    run_id = submitted.get('run_id')
    if not _uuid(run_id) or run_id == source or submitted.get('revision_id') != revision or submitted.get('replay_of') != source:
        raise SmokeError()
    report.update(run_id=run_id, replay_submitted=True)
    report['stage'] = 'poll'
    expires = time.monotonic() + POLL_SECONDS
    while True:
        current = _request(config, token, 'GET', '/v1/runs/' + run_id)
        if (current.get('run_id') != run_id or current.get('revision_id') != revision
                or current.get('replay_of') != source):
            raise SmokeError()
        state = current.get('execution_status')
        if state == 'SUCCEEDED':
            break
        if state not in {'QUEUED', 'RUNNING'} or time.monotonic() >= expires:
            raise SmokeError()
        time.sleep(0.25)
    report.update(new_run_completed=True, same_revision=True, replay_link_verified=True)
    report['stage'] = 'compare'
    result = _request(config, token, 'GET', '/v1/runs/' + run_id + '/result')
    if (result.get('run_id') != run_id or result.get('revision_id') != revision
            or not isinstance(result.get('provenance'), dict) or result['provenance'].get('replay_of') != source):
        raise SmokeError()
    values = _values(result)
    if not (math.isclose(values[0], original[0], rel_tol=1e-12, abs_tol=1e-30)
            and all(math.isclose(value, target, rel_tol=1e-12, abs_tol=1e-20)
                    for row, targets in zip(values[1], original[1]) for value, target in zip(row, targets))):
        raise SmokeError()
    report['source_values_matched'] = True
    if not _reference_matches(values):
        raise SmokeError()
    report.update(independent_reference_matched=True, physical_validation_unchanged=True,
                  new_calculation_verified=True, energy_j=values[0], forces_n=values[1],
                  status='success', stage='complete', failure_reason='none')


def run(config):
    report = _initial_report()
    try:
        config = validate_config(config)
    except Exception:
        return report
    try:
        with helper._deadline(90):
            _perform(config, report)
    except Exception:
        report['failure_reason'] = FAILURE_BY_STAGE.get(report['stage'], 'result_mismatch')
    return report


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or value['scope'] != 'post_reboot_authenticated_calculation'
            or not isinstance(value['status'], str) or value['status'] not in {'success', 'failed'}
            or not isinstance(value['stage'], str) or value['stage'] not in STAGES
            or not isinstance(value['failure_reason'], str) or value['failure_reason'] not in FAILURES
            or any(type(value[field]) is not bool for field in BOOLEANS)
            or value['physical_validation_status'] != 'unvalidated'
            or value['run_id'] is not None and not _uuid(value['run_id'])
            or value['energy_j'] is not None and not _finite(value['energy_j'])
            or (value['energy_j'] is None) != (value['forces_n'] is None)):
        raise ValueError('invalid smoke report')
    if value['forces_n'] is not None:
        forces = value['forces_n']
        if (not isinstance(forces, list) or len(forces) != 2
                or any(not isinstance(row, list) or len(row) != 3 or any(not _finite(v) for v in row) for row in forces)):
            raise ValueError('invalid smoke report')
    if (value['status'] == 'success') != (value['stage'] == 'complete' and value['failure_reason'] == 'none'):
        raise ValueError('invalid smoke report')
    if value['status'] == 'failed' and value['failure_reason'] == 'none':
        raise ValueError('invalid smoke report')
    if value['status'] == 'success' and (not all(value[field] for field in BOOLEANS)
            or value['run_id'] is None or value['energy_j'] is None
            or not _reference_matches((value['energy_j'], value['forces_n']))):
        raise ValueError('invalid smoke report')
    if (value['new_calculation_verified'] and value['status'] != 'success'
            or value['replay_submitted'] != (value['run_id'] is not None)):
        raise ValueError('invalid smoke report')
    return dict(value)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
            raise ValueError
        return validate_report(helper._json(raw))
    except Exception:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        report = run(helper._argument(argv[0])) if len(argv) == 1 else _initial_report()
        report = validate_report(report)
    except Exception:
        report = _initial_report()
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if report['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
