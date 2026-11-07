#!/usr/bin/env python3
"""Read the native ARM feature allowlist and one receipt-bound CP2K failure log."""

import base64
from contextlib import ExitStack
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

if 'shared' not in globals():
    spec = importlib.util.spec_from_file_location('quanta_fixed_diagnostic',
                                                 Path(__file__).with_name('diagnose_atomistic_image.py'))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)

POLICY = shared.DiagnosticPolicy(
    'inspect-atomistic-host-isa', Path('.github/oci/atomistic-host-isa-request.json'),
    'QUANTA_HOST_ISA', 'atomistic_host_isa', 'b7bfa8f90a7d5d05e74f7d8fefefe3be72cfc379',
    42337645536, 42337645488, '.github/workflows/oci-atomistic-host-isa-tests.yml',
    frozenset({'atomistic host ISA diagnostic (x86_64)', 'atomistic host ISA diagnostic (aarch64)'}),
)
PRIOR_REQUEST = '1c4f2a16-408d-4b74-871f-19d727726a09'
LOG_PATH = Path('/srv/quanta/atomistic-probes') / PRIOR_REQUEST / 'run/he-dz/raw/cp2k.out'
LOG_SIZE = 27762
LOG_SHA = 'ead898b2528ebc029a78a16247b03fe7aec5acfb74e4e24499353828553a50fc'
LOG_BINDING = {'benchmark_run_id': 42339547954, 'request_id': PRIOR_REQUEST, 'case': 'he-dz',
               'bytes': LOG_SIZE, 'sha256': LOG_SHA, 'recorded_wait4_returncode': -4}
FAILURES = shared.FAILURES | {'hwcap_unavailable', 'failure_log_unavailable', 'failure_log_mismatch'}

# Linux arm64 UAPI arch/arm64/include/uapi/asm/hwcap.h, AT_HWCAP and AT_HWCAP2.
HWCAP_BITS = {
    'fp': 0, 'asimd': 1, 'aes': 3, 'pmull': 4, 'crc32': 7, 'atomics': 8, 'fphp': 9,
    'asimdhp': 10, 'asimdrdm': 12, 'jscvt': 13, 'fcma': 14, 'lrcpc': 15, 'sha3': 17,
    'asimddp': 20, 'sha512': 21, 'sve': 22, 'asimdfhm': 23, 'ilrcpc': 26, 'flagm': 27,
    'sb': 29, 'paca': 30, 'pacg': 31,
}
HWCAP2_BITS = {'sve2': 1, 'flagm2': 7, 'frint': 8, 'i8mm': 13, 'bf16': 14, 'bti': 17, 'sme': 23}
STAGE_MARKERS = (
    ('program_ended', b'PROGRAM ENDED AT'), ('energy_reported', b'ENERGY|'),
    ('scf_started', b'SCF WAVEFUNCTION OPTIMIZATION'), ('qs_initialization', b'QS|'),
    ('cp2k_banner', b'CP2K|'),
)
MODULE_MARKERS = (b'libxsmm', b'libopenblas', b'libint2', b'libtorch', b'libfftw3', b'libcp2k',
                  b'qs_scf', b'qs_initial', b'grid_cpu', b'dbcsr', b'mpich')
FALSE_FIELDS = frozenset({'production_restart_attempted', 'production_configuration_written',
                          'database_read', 'private_environment_read', 'image_pull_attempted',
                          'image_execution_attempted'})
CONFIG_FIELDS = ('source_sha', 'request_id', 'control_sha')


def read_features():
    try:
        getauxval = ctypes.CDLL(None, use_errno=True).getauxval
        getauxval.argtypes = (ctypes.c_ulong,)
        getauxval.restype = ctypes.c_ulong
        features = {}
        for entry, bits in ((16, HWCAP_BITS), (26, HWCAP2_BITS)):
            ctypes.set_errno(0)
            value = getauxval(entry)
            if ctypes.get_errno():
                raise OSError()
            features.update({name: bool(value & (1 << bit)) for name, bit in bits.items()})
        return features
    except (AttributeError, OSError) as exc:
        raise shared.DiagnosticError('hwcap_unavailable') from exc


def read_bound_log(root, components, *, size, digest, owner):
    """Traverse via directory descriptors and verify bytes before interpreting them."""
    dirs = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        fd = os.open(root, dirs)
        stack.callback(os.close, fd)
        for index, name in enumerate(components[:-1]):
            fd = os.open(name, dirs, dir_fd=fd)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            expected = (0, 0) if index < 3 else owner
            if (info.st_uid, info.st_gid) != expected or info.st_mode & (0o022 if index < 3 else 0o077):
                raise shared.DiagnosticError('failure_log_unavailable')
        log_fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(log_fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid) != owner
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise shared.DiagnosticError('failure_log_unavailable')
            if info.st_size != size:
                raise shared.DiagnosticError('failure_log_mismatch')
            raw = stream.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise shared.DiagnosticError('failure_log_mismatch')
    return raw


def read_log():
    try:
        return read_bound_log('/', LOG_PATH.parts[1:], size=LOG_SIZE, digest=LOG_SHA, owner=(1001, 1001))
    except OSError as exc:
        raise shared.DiagnosticError('failure_log_unavailable') from exc


def log_observation(raw):
    folded = raw.lower()
    backtrace = folded.partition(b'backtrace for this error:')[2]
    return {**LOG_BINDING,
            'sigill_text_observed': bool(re.search(rb'\bsigill\b|\billegal instruction\b', folded)),
            'last_stage_marker': next((name for name, marker in STAGE_MARKERS if marker in raw), 'none'),
            'backtrace_header_observed': b'backtrace for this error:' in folded,
            'backtrace_modules': [name.decode('ascii') for name in MODULE_MARKERS if name in backtrace]}


def inspect(result, _run):
    result['arm64_elf_hwcaps'] = read_features()
    result['failure_log'] = log_observation(read_log())
    return True


def remote(config_value, *, run=shared.run_readonly):
    def snapshot_only(command):
        if command not in (shared.SERVICE_COMMAND, shared.CONTAINER_COMMAND):
            raise shared.DiagnosticError('command_denied')
        return run(command)

    return shared.remote(config_value, run=snapshot_only, policy=POLICY, inspect=inspect, failures=FAILURES)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= shared.MAX_OUTPUT:
            return None
        value = shared.parse(raw)
        required = {'scope', 'operation', 'status', 'stage', 'physical_validation_status'} | FALSE_FIELDS
        optional = {*CONFIG_FIELDS, 'before', 'after', 'postflight_verified', 'production_container_preserved',
                    'arm64_elf_hwcaps', 'failure_log', 'failure_reason'}
        if (not isinstance(value, dict) or not required <= value.keys() or set(value) - required - optional
                or value['scope'] != 'oci_' + POLICY.scope + '_diagnostic' or value['operation'] != POLICY.operation
                or value['status'] not in {'success', 'failed'} or value['stage'] not in shared.STAGES
                or value['physical_validation_status'] != 'unvalidated'
                or any(value[field] is not False for field in FALSE_FIELDS)):
            return None
        if set(CONFIG_FIELDS) & value.keys():
            shared.config({key: value[key] for key in CONFIG_FIELDS}, source_sha=POLICY.source_sha)
        for name in ('before', 'after'):
            if name in value:
                snap = value[name]
                if (set(snap) != {'services_active', 'container_identity_sha256'} or snap['services_active'] is not True
                        or not re.fullmatch('[0-9a-f]{64}', snap['container_identity_sha256'])):
                    return None
        if any(type(value[name]) is not bool for name in ('postflight_verified', 'production_container_preserved') if name in value):
            return None
        if 'failure_reason' in value and value['failure_reason'] not in FAILURES:
            return None
        if 'arm64_elf_hwcaps' in value:
            caps = value['arm64_elf_hwcaps']
            if set(caps) != HWCAP_BITS.keys() | HWCAP2_BITS.keys() or any(type(bit) is not bool for bit in caps.values()):
                return None
        if 'failure_log' in value:
            log = value['failure_log']
            flags = {'sigill_text_observed', 'backtrace_header_observed'}
            modules = log['backtrace_modules']
            if (set(log) != LOG_BINDING.keys() | flags | {'last_stage_marker', 'backtrace_modules'}
                    or any(type(log[key]) is not type(expected) or log[key] != expected for key, expected in LOG_BINDING.items())
                    or any(type(log[key]) is not bool for key in flags)
                    or log['last_stage_marker'] not in {'none', *(name for name, _ in STAGE_MARKERS)}
                    or not isinstance(modules, list)
                    or modules != [name.decode('ascii') for name in MODULE_MARKERS if name.decode('ascii') in modules]
                    or (modules and not log['backtrace_header_observed'])):
                return None
        if value['status'] == 'success' and (value['stage'] != 'complete' or 'failure_reason' in value
                or not {'arm64_elf_hwcaps', 'failure_log', 'before', 'after', *CONFIG_FIELDS} <= value.keys()
                or value['postflight_verified'] is not True or value['production_container_preserved'] is not True
                or value['before'] != value['after']):
            return None
        return value
    except Exception:
        return None


def remote_source():
    common = Path(shared.__file__).read_text(encoding='utf-8')
    loader = ("import types\nshared = types.ModuleType('quanta_fixed_diagnostic')\n"
              "shared.__file__ = '/srv/quanta/fixed/deploy/oci/diagnostic.py'\n"
              f"exec(compile({common!r}, '<fixed-shared-diagnostic>', 'exec'), shared.__dict__)\n")
    return loader + Path(__file__).read_text(encoding='utf-8')


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--fixed-remote':
        try:
            raw = base64.b64decode(sys.argv[2], validate=True)
            cfg = shared.config(shared.parse(raw), source_sha=POLICY.source_sha)
            if len(sys.argv[2]) > 2048 or raw != shared.encoded(cfg):
                raise ValueError()
        except Exception:
            cfg = {}
        result = remote(cfg)
    elif sys.argv[1:] == ['--authorize']:
        result = shared.authorize(policy=POLICY)
        if result['status'] == 'authorized':
            try:
                with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                    for key in ('operation', 'source_sha', 'request_id'):
                        stream.write(key + '=' + result[key] + '\n')
            except Exception:
                result = {'scope': POLICY.scope + '_request', 'status': 'denied', 'stage': 'output'}
    elif len(sys.argv) == 1:
        result = shared.probe(policy=POLICY, source=remote_source, sanitizer=sanitize_report)
    else:
        result = {'scope': 'ssh_' + POLICY.scope + '_diagnostic', 'operation': POLICY.operation,
                  'status': 'configuration_invalid', 'authentication_attempted': False}
    print(shared.encoded(result).decode('ascii'))
    return 0 if result['status'] in {'success', 'authorized'} else 2


if __name__ == '__main__':
    raise SystemExit(main())
