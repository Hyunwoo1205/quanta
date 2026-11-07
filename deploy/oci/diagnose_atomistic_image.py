#!/usr/bin/env python3
"""Read one already-present immutable CP2K image; never pull or execute it."""
from __future__ import annotations

import base64
from collections import namedtuple
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[2]
REQUEST = Path('.github/oci/atomistic-image-request.json')
REPOSITORY = 'Hyunwoo1205/quanta'
OPERATION = 'inspect-atomistic-image'
SOURCE_SHA = 'b621e836af61d7b63933ab7802722fa1ee79f531'
SOURCE_CI = 42262527946
NATIVE_CI = 42262528023
CONTROL_WORKFLOW = '.github/workflows/oci-atomistic-image-tests.yml'
CONTROL_JOBS = frozenset({'atomistic image diagnostic (x86_64)', 'atomistic image diagnostic (aarch64)'})
NATIVE_WORKFLOW = '.github/workflows/atomistic-a03.yml'
NATIVE_JOBS = frozenset({'atomistic A03 (x86_64)', 'atomistic A03 (aarch64)'})
IMAGE = 'docker.io/cp2k/cp2k@sha256:ab4826caab2833c856df3455781fe57771ec04da7988588e0b0b6f0e687ecade'
EXPECTED_CONFIG = 'sha256:882a6f30ac4d9e705b5b3a474f9085c19d7f820b1531a4526b320e3f1e164c95'
LOCK = Path('/run/quanta-application-upgrade.lock')
DOCKER = ('/usr/bin/docker', '--host', 'unix:///var/run/docker.sock')
IMAGE_FORMAT = ('{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}},'
                '"Architecture":{{json .Architecture}},"Os":{{json .Os}},'
                '"RootFS":{{json .RootFS}},"Config":{"Entrypoint":{{json .Config.Entrypoint}},'
                '"WorkingDir":{{json .Config.WorkingDir}}}}')
SERVER_FORMAT = ('{"Version":{{json .Server.Version}},"ApiVersion":{{json .Server.APIVersion}},'
                 '"MinAPIVersion":{{json .Server.MinAPIVersion}},"Os":{{json .Server.Os}},'
                 '"Arch":{{json .Server.Arch}}}')
INFO_FORMAT = '{"Driver":{{json .Driver}},"DriverStatus":{{json .DriverStatus}}}'
DESCRIPTOR_FORMAT = ('{{if .Descriptor}}{"mediaType":{{json .Descriptor.MediaType}},'
                     '"digest":{{json .Descriptor.Digest}},"size":{{json .Descriptor.Size}}'
                     '{{if .Descriptor.Platform}},"platform":{"os":{{json .Descriptor.Platform.OS}},'
                     '"architecture":{{json .Descriptor.Platform.Architecture}}'
                     '{{if .Descriptor.Platform.Variant}},"variant":{{json .Descriptor.Platform.Variant}}{{end}}}'
                     '{{end}}}{{else}}null{{end}}')
CONTAINER_FORMAT = '{{.Id}} {{.State.Pid}} {{.Image}} {{.State.StartedAt}} {{.State.Running}}'
SERVICE_COMMAND = ('/usr/bin/systemctl', 'is-active', 'quanta-boot.service', 'quanta-https.service')
CONTAINER_COMMAND = DOCKER + ('inspect', '--type', 'container', '--format', CONTAINER_FORMAT, 'quanta')
DEFAULT_COMMAND = DOCKER + ('image', 'inspect', '--format', IMAGE_FORMAT, IMAGE)
PLATFORM_COMMAND = DOCKER + ('image', 'inspect', '--platform', 'linux/arm64', '--format', IMAGE_FORMAT, IMAGE)
DESCRIPTOR_COMMAND = DOCKER + ('image', 'inspect', '--format', DESCRIPTOR_FORMAT, IMAGE)
PLATFORM_DESCRIPTOR_COMMAND = DOCKER + ('image', 'inspect', '--platform', 'linux/arm64', '--format', DESCRIPTOR_FORMAT, IMAGE)
HELP_COMMAND = DOCKER + ('image', 'inspect', '--help')
SERVER_COMMAND = DOCKER + ('version', '--format', SERVER_FORMAT)
INFO_COMMAND = DOCKER + ('info', '--format', INFO_FORMAT)
COMMANDS = frozenset({SERVICE_COMMAND, CONTAINER_COMMAND, DEFAULT_COMMAND, PLATFORM_COMMAND,
                      DESCRIPTOR_COMMAND, PLATFORM_DESCRIPTOR_COMMAND, HELP_COMMAND, SERVER_COMMAND, INFO_COMMAND})
MAX_OUTPUT = 32768
MAX_COMMAND_OUTPUT = 65536
MAX_SOURCE = 65536
COMMAND_STATUSES = frozenset({'observed', 'command_failed', 'timeout', 'output_limit', 'output_invalid',
                              'unsupported', 'support_unknown'})
STAGES = frozenset({'config', 'lock', 'before', 'inspect', 'after', 'complete'})
FAILURES = frozenset({'configuration_invalid', 'native_root_required', 'lock_unavailable', 'lock_metadata',
                      'command_denied', 'production_snapshot', 'diagnostic_incomplete', 'production_changed',
                      'operation_failed'})
SHA = re.compile(r'sha256:[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[0-9A-Za-z_.+-]{1,96}\Z')
DiagnosticPolicy = namedtuple('DiagnosticPolicy', 'operation request env_prefix scope source_sha source_ci native_ci control_workflow control_jobs')
IMAGE_POLICY = DiagnosticPolicy(OPERATION, REQUEST, 'QUANTA_IMAGE', 'atomistic_image', SOURCE_SHA,
                                SOURCE_CI, NATIVE_CI, CONTROL_WORKFLOW, CONTROL_JOBS)


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _uuid(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4


def config(value, *, source_sha=SOURCE_SHA):
    if (not isinstance(value, dict) or set(value) != {'source_sha', 'request_id', 'control_sha'}
            or value['source_sha'] != source_sha or not _uuid(value['request_id'])
            or not isinstance(value['control_sha'], str) or not re.fullmatch('[0-9a-f]{40}', value['control_sha'])):
        raise ValueError('configuration denied')
    return dict(value)


def module(name):
    if name not in {'probe_login', 'probe_inventory', 'authorize_application_upgrade'}:
        raise ValueError('module denied')
    spec = importlib.util.spec_from_file_location('quanta_image_' + name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def pins(env, *, policy=IMAGE_POLICY):
    sha, run = env.get(policy.env_prefix + '_CONTROL_SHA'), env.get(policy.env_prefix + '_CONTROL_CI_RUN')
    if (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha)
            or not isinstance(run, str) or not re.fullmatch('[1-9][0-9]{0,18}', run) or int(run) > 2**63 - 1):
        raise ValueError('control pin denied')
    return sha, int(run)


def read_request(path=None, environ=None, *, policy=IMAGE_POLICY):
    path = policy.request if path is None else path
    env = os.environ if environ is None else environ
    if (env.get('GITHUB_REPOSITORY') != REPOSITORY or env.get('GITHUB_REF') != 'refs/heads/ops/oci'
            or env.get('GITHUB_EVENT_NAME') != 'push' or any(p.is_symlink() for p in path.parents)):
        raise ValueError('request denied')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024:
        raise ValueError('request denied')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('request denied')
        raw = stream.read(1025)
    value = parse(raw)
    if (len(raw) > 1024 or not isinstance(value, dict)
            or set(value) != {'schema_version', 'operation', 'source_sha', 'request_id'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] != policy.operation or value['source_sha'] != policy.source_sha or not _uuid(value['request_id'])):
        raise ValueError('request denied')
    return value


def authorize(environ=None, *, path=None, opener=None, runner=None, policy=IMAGE_POLICY):
    env = os.environ if environ is None else environ
    stage = 'request'
    try:
        request = read_request(path, env, policy=policy)
        control_sha, control_run = pins(env, policy=policy)
        base = module('authorize_application_upgrade')
        stage = 'control_checkout'
        mapped = dict(env, QUANTA_APPLICATION_CONTROL_SHA=control_sha,
                      QUANTA_APPLICATION_CONTROL_CI_RUN=str(control_run))
        if not base.control_checkout_matches(mapped, runner=runner, root=ROOT):
            raise ValueError()
        for label, run_id, sha, workflow, names in (
                ('control_ci', control_run, control_sha, policy.control_workflow, policy.control_jobs),
                ('source_ci', policy.source_ci, policy.source_sha, base.APP_WORKFLOW, base.APP_JOB_NAMES),
                ('native_ci', policy.native_ci, policy.source_sha, NATIVE_WORKFLOW, NATIVE_JOBS)):
            stage = label
            run = base.api_get('/actions/runs/' + str(run_id), env, opener=opener)
            jobs = base.api_get('/actions/runs/' + str(run_id) + '/jobs?filter=latest&per_page=100', env, opener=opener)
            if not base.successful(run, sha, workflow, run_id=run_id) or not base.successful_jobs(jobs, run_id, names):
                raise ValueError()
        return {'scope': policy.scope + '_request', 'status': 'authorized', **request,
                'control_sha': control_sha, 'control_ci_run': control_run,
                'source_ci_run': policy.source_ci, 'native_ci_run': policy.native_ci}
    except Exception:
        return {'scope': policy.scope + '_request', 'status': 'denied', 'stage': stage}


class DiagnosticError(Exception):
    pass


def run_readonly(command, *, timeout=5, limit=MAX_COMMAND_OUTPUT):
    if not isinstance(command, tuple) or command not in COMMANDS:
        raise DiagnosticError('command_denied')
    process = None
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': '/nonexistent',
                                        'DOCKER_CONFIG': '/nonexistent', 'DOCKER_HOST': 'unix:///var/run/docker.sock'})
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return 'timeout', b''
                part = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(data)))
                if not part:
                    code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                    return ('observed', bytes(data)) if code == 0 else ('command_failed', b'')
                data.extend(part)
                if len(data) > limit:
                    return 'output_limit', b''
    except subprocess.TimeoutExpired:
        return 'timeout', b''
    except Exception:
        return 'command_failed', b''
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except Exception:
                pass
            process.stdout.close()


def image_value(value):
    if not isinstance(value, dict) or set(value) != {'Id', 'RepoDigests', 'Architecture', 'Os', 'RootFS', 'Config'}:
        raise ValueError()
    if (not isinstance(value['Id'], str) or not SHA.fullmatch(value['Id'])
            or value['Architecture'] != 'arm64' or value['Os'] != 'linux'):
        raise ValueError()
    digests = value['RepoDigests']
    if (not isinstance(digests, list) or not 1 <= len(digests) <= 32
            or any(not isinstance(d, str) or not re.fullmatch(r'(?:docker\.io/)?cp2k/cp2k@sha256:[0-9a-f]{64}', d) for d in digests)):
        raise ValueError()
    rootfs, cfg = value['RootFS'], value['Config']
    if (not isinstance(rootfs, dict) or set(rootfs) != {'Type', 'Layers'} or rootfs['Type'] != 'layers'
            or not isinstance(rootfs['Layers'], list) or len(rootfs['Layers']) > 256
            or any(not isinstance(d, str) or not SHA.fullmatch(d) for d in rootfs['Layers'])
            or not isinstance(cfg, dict) or set(cfg) != {'Entrypoint', 'WorkingDir'}
            or not isinstance(cfg['Entrypoint'], list) or not 1 <= len(cfg['Entrypoint']) <= 8
            or any(not isinstance(v, str) or not re.fullmatch(r'/[0-9A-Za-z_./+-]{1,255}', v) for v in cfg['Entrypoint'])
            or not isinstance(cfg['WorkingDir'], str) or not re.fullmatch(r'/[0-9A-Za-z_./+-]{0,255}', cfg['WorkingDir'])):
        raise ValueError()
    return value


def descriptor_value(value):
    if value is None:
        return None
    if (not isinstance(value, dict) or not {'mediaType', 'digest', 'size'} <= value.keys()
            or not isinstance(value['mediaType'], str) or not re.fullmatch(r'[0-9A-Za-z.+/-]{1,128}', value['mediaType'])
            or not isinstance(value['digest'], str) or not SHA.fullmatch(value['digest'])
            or type(value['size']) is not int or not 0 <= value['size'] <= 2**63 - 1):
        raise ValueError()
    selected = {key: value[key] for key in ('mediaType', 'digest', 'size')}
    if 'platform' in value and value['platform'] is not None:
        p = value['platform']
        if not isinstance(p, dict) or not {'os', 'architecture'} <= p.keys():
            raise ValueError()
        platform_fields = {key: p[key] for key in ('os', 'architecture', 'variant') if key in p}
        if any(not isinstance(v, str) or not TOKEN.fullmatch(v) for v in platform_fields.values()):
            raise ValueError()
        selected['platform'] = platform_fields
    return selected


def server_value(value):
    keys = {'Version', 'ApiVersion', 'MinAPIVersion', 'Os', 'Arch'}
    if (not isinstance(value, dict) or set(value) != keys
            or any(not isinstance(v, str) or not TOKEN.fullmatch(v) for v in value.values())):
        raise ValueError()
    return value


def storage_value(value):
    if not isinstance(value, dict) or set(value) != {'Driver', 'DriverStatus'}:
        raise ValueError()
    if not isinstance(value['Driver'], str) or not TOKEN.fullmatch(value['Driver']):
        raise ValueError()
    pairs = value['DriverStatus']
    if pairs is not None and (not isinstance(pairs, list) or len(pairs) > 32
            or any(not isinstance(p, list) or len(p) != 2 or any(not isinstance(s, str) or len(s) > 256 for s in p) for p in pairs)):
        raise ValueError()
    # Never publish paths, proxy settings or other unrestricted engine info.
    allowed = {'driver-type', 'Backing Filesystem', 'Supports d_type', 'Using metacopy', 'Native Overlay Diff', 'userxattr'}
    selected = []
    for key, item in pairs or []:
        if key in allowed:
            if not re.fullmatch(r'[0-9A-Za-z_.+ -]{1,96}', item):
                raise ValueError()
            selected.append([key, item])
    return {'Driver': value['Driver'], 'DriverStatus': selected}


def observe(command, validator, run):
    status, raw = run(command)
    if status != 'observed':
        return {'status': status if status in COMMAND_STATUSES else 'command_failed'}
    try:
        value = validator(parse(raw))
        return {'status': 'observed', 'value': value}
    except Exception:
        return {'status': 'output_invalid'}


def snapshot(run):
    status, raw = run(SERVICE_COMMAND)
    if status != 'observed' or raw != b'active\nactive\n':
        raise DiagnosticError('production_snapshot')
    status, raw = run(CONTAINER_COMMAND)
    if (status != 'observed' or len(raw) > 1024
            or not re.fullmatch(rb'[0-9a-f]{64} [1-9][0-9]* sha256:[0-9a-f]{64} [0-9TZ:.+-]+ true\n?', raw)):
        raise DiagnosticError('production_snapshot')
    return {'services_active': True, 'container_identity_sha256': hashlib.sha256(raw).hexdigest()}


def inspect_image(result, run):
    result['selected_image'] = IMAGE
    result['expected_config_digest'] = EXPECTED_CONFIG
    result['default_inspect'] = observe(DEFAULT_COMMAND, image_value, run)
    result['default_descriptor'] = observe(DESCRIPTOR_COMMAND, descriptor_value, run)
    help_status, help_raw = run(HELP_COMMAND)
    supported = help_status == 'observed' and b'--platform' in help_raw
    result['platform_inspect'] = observe(PLATFORM_COMMAND, image_value, run) if supported else {
        'status': 'unsupported' if help_status == 'observed' else 'support_unknown'}
    result['platform_descriptor'] = observe(PLATFORM_DESCRIPTOR_COMMAND, descriptor_value, run) if supported else {
        'status': 'unsupported' if help_status == 'observed' else 'support_unknown'}
    result['docker_server'] = observe(SERVER_COMMAND, server_value, run)
    result['docker_storage'] = observe(INFO_COMMAND, storage_value, run)
    if result['default_inspect']['status'] == 'observed':
        image = result['default_inspect']['value']
        result['observed_id_equals_expected_config'] = image['Id'] == EXPECTED_CONFIG
        result['selected_repo_digest_present'] = any(d.removeprefix('docker.io/') == IMAGE.removeprefix('docker.io/') for d in image['RepoDigests'])
    return all(result[key]['status'] == 'observed' for key in ('default_inspect', 'docker_server', 'docker_storage'))


def remote(config_value, *, run=run_readonly, policy=IMAGE_POLICY, inspect=inspect_image, failures=FAILURES):
    stage = 'config'
    result = {'scope': 'oci_' + policy.scope + '_diagnostic', 'operation': policy.operation, 'status': 'failed',
              'stage': stage, 'production_restart_attempted': False, 'production_configuration_written': False,
              'database_read': False, 'private_environment_read': False, 'image_pull_attempted': False,
              'image_execution_attempted': False, 'physical_validation_status': 'unvalidated'}
    fd = None
    before = None
    try:
        cfg = config(config_value, source_sha=policy.source_sha)
        result.update(cfg)
        if os.geteuid() != 0 or platform.machine() != 'aarch64':
            raise DiagnosticError('native_root_required')
        stage = 'lock'
        for parent in LOCK.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise DiagnosticError('lock_metadata')
        fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise DiagnosticError('lock_metadata')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage = 'before'
        before = snapshot(run)
        result['before'] = before
        stage = 'inspect'
        complete = inspect(result, run)
        stage = 'after'
        after = snapshot(run)
        result['after'] = after
        result['production_container_preserved'] = after == before
        if after != before:
            raise DiagnosticError('production_changed')
        if not complete:
            raise DiagnosticError('diagnostic_incomplete')
        stage = 'complete'
        result['status'] = 'success'
    except Exception as error:
        reason = str(error) if isinstance(error, DiagnosticError) else ('lock_unavailable' if stage == 'lock' else 'operation_failed')
        result['failure_reason'] = reason if reason in failures else 'operation_failed'
    finally:
        if before is not None:
            try:
                after = snapshot(run)
                result['after'] = after
                result['production_container_preserved'] = after == before
                result['postflight_verified'] = True
                if after != before:
                    result['status'] = 'failed'
                    result['failure_reason'] = 'production_changed'
            except Exception:
                result['postflight_verified'] = False
                result['status'] = 'failed'
                result['failure_reason'] = 'production_snapshot'
        if fd is not None:
            os.close(fd)
        result['stage'] = stage
    return result


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT:
            return None
        value = parse(raw)
        required = {'scope', 'operation', 'status', 'stage', 'production_restart_attempted',
                    'production_configuration_written', 'database_read', 'private_environment_read',
                    'image_pull_attempted', 'image_execution_attempted', 'physical_validation_status'}
        optional = {'source_sha', 'request_id', 'control_sha', 'before', 'after', 'selected_image',
                    'expected_config_digest', 'default_inspect', 'default_descriptor', 'platform_inspect',
                    'platform_descriptor', 'docker_server', 'docker_storage', 'observed_id_equals_expected_config',
                    'selected_repo_digest_present', 'production_container_preserved', 'postflight_verified', 'failure_reason'}
        if (not isinstance(value, dict) or not required <= value.keys() or set(value) - required - optional
                or value['scope'] != 'oci_atomistic_image_diagnostic' or value['operation'] != OPERATION
                or value['status'] not in {'success', 'failed'} or value['stage'] not in STAGES
                or value['physical_validation_status'] != 'unvalidated'
                or any(value[key] is not False for key in ('production_restart_attempted', 'production_configuration_written',
                                                           'database_read', 'private_environment_read', 'image_pull_attempted', 'image_execution_attempted'))):
            return None
        if {'source_sha', 'request_id', 'control_sha'} & value.keys():
            config({key: value[key] for key in ('source_sha', 'request_id', 'control_sha')})
        if 'selected_image' in value and value['selected_image'] != IMAGE:
            return None
        if 'expected_config_digest' in value and value['expected_config_digest'] != EXPECTED_CONFIG:
            return None
        for key in ('before', 'after'):
            if key in value:
                snap = value[key]
                if (not isinstance(snap, dict) or set(snap) != {'services_active', 'container_identity_sha256'}
                        or snap['services_active'] is not True or not isinstance(snap['container_identity_sha256'], str)
                        or not re.fullmatch('[0-9a-f]{64}', snap['container_identity_sha256'])):
                    return None
        validators = {'default_inspect': image_value, 'platform_inspect': image_value,
                      'default_descriptor': descriptor_value, 'platform_descriptor': descriptor_value,
                      'docker_server': server_value, 'docker_storage': storage_value}
        for key, validator in validators.items():
            if key in value:
                observation = value[key]
                if not isinstance(observation, dict) or observation.get('status') not in COMMAND_STATUSES:
                    return None
                if observation['status'] == 'observed':
                    if set(observation) != {'status', 'value'} or validator(observation['value']) != observation['value']:
                        return None
                elif set(observation) != {'status'}:
                    return None
        for key in ('observed_id_equals_expected_config', 'selected_repo_digest_present', 'production_container_preserved', 'postflight_verified'):
            if key in value and type(value[key]) is not bool:
                return None
        if 'failure_reason' in value and value['failure_reason'] not in FAILURES:
            return None
        if value['status'] == 'success' and (value['stage'] != 'complete' or value.get('postflight_verified') is not True
                or value.get('production_container_preserved') is not True or not all(key in value and value[key]['status'] == 'observed'
                    for key in ('default_inspect', 'docker_server', 'docker_storage'))):
            return None
        return value
    except Exception:
        return None


def remote_command(source, value, *, policy=IMAGE_POLICY):
    value = config(value, source_sha=policy.source_sha)
    raw = source.encode('utf-8')
    if not 1 <= len(raw) <= MAX_SOURCE or b'\0' in raw:
        raise ValueError('source denied')
    compile(source, '<fixed-image-diagnostic>', 'exec')
    packed = zlib.compress(raw, 9)
    if len(packed) > 32768:
        raise ValueError('source denied')
    bootstrap = ("import base64,hashlib,sys,zlib\n"
                 "if len(sys.argv)!=3 or len(sys.argv[1])>43692 or len(sys.argv[2])>2048:raise ValueError()\n"
                 "p=base64.b64decode(sys.argv[1],validate=True)\n"
                 "d=zlib.decompressobj();r=d.decompress(p,65537)\n"
                 "if len(p)>32768 or len(r)>65536 or d.unconsumed_tail or not d.eof or d.unused_data:raise ValueError()\n"
                 "if hashlib.sha256(r).hexdigest()!='" + hashlib.sha256(raw).hexdigest() + "':raise ValueError()\n"
                 "sys.argv=['<fixed-image-diagnostic>','--fixed-remote',sys.argv[2]]\n"
                 "exec(compile(r.decode('utf-8'),'<fixed-image-diagnostic>','exec'),{'__name__':'__main__','__file__':'<fixed-image-diagnostic>'})\n")
    command = '/usr/bin/sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(bootstrap)
    command += ' ' + shlex.quote(base64.b64encode(packed).decode('ascii'))
    command += ' ' + shlex.quote(base64.b64encode(encoded(value)).decode('ascii'))
    if len(command.encode('utf-8')) > 120000:
        raise ValueError('command denied')
    return command


def probe(environ=None, *, authorizer=None, runner=None, policy=IMAGE_POLICY, source=None, sanitizer=sanitize_report):
    env = os.environ if environ is None else environ
    result = {'scope': 'ssh_' + policy.scope + '_diagnostic', 'operation': policy.operation,
              'status': 'not_configured', 'authentication_attempted': False}
    if env.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true' or env.get(policy.env_prefix + '_OPERATION') != policy.operation:
        return result
    try:
        authorized = authorize(env, policy=policy) if authorizer is None else authorizer(env)
        if (authorized.get('status') != 'authorized' or authorized.get('operation') != policy.operation
                or authorized.get('source_sha') != env.get(policy.env_prefix + '_SOURCE_SHA')
                or authorized.get('request_id') != env.get(policy.env_prefix + '_REQUEST_ID')):
            raise ValueError()
        cfg = config({key: authorized[key] for key in ('source_sha', 'request_id', 'control_sha')}, source_sha=policy.source_sha)
        source_text = Path(__file__).read_text(encoding='utf-8') if source is None else source()
        command = remote_command(source_text, cfg, policy=policy)
        login, transport = module('probe_login'), module('probe_inventory')
        host, pin = env.get('QUANTA_OCI_HOST'), login._normalized_host_key(env.get('QUANTA_OCI_HOST_KEY'))
        error, key = login._key_bytes(env.get('QUANTA_OCI_PPK'))
        if not login._global_ipv4(host) or pin is None or error is not None:
            raise ValueError()
    except Exception:
        result['status'] = 'configuration_invalid'
        return result
    capture = (lambda cmd, child_env, directory: transport._capture(cmd, child_env, directory, timeout=90, limit=MAX_OUTPUT)) if runner is None else runner
    try:
        with tempfile.TemporaryDirectory(prefix='quanta-image-inspect-') as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / 'identity.ppk'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(key)
            args = [login.PLINK, '-ssh', '-2', '-4', '-batch', '-noagent', '-no-trivial-auth',
                    '-a', '-x', '-T', '-noshare', '-P', '22', '-l', 'ubuntu', '-i', str(path), '-hostkey', pin, host, command]
            state, raw, attempted = capture(args, {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, directory)
            result['authentication_attempted'] = attempted
            value = sanitizer(raw) if state in {'success', 'failed'} else None
            if value is not None and all(value.get(k) == cfg[k] for k in cfg):
                result['result'] = value
                result['status'] = 'success' if state == 'success' and value['status'] == 'success' else 'remote_failed'
            else:
                result['status'] = state if state in {'timeout', 'output_limit'} else 'remote_failed'
    except Exception:
        result['status'] = 'failed'
    return result


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--fixed-remote':
        try:
            raw = base64.b64decode(sys.argv[2], validate=True)
            cfg = config(parse(raw))
            if len(sys.argv[2]) > 2048 or raw != encoded(cfg):
                raise ValueError()
            result = remote(cfg)
        except Exception:
            result = remote({})
    elif sys.argv[1:] == ['--authorize']:
        result = authorize()
        if result['status'] == 'authorized':
            try:
                with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                    for key in ('operation', 'source_sha', 'request_id'):
                        stream.write(key + '=' + str(result[key]) + '\n')
            except Exception:
                result = {'scope': 'atomistic_image_request', 'status': 'denied', 'stage': 'output'}
    else:
        result = probe() if len(sys.argv) == 1 else {'scope': 'ssh_atomistic_image_diagnostic',
            'operation': OPERATION, 'status': 'configuration_invalid', 'authentication_attempted': False}
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result.get('status') in {'success', 'authorized'} else 2


if __name__ == '__main__':
    raise SystemExit(main())
