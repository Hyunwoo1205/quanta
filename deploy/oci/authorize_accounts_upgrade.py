#!/usr/bin/env python3
"""Authorize a fixed account upgrade against separately pinned control and app CI."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.request
import uuid

REPOSITORY = 'Hyunwoo1205/quanta'
API_ROOT = 'https://api.github.com/repos/' + REPOSITORY
REQUEST = Path('.github/oci/accounts-request.json')
ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = frozenset({'upgrade-accounts', 'verify-accounts'})
CONTROL_WORKFLOW = '.github/workflows/oci-accounts-tests.yml'
APP_WORKFLOW = '.github/workflows/ci.yml'
MAX_RESPONSE = 1024 * 1024


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def read_request(path=REQUEST, environ=None):
    env = os.environ if environ is None else environ
    if (env.get('GITHUB_REPOSITORY') != REPOSITORY or env.get('GITHUB_REF') != 'refs/heads/ops/oci'
            or env.get('GITHUB_EVENT_NAME') != 'push'):
        raise ValueError('request denied')
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('request denied')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024:
        raise ValueError('request denied')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('request denied')
        raw = stream.read(1025)
    value = parse(raw)
    if (len(raw) > 1024 or not isinstance(value, dict)
            or set(value) != {'schema_version', 'operation', 'source_sha', 'request_id'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['operation'], str) or value['operation'] not in OPERATIONS
            or not isinstance(value['source_sha'], str) or not re.fullmatch(r'[0-9a-f]{40}', value['source_sha'])
            or not isinstance(value['request_id'], str)):
        raise ValueError('request denied')
    identifier = uuid.UUID(value['request_id'])
    if str(identifier) != value['request_id'] or identifier.version != 4:
        raise ValueError('request denied')
    return value


def control_pin(environ=None):
    env = os.environ if environ is None else environ
    sha, run = env.get('QUANTA_ACCOUNTS_CONTROL_SHA'), env.get('QUANTA_ACCOUNTS_CONTROL_CI_RUN')
    if (not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha)
            or not isinstance(run, str) or not re.fullmatch(r'[1-9][0-9]{0,18}', run)
            or int(run) > 2**63 - 1):
        raise ValueError('control pin denied')
    return sha, int(run)


def control_checkout_matches(environ=None, *, runner=None, root=ROOT):
    try:
        sha, _ = control_pin(environ)
        run = subprocess.run if runner is None else runner
        environment = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        common = dict(stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
            timeout=5, check=False, env=environment)
        head = run(['/usr/bin/git', '-C', str(root), 'rev-parse', '--verify', 'HEAD'], stdout=subprocess.PIPE, **common)
        if head.returncode != 0 or head.stdout != (sha + '\n').encode('ascii'):
            return False
        clean = run(['/usr/bin/git', '-C', str(root), 'diff', '--quiet', '--no-ext-diff',
            '--no-textconv', 'HEAD', '--'], stdout=subprocess.DEVNULL, **common)
        return clean.returncode == 0
    except Exception:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api_get(suffix, environ, *, opener=None):
    token = environ.get('QUANTA_CI_READ_TOKEN', '')
    if (not isinstance(token, str) or not 1 <= len(token) <= 4096
            or any(ord(character) < 33 or ord(character) > 126 for character in token)):
        raise ValueError('CI access denied')
    url = API_ROOT + suffix
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'quanta-fixed-accounts-upgrade-gate'})
    open_url = urllib.request.build_opener(NoRedirect()).open if opener is None else opener
    with open_url(request, timeout=10) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError('CI access denied')
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError('CI response too large')
    return parse(raw)


def successful(value, sha, path, *, run_id=None):
    return (isinstance(value, dict) and type(value.get('id')) is int
        and (run_id is None or value['id'] == run_id) and value.get('head_sha') == sha
        and value.get('head_branch') == 'main' and value.get('event') == 'push'
        and value.get('path') == path and value.get('status') == 'completed'
        and value.get('conclusion') == 'success')


def authorize(environ=None, *, path=REQUEST, opener=None, runner=None):
    env = os.environ if environ is None else environ
    stage = 'request'
    try:
        request = read_request(path, env)
        stage = 'control_checkout'
        control_sha, control_run = control_pin(env)
        if not control_checkout_matches(env, runner=runner):
            raise ValueError()
        stage = 'control_ci'
        control = api_get('/actions/runs/' + str(control_run), env, opener=opener)
        if not successful(control, control_sha, CONTROL_WORKFLOW, run_id=control_run):
            raise ValueError()
        stage = 'app_ci'
        listing = api_get('/actions/runs?head_sha=' + request['source_sha'] + '&event=push&branch=main&per_page=100', env, opener=opener)
        if not isinstance(listing, dict) or not isinstance(listing.get('workflow_runs'), list):
            raise ValueError()
        passed = [run for run in listing['workflow_runs'] if successful(run, request['source_sha'], APP_WORKFLOW)]
        if not passed:
            raise ValueError()
        app_run = max(passed, key=lambda item: item['id'])['id']
        return {'scope': 'accounts_upgrade_request', 'status': 'authorized', **request,
            'app_ci_run': app_run}
    except Exception:
        return {'scope': 'accounts_upgrade_request', 'status': 'denied', 'stage': stage}


def main():
    result = authorize() if len(sys.argv) == 1 else {
        'scope': 'accounts_upgrade_request', 'status': 'denied', 'stage': 'request'}
    if result['status'] == 'authorized':
        try:
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                for field in ('operation', 'source_sha', 'request_id', 'app_ci_run'):
                    stream.write(field + '=' + str(result[field]) + '\n')
        except Exception:
            result = {'scope': 'accounts_upgrade_request', 'status': 'denied', 'stage': 'output'}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'authorized' else 2


if __name__ == '__main__':
    raise SystemExit(main())
