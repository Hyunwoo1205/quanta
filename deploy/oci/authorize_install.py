#!/usr/bin/env python3
"""Authorize one protected install request against a completed fixed native CI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import uuid
import urllib.request

SOURCE_SHA = '1738107301ef873bfe5e01f930866c2a74e4ec3f'
CI_RUN = 42064056609
CI_URL = 'https://api.github.com/repos/Hyunwoo1205/quanta/actions/runs/' + str(CI_RUN)
OPERATIONS = frozenset({'install-app', 'install-https', 'configure-web-firewall', 'verify-backup', 'diagnose-https'})
REQUEST = Path('.github/oci/install-request.json')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def read_request(path=REQUEST, environ=None):
    environ = os.environ if environ is None else environ
    if (environ.get('GITHUB_REPOSITORY') != 'Hyunwoo1205/quanta'
            or environ.get('GITHUB_REF') != 'refs/heads/ops/oci'
            or environ.get('GITHUB_EVENT_NAME') != 'push'):
        raise ValueError('request denied')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError('request denied')
    with path.open('rb') as stream:
        raw = stream.read(1025)
    value = json.loads(raw, object_pairs_hook=unique)
    if (len(raw) > 1024 or not isinstance(value, dict)
            or set(value) != {'schema_version', 'operation', 'source_sha', 'request_id'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['operation'], str) or value['operation'] not in OPERATIONS
            or value['source_sha'] != SOURCE_SHA
            or not isinstance(value['request_id'], str) or len(value['request_id']) != 36
            or str(uuid.UUID(value['request_id'])) != value['request_id']):
        raise ValueError('request denied')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def ci_passed(environ=None, *, opener=None):
    environ = os.environ if environ is None else environ
    token = environ.get('QUANTA_CI_READ_TOKEN', '')
    if not isinstance(token, str) or not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        return False
    request = urllib.request.Request(CI_URL, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'quanta-fixed-install-gate',
    })
    opener = urllib.request.build_opener(NoRedirect()).open if opener is None else opener
    try:
        with opener(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != CI_URL:
                return False
            raw = response.read(262145)
        if len(raw) > 262144:
            return False
        value = json.loads(raw, object_pairs_hook=unique)
        return (isinstance(value, dict) and type(value.get('id')) is int and value['id'] == CI_RUN
                and value.get('head_sha') == SOURCE_SHA and value.get('head_branch') == 'main'
                and value.get('event') == 'push' and value.get('path') == '.github/workflows/ci.yml'
                and value.get('status') == 'completed' and value.get('conclusion') == 'success')
    except Exception:
        return False


def main():
    stage = 'request'
    try:
        request = read_request()
        stage = 'native_ci'
        if not ci_passed():
            raise ValueError('native CI not ready')
        output = os.environ.get('GITHUB_OUTPUT')
        if output:
            with open(output, 'a', encoding='utf-8') as stream:
                stream.write('operation=' + request['operation'] + '\n')
        print(json.dumps({'scope': 'install_request', 'status': 'authorized',
                          'operation': request['operation'], 'request_id': request['request_id']}, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'scope': 'install_request', 'status': 'denied', 'stage': stage}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
