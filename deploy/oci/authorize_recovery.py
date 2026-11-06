#!/usr/bin/env python3
"""Authorize a fixed recovery operation against separate app and control CI pins.

Run from the request checkout, using this file from a separately pinned control
checkout. No SSH credential is read, requested, or emitted by this gate.
"""
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

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
APP_CI_RUN = 42064056609
REPOSITORY = "Hyunwoo1205/quanta"
API_ROOT = "https://api.github.com/repos/" + REPOSITORY + "/actions/runs/"
OPERATIONS = frozenset({"audit-recovery", "prepare-recovery", "export-recovery",
                        "reboot-recovery", "verify-reboot", "post-reboot-compute",
                        "compare-recovery", "refresh-recovery"})
REQUEST = Path(".github/oci/install-request.json")
CONTROL_ROOT = Path(__file__).resolve().parents[2]
CONTROL_WORKFLOW = ".github/workflows/oci-recovery-tests.yml"
MAX_RESPONSE = 262144


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))


def read_request(path=REQUEST, environ=None):
    environ = os.environ if environ is None else environ
    if (environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or environ.get("GITHUB_REF") != "refs/heads/ops/oci"
            or environ.get("GITHUB_EVENT_NAME") != "push"):
        raise ValueError("request denied")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("request denied")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024:
        raise ValueError("request denied")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("request denied")
        raw = stream.read(1025)
    value = parse(raw)
    if (len(raw) > 1024 or not isinstance(value, dict)
            or set(value) != {"schema_version", "operation", "source_sha", "request_id"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["operation"], str) or value["operation"] not in OPERATIONS
            or value["source_sha"] != SOURCE_SHA
            or not isinstance(value["request_id"], str) or len(value["request_id"]) != 36):
        raise ValueError("request denied")
    identifier = uuid.UUID(value["request_id"])
    if str(identifier) != value["request_id"] or identifier.version != 4:
        raise ValueError("request denied")
    return value


def control_pin(environ=None):
    environ = os.environ if environ is None else environ
    sha, run = environ.get("QUANTA_CONTROL_SHA"), environ.get("QUANTA_CONTROL_CI_RUN")
    if (not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None
            or not isinstance(run, str) or re.fullmatch(r"[1-9][0-9]{0,18}", run) is None
            or int(run) > 2**63 - 1):
        raise ValueError("control pin denied")
    return sha, int(run)


def control_checkout_matches(environ=None, *, runner=None, root=CONTROL_ROOT):
    try:
        sha, _ = control_pin(environ)
        runner = subprocess.run if runner is None else runner
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C",
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        result = runner(["/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, shell=False, timeout=5, check=False,
                        env=environment)
        if result.returncode != 0 or result.stdout != (sha + "\n").encode("ascii"):
            return False
        clean = runner(["/usr/bin/git", "-C", str(root), "diff", "--quiet", "--no-ext-diff",
                        "--no-textconv", "HEAD", "--"], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
                       timeout=5, check=False, env=environment)
        return clean.returncode == 0
    except Exception:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def ci_passed(run, sha, path, environ=None, *, opener=None):
    environ = os.environ if environ is None else environ
    token = environ.get("QUANTA_CI_READ_TOKEN", "")
    if (not isinstance(token, str) or not 1 <= len(token) <= 4096
            or any(ord(character) < 33 or ord(character) > 126 for character in token)):
        return False
    url = API_ROOT + str(run)
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "quanta-fixed-recovery-gate",
    })
    opener = urllib.request.build_opener(NoRedirect()).open if opener is None else opener
    try:
        with opener(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != url:
                return False
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            return False
        value = parse(raw)
        return (isinstance(value, dict) and type(value.get("id")) is int and value["id"] == run
                and value.get("head_sha") == sha and value.get("head_branch") == "main"
                and value.get("event") == "push" and value.get("path") == path
                and value.get("status") == "completed" and value.get("conclusion") == "success")
    except Exception:
        return False


def authorize(environ=None, *, path=REQUEST, opener=None, runner=None):
    environ = os.environ if environ is None else environ
    stage = "request"
    try:
        request = read_request(path, environ)
        stage = "control_checkout"
        control_sha, control_run = control_pin(environ)
        if not control_checkout_matches(environ, runner=runner):
            raise ValueError()
        stage = "app_ci"
        if not ci_passed(APP_CI_RUN, SOURCE_SHA, ".github/workflows/ci.yml", environ, opener=opener):
            raise ValueError()
        stage = "control_ci"
        if not ci_passed(control_run, control_sha, CONTROL_WORKFLOW, environ, opener=opener):
            raise ValueError()
        return {"scope": "recovery_request", "status": "authorized",
                "operation": request["operation"], "request_id": request["request_id"]}
    except Exception:
        return {"scope": "recovery_request", "status": "denied", "stage": stage}


def main():
    result = authorize() if len(sys.argv) == 1 else {
        "scope": "recovery_request", "status": "denied", "stage": "request"}
    if result["status"] == "authorized":
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            try:
                with open(output, "a", encoding="utf-8") as stream:
                    stream.write("operation=" + result["operation"] + "\n")
                    stream.write("request_id=" + result["request_id"] + "\n")
            except Exception:
                result = {"scope": "recovery_request", "status": "denied", "stage": "output"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "authorized" else 2


if __name__ == "__main__":
    raise SystemExit(main())
