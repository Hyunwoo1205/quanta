#!/usr/bin/env python3
"""Fixed recovery operations over the unchanged pinned PPK transport.

Scheduling a reboot is a request acknowledgement, never proof of a new boot.
Disconnects are failures; this process never retries a reboot request.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile


def _module(name):
    spec = importlib.util.spec_from_file_location("quanta_recovery_" + name,
                                               Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
OPERATIONS = {"audit-recovery": "audit_recovery", "prepare-recovery": "recovery_backup",
              "export-recovery": "export_recovery", "reboot-recovery": "reboot_recovery",
              "verify-reboot": "reboot_recovery", "post-reboot-compute": "recovery_smoke",
              "compare-recovery": "reboot_recovery", "refresh-recovery": "recovery_backup",
              "diagnose-peer-recovery": "reboot_recovery"}
BOOT_OPERATIONS = frozenset({"reboot-recovery", "verify-reboot", "compare-recovery", "diagnose-peer-recovery"})
ACTION_OPERATIONS = BOOT_OPERATIONS | {"refresh-recovery"}
TIMEOUTS = {"audit-recovery": 120, "prepare-recovery": 600, "export-recovery": 600,
            "reboot-recovery": 300, "verify-reboot": 300, "post-reboot-compute": 180,
            "compare-recovery": 300, "refresh-recovery": 600, "diagnose-peer-recovery": 300}
FAILURES = frozenset({"control_checkout_invalid", "audit_module_invalid", "configuration_invalid"})
MAX_EXPORT = 128 * 1024**2
EXPORT_PATH = Path(".cache/recovery-backup.cms")


def report(status, attempted=False, *, operation=None, result=None, failure_reason=None,
           ciphertext=None):
    value = {"scope": "ssh_fixed_recovery", "status": status,
             "authentication_attempted": attempted}
    if isinstance(operation, str) and operation in OPERATIONS:
        value["requested_operation"] = operation
    if result is not None:
        value["result"] = result
    if failure_reason in FAILURES:
        value["failure_reason"] = failure_reason
    if ciphertext is not None:
        value["ciphertext"] = ciphertext
    return value


def _payload(operation):
    """Only these fixed, reviewed module names can become the remote program."""
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ValueError("unsupported recovery operation")
    name = OPERATIONS[operation]
    source = Path(__file__).with_name(name + ".py").read_text(encoding="utf-8")
    helpers = ()
    if operation in {"prepare-recovery", "export-recovery", "post-reboot-compute", "refresh-recovery"}:
        helpers = (("verify_backup", "quanta_fixed_backup"),)
    elif operation in BOOT_OPERATIONS:
        helpers = (("verify_backup", "quanta_fixed_backup"), ("audit_recovery", "quanta_fixed_audit"))
    if helpers:
        pieces = ["import sys, types\n"]
        for filename, module_name in helpers:
            helper = Path(__file__).with_name(filename + ".py").read_text(encoding="utf-8")
            sys.modules[module_name] = _module(filename)
            pieces += ["_fixed = types.ModuleType(" + repr(module_name) + ")\n",
                       "exec(compile(" + repr(helper) + ", '<quanta-fixed-helper>', 'exec'), _fixed.__dict__)\n",
                       "sys.modules[" + repr(module_name) + "] = _fixed\n"]
        pieces.append("exec(compile(" + repr(source) + ", '<quanta-fixed-recovery>', 'exec'))\n")
        remote = "".join(pieces)
    else:
        remote = source
    return _module(name), remote


def _cms_der(raw):
    """Bounded DER CMS AuthEnvelopedData container, without exposing bytes."""
    if not isinstance(raw, bytes) or not 64 <= len(raw) <= MAX_EXPORT or raw[0] != 0x30:
        return False
    count = raw[1] & 0x7f
    if raw[1] < 0x80:
        size, start = raw[1], 2
    elif not 1 <= count <= 4 or len(raw) <= 2 + count or raw[2] == 0:
        return False
    else:
        size, start = int.from_bytes(raw[2:2 + count], "big"), 2 + count
        if size < 128 or count > 1 and size < 256**(count - 1):
            return False
    oid = bytes.fromhex("060b2a864886f70d0109100117")
    return size + start == len(raw) and raw[start:start + len(oid)] == oid


def _save_ciphertext(raw, path=EXPORT_PATH):
    if not _cms_der(raw):
        raise ValueError("invalid encrypted recovery payload")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("invalid export destination")
    path.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("invalid export destination")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def probe(environ=None, *, runner=None):
    environ = os.environ if environ is None else environ
    operation = environ.get("QUANTA_OCI_INSTALL_OPERATION")
    if (environ.get("QUANTA_OCI_AUTH_CONFIRMED") != "true"
            or not isinstance(operation, str) or operation not in OPERATIONS):
        return report("not_configured")
    try:
        gate = _module("authorize_recovery")
        if not gate.control_checkout_matches(environ):
            return report("configuration_invalid", operation=operation, failure_reason="control_checkout_invalid")
        transport = _module("probe_inventory")
        login = _module("probe_login")
        audit, source = _payload(operation)
    except Exception:
        return report("configuration_invalid", operation=operation, failure_reason="audit_module_invalid")
    host = environ.get("QUANTA_OCI_HOST")
    pin = login._normalized_host_key(environ.get("QUANTA_OCI_HOST_KEY"))
    error, key = login._key_bytes(environ.get("QUANTA_OCI_PPK"))
    if not login._global_ipv4(host) or pin is None or error is not None:
        return report("not_configured", operation=operation)
    config = {"source_sha": SOURCE_SHA, "public_origin": environ.get("QUANTA_PUBLIC_ORIGIN", ""),
              "auth_mode": environ.get("QUANTA_AUTH_MODE", "")}
    try:
        audit.validate_config(config)
        encoded = base64.b64encode(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
    except Exception:
        return report("configuration_invalid", operation=operation, failure_reason="configuration_invalid")
    remote = "/usr/bin/sudo -n /usr/bin/python3 -I -B -c " + shlex.quote(source) + " " + shlex.quote(encoded)
    if operation in ACTION_OPERATIONS:
        remote += " " + shlex.quote(operation)
    runner = (lambda command, environment, directory: transport._capture(
        command, environment, directory, timeout=TIMEOUTS[operation],
        limit=MAX_EXPORT if operation == "export-recovery" else 8192)) if runner is None else runner
    attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix="quanta-recovery-audit-") as directory:
            os.chmod(directory, 0o700)
            key_path = Path(directory) / "identity.ppk"
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(key)
            command = [login.PLINK, "-ssh", "-2", "-4", "-batch", "-noagent",
                       "-no-trivial-auth", "-a", "-x", "-T", "-noshare", "-P", "22",
                       "-l", "ubuntu", "-i", str(key_path), "-hostkey", pin, host, remote]
            environment = {"HOME": directory, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
            status, raw, attempted = runner(command, environment, directory)
            if operation == "export-recovery":
                if status == "success":
                    try:
                        exported = _save_ciphertext(raw)
                    except Exception:
                        return report("invalid_output", attempted, operation=operation)
                    return report("success", attempted, operation=operation, ciphertext=exported)
                return report(status if status in {"timeout", "output_limit"} else "remote_failed",
                              attempted, operation=operation)
            if status in {"success", "failed"}:
                result = audit.sanitize_report(raw)
                if result is not None:
                    if operation in BOOT_OPERATIONS and result.get("action") != operation:
                        return report("invalid_output" if status == "success" else "remote_failed",
                                      attempted, operation=operation)
                    success = status == "success" and result.get("status") == "success"
                    return report("success" if success else "remote_failed", attempted,
                                  operation=operation, result=result)
                return report("invalid_output" if status == "success" else "remote_failed", attempted,
                              operation=operation)
            return report(status if status in {"timeout", "output_limit"} else "failed", attempted,
                          operation=operation)
    except Exception:
        return report("failed", attempted, operation=operation)


def main():
    try:
        value = probe()
    except Exception:
        value = report("failed")
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0 if value["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
