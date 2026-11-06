#!/usr/bin/env python3
"""Export only a prepared SQLite snapshot as recipient-encrypted CMS DER.

Remote success writes ciphertext bytes, never JSON or plaintext, to stdout.
Failure writes nothing to stdout. The runner must not log the captured bytes.
The separately pinned controller injects quanta_fixed_backup before execution.
"""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
import uuid

import quanta_fixed_backup as helper

EMBEDDED_RECIPIENT_CERT = '-----BEGIN CERTIFICATE-----\nMIIFRTCCAy2gAwIBAgIUPnMPA4xs0HSyHPfA8lPUDiwY7Q4wDQYJKoZIhvcNAQEL\nBQAwMjEwMC4GA1UEAwwnUXVhbnRhIHByaXZhdGUgYmFja3VwIHJlY292ZXJ5IDIw\nMjYxMTA2MB4XDTI2MTEwNjAzMzQyNFoXDTM2MTEwMzAzMzQyNFowMjEwMC4GA1UE\nAwwnUXVhbnRhIHByaXZhdGUgYmFja3VwIHJlY292ZXJ5IDIwMjYxMTA2MIICIjAN\nBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAteD8D0Ew9MejTvP7Sb4Bph4MQWSX\n73UZ8+C8Ne2JFz90KwJOLMXpPTw9iDyv6gkL6igGaPew/rcDHzekLxAJsF3TSqle\nUsrKsjycPmRUyGdsQKRvxPovU2xvIHpIADAPckG6AouLtm4z/FtBLcL4g3sVzi1U\nWUlQuDlxlSdRhYkd2YOYk2+cisTmPkbTnzUy5iE2mvfDi7U90HzqtedwqvWVKQUr\nZjlbdGpEOBS/2zJq5YJNXHlVb6TK+E15T/MrFRgtqhfyEY40FI/Pdm+798n9Qffi\nQ7mipu/QDm0s2fiYiyKacJ7n2vcKV20EazuyE//l7Zz8OVnX9lP7MlbbNom75EMi\nKJIVl9As3Vae/XKZ+S1Ri34XdCARHwmINt4g9bxDNZF99d+UbYhBRZaLVT0oj6ed\n41osAwQVrhVFyUdqDOrueF91BdqdlQeTgV1oLcCgZ6+ETKoFkAQLr8y8YAuKDqc8\nBsqkJ5eyedxgTBvbeK/H0BPgrLN4ECarg65rwedhk6By31IdMnJ/hBd6vD1W2IjH\n3pvdK/VUXpNlJOX1t2BQaXrPmhUS01CgWJc8LOauWTdt7KrpyT1lN7r7gk43QOlM\nsTrpP9xKTEwZOD2YoqqE5xCPJp9N8Xv3JflzmuozmzkSxfNWug2ZAjEs+09SwHAv\n4laBeiiObKvgE1kCAwEAAaNTMFEwHQYDVR0OBBYEFNDjOo2Hmo6PqtDWDpphTqXT\nctWfMB8GA1UdIwQYMBaAFNDjOo2Hmo6PqtDWDpphTqXTctWfMA8GA1UdEwEB/wQF\nMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAAVFwgQjRXZb9rERDz1vxBJdAfrI3cMk\n2f3oec076YMcuwwCLJEnS195HqSwen4E2sko22L6yyY/bfaDOlnTRukLXvlTYvJQ\nBKZTC5u5IWjmJ3tIJBtNC8HV3ALGS4XwLV8NRbKmouW7eOnCgoQ07Nu9hBM62P27\nOgrH9IVR/lTSbSothgtcxiuhnuTaTg/kgPOHWX4AUTcIIzVJLSHnFPriRfpKC2Fg\nchU6W8jkMBe6NnZW4Gl5phU/+7Rn4d1QjcxR+gYHpGerHc2MrUMXMployPEJwS8I\niCOjvSUKfZTwSK5fBoyj9aqDrqnPAnPHqHGiDTqVc9N7zHtijN9NInz1v95Nkr7M\nbuo5LV5wj+zdVwPVxbJQMHGMvAAt4e/zbusxwtwIQJsyphdblhlDhW8GVb8E52Kp\nvBeTkgjHf+kRmxftlxfW4B6JlweL98/daS28Gnf/eLybC4qyfKoZpyCNxq5IjTKR\nn0rDF4uF1+pNVqT11qIvPZyr0KpzJYNd8v2BbaCEjvmf5zUcvdqAz3hg53pmsPQm\nMWUHbT5vA3nybcPuc/qjOAODRNxrU7iYHImR9rBTy92b3/bbu95bHZ27XAV/u68Z\nacZyZprIPyVFqNrJ0MQaEKEDzh0Hja9IkERTdHFfY0oViXjaogUrojtPVgwaG+bd\nKboxacuQ7L24\n-----END CERTIFICATE-----\n'
EXPECTED_CERT_SHA256 = "eb1fa7254d19ad31cf89352788bc87db63769dffd12930e7c57df373bc818c6a"
BASELINE = Path('/etc/quanta/recovery-backup.json')
LOCK = Path('/run/quanta-recovery.lock')
OPENSSL = '/usr/bin/openssl'
MAX_CIPHERTEXT_BYTES = 128 * 1024**2
MAX_EXPORT = MAX_CIPHERTEXT_BYTES
MAX_DATABASE_BYTES = MAX_CIPHERTEXT_BYTES - 4 * 1024**2
MAX_BASELINE_AGE_SECONDS = 24 * 60 * 60
BASELINE_FIELDS = frozenset({'schema_version', 'source_sha', 'boot_id', 'snapshot',
                             'database_size', 'database_sha256', 'created_at'})


def validate_config(config):
    return helper.validate_config(config)


def _baseline(config):
    value = helper._json(helper._read_root(BASELINE, private=True))
    if (not isinstance(value, dict) or set(value) != BASELINE_FIELDS
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['source_sha'] != config['source_sha']
            or not isinstance(value['boot_id'], str)
            or str(uuid.UUID(value['boot_id'])) != value['boot_id']
            or not isinstance(value['snapshot'], str)
            or not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}', value['snapshot'])
            or uuid.UUID(hex=value['snapshot'][17:]).version != 4
            or type(value['database_size']) is not int
            or not 1 <= value['database_size'] <= MAX_DATABASE_BYTES
            or not isinstance(value['database_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['database_sha256'])
            or not isinstance(value['created_at'], str)):
        raise helper.VerificationError()
    datetime.strptime(value['snapshot'][:16], '%Y%m%dT%H%M%SZ')
    created = datetime.strptime(value['created_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - created).total_seconds()
    if not 0 <= age <= MAX_BASELINE_AGE_SECONDS:
        raise helper.VerificationError()
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if boot_id != value['boot_id']:
        raise helper.VerificationError()
    return value


def _lock():
    helper._root_parents(LOCK)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise helper.VerificationError()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _add_snapshot_file(archive, path, arcname, device, expected_size=None, expected_hash=None):
    before = helper._private_file(path, device, maximum=MAX_DATABASE_BYTES)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise helper.VerificationError()
        raw = source.read(MAX_DATABASE_BYTES + 1)
        final = os.fstat(source.fileno())
    if (len(raw) != before.st_size or len(raw) > MAX_DATABASE_BYTES
            or (final.st_size, final.st_mtime_ns) != (before.st_size, before.st_mtime_ns)
            or expected_size is not None and len(raw) != expected_size
            or expected_hash is not None and hashlib.sha256(raw).hexdigest() != expected_hash):
        raise helper.VerificationError()
    current = helper._private_file(path, device, maximum=MAX_DATABASE_BYTES)
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
        raise helper.VerificationError()
    entry = tarfile.TarInfo(arcname)
    entry.size, entry.mode = len(raw), 0o600
    entry.uid = entry.gid = 10001
    entry.mtime = 0
    archive.addfile(entry, io.BytesIO(raw))


def _check_der(raw):
    """Require one bounded, definite-length ASN.1 SEQUENCE; not a CMS validator."""
    if not isinstance(raw, bytes) or not 128 <= len(raw) <= MAX_CIPHERTEXT_BYTES or raw[0] != 0x30:
        raise ValueError('invalid encrypted export')
    second = raw[1]
    if second < 0x80:
        length, offset = second, 2
    else:
        count = second & 0x7f
        if not 1 <= count <= 4 or len(raw) < 2 + count or raw[2] == 0:
            raise ValueError('invalid encrypted export')
        length, offset = int.from_bytes(raw[2:2 + count], 'big'), 2 + count
        if length < 128:
            raise ValueError('invalid encrypted export')
    if offset + length != len(raw):
        raise ValueError('invalid encrypted export')


def export_bytes(config):
    config = validate_config(config)
    if os.geteuid() != 0:
        raise helper.VerificationError()
    if helper._json(helper._read_root(helper.ETC / 'installed.json', private=True)) != config:
        raise helper.VerificationError()
    cert = EMBEDDED_RECIPIENT_CERT.encode('ascii')
    if (not 128 <= len(cert) <= 8192 or not cert.startswith(b'-----BEGIN CERTIFICATE-----\n')
            or not cert.endswith(b'-----END CERTIFICATE-----\n')
            or hashlib.sha256(cert).hexdigest() != EXPECTED_CERT_SHA256):
        raise helper.VerificationError()
    helper._root_parents(Path(OPENSSL))
    openssl = os.lstat(OPENSSL)
    if not stat.S_ISREG(openssl.st_mode) or openssl.st_uid != 0 or openssl.st_mode & 0o022:
        raise helper.VerificationError()
    descriptor = _lock()
    try:
        baseline = _baseline(config)
        device = os.lstat(helper.ROOT).st_dev
        if device != os.lstat('/').st_dev:
            raise helper.VerificationError()
        helper._private_dir(helper.BACKUPS, device)
        snapshot = helper.BACKUPS / baseline['snapshot']
        helper._private_dir(snapshot, device)
        helper._children(snapshot, {'jobs.sqlite3', 'manifest.json'})
        helper._private_file(snapshot / 'manifest.json', device, maximum=1024**2)
        if helper._hash(snapshot / 'jobs.sqlite3', device) != (
                baseline['database_size'], bytes.fromhex(baseline['database_sha256'])):
            raise helper.VerificationError()
        # Plaintext temporary files remain on the host in a private /run directory.
        with tempfile.TemporaryDirectory(prefix='quanta-recovery-export-', dir='/run') as directory:
            work = Path(directory)
            os.chmod(work, 0o700)
            certificate, plaintext, ciphertext = work / 'recipient.pem', work / 'backup.tar', work / 'backup.cms'
            certificate.write_bytes(cert)
            os.chmod(certificate, 0o600)
            with plaintext.open('xb') as output:
                os.chmod(plaintext, 0o600)
                with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                    _add_snapshot_file(archive, snapshot / 'jobs.sqlite3', 'backup/jobs.sqlite3', device,
                        baseline['database_size'], baseline['database_sha256'])
                    _add_snapshot_file(archive, snapshot / 'manifest.json', 'backup/manifest.json', device)
            helper._quiet([OPENSSL, 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER',
                           '-in', str(plaintext), '-out', str(ciphertext), '-recip', str(certificate),
                           '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256'], timeout=120)
            if not 128 <= ciphertext.stat().st_size <= MAX_CIPHERTEXT_BYTES:
                raise helper.VerificationError()
            raw = ciphertext.read_bytes()
            _check_der(raw)
            return raw
    finally:
        os.close(descriptor)


def save_ciphertext(raw):
    """Runner-only: save a fixed encrypted artifact; return non-sensitive metadata."""
    _check_der(raw)
    cache = Path('.cache')
    try:
        cache.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = os.lstat(cache)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('invalid encrypted export destination')
    path = cache / 'recovery-backup.cms'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return {'scope': 'encrypted_recovery_export', 'status': 'success',
            'ciphertext_bytes': len(raw), 'ciphertext_sha256': hashlib.sha256(raw).hexdigest(),
            'plaintext_logged': False, 'off_host_backup_verified': False}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) != 1:
            raise ValueError
        config = helper._argument(argv[0])
        with helper._deadline(300):
            raw = export_bytes(config)
    except Exception:
        return 2
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
