"""Private Gmail SMTP delivery, separate from account passwords and job data.

Only a server owner can configure this adapter through the trusted HTTP layer.
The SMTP host, TLS policy and sender are fixed; recipients cannot select them.
Attempts have a persistent bounded budget so a restart cannot reset it.
"""
from __future__ import annotations

from contextlib import contextmanager
from email.message import EmailMessage
from email.policy import SMTP
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import ssl
import stat
import time


SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 10
MAX_DAILY_ATTEMPTS = 100
MAX_MINUTE_ATTEMPTS = 10
MAX_CONFIG_BYTES = 4096
MAX_MESSAGE_BYTES = 16_384
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@" + _LABEL + r"(?:\." + _LABEL + r")+\Z")


class MailUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("Verification email is temporarily unavailable")


def _email(value):
    if not isinstance(value, str) or len(value) > 254 or not _EMAIL.fullmatch(value):
        raise ValueError("A valid single email address is required")
    return value.lower()


class GmailMailer:
    def __init__(self, directory, *, smtp_factory=None, clock=time.time):
        self.directory = Path(directory)
        self.path = self.directory / "gmail-smtp.json"
        self.budget_path = self.directory / "gmail-budget.json"
        self.lock_path = self.directory / "gmail-mail.lock"
        self._smtp_factory = smtp_factory or smtplib.SMTP_SSL
        self._clock = clock
        self._directory()

    def _directory(self):
        if not self.directory.is_absolute():
            raise MailUnavailable()
        for path in (self.directory, *self.directory.parents):
            if stat.S_ISLNK(os.lstat(path).st_mode):
                raise MailUnavailable()
        info = os.lstat(self.directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise MailUnavailable()

    @staticmethod
    def _metadata(value):
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) != 0o600):
            raise MailUnavailable()

    def _read(self, path, *, maximum=MAX_CONFIG_BYTES):
        self._directory()
        before = os.lstat(path)
        self._metadata(before)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            self._metadata(opened)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise MailUnavailable()
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise MailUnavailable()
        def unique(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise MailUnavailable()
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _value: (_ for _ in ()).throw(MailUnavailable()))

    def _write(self, path, value):
        self._directory()
        try:
            self._metadata(os.lstat(path))
        except FileNotFoundError:
            pass
        temporary = self.directory / (".gmail-" + secrets.token_hex(16))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @contextmanager
    def _lock(self):
        self._directory()
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            self._metadata(info)
            linked = os.lstat(self.lock_path)
            if (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino):
                raise MailUnavailable()
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    @staticmethod
    def validate_credentials(smtp_username, smtp_password):
        username = _email(smtp_username)
        # Google displays the 16-character app password in groups of four.
        if not isinstance(smtp_password, str) or len(smtp_password) > 32:
            raise ValueError("A Google app password is required")
        password = smtp_password.replace(" ", "")
        if not re.fullmatch(r"[A-Za-z0-9]{16}", password):
            raise ValueError("A Google app password must contain 16 letters or digits")
        return username, password

    def _configuration(self):
        value = self._read(self.path)
        if (not isinstance(value, dict) or set(value) != {"schema_version", "provider", "username", "app_password"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["provider"] != "gmail"):
            raise MailUnavailable()
        username, password = self.validate_credentials(value["username"], value["app_password"])
        if username != value["username"] or password != value["app_password"]:
            raise MailUnavailable()
        return username, password

    @property
    def configured(self):
        try:
            self._configuration()
            return True
        except (OSError, ValueError, MailUnavailable):
            return False

    def configure(self, smtp_username, smtp_password):
        username, password = self.validate_credentials(smtp_username, smtp_password)
        try:
            with self._lock():
                self._write(self.path, {"schema_version": 1, "provider": "gmail",
                    "username": username, "app_password": password})
        except (OSError, ValueError, MailUnavailable):
            raise MailUnavailable() from None

    def _reserve(self):
        now = self._clock()
        if type(now) not in {int, float} or not 0 < now < 2**53:
            raise MailUnavailable()
        with self._lock():
            try:
                value = self._read(self.budget_path, maximum=8192)
            except FileNotFoundError:
                value = {"schema_version": 1, "attempts": []}
            if (not isinstance(value, dict) or set(value) != {"schema_version", "attempts"}
                    or type(value["schema_version"]) is not int or value["schema_version"] != 1
                    or not isinstance(value["attempts"], list) or len(value["attempts"]) > MAX_DAILY_ATTEMPTS
                    or any(type(stamp) not in {int, float} or not 0 < stamp <= now for stamp in value["attempts"])):
                raise MailUnavailable()
            recent = [stamp for stamp in value["attempts"] if stamp > now - 86400]
            if len(recent) >= MAX_DAILY_ATTEMPTS or sum(stamp > now - 60 for stamp in recent) >= MAX_MINUTE_ATTEMPTS:
                raise MailUnavailable()
            self._write(self.budget_path, {"schema_version": 1, "attempts": recent + [now]})

    def __call__(self, recipient, subject, body):
        try:
            recipient = _email(recipient)
            if (not isinstance(subject, str) or not 1 <= len(subject) <= 120
                    or any(ord(char) < 32 or ord(char) == 127 for char in subject)
                    or not isinstance(body, str) or not 1 <= len(body.encode("utf-8")) <= 8192):
                raise MailUnavailable()
            username, password = self._configuration()
            message = EmailMessage(policy=SMTP)
            message["From"], message["To"], message["Subject"] = username, recipient, subject
            message.set_content(body)
            if len(message.as_bytes()) > MAX_MESSAGE_BYTES:
                raise MailUnavailable()
            self._reserve()
            context = ssl.create_default_context()
            with self._smtp_factory(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context) as connection:
                connection.login(username, password)
                refused = connection.send_message(message, from_addr=username, to_addrs=[recipient])
                if refused:
                    raise MailUnavailable()
        except Exception:
            # SMTP exceptions can include addresses or credentials; never expose them.
            raise MailUnavailable() from None
