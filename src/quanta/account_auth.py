"""Private local accounts, verified email challenges and opaque server sessions.

This module never reads or changes the scientific jobs database. Transport,
same-origin/CSRF enforcement and secure cookie attributes belong to the HTTP
adapter. A mailer is injected by the server; request data never selects a mail
host. Only an authenticated owner bootstrap can reserve the legacy ``local``
principal, and proving that email remains required before account creation.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
import uuid

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024**2
PASSWORD_SCHEME = "scrypt-v1:n=131072:r=8:p=1:dklen=32:maxmem=268435456"
PASSWORD_MIN = 15
PASSWORD_MAX = 256
CHALLENGE_TTL = 600
CHALLENGE_ATTEMPTS = 5
RESEND_SECONDS = 30
SESSION_IDLE = 86400
SESSION_ABSOLUTE = 7 * 86400
EMAIL_WINDOW = 900
EMAIL_LIMIT = 6
GLOBAL_EMAIL_WINDOW = 3600
GLOBAL_EMAIL_LIMIT = 50
LOGIN_WINDOW = 300
LOGIN_LIMIT = 8
GLOBAL_LOGIN_WINDOW = 60
GLOBAL_LOGIN_LIMIT = 30
MAX_ACCOUNTS = 10000
MAX_DATABASE_BYTES = 128 * 1024**2
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
_USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}\Z")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@" + _LABEL + r"(?:\." + _LABEL + r")+\Z")
_PURPOSES = frozenset({"signup", "login", "mfa_enable", "mfa_disable", "reset"})


class AuthError(Exception):
    """An intentionally bounded, public error without credential details."""

    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


@dataclass(frozen=True)
class AuthResult:
    payload: dict
    session_token: str | None = field(default=None, repr=False)
    clear_session: bool = False


def _invalid():
    return AuthError(422, "AUTH_INPUT", "The account request is invalid")


def _denied():
    return AuthError(401, "UNAUTHORIZED", "The credentials or verification code are invalid")


def _unavailable():
    return AuthError(503, "AUTH_UNAVAILABLE", "Account verification is temporarily unavailable")


def _email(value):
    if not isinstance(value, str) or len(value) > 254 or not value.isascii():
        raise _invalid()
    value = value.lower()
    if not _EMAIL.fullmatch(value):
        raise _invalid()
    return value


def _username(value):
    if not isinstance(value, str) or not value.isascii():
        raise _invalid()
    value = value.lower()
    if not _USERNAME.fullmatch(value):
        raise _invalid()
    return value


def _password(value):
    if (not isinstance(value, str) or not PASSWORD_MIN <= len(value) <= PASSWORD_MAX
            or value.isspace() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise _invalid()
    try:
        if len(value.encode("utf-8")) > 1024:
            raise _invalid()
    except UnicodeEncodeError:
        raise _invalid() from None
    return value


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N,
                          r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM, dklen=32)


class AccountStore:
    """One bounded account database, independently protected from job records.

    ``mailer(email, subject, body)`` must return only after acceptance or raise;
    acceptance does not mark an email verified. ``password_hasher`` is a test
    injection taking (password, salt) and returning exactly 32 bytes. Production
    callers omit it and use the pinned scrypt parameters above.
    """

    def __init__(self, directory, owner_secret, *, mailer=None, clock=time.time,
                 password_hasher=None):
        self.directory = Path(directory).absolute()
        self.path = self.directory / "auth.sqlite3"
        if isinstance(owner_secret, str) and _TOKEN.fullmatch(owner_secret):
            owner_secret = bytes.fromhex(owner_secret)
        if not isinstance(owner_secret, bytes) or len(owner_secret) < 32:
            raise ValueError("An independently supplied private owner secret is required")
        self._secret = hmac.digest(owner_secret, b"quanta-account-auth-v1", "sha256")
        self._mailer, self._clock = mailer, clock
        self._hasher = password_hasher or _scrypt
        self._lock = threading.RLock()
        self._hash_lock = threading.Lock()
        self._dummy_salt = secrets.token_bytes(32)
        self._private_directory()
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._private_file()
        with self._transaction() as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables and tables != {"meta", "accounts", "sessions", "challenges", "rate_windows"}:
                raise _unavailable()
            schema = """
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts(
                    id TEXT PRIMARY KEY,owner TEXT NOT NULL UNIQUE,username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,salt BLOB NOT NULL,digest BLOB NOT NULL,
                    mfa INTEGER NOT NULL CHECK(mfa IN(0,1)),
                    admin INTEGER NOT NULL CHECK(admin IN(0,1)),version INTEGER NOT NULL,
                    verified_at REAL NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS one_admin ON accounts(admin) WHERE admin=1;
                CREATE TABLE IF NOT EXISTS sessions(
                    token_hash BLOB PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),
                    created REAL NOT NULL,last_seen REAL NOT NULL,expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS challenges(
                    id TEXT PRIMARY KEY,purpose TEXT NOT NULL,email TEXT NOT NULL,account_id TEXT,
                    session_hash BLOB,auth_version INTEGER,code_hash BLOB NOT NULL,state TEXT NOT NULL,
                    expires REAL NOT NULL,attempts INTEGER NOT NULL,created REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS challenge_email ON challenges(email,purpose,created);
                CREATE TABLE IF NOT EXISTS rate_windows(
                    key BLOB PRIMARY KEY,started REAL NOT NULL,count INTEGER NOT NULL);
            """
            for statement in schema.split(";"):
                if statement.strip():
                    db.execute(statement)
            row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                db.execute("INSERT INTO meta VALUES('schema_version','1')")
            elif row[0] != "1":
                raise _unavailable()
            scheme = db.execute("SELECT value FROM meta WHERE key='password_scheme'").fetchone()
            if scheme is None:
                if db.execute("SELECT 1 FROM accounts LIMIT 1").fetchone() is not None:
                    raise _unavailable()
                db.execute("INSERT INTO meta VALUES('password_scheme',?)", (PASSWORD_SCHEME,))
            elif scheme[0] != PASSWORD_SCHEME:
                raise _unavailable()

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise _unavailable()
        return float(value)

    def _private_directory(self):
        try:
            for parent in (*reversed(self.directory.parents), self.directory):
                if stat.S_ISLNK(os.lstat(parent).st_mode):
                    raise _unavailable()
            info = os.lstat(self.directory)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise _unavailable()
        except OSError:
            raise _unavailable() from None

    def _private_file(self):
        self._private_directory()
        try:
            info = os.lstat(self.path)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > MAX_DATABASE_BYTES):
                raise _unavailable()
            return info
        except OSError:
            raise _unavailable() from None

    @contextmanager
    def _transaction(self):
        with self._lock:
            before = self._private_file()
            db = None
            try:
                db = sqlite3.connect(self.path, timeout=2, isolation_level=None)
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("PRAGMA trusted_schema=OFF")
                if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
                    raise _unavailable()
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                after = self._private_file()
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise _unavailable()
                yield db
                if db.in_transaction:
                    db.commit()
            except sqlite3.Error:
                if db is not None and db.in_transaction:
                    db.rollback()
                raise _unavailable() from None
            except BaseException:
                if db is not None and db.in_transaction:
                    db.rollback()
                raise
            finally:
                if db is not None:
                    db.close()

    @property
    def mail_configured(self):
        try:
            return self._mailer is not None and bool(getattr(self._mailer, "configured", True))
        except Exception:
            return False

    def _require_mail(self):
        if not self.mail_configured:
            raise AuthError(503, "MAIL_UNAVAILABLE", "Verification email delivery is not configured")

    @staticmethod
    def _account(row):
        return {"id": row["id"], "owner": row["owner"], "username": row["username"],
                "email": row["email"], "mfa_enabled": bool(row["mfa"]), "is_admin": bool(row["admin"])}

    def _token_hash(self, token):
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return None
        return hashlib.sha256(token.encode("ascii")).digest()

    def _csrf(self, token):
        return hmac.digest(self._secret, b"csrf\x00" + token.encode("ascii"), "sha256").hex()

    def _session_account(self, db, token, now, *, touch=False):
        digest = self._token_hash(token)
        if digest is None:
            return None
        row = db.execute("SELECT a.*,s.created,s.last_seen,s.expires FROM sessions s "
                         "JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=?", (digest,)).fetchone()
        if row is None:
            return None
        if (now < row["created"] or now >= row["expires"] or now - row["last_seen"] >= SESSION_IDLE):
            db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
            return None
        if touch:
            db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, digest))
        return row

    def identity(self, token, *, touch=True):
        with self._transaction() as db:
            row = self._session_account(db, token, self._now(), touch=touch)
            if row is None:
                return None
            return {**self._account(row), "csrf_token": self._csrf(token)}

    def status(self, session_token=None):
        with self._transaction() as db:
            owner = db.execute("SELECT value FROM meta WHERE key='owner_email'").fetchone()
            row = self._session_account(db, session_token, self._now(), touch=True)
            return {"mode": "account", "authenticated": row is not None,
                    "configured": owner is not None and self.mail_configured,
                    "bootstrap_required": owner is None, "mail_configured": self.mail_configured,
                    "registration": "open", "principal": self._account(row) if row is not None else None,
                    "csrf_token": self._csrf(session_token) if row is not None else None}

    def configure_owner(self, email, *, owner_authorized=False):
        if owner_authorized is not True:
            raise AuthError(403, "OWNER_REQUIRED", "The private owner setup credential is required")
        email = _email(email)
        with self._transaction() as db:
            row = db.execute("SELECT value FROM meta WHERE key='owner_email'").fetchone()
            if row is not None and row[0] != email:
                if db.execute("SELECT 1 FROM accounts WHERE email=? OR owner='local' OR admin=1", (email,)).fetchone():
                    raise AuthError(409, "OWNER_CONFIGURED", "The owner account has already been established")
                # A mistyped reservation may be corrected only by the private
                # owner credential, before a legacy-owner account exists. The
                # old mailbox's in-flight proof must not acquire the new role.
                db.execute("UPDATE meta SET value=? WHERE key='owner_email'", (email,))
                db.execute("UPDATE challenges SET state='invalid' WHERE email=? AND purpose='signup' AND state IN('pending','sent')", (row[0],))
            if row is None:
                if db.execute("SELECT 1 FROM accounts WHERE email=? OR owner='local' OR admin=1", (email,)).fetchone():
                    raise AuthError(409, "OWNER_CONFIGURED", "The owner account has already been reserved")
                db.execute("INSERT INTO meta VALUES('owner_email',?)", (email,))
        return AuthResult({"configured": True})

    def _require_owner_setup(self, db):
        row = db.execute("SELECT value FROM meta WHERE key='owner_email'").fetchone()
        if row is None:
            raise AuthError(503, "OWNER_SETUP_REQUIRED", "The private owner setup must be completed first")
        return row[0]

    def _rate(self, db, category, key, now, window, limit):
        digest = hmac.digest(self._secret, (category + "\x00" + key).encode("utf-8"), "sha256")
        row = db.execute("SELECT started,count FROM rate_windows WHERE key=?", (digest,)).fetchone()
        if row is None or now >= row["started"] + window:
            db.execute("INSERT OR REPLACE INTO rate_windows VALUES(?,?,1)", (digest, now))
        elif now < row["started"] or row["count"] >= limit:
            raise AuthError(429, "AUTH_RATE_LIMIT", "Too many verification attempts; try again later")
        else:
            db.execute("UPDATE rate_windows SET count=count+1 WHERE key=?", (digest,))

    def _cleanup(self, db, now):
        db.execute("DELETE FROM sessions WHERE expires<=? OR last_seen<=?", (now, now-SESSION_IDLE))
        db.execute("DELETE FROM challenges WHERE created<?", (now-86400,))
        db.execute("DELETE FROM rate_windows WHERE started<?", (now-86400,))

    def _code_digest(self, identifier, purpose, email, account_id, session_hash, auth_version, code):
        parts = (identifier, purpose, email, account_id or "", (session_hash or b"").hex(),
                 "" if auth_version is None else str(auth_version), code)
        return hmac.digest(self._secret, "\x00".join(parts).encode("ascii"), "sha256")

    def _issue(self, purpose, email, *, account_id=None, session_hash=None, expected_version=None):
        if purpose not in _PURPOSES:
            raise ValueError("Unsupported account verification purpose")
        self._require_mail()
        now, identifier, code = self._now(), secrets.token_hex(32), f"{secrets.randbelow(1000000):06d}"
        with self._transaction() as db:
            self._require_owner_setup(db)
            account = None if account_id is None else db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
            auth_version = account["version"] if account is not None else None
            if (account_id is not None and (account is None or account["email"] != email)
                    or expected_version is not None and auth_version != expected_version):
                raise _denied()
            if session_hash is not None:
                session = db.execute("SELECT created,last_seen,expires FROM sessions WHERE token_hash=? AND account_id=?", (session_hash, account_id)).fetchone()
                if (session is None or now < session["created"] or now >= session["expires"]
                        or now-session["last_seen"] >= SESSION_IDLE):
                    raise _denied()
            self._cleanup(db, now)
            self._rate(db, "email-global", "all", now, GLOBAL_EMAIL_WINDOW, GLOBAL_EMAIL_LIMIT)
            self._rate(db, "email-address", email, now, EMAIL_WINDOW, EMAIL_LIMIT)
            failed = db.execute("SELECT COALESCE(sum(attempts),0) FROM challenges WHERE email=? AND purpose=? AND created>=?",
                                (email, purpose, now-EMAIL_WINDOW)).fetchone()[0]
            if failed >= CHALLENGE_ATTEMPTS:
                raise AuthError(429, "AUTH_RATE_LIMIT", "Too many verification attempts; try again later")
            previous = db.execute("SELECT max(created) FROM challenges WHERE email=? AND state IN('pending','sent')", (email,)).fetchone()[0]
            if previous is not None and now - previous < RESEND_SECONDS:
                raise AuthError(429, "AUTH_RATE_LIMIT", "Wait before requesting another verification email")
            db.execute("UPDATE challenges SET state='invalid' WHERE email=? AND purpose=? AND state IN('pending','sent')", (email, purpose))
            digest = self._code_digest(identifier, purpose, email, account_id, session_hash, auth_version, code)
            db.execute("INSERT INTO challenges VALUES(?,?,?,?,?,?,?, 'pending',?,0,?)",
                       (identifier, purpose, email, account_id, session_hash, auth_version, digest, now+CHALLENGE_TTL, now))
        try:
            self._mailer(email, "Quanta verification", "Your Quanta verification code is " + code + ".\n"
                         "It expires in 10 minutes. If you did not request it, ignore this message.")
        except Exception:
            with self._transaction() as db:
                db.execute("UPDATE challenges SET state='invalid' WHERE id=? AND state='pending'", (identifier,))
            raise AuthError(503, "MAIL_UNAVAILABLE", "Verification email delivery is temporarily unavailable") from None
        with self._transaction() as db:
            changed = db.execute("UPDATE challenges SET state='sent' WHERE id=? AND state='pending' AND expires>?", (identifier, self._now())).rowcount
            if changed != 1:
                raise AuthError(503, "MAIL_UNAVAILABLE", "The verification request is no longer available")
        return AuthResult({"challenge_id": identifier, "expires_in": CHALLENGE_TTL,
                           "message": "If the address is eligible, a verification email has been sent."})

    def _checked_challenge(self, db, identifier, code, purpose, now, *, session_hash=None):
        """Update failed-attempt budgets; callers commit before raising denial."""
        if (not isinstance(identifier, str) or not _TOKEN.fullmatch(identifier)
                or not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code)):
            return None
        row = db.execute("SELECT * FROM challenges WHERE id=?", (identifier,)).fetchone()
        if (row is None or row["purpose"] != purpose or row["state"] != "sent"
                or row["expires"] <= now or now < row["created"] or row["attempts"] >= CHALLENGE_ATTEMPTS
                or (row["session_hash"] is not None and row["session_hash"] != session_hash)):
            return None
        failed = db.execute("SELECT COALESCE(sum(attempts),0) FROM challenges WHERE email=? AND purpose=? AND created>=?",
                            (row["email"], purpose, now-EMAIL_WINDOW)).fetchone()[0]
        if failed >= CHALLENGE_ATTEMPTS:
            db.execute("UPDATE challenges SET state='invalid' WHERE id=?", (identifier,))
            return None
        if row["account_id"] is not None:
            account = db.execute("SELECT version,email FROM accounts WHERE id=?", (row["account_id"],)).fetchone()
            if account is None or account["version"] != row["auth_version"] or account["email"] != row["email"]:
                db.execute("UPDATE challenges SET state='invalid' WHERE id=?", (identifier,))
                return None
        digest = self._code_digest(row["id"], row["purpose"], row["email"], row["account_id"], row["session_hash"], row["auth_version"], code)
        if not hmac.compare_digest(digest, row["code_hash"]):
            db.execute("UPDATE challenges SET attempts=attempts+1,state=CASE WHEN attempts+1>=? THEN 'invalid' ELSE state END WHERE id=?",
                       (CHALLENGE_ATTEMPTS, identifier))
            if failed + 1 >= CHALLENGE_ATTEMPTS:
                db.execute("UPDATE challenges SET state='invalid' WHERE email=? AND purpose=? AND state IN('pending','sent')",
                           (row["email"], purpose))
            return None
        return row

    def _hash(self, password, salt):
        if not self._hash_lock.acquire(blocking=False):
            raise AuthError(429, "AUTH_BUSY", "Password verification is busy; try again shortly")
        try:
            value = self._hasher(password, salt)
            if not isinstance(value, bytes) or len(value) != 32:
                raise _unavailable()
            return value
        except AuthError:
            raise
        except Exception:
            raise _unavailable() from None
        finally:
            self._hash_lock.release()

    def _new_session(self, db, account_id, now):
        # A bounded set per user prevents unbounded session accumulation.
        db.execute("DELETE FROM sessions WHERE token_hash IN(SELECT token_hash FROM sessions WHERE account_id=? ORDER BY created DESC LIMIT -1 OFFSET 9)", (account_id,))
        token = secrets.token_hex(32)
        db.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (self._token_hash(token), account_id, now, now, now+SESSION_ABSOLUTE))
        row = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return AuthResult({"authenticated": True, "account": self._account(row), "csrf_token": self._csrf(token)}, token)

    def request_signup(self, email):
        return self._issue("signup", _email(email))

    def complete_signup(self, challenge_id, code, username, password):
        username, password, now = _username(username), _password(password), self._now()
        denied, result = False, None
        with self._transaction() as db:
            owner_email = self._require_owner_setup(db)
            row = self._checked_challenge(db, challenge_id, code, "signup", now)
            if row is None:
                denied = True
            else:
                self._rate(db, "hash-global", "all", now, GLOBAL_LOGIN_WINDOW, GLOBAL_LOGIN_LIMIT)
                if db.execute("SELECT count(*) FROM accounts").fetchone()[0] >= MAX_ACCOUNTS:
                    raise AuthError(503, "ACCOUNT_CAPACITY", "Account registration is temporarily unavailable")
                if db.execute("SELECT 1 FROM accounts WHERE username=? OR email=?", (username, row["email"])).fetchone():
                    raise AuthError(409, "ACCOUNT_UNAVAILABLE", "The account name or email is unavailable")
                salt, identifier = secrets.token_bytes(32), str(uuid.uuid4())
                digest = self._hash(password, salt)
                admin = row["email"] == owner_email
                owner = "local" if admin else "account-" + uuid.uuid4().hex
                db.execute("INSERT INTO accounts VALUES(?,?,?,?,?,?,0,?,0,?)",
                           (identifier, owner, username, row["email"], salt, digest, int(admin), now))
                db.execute("UPDATE challenges SET state='used' WHERE id=?", (challenge_id,))
                result = self._new_session(db, identifier, now)
        if denied:
            raise _denied()
        return result

    def login(self, username, password):
        username, password, now = _username(username), _password(password), self._now()
        with self._transaction() as db:
            # Password-only use may never send mail. Bound the attacker-chosen
            # username buckets even when no email operation runs maintenance.
            self._cleanup(db, now)
            self._rate(db, "hash-global", "all", now, GLOBAL_LOGIN_WINDOW, GLOBAL_LOGIN_LIMIT)
            self._rate(db, "login-name", username, now, LOGIN_WINDOW, LOGIN_LIMIT)
            row = db.execute("SELECT * FROM accounts WHERE username=?", (username,)).fetchone()
        salt = bytes(row["salt"]) if row is not None else self._dummy_salt
        digest = self._hash(password, salt)
        if row is None or not hmac.compare_digest(digest, bytes(row["digest"])):
            raise _denied()
        if row["mfa"]:
            result = self._issue("login", row["email"], account_id=row["id"], expected_version=row["version"])
            return AuthResult({**result.payload, "mfa_required": True})
        with self._transaction() as db:
            fresh = db.execute("SELECT * FROM accounts WHERE id=?", (row["id"],)).fetchone()
            # A concurrent reset/MFA change invalidates the checked credentials.
            if (fresh is None or fresh["version"] != row["version"]
                    or fresh["digest"] != row["digest"] or fresh["mfa"] != row["mfa"]):
                raise _denied()
            return self._new_session(db, row["id"], self._now())

    def complete_login(self, challenge_id, code):
        denied, result, now = False, None, self._now()
        with self._transaction() as db:
            row = self._checked_challenge(db, challenge_id, code, "login", now)
            account = None if row is None else db.execute("SELECT * FROM accounts WHERE id=?", (row["account_id"],)).fetchone()
            if row is None or account is None or not account["mfa"] or account["email"] != row["email"]:
                denied = True
            else:
                db.execute("UPDATE challenges SET state='used' WHERE id=?", (challenge_id,))
                result = self._new_session(db, account["id"], now)
        if denied:
            raise _denied()
        return result

    def request_mfa(self, token, password, enabled):
        if type(enabled) is not bool:
            raise _invalid()
        password, now = _password(password), self._now()
        with self._transaction() as db:
            row = self._session_account(db, token, now)
            if row is None:
                raise _denied()
            self._rate(db, "hash-global", "all", now, GLOBAL_LOGIN_WINDOW, GLOBAL_LOGIN_LIMIT)
            self._rate(db, "login-name", row["username"], now, LOGIN_WINDOW, LOGIN_LIMIT)
        if not hmac.compare_digest(self._hash(password, bytes(row["salt"])), bytes(row["digest"])):
            raise _denied()
        return self._issue("mfa_enable" if enabled else "mfa_disable", row["email"],
                           account_id=row["id"], session_hash=self._token_hash(token), expected_version=row["version"])

    def complete_mfa(self, token, challenge_id, code):
        denied, result, now = False, None, self._now()
        with self._transaction() as db:
            account = self._session_account(db, token, now)
            raw = db.execute("SELECT purpose FROM challenges WHERE id=?", (challenge_id,)).fetchone() if isinstance(challenge_id, str) else None
            purpose = raw[0] if raw is not None and raw[0] in {"mfa_enable", "mfa_disable"} else "mfa_enable"
            row = self._checked_challenge(db, challenge_id, code, purpose, now, session_hash=self._token_hash(token))
            if account is None or row is None or row["account_id"] != account["id"] or row["email"] != account["email"]:
                denied = True
            else:
                db.execute("UPDATE accounts SET mfa=?,version=version+1 WHERE id=?", (int(purpose == "mfa_enable"), account["id"]))
                db.execute("UPDATE challenges SET state='used' WHERE id=?", (challenge_id,))
                db.execute("UPDATE challenges SET state='invalid' WHERE account_id=? AND state IN('pending','sent')", (account["id"],))
                db.execute("DELETE FROM sessions WHERE account_id=?", (account["id"],))
                result = self._new_session(db, account["id"], now)
        if denied:
            raise _denied()
        return result

    def logout(self, token):
        with self._transaction() as db:
            digest = self._token_hash(token)
            if digest is not None:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
        return AuthResult({"authenticated": False}, clear_session=True)

    def request_password_reset(self, email):
        email = _email(email)
        with self._transaction() as db:
            row = db.execute("SELECT id FROM accounts WHERE email=?", (email,)).fetchone()
        return self._issue("reset", email, account_id=row[0] if row is not None else None)

    def complete_password_reset(self, challenge_id, code, new_password):
        password, now = _password(new_password), self._now()
        denied = False
        with self._transaction() as db:
            row = self._checked_challenge(db, challenge_id, code, "reset", now)
            account = None if row is None or row["account_id"] is None else db.execute("SELECT * FROM accounts WHERE id=?", (row["account_id"],)).fetchone()
            if row is None or account is None or account["email"] != row["email"]:
                denied = True
            else:
                self._rate(db, "hash-global", "all", now, GLOBAL_LOGIN_WINDOW, GLOBAL_LOGIN_LIMIT)
                salt = secrets.token_bytes(32)
                digest = self._hash(password, salt)
                db.execute("UPDATE accounts SET salt=?,digest=?,version=version+1 WHERE id=?", (salt, digest, account["id"]))
                db.execute("UPDATE challenges SET state='used' WHERE id=?", (challenge_id,))
                db.execute("UPDATE challenges SET state='invalid' WHERE account_id=? AND state IN('pending','sent')", (account["id"],))
                db.execute("DELETE FROM sessions WHERE account_id=?", (account["id"],))
        if denied:
            raise _denied()
        return AuthResult({"password_changed": True, "authenticated": False}, clear_session=True)
