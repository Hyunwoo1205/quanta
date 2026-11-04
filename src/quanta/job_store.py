"""Transactional, owner-scoped service records backed by SQLite.

JSON records preserve authored number spellings such as signed zero; canonical
bytes are used only for the explicitly canonical idempotency request identity.
The single numerical worker is enforced both by its process lock and atomic claim.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import time
import uuid

from .hashing import canonical_bytes

TERMINAL = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})


class ServiceError(ValueError):
    def __init__(self, status: int, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details or {}


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _same_record(left, right) -> bool:
    if canonical_bytes(left) != canonical_bytes(right):
        return False
    def zeros(a, b):
        if isinstance(a, dict):
            return all(zeros(value, b[key]) for key, value in a.items())
        if isinstance(a, list):
            return all(zeros(value, other) for value, other in zip(a, b))
        if isinstance(a, (int, float)) and not isinstance(a, bool) and a == 0:
            return math.copysign(1, a) == math.copysign(1, b)
        return True
    return zeros(left, right)


def _date(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def _error(code: str, message: str) -> dict:
    if code in {"QUEUE_TIMEOUT", "RESOURCE_LIMIT"}:
        category = "resource"
    elif code in {"MODEL_UNSUPPORTED", "PORT_INCOMPATIBLE", "REPRESENTATION_UNSUPPORTED", "REGISTRY_SNAPSHOT_UNAVAILABLE"}:
        category = "support"
    elif code in {"EXPRESSION_DOMAIN", "NUM_NOT_CONVERGED", "NUM_GRID_NOT_CONVERGED"}:
        category = "numerical"
    elif code in {"INPUT_SCHEMA", "INPUT_SEMANTIC", "IDEMPOTENCY_CONFLICT", "REVISION_CONFLICT"}:
        category = "input"
    else:
        category = "runtime"
    return {"code": code, "category": category,
            "message": message, "path": None, "step_id": None, "branch_index": None,
            "retryable": code in {"QUEUE_TIMEOUT", "ENGINE_FAILURE"}, "details": {}}


class JobStore:
    """Each method opens a short transaction; no connection crosses a thread."""

    def __init__(self, directory: str | Path, *, clock=time.time, max_queued: int = 10,
                 max_queue_wait: float = 600, idempotency_seconds: float = 86400):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "jobs.sqlite3"
        self.clock = clock
        self.max_queued = max_queued
        self.max_queue_wait = max_queue_wait
        self.idempotency_seconds = idempotency_seconds
        with self._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS experiments (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, experiment_id TEXT UNIQUE NOT NULL,
                    owner TEXT NOT NULL, title TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS revisions (
                    revision_id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(experiment_id),
                    owner TEXT NOT NULL, envelope TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE NOT NULL,
                    owner TEXT NOT NULL, revision_id TEXT NOT NULL REFERENCES revisions(revision_id),
                    status TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
                    replay_of TEXT, plan TEXT NOT NULL, progress TEXT NOT NULL, diagnostics TEXT NOT NULL,
                    report TEXT);
                CREATE TABLE IF NOT EXISTS idempotency (
                    owner TEXT NOT NULL, endpoint TEXT NOT NULL, key TEXT NOT NULL,
                    body_sha TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(run_id), expires_at REAL NOT NULL,
                    PRIMARY KEY(owner,endpoint,key));
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(run_id),
                    at REAL NOT NULL, status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
                    metadata TEXT NOT NULL, data BLOB NOT NULL);
                CREATE INDEX IF NOT EXISTS runs_queue ON runs(status,seq);
                CREATE INDEX IF NOT EXISTS experiments_owner ON experiments(owner,seq);
                CREATE TRIGGER IF NOT EXISTS immutable_revision BEFORE UPDATE ON revisions
                    BEGIN SELECT RAISE(ABORT,'immutable revision'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_terminal BEFORE UPDATE ON runs
                    WHEN OLD.status IN ('SUCCEEDED','FAILED','CANCELLED')
                    BEGIN SELECT RAISE(ABORT,'immutable terminal run'); END;
            """)
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.rollback()
                raise
            else:
                db.commit()

    @staticmethod
    def _owned(db, table: str, column: str, owner: str, ident: str):
        row = db.execute(f"SELECT * FROM {table} WHERE {column}=? AND owner=?", (ident, owner)).fetchone()
        if row is None:
            raise ServiceError(404, "NOT_FOUND", "The requested record does not exist")
        return row

    def create_experiment(self, owner: str, title: str) -> dict:
        ident, now = str(uuid.uuid4()), self.clock()
        with self._transaction() as db:
            db.execute("INSERT INTO experiments(experiment_id,owner,title,created_at) VALUES(?,?,?,?)",
                       (ident, owner, title, now))
        return {"experiment_id": ident, "title": title, "created_at": _date(now), "revision_ids": []}

    def get_experiment(self, owner: str, experiment_id: str) -> dict:
        with self._connection() as db:
            row = self._owned(db, "experiments", "experiment_id", owner, experiment_id)
            revisions = [r[0] for r in db.execute("SELECT revision_id FROM revisions WHERE experiment_id=? ORDER BY rowid", (experiment_id,))]
        return {"experiment_id": experiment_id, "title": row["title"], "created_at": _date(row["created_at"]), "revision_ids": revisions}

    def list_experiments(self, owner: str, *, limit: int = 50, cursor: str | None = None) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ServiceError(422, "INPUT_SCHEMA", "limit must be an integer between 1 and 100")
        with self._connection() as db:
            seq = 0
            if cursor is not None:
                row = self._owned(db, "experiments", "experiment_id", owner, cursor)
                seq = row["seq"]
            rows = db.execute("SELECT * FROM experiments WHERE owner=? AND seq>? ORDER BY seq LIMIT ?", (owner, seq, limit+1)).fetchall()
            items = [{"experiment_id": r["experiment_id"], "title": r["title"], "created_at": _date(r["created_at"])} for r in rows[:limit]]
        return {"items": items, "next_cursor": items[-1]["experiment_id"] if len(rows) > limit else None}

    def create_revision(self, owner: str, experiment_id: str, body: dict) -> dict:
        """Store an already validated revision body under server-generated identity."""
        envelope = {"schema_version": body["schema_version"], "title": body["title"], "definition": body["definition"],
                    "experiment_id": experiment_id, "revision_id": str(uuid.uuid4()), "created_at": _date(self.clock())}
        encoded = _json(envelope)
        with self._transaction() as db:
            self._owned(db, "experiments", "experiment_id", owner, experiment_id)
            db.execute("INSERT INTO revisions VALUES(?,?,?,?)", (envelope["revision_id"], experiment_id, owner, encoded))
        return json.loads(encoded)

    def get_revision(self, owner: str, revision_id: str) -> dict:
        with self._connection() as db:
            return json.loads(self._owned(db, "revisions", "revision_id", owner, revision_id)["envelope"])

    def _event(self, db, run_id: str, status: str, now: float):
        db.execute("INSERT INTO events(run_id,at,status) VALUES(?,?,?)", (run_id, now, status))

    def _run(self, db, row, *, include_report=False) -> dict:
        result = {"run_id": row["run_id"], "revision_id": row["revision_id"], "execution_status": row["status"],
                  "created_at": _date(row["created_at"]), "updated_at": _date(row["updated_at"]),
                  "replay_of": row["replay_of"], "progress": json.loads(row["progress"]),
                  "diagnostics": json.loads(row["diagnostics"]),
                  "artifacts": [json.loads(a[0]) for a in db.execute("SELECT metadata FROM artifacts WHERE run_id=? ORDER BY rowid", (row["run_id"],))],
                  "events": [{"execution_status": e["status"], "at": _date(e["at"])} for e in db.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (row["run_id"],))]}
        plan = json.loads(row["plan"])
        result.update(input_sha256=plan.get("input_sha256"), resolved_input_sha256=plan.get("resolved_input_sha256"))
        if include_report:
            result.update(owner=row["owner"], plan=plan, report=json.loads(row["report"]) if row["report"] else None)
        if row["report"]:
            report = json.loads(row["report"])
            payload = report.get("result") or {}
            for name in ("numerical_status", "resolution_status", "physical_validation_status", "partial", "execution_fingerprint"):
                if name in payload:
                    result[name] = payload[name]
        return result

    def _expire_queue(self, db, now):
        rows = db.execute("SELECT run_id FROM runs WHERE status='QUEUED' AND created_at<=?", (now-self.max_queue_wait,)).fetchall()
        for row in rows:
            db.execute("UPDATE runs SET status='FAILED',updated_at=?,diagnostics=? WHERE run_id=?", (now, _json([_error("QUEUE_TIMEOUT", "The queued run exceeded the queue-wait limit")]), row[0]))
            self._event(db, row[0], "FAILED", now)

    def submit(self, owner: str, revision_id: str, plan: dict, *, idempotency_key: str,
               endpoint: str = "/v1/runs", body: dict | None = None, replay_of: str | None = None) -> tuple[dict, bool]:
        if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 200 or any(ord(c) < 33 or ord(c) > 126 for c in idempotency_key):
            raise ServiceError(422, "INPUT_SCHEMA", "Idempotency-Key must contain 1 to 200 visible ASCII characters")
        body_sha = hashlib.sha256(canonical_bytes(body if body is not None else {"revision_id": revision_id})).hexdigest()
        now = self.clock()
        with self._transaction() as db:
            self._owned(db, "revisions", "revision_id", owner, revision_id)
            if replay_of is not None:
                self._owned(db, "runs", "run_id", owner, replay_of)
            previous = db.execute("SELECT * FROM idempotency WHERE owner=? AND endpoint=? AND key=?", (owner, endpoint, idempotency_key)).fetchone()
            if previous and previous["expires_at"] > now:
                if previous["body_sha"] != body_sha:
                    raise ServiceError(409, "IDEMPOTENCY_CONFLICT", "This key was already used with a different request body")
                row = db.execute("SELECT * FROM runs WHERE run_id=?", (previous["run_id"],)).fetchone()
                return self._run(db, row), False
            if previous:
                db.execute("DELETE FROM idempotency WHERE owner=? AND endpoint=? AND key=?", (owner, endpoint, idempotency_key))
            self._expire_queue(db, now)
            count = db.execute("SELECT count(*) FROM runs WHERE owner=? AND status='QUEUED'", (owner,)).fetchone()[0]
            if count >= self.max_queued:
                raise ServiceError(429, "RESOURCE_LIMIT", "The owner queue is full", {"limit": self.max_queued, "requested": count+1})
            run_id = str(uuid.uuid4())
            steps = len(plan["frozen_plan"]["expanded_steps"])
            progress = {"completed_steps": 0, "total_steps": steps, "active_step": None, "active_branch": None}
            db.execute("INSERT INTO runs(run_id,owner,revision_id,status,created_at,updated_at,replay_of,plan,progress,diagnostics) VALUES(?,?,?,'QUEUED',?,?,?,?,?,?)",
                       (run_id, owner, revision_id, now, now, replay_of, _json(plan), _json(progress), "[]"))
            db.execute("INSERT INTO idempotency VALUES(?,?,?,?,?,?)", (owner, endpoint, idempotency_key, body_sha, run_id, now+self.idempotency_seconds))
            self._event(db, run_id, "QUEUED", now)
            return self._run(db, db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()), True

    def lookup_idempotency(self, owner: str, endpoint: str, key: str, body: dict) -> dict | None:
        body_sha = hashlib.sha256(canonical_bytes(body)).hexdigest()
        with self._connection() as db:
            previous = db.execute("SELECT * FROM idempotency WHERE owner=? AND endpoint=? AND key=? AND expires_at>?",
                                  (owner, endpoint, key, self.clock())).fetchone()
            if previous is None:
                return None
            if previous["body_sha"] != body_sha:
                raise ServiceError(409, "IDEMPOTENCY_CONFLICT", "This key was already used with a different request body")
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (previous["run_id"],)).fetchone()
            return self._run(db, row)

    def get_job(self, run_id: str) -> dict:
        """Trusted worker lookup; never expose this method as an HTTP route."""
        with self._connection() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise ServiceError(404, "NOT_FOUND", "The requested record does not exist")
            result = self._run(db, row, include_report=True)
            result["revision"] = json.loads(self._owned(db, "revisions", "revision_id", row["owner"], row["revision_id"])["envelope"])
            return result

    def get_run(self, owner: str, run_id: str, *, include_report: bool = False) -> dict:
        with self._connection() as db:
            return self._run(db, self._owned(db, "runs", "run_id", owner, run_id), include_report=include_report)

    def get_report(self, owner: str, run_id: str) -> dict | None:
        return self.get_run(owner, run_id, include_report=True)["report"]

    def list_runs(self, owner: str, *, experiment_id: str | None = None,
                  limit: int = 50, cursor: str | None = None) -> dict:
        """Newest-first durable history, with owner-scoped opaque run cursors."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ServiceError(422, "INPUT_SCHEMA", "limit must be an integer between 1 and 100")
        with self._connection() as db:
            if experiment_id is not None:
                self._owned(db, "experiments", "experiment_id", owner, experiment_id)
            clauses, parameters = ["r.owner=?"], [owner]
            if experiment_id is not None:
                clauses.append("v.experiment_id=?")
                parameters.append(experiment_id)
            if cursor is not None:
                previous = self._owned(db, "runs", "run_id", owner, cursor)
                if experiment_id is not None:
                    revision = self._owned(db, "revisions", "revision_id", owner, previous["revision_id"])
                    if revision["experiment_id"] != experiment_id:
                        raise ServiceError(404, "NOT_FOUND", "The requested record does not exist")
                clauses.append("r.seq<?")
                parameters.append(previous["seq"])
            rows = db.execute("SELECT r.*,v.experiment_id FROM runs r JOIN revisions v "
                              "ON v.revision_id=r.revision_id WHERE " + " AND ".join(clauses)
                              + " ORDER BY r.seq DESC LIMIT ?", (*parameters, limit + 1))
            # A report can be large. Keep only one source row at a time while
            # materializing bounded metadata, rather than buffering reports.
            items, more = [], False
            for index, row in enumerate(rows):
                if index == limit:
                    more = True
                    break
                items.append({**self._run(db, row), "experiment_id": row["experiment_id"]})
        return {"items": items, "next_cursor": items[-1]["run_id"] if more else None}

    def claim_next(self) -> dict | None:
        now = self.clock()
        with self._transaction() as db:
            self._expire_queue(db, now)
            if db.execute("SELECT 1 FROM runs WHERE status IN ('RUNNING','CANCEL_REQUESTED') LIMIT 1").fetchone():
                return None
            row = db.execute("SELECT * FROM runs WHERE status='QUEUED' ORDER BY seq LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE runs SET status='RUNNING',updated_at=? WHERE run_id=?", (now, row["run_id"]))
            self._event(db, row["run_id"], "RUNNING", now)
            claimed = self._run(db, db.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone(), include_report=True)
            claimed["revision"] = json.loads(self._owned(db, "revisions", "revision_id", row["owner"], row["revision_id"])["envelope"])
            return claimed

    def update_progress(self, run_id: str, progress: dict) -> bool:
        with self._transaction() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None or row["status"] != "RUNNING":
                return False
            old = json.loads(row["progress"])
            if (not isinstance(progress, dict)
                    or set(progress) != {"completed_steps", "total_steps", "active_step", "active_branch"}
                    or type(progress["completed_steps"]) is not int or type(progress["total_steps"]) is not int
                    or progress["total_steps"] != old["total_steps"]
                    or not old["completed_steps"] <= progress["completed_steps"] <= old["total_steps"]
                    or (progress["active_step"] is not None and not isinstance(progress["active_step"], str))
                    or (progress["active_branch"] is not None and (type(progress["active_branch"]) is not int or progress["active_branch"] < 0))):
                raise ServiceError(422, "INPUT_SEMANTIC", "Invalid or decreasing step progress")
            db.execute("UPDATE runs SET progress=?,updated_at=? WHERE run_id=?", (_json(progress), self.clock(), run_id))
            return True

    def cancel(self, owner: str, run_id: str) -> tuple[dict, bool]:
        with self._transaction() as db:
            row = self._owned(db, "runs", "run_id", owner, run_id)
            status = row["status"]
            changed = status in {"QUEUED", "RUNNING"}
            if changed:
                next_status = "CANCELLED" if status == "QUEUED" else "CANCEL_REQUESTED"
                now = self.clock()
                diagnostics = [_error("CANCELLED", "Cancellation was requested before execution" if status == "QUEUED" else "Cancellation was requested")]
                db.execute("UPDATE runs SET status=?,updated_at=?,diagnostics=? WHERE run_id=?", (next_status, now, _json(diagnostics), run_id))
                self._event(db, run_id, next_status, now)
                row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            return self._run(db, row), changed

    def cancellation_requested(self, run_id: str) -> bool:
        with self._connection() as db:
            row = db.execute("SELECT status FROM runs WHERE run_id=?", (run_id,)).fetchone()
            return row is None or row[0] in {"CANCEL_REQUESTED", "CANCELLED"}

    def finish(self, run_id: str, report: dict) -> dict:
        """Publish a complete validated report atomically with its artifact bytes.

        If cancellation won the transaction race, a non-cancelled report is not
        published. The caller must provide its cancellation-finalized report.
        """
        result = report.get("result")
        if not result or result.get("run_id") != run_id or result.get("execution_status") not in TERMINAL:
            raise ServiceError(422, "INPUT_SEMANTIC", "The result does not identify a terminal execution")
        status = result["execution_status"]
        # Validate outside the write transaction: integrity checking may inspect
        # a large report but must not hold the queue's publication lock.
        from .run_store import validate_run_report
        checked = validate_run_report(report)
        if not checked["valid"]:
            raise ServiceError(422, "BUNDLE_INTEGRITY", "Execution report failed validation", {"errors": checked["errors"]})
        contents = report.get("artifact_contents", {})
        artifacts = []
        for metadata in result.get("artifacts", []):
            raw = contents.get(metadata["artifact_id"])
            if not isinstance(raw, str):
                raise ServiceError(422, "INPUT_SEMANTIC", "Artifact content is missing")
            data = raw.encode("utf-8")
            if len(data) != metadata["size_bytes"] or hashlib.sha256(data).hexdigest() != metadata["sha256"]:
                raise ServiceError(422, "INPUT_SEMANTIC", "Artifact content does not match its manifest")
            artifacts.append((metadata["artifact_id"], run_id, _json(metadata), data))
        encoded = _json(report)
        now = self.clock()
        with self._transaction() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise ServiceError(404, "NOT_FOUND", "The requested record does not exist")
            if row["status"] in TERMINAL:
                return self._run(db, row)
            if (not _same_record(report.get("plan"), json.loads(row["plan"]))
                    or result.get("revision_id") != row["revision_id"]
                    or result.get("provenance", {}).get("replay_of") != row["replay_of"]):
                raise ServiceError(409, "REVISION_CONFLICT", "Execution evidence differs from the frozen submission")
            if row["status"] == "CANCEL_REQUESTED" and status != "CANCELLED":
                return self._run(db, row)
            if row["status"] != "CANCEL_REQUESTED" and status == "CANCELLED":
                raise ServiceError(409, "STATE_CONFLICT", "Cancellation was not committed before the result")
            if row["status"] != "RUNNING" and status != "CANCELLED":
                raise ServiceError(409, "STATE_CONFLICT", "Only a running job may publish a result")
            progress = json.loads(row["progress"])
            progress.update(completed_steps=max(progress["completed_steps"], sum(s["outcome"] != "CANCELLED" for s in result.get("steps", []))), active_step=None, active_branch=None)
            db.execute("UPDATE runs SET status=?,updated_at=?,report=?,progress=?,diagnostics=? WHERE run_id=?",
                       (status, now, encoded, _json(progress), _json(result.get("errors", [])), run_id))
            db.executemany("INSERT INTO artifacts VALUES(?,?,?,?)", artifacts)
            self._event(db, run_id, status, now)
            return self._run(db, db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone())

    def fail(self, run_id: str, code: str, message: str) -> dict:
        now = self.clock()
        with self._transaction() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise ServiceError(404, "NOT_FOUND", "The requested record does not exist")
            if row["status"] not in TERMINAL:
                status = "CANCELLED" if row["status"] == "CANCEL_REQUESTED" else "FAILED"
                progress = json.loads(row["progress"])
                progress.update(active_step=None, active_branch=None)
                db.execute("UPDATE runs SET status=?,updated_at=?,diagnostics=?,progress=? WHERE run_id=?", (status, now, _json([_error(code, message)]), _json(progress), run_id))
                self._event(db, run_id, status, now)
                row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            return self._run(db, row)

    def get_artifacts(self, owner: str, run_id: str) -> list[dict]:
        return self.get_run(owner, run_id)["artifacts"]

    def get_artifact(self, owner: str, artifact_id: str) -> tuple[dict, bytes]:
        with self._connection() as db:
            row = db.execute("SELECT a.* FROM artifacts a JOIN runs r ON a.run_id=r.run_id WHERE a.artifact_id=? AND r.owner=?", (artifact_id, owner)).fetchone()
            if row is None:
                raise ServiceError(404, "NOT_FOUND", "The requested record does not exist")
            data, metadata = bytes(row["data"]), json.loads(row["metadata"])
            if len(data) != metadata["size_bytes"] or hashlib.sha256(data).hexdigest() != metadata["sha256"]:
                raise ServiceError(500, "STORAGE_INTEGRITY", "Stored artifact bytes failed integrity verification")
            return metadata, data

    def recover_interrupted(self) -> int:
        """Call only while holding the service's exclusive numerical-worker lock."""
        now = self.clock()
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM runs WHERE status IN ('RUNNING','CANCEL_REQUESTED')").fetchall()
            for row in rows:
                status = "CANCELLED" if row["status"] == "CANCEL_REQUESTED" else "FAILED"
                diagnostic = _error("ENGINE_FAILURE", "The service stopped during execution; replay starts a new run")
                progress = json.loads(row["progress"])
                progress.update(active_step=None, active_branch=None)
                db.execute("UPDATE runs SET status=?,updated_at=?,diagnostics=?,progress=? WHERE run_id=?", (status, now, _json([diagnostic]), _json(progress), row["run_id"]))
                self._event(db, row["run_id"], status, now)
            self._expire_queue(db, now)
            return len(rows)
