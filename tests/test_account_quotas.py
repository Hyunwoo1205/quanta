"""Public-account admission boundaries against real, transactional SQLite."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from quanta import job_store as module
from quanta.job_store import JobStore, ServiceError


FIRST = "account-" + "a" * 32
SECOND = "account-" + "b" * 32
PLAN = {"frozen_plan": {"expanded_steps": []}}
BODY = {"schema_version": "0.2.0", "title": "Quota test", "definition": {}}


class AccountQuotaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "store"
        self.now = 100_000.0
        self.store = JobStore(self.directory, clock=lambda: self.now)

    def revision(self, owner=FIRST):
        experiment = self.store.create_experiment(owner, "Private experiment")
        return self.store.create_revision(owner, experiment["experiment_id"], BODY)["revision_id"]

    def submit(self, owner, revision, key):
        return self.store.submit(owner, revision, PLAN, idempotency_key=key)

    def denied(self, function, resource):
        with self.assertRaises(ServiceError) as error:
            function()
        self.assertEqual(error.exception.status, 429)
        self.assertEqual(error.exception.code, "RESOURCE_LIMIT")
        self.assertEqual(error.exception.details["resource"], resource)

    def stored_bytes(self, owner, size, key):
        revision = self.revision(owner)
        run, _ = self.submit(owner, revision, key)
        self.store.fail(run["run_id"], "ENGINE_FAILURE", "Synthetic terminal fixture")
        with self.store._transaction() as db:
            db.execute("INSERT INTO artifacts VALUES(?,?,?,zeroblob(?))",
                       ("artifact-" + key, run["run_id"], json.dumps({"fixture": True}), size))
        return run

    def test_experiment_quota_is_per_public_account_and_legacy_owners_are_unchanged(self):
        with patch.object(module, "ACCOUNT_EXPERIMENT_LIMIT", 2):
            for _ in range(2):
                self.store.create_experiment(FIRST, "Own")
            self.denied(lambda: self.store.create_experiment(FIRST, "Third"), "experiments")
            self.store.create_experiment(SECOND, "Other owner")
            for owner in ("local", "existing-access-principal", "account-" + "A" * 32,
                          "account-" + "a" * 33, "account-" + "g" * 32):
                for _ in range(3):
                    self.store.create_experiment(owner, "Existing policy")
        self.assertEqual(len(self.store.list_experiments(FIRST)["items"]), 2)
        self.assertEqual(len(self.store.list_experiments(SECOND)["items"]), 1)

    def test_revision_quota_preserves_ownership_error_before_admission(self):
        experiment = self.store.create_experiment(FIRST, "Own")
        with patch.object(module, "ACCOUNT_REVISION_LIMIT", 2):
            for _ in range(2):
                self.store.create_revision(FIRST, experiment["experiment_id"], BODY)
            self.denied(lambda: self.store.create_revision(FIRST, experiment["experiment_id"], BODY), "revisions")
            with self.assertRaises(ServiceError) as error:
                self.store.create_revision(SECOND, experiment["experiment_id"], BODY)
            self.assertEqual(error.exception.status, 404)
        self.assertEqual(len(self.store.get_experiment(FIRST, experiment["experiment_id"])["revision_ids"]), 2)

    def test_rolling_run_limit_keeps_idempotency_and_expires_after_24_hours(self):
        revision = self.revision()
        with patch.object(module, "ACCOUNT_RUNS_PER_DAY", 2):
            original = None
            for key in ("first", "second"):
                run, created = self.submit(FIRST, revision, key)
                self.assertTrue(created)
                original = original or run
                self.store.fail(run["run_id"], "ENGINE_FAILURE", "Fixture completed")
            self.denied(lambda: self.submit(FIRST, revision, "third"), "new_runs_per_rolling_24_hours")
            repeated, created = self.submit(FIRST, revision, "first")
            self.assertFalse(created)
            self.assertEqual(repeated["run_id"], original["run_id"])
            with self.assertRaises(ServiceError) as error:
                self.submit(SECOND, revision, "first")
            self.assertEqual(error.exception.status, 404)
            self.now += 86400
            _, created = self.submit(FIRST, revision, "fresh-day")
            self.assertTrue(created)

    def test_queued_running_and_cancellation_pending_each_hold_the_single_account_slot(self):
        revision = self.revision()
        run, _ = self.submit(FIRST, revision, "first")
        self.denied(lambda: self.submit(FIRST, revision, "second"), "active_runs")
        self.assertEqual(self.store.claim_next()["run_id"], run["run_id"])
        self.denied(lambda: self.submit(FIRST, revision, "second"), "active_runs")
        result, _ = self.store.cancel(FIRST, run["run_id"])
        self.assertEqual(result["execution_status"], "CANCEL_REQUESTED")
        self.denied(lambda: self.submit(FIRST, revision, "second"), "active_runs")
        self.store.fail(run["run_id"], "ENGINE_FAILURE", "Cancellation child exited")
        self.assertTrue(self.submit(FIRST, revision, "second")[1])

    def test_global_public_active_limit_excludes_the_legacy_owner(self):
        legacy_revision = self.revision("local")
        for index in range(3):
            self.submit("local", legacy_revision, "legacy-" + str(index))
        first_revision, second_revision = self.revision(), self.revision(SECOND)
        with patch.object(module, "PUBLIC_ACTIVE_RUN_LIMIT", 1):
            first, _ = self.submit(FIRST, first_revision, "first")
            self.denied(lambda: self.submit(SECOND, second_revision, "second"), "shared_active_runs")
            self.store.cancel(FIRST, first["run_id"])
            self.assertTrue(self.submit(SECOND, second_revision, "second")[1])

    def test_artifact_budget_reserves_a_full_run_before_admission(self):
        with patch.object(module, "ACCOUNT_ARTIFACT_BYTES", 100), \
                patch.object(module, "RUN_ARTIFACT_RESERVATION_BYTES", 32):
            self.stored_bytes(FIRST, 69, "stored-first")
            revision = self.revision()
            self.denied(lambda: self.submit(FIRST, revision, "no-space"), "artifact_bytes")
            self.stored_bytes(SECOND, 68, "stored-second")
            other_revision = self.revision(SECOND)
            self.assertTrue(self.submit(SECOND, other_revision, "exact-space")[1])

    def test_global_artifact_budget_includes_other_public_active_reservations_only(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(module, "ACCOUNT_ARTIFACT_BYTES", 1000))
            stack.enter_context(patch.object(module, "PUBLIC_ARTIFACT_BYTES", 114))
            stack.enter_context(patch.object(module, "RUN_ARTIFACT_RESERVATION_BYTES", 32))
            self.stored_bytes("local", 1000, "legacy-storage")
            self.stored_bytes("account-not-a-generated-owner", 1000, "unrelated-storage")
            self.stored_bytes(FIRST, 51, "public-storage")
            other_revision = self.revision(SECOND)
            other, _ = self.submit(SECOND, other_revision, "public-reservation")
            revision = self.revision(FIRST)
            self.denied(lambda: self.submit(FIRST, revision, "would-overcommit"), "shared_artifact_bytes")
            self.store.cancel(SECOND, other["run_id"])
            self.assertTrue(self.submit(FIRST, revision, "would-overcommit")[1])

    def test_global_scientific_record_cap_counts_each_kind_and_no_legacy_rows(self):
        for _ in range(4):
            self.store.create_experiment("local", "Unchanged legacy record")
        with patch.object(module, "PUBLIC_RECORD_LIMIT", 3):
            revision = self.revision()
            self.submit(FIRST, revision, "third-public-record")
            self.denied(lambda: self.store.create_experiment(SECOND, "Fourth public record"), "shared_scientific_records")
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM experiments WHERE owner=?", (SECOND,)).fetchone()[0], 0)

    def test_two_connections_cannot_both_claim_the_last_experiment_slot(self):
        another = JobStore(self.directory, clock=lambda: self.now)
        barrier = threading.Barrier(2)
        def create(store):
            barrier.wait(timeout=5)
            try:
                store.create_experiment(FIRST, "Contended final slot")
                return "created"
            except ServiceError as exc:
                return exc.status
        with patch.object(module, "ACCOUNT_EXPERIMENT_LIMIT", 1), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, (self.store, another)))
        self.assertCountEqual(results, ["created", 429])
        self.assertEqual(len(self.store.list_experiments(FIRST)["items"]), 1)

    def test_two_connections_cannot_both_admit_a_public_run_and_retry_does_not_add_events(self):
        revision = self.revision()
        another = JobStore(self.directory, clock=lambda: self.now)
        barrier = threading.Barrier(2)
        def submit(item):
            store, key = item
            barrier.wait(timeout=5)
            try:
                return store.submit(FIRST, revision, PLAN, idempotency_key=key)[0]
            except ServiceError as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, ((self.store, "contender-a"), (another, "contender-b"))))
        successes = [result for result in results if isinstance(result, dict)]
        self.assertEqual(len(successes), 1)
        self.assertIn(429, results)
        with self.store._connection() as db:
            key = db.execute("SELECT key FROM idempotency").fetchone()[0]
        repeated, created = self.submit(FIRST, revision, key)
        self.assertFalse(created)
        self.assertEqual(repeated["run_id"], successes[0]["run_id"])
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 1)

    def test_queue_expiry_releases_the_active_reservation_before_admission(self):
        self.store.max_queue_wait = 1
        revision = self.revision()
        old, _ = self.submit(FIRST, revision, "old")
        self.now += 2
        new, created = self.submit(FIRST, revision, "replacement")
        self.assertTrue(created)
        self.assertNotEqual(old["run_id"], new["run_id"])
        self.assertEqual(self.store.get_run(FIRST, old["run_id"])["execution_status"], "FAILED")

    def test_two_public_accounts_cannot_both_take_last_shared_active_slot(self):
        first_revision, second_revision = self.revision(), self.revision(SECOND)
        another = JobStore(self.directory, clock=lambda: self.now)
        barrier = threading.Barrier(2)
        def submit(item):
            store, owner, revision = item
            barrier.wait(timeout=5)
            try:
                store.submit(owner, revision, PLAN, idempotency_key="shared-final-slot")
                return "created"
            except ServiceError as exc:
                return exc.status
        with patch.object(module, "PUBLIC_ACTIVE_RUN_LIMIT", 1), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, ((self.store, FIRST, first_revision), (another, SECOND, second_revision))))
        self.assertCountEqual(results, ["created", 429])

    def test_publication_cannot_overrun_reservation_or_leave_partial_artifacts(self):
        revision = self.revision()
        run, _ = self.submit(FIRST, revision, "publish")
        self.store.claim_next()
        artifact_id = str(uuid.uuid4())
        def report(size):
            content = "x" * size
            return {"plan": PLAN, "artifact_contents": {artifact_id: content}, "result": {
                "run_id": run["run_id"], "revision_id": revision, "execution_status": "SUCCEEDED",
                "provenance": {"replay_of": None}, "steps": [], "artifacts": [{
                    "artifact_id": artifact_id, "size_bytes": size,
                    "sha256": hashlib.sha256(content.encode()).hexdigest()}]}}
        # This test isolates the publication boundary after the independent
        # scientific report validator. All stored rows and transactions are real.
        with patch.object(module, "RUN_ARTIFACT_RESERVATION_BYTES", 32), \
                patch("quanta.run_store.validate_run_report", return_value={"valid": True}):
            self.denied(lambda: self.store.finish(run["run_id"], report(33)), "run_artifact_bytes")
            with self.store._connection() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM artifacts").fetchone()[0], 0)
                current = db.execute("SELECT status,report FROM runs WHERE run_id=?", (run["run_id"],)).fetchone()
                self.assertEqual(tuple(current), ("RUNNING", None))
            result = self.store.finish(run["run_id"], report(32))
            self.assertEqual(result["execution_status"], "SUCCEEDED")
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT length(data) FROM artifacts").fetchone()[0], 32)

    def test_publication_failure_does_not_change_other_account_or_legacy_data(self):
        local_revision = self.revision("local")
        local_run, _ = self.submit("local", local_revision, "legacy")
        self.store.cancel("local", local_run["run_id"])
        before = self.store.get_run("local", local_run["run_id"])
        revision = self.revision()
        run, _ = self.submit(FIRST, revision, "public")
        self.store.claim_next()
        with self.store._transaction() as db:
            with patch.object(module, "RUN_ARTIFACT_RESERVATION_BYTES", 32):
                self.denied(lambda: self.store._public_artifact_publication(db, FIRST, 33), "run_artifact_bytes")
                self.store._public_artifact_publication(db, "local", 1000000)
        self.assertEqual(self.store.get_run("local", local_run["run_id"]), before)
        self.assertEqual(self.store.get_run(FIRST, run["run_id"])["execution_status"], "RUNNING")


if __name__ == "__main__":
    unittest.main()
