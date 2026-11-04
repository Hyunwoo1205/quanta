"""A dead worker exits the actual server so the host can restart it."""
from __future__ import annotations

import asyncio
import fcntl
import os
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace

from quanta.production_server import ProductionServer


def test_worker_watchdog_and_normal_shutdown_have_different_outcomes():
    app = SimpleNamespace(_started=True, worker=SimpleNamespace(healthy=False))
    failed = ProductionServer(app, port=0)
    failed.started = True
    assert asyncio.run(failed.on_tick(1)) is True
    assert failed.worker_failed
    normal = ProductionServer(app, port=0)
    normal.started = True
    normal.should_exit = True
    assert asyncio.run(normal.on_tick(1)) is True
    assert not normal.worker_failed
    starting = ProductionServer(app, port=0)
    assert asyncio.run(starting.on_tick(1)) is False


def test_actual_cli_exits_nonzero_when_numerical_supervisor_dies(tmp_path):
    store = tmp_path / "service"
    env = {**os.environ, "QUANTA_PUBLIC_ORIGIN": "https://quanta.example.com",
           "QUANTA_ACCESS_TEAM_DOMAIN": "quanta.cloudflareaccess.com",
           "QUANTA_ACCESS_AUDIENCE": "supervision-test",
           "QUANTA_ALLOWED_EMAIL": "owner@example.com"}
    process = subprocess.Popen([sys.executable, "-m", "quanta", "serve-production",
        "--store", str(store), "--port", "0"], env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            lock = store / "worker.lock"
            if lock.is_file():
                with lock.open("rb") as fd:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        break
            assert process.poll() is None, process.stderr.read().decode()
            time.sleep(0.025)
        else:
            raise AssertionError("Production numerical worker did not start")
        # This is a real fatal database error in claim_next, not a fake health flag.
        with sqlite3.connect(store / "jobs.sqlite3") as db:
            db.execute("DROP TABLE runs")
        _, error = process.communicate(timeout=10)
        assert process.returncode == 2, error.decode()
        # Shutdown relinquishes the process lock, allowing a replacement owner.
        with (store / "worker.lock").open("rb") as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
