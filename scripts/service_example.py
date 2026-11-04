#!/usr/bin/env python3
"""Submit an example to an already-running local Quanta API and show its result."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8765")
    args = parser.parse_args()
    token = os.environ.get("QUANTA_API_TOKEN")
    if not token:
        parser.error("Set QUANTA_API_TOKEN to the same token used by quanta serve")
    source = json.loads(args.file.read_text(encoding="utf-8"))

    def request(method, path, body=None, key=None):
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        raw = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8") if body is not None else None
        with urlopen(Request(args.url.rstrip("/") + path, data=raw, headers=headers, method=method), timeout=15) as response:
            return json.load(response)

    ready_deadline = time.monotonic() + 10
    while True:
        try:
            request("GET", "/v1/capabilities")
            break
        except HTTPError:
            raise
        except URLError:
            if time.monotonic() >= ready_deadline:
                raise
            time.sleep(0.1)
    experiment = request("POST", "/v1/experiments", {"title": source["title"]})
    revision = request("POST", f"/v1/experiments/{experiment['experiment_id']}/revisions",
                       {key: source[key] for key in ("schema_version", "title", "definition")})
    run = request("POST", "/v1/runs", {"revision_id": revision["revision_id"]}, key=str(uuid.uuid4()))
    print("run_id: " + run["run_id"], flush=True)
    end = time.monotonic() + 150
    while run["execution_status"] not in {"SUCCEEDED", "FAILED", "CANCELLED"}:
        if time.monotonic() >= end:
            raise TimeoutError("The client stopped waiting; query the printed run_id for its durable status")
        time.sleep(0.2)
        run = request("GET", f"/v1/runs/{run['run_id']}")
    print(json.dumps(run, ensure_ascii=False, indent=2, allow_nan=False))
    if run["artifacts"]:
        result = request("GET", f"/v1/runs/{run['run_id']}/result")
        for step in result["steps"]:
            print(json.dumps({"step_id": step["step_id"], "outcome": step["outcome"], "payload": step["payload"]},
                             ensure_ascii=False, indent=2, allow_nan=False))
    return 0 if run["execution_status"] == "SUCCEEDED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
