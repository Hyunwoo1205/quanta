#!/usr/bin/env python3
"""Run the standalone A03 probe beside a temporary, independent Quanta service."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output.exists():
        parser.error('output directory must be new')
    output.parent.mkdir(parents=True, exist_ok=True)
    # This temporary API has no production data, account or mail configuration.
    with tempfile.TemporaryDirectory(prefix='quanta-a03-web-') as private:
        env = {**os.environ, 'QUANTA_API_TOKEN': secrets.token_urlsafe(32)}
        log_path = Path(private) / 'service.log'
        with log_path.open('wb') as log:
            service = subprocess.Popen(
                [sys.executable, '-m', 'quanta', 'serve', '--store', str(Path(private) / 'store'), '--port', '8765'],
                env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
            try:
                ready = False
                for _ in range(100):
                    if service.poll() is not None:
                        raise RuntimeError('independent Quanta service exited before probe')
                    try:
                        with urllib.request.urlopen('http://127.0.0.1:8765/', timeout=1) as response:
                            ready = response.status == 200
                        if ready:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                if not ready:
                    raise RuntimeError('independent Quanta service did not become ready')
                return subprocess.call([
                    sys.executable, 'scripts/verify_atomistic_a03.py',
                    '--output-dir', str(output), '--case-timeout', '180',
                    '--web-origin', 'http://127.0.0.1:8765',
                ])
            finally:
                if service.poll() is None:
                    os.killpg(service.pid, signal.SIGTERM)
                try:
                    service.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(service.pid, signal.SIGKILL)
                    service.wait(timeout=5)
                if output.exists():
                    (output / 'independent-web-scope.json').write_text(json.dumps({
                        'scope': 'temporary native CI Quanta API; no OCI or production data',
                        'service_exit_code': service.returncode,
                        'production_service_verified': False,
                    }, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
