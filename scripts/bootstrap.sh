#!/bin/sh
set -eu

QUANTA_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$QUANTA_ROOT"
QUANTA_PYTHON=${QUANTA_PYTHON:-python3}
QUANTA_VENV=${QUANTA_VENV:-.venv}
QUANTA_WHEELHOUSE=${QUANTA_WHEELHOUSE:-.cache/wheels}

QUANTA_LOCK=$("$QUANTA_PYTHON" -c 'import platform, sys; from pathlib import Path; assert platform.python_implementation() == "CPython" and platform.python_version() == "3.12.14", "CPython 3.12.14 is required"; sys.path.insert(0, "src"); from quanta.profiles import profile_for_host, load_lock_files; load_lock_files((Path.cwd(),)); print(profile_for_host()["lock_text"])')
if [ ! -x "$QUANTA_VENV/bin/python" ]; then
  "$QUANTA_PYTHON" -m venv "$QUANTA_VENV"
fi
QUANTA_ENV_PYTHON="$QUANTA_VENV/bin/python"
"$QUANTA_ENV_PYTHON" -c 'import platform, sys; assert platform.python_implementation() == "CPython" and platform.python_version() == "3.12.14", "Existing venv uses a different Python"; sys.path.insert(0, "src"); from quanta.profiles import profile_for_host; profile_for_host()'

export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export PIP_DISABLE_PIP_VERSION_CHECK=1

if [ "${QUANTA_OFFLINE:-0}" = "1" ]; then
  "$QUANTA_ENV_PYTHON" -m pip install --no-index --find-links "$QUANTA_WHEELHOUSE" --only-binary=:all: --require-hashes -r "$QUANTA_LOCK"
else
  "$QUANTA_ENV_PYTHON" -m pip install --index-url https://pypi.org/simple --only-binary=:all: --require-hashes -r "$QUANTA_LOCK"
fi
"$QUANTA_ENV_PYTHON" -m pip install --no-deps --no-build-isolation -e .
"$QUANTA_ENV_PYTHON" -m pip check
"$QUANTA_ENV_PYTHON" scripts/check_environment.py
