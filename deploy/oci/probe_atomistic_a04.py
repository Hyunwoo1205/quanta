#!/usr/bin/env python3
"""Invoke only the fixed A04 isolated benchmark over the existing OCI transport."""
import importlib.util
from pathlib import Path


def main():
    path = Path(__file__).with_name('probe_atomistic.py')
    spec = importlib.util.spec_from_file_location('quanta_a04_atomistic_transport', path)
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    return transport.main(a04=True)


if __name__ == '__main__':
    raise SystemExit(main())
