"""Independent fixtures from the frozen 0.2.0 contract examples."""

import json
from pathlib import Path

import pytest


CONTRACT_DIR = Path(__file__).resolve().parents[1] / "contracts" / "v0.2.0"


@pytest.fixture
def contract_dir():
    return CONTRACT_DIR


@pytest.fixture
def pair():
    return json.loads((CONTRACT_DIR / "examples" / "pair_revision.json").read_text())


@pytest.fixture
def quantum():
    return json.loads((CONTRACT_DIR / "examples" / "quantum_revision.json").read_text())
