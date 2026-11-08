"""Analytic regression for the CUTOFF diagnostic's real Fourier resampling."""

from pathlib import Path

import numpy as np


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def test_upsampling_splits_the_even_source_nyquist_mode(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    from diagnose_atomistic_cutoff_density import _trigonometric_axis

    def field(count):
        phase = 2 * np.pi * np.arange(count) / count
        wave = 0.25 + np.sin(2 * phase) - 0.7 * np.cos(4 * phase)
        return wave[:, None, None] * np.arange(1, 7).reshape(1, 2, 3)

    actual = _trigonometric_axis(field(8), 12, axis=0)
    np.testing.assert_allclose(actual, field(12), atol=2e-14, rtol=0)


def test_downsampling_folds_modes_and_merges_the_target_nyquist_mode(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    from diagnose_atomistic_cutoff_density import _trigonometric_axis

    def field(count):
        phase = 2 * np.pi * np.arange(count) / count
        wave = 0.25 + np.sin(5 * phase) + 0.2 * np.sin(4 * phase)
        wave += 0.3 * np.cos(4 * phase) - 0.7 * np.cos(6 * phase)
        return wave[None, :, None] * np.arange(1, 7).reshape(2, 1, 3)

    actual = _trigonometric_axis(field(12), 8, axis=1)
    np.testing.assert_allclose(actual, field(8), atol=2e-14, rtol=0)
