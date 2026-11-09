"""Analytic regression for the CUTOFF diagnostic's real Fourier resampling."""

from pathlib import Path

import numpy as np
import pytest


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


def test_he16_large_grid_axis_matches_an_analytic_periodic_field(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    from diagnose_atomistic_cutoff_density import _trigonometric_axis

    def field(count):
        phase = 2 * np.pi * np.arange(count) / count
        return (0.125 + 0.2 * np.sin(13 * phase) - 0.4 * np.cos(180 * phase))[None, None, :]

    actual = _trigonometric_axis(field(360), 384, axis=2)
    np.testing.assert_allclose(actual, field(384), atol=2e-13, rtol=0)


def test_large_grid_diagnostic_requires_explicit_16_angstrom_limit(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    import diagnose_atomistic_cutoff_density as diagnostic

    class ReachedNativeReader(Exception):
        pass

    def stop_before_array_allocation(*args):
        raise ReachedNativeReader

    def bounded_count(attempt, cell, *, maximum_axis_count):
        if attempt["axis_count"] > maximum_axis_count:
            raise ValueError("distinct bounded axis")
        return attempt["axis_count"]

    monkeypatch.setattr(diagnostic, "_grid_count", bounded_count)
    monkeypatch.setattr(diagnostic, "_require_aligned_atoms", lambda *args: None)
    monkeypatch.setattr(diagnostic, "_native_grid", stop_before_array_allocation)
    cube = Path("unused.cube")
    reference = {"axis_count": 384, "density": {}}
    candidate = {"axis_count": 360, "density": {}}

    with pytest.raises(ValueError, match="distinct bounded"):
        diagnostic.diagnose_cutoff_density(reference, candidate, cube, cube, 16)
    with pytest.raises(ValueError, match="Unsupported.*axis limit"):
        diagnostic.diagnose_cutoff_density(reference, candidate, cube, cube, 12, maximum_axis_count=400)
    with pytest.raises(ValueError, match="Unsupported.*axis limit"):
        diagnostic.diagnose_cutoff_density(reference, candidate, cube, cube, 16, maximum_axis_count=401)
    with pytest.raises(ValueError, match="distinct bounded"):
        diagnostic.diagnose_cutoff_density(
            {**reference, "axis_count": 401}, candidate, cube, cube, 16, maximum_axis_count=400,
        )
    with pytest.raises(ReachedNativeReader):
        diagnostic.diagnose_cutoff_density(reference, candidate, cube, cube, 16, maximum_axis_count=400)
