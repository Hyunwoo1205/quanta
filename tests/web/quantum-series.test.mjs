import assert from 'node:assert/strict';
import test from 'node:test';

import { quantumSeries, chartPoints } from '../../src/quanta/web/view-model.mjs';

// Matches module_results/quantum_stationary.schema.json: real/imag are arrays
// inside the `states` object. The endpoints represent Dirichlet zero values.
function registeredPayload() {
  return {
    operation: 'eigenstates',
    x_m: [0, 0.25e-9, 0.5e-9, 0.75e-9, 1e-9],
    energies_j: [1.2e-20, 4.8e-20],
    states: {
      real: [[0, 2e4, 3e4, 2e4, 0], [0, 3e4, -0, -3e4, 0]],
      imag: [[0, 0, 0, 0, 0], [0, 1e4, 0, -1e4, 0]],
    },
    density_per_m: [[0, 4e8, 9e8, 4e8, 0], [0, 1e9, 0, 1e9, 0]],
  };
}

test('wave selector reads actual nested states.real and retains the selected state', () => {
  const payload = registeredPayload();
  payload.psi = [[99, 99, 99, 99, 99]]; // A similarly named unsupported field is not data.
  const selected = quantumSeries(payload, 1);
  assert.equal(selected.available, true);
  assert.strictEqual(selected.xs, payload.x_m);
  assert.strictEqual(selected.ys, payload.states.real[1]);
  assert.deepEqual(selected.ys, [0, 3e4, -0, -3e4, 0]);
  assert.ok(Object.is(selected.ys[2], -0));
  assert.equal(selected.kind, 'wave');
  assert.equal(selected.unit, 'm⁻¹ᐟ²');
  assert.match(selected.label, /Re ψ/);
});

test('a nonexistent psi field never substitutes for a missing registered wavefunction', () => {
  const payload = { x_m: [0, 1e-9], psi: [[0, 99]], states: [[0, 99]] };
  const selected = quantumSeries(payload, 0, 'wave');
  assert.equal(selected.available, false);
  assert.deepEqual(selected.xs, []);
  assert.deepEqual(selected.ys, []);
});

test('density selector uses the actual optional density array with density SI units', () => {
  const payload = registeredPayload();
  const selected = quantumSeries(payload, 1, 'density');
  assert.equal(selected.available, true);
  assert.strictEqual(selected.ys, payload.density_per_m[1]);
  assert.deepEqual(selected.ys, [0, 1e9, 0, 1e9, 0]);
  assert.equal(selected.unit, 'm⁻¹');
  assert.match(selected.label, /확률 밀도/);
});

test('missing optional density stays unavailable rather than deriving it or inventing zeros', () => {
  const payload = registeredPayload();
  delete payload.density_per_m;
  const selected = quantumSeries(payload, 0, 'density');
  assert.equal(selected.available, false);
  assert.deepEqual(selected.xs, []);
  assert.deepEqual(selected.ys, []);
  assert.equal(selected.unit, 'm⁻¹');
  assert.equal(quantumSeries(payload, 0, 'wave').available, true);
});

test('state indices and requested data kinds must refer to an available actual array', () => {
  const payload = registeredPayload();
  for (const state of [-1, 2, 0.5, '0', null, NaN, Infinity]) {
    assert.equal(quantumSeries(payload, state, 'wave').available, false, String(state));
  }
  const imaginary = quantumSeries(payload, 0, 'imaginary');
  assert.equal(imaginary.available, false);
  assert.deepEqual(imaginary.ys, []);
  assert.equal(imaginary.unit, '—');
});

test('selection does not change source arrays or mix real and imaginary components', () => {
  const payload = registeredPayload();
  const before = structuredClone(payload);
  Object.freeze(payload.x_m);
  for (const row of [...payload.states.real, ...payload.states.imag, ...payload.density_per_m]) Object.freeze(row);
  Object.freeze(payload.states.real);
  Object.freeze(payload.states.imag);
  Object.freeze(payload.states);
  Object.freeze(payload.density_per_m);
  Object.freeze(payload);
  const wave = quantumSeries(payload, 1, 'wave');
  quantumSeries(payload, 0, 'density');
  assert.equal(wave.ys[1], 3e4);
  assert.notEqual(wave.ys[1], Math.hypot(3e4, 1e4));
  assert.deepEqual(payload, before);
});

test('shape mismatch, absent samples and wholly nonfinite data remain unavailable', () => {
  for (const payload of [
    null,
    { x_m: [], states: { real: [[]] } },
    { x_m: [0, 1e-9], states: { real: [[1]] } },
    { x_m: [0, 1e-9], states: { real: [[NaN, Infinity]] } },
    { x_m: ['0', '1'], states: { real: [[1, 2]] } },
  ]) {
    const selected = quantumSeries(payload);
    assert.equal(selected.available, false);
    assert.deepEqual(selected.ys, []);
  }
});

test('finite quantum samples feed the chart directly without replacing missing samples', () => {
  const payload = { x_m: [0, 1e-9, 2e-9], states: { real: [[NaN, -2e4, 4e4]] } };
  const selected = quantumSeries(payload);
  assert.equal(selected.available, true);
  const chart = chartPoints(selected.xs, selected.ys, 300, 200, 20);
  assert.deepEqual(chart.samples.map(({ x, y }) => [x, y]), [[1e-9, -2e4], [2e-9, 4e4]]);
  assert.equal(chart.samples.length, 2);
  assert.equal(chart.empty, false);
});
