import assert from 'node:assert/strict';
import test from 'node:test';
import {
  readDynamicsPayload, cameraForFrames, projectPoint, selectFrameAtFraction,
  fractionAtFrame, dynamicsSeries, frameParticle,
} from '../../src/quanta/web/dynamics-model.mjs';

function frame(step, dt = .125) {
  const time = step * dt;
  return { step_index: step, time_s: time,
    positions_m: [[-1 + .125 * time, -0, 0], [1, 0, 0]],
    velocities_m_per_s: [[.125, -0, 0], [0, 0, 0]], forces_n: [[0, -0, 0], [0, 0, 0]],
    potential_energy_j: -0, kinetic_energy_j: .0078125, total_energy_j: .0078125,
    linear_momentum_kg_m_per_s: [.125, -0, 0], angular_momentum_kg_m2_per_s: [0, 0, 0] };
}

function leg(factor = 1) {
  return { refinement_factor: factor, dt_s: .125 / factor, requested_steps: 8 * factor,
    completed_steps: 8 * factor, force_evaluations: 8 * factor + 1, completed_force_evaluations: 8 * factor + 1,
    sampled_frames: Array.from({ length: 9 }, (_, index) => frame(index * factor, .125 / factor)),
    max_energy_drift_scaled: 0, max_momentum_drift_scaled: 0, max_angular_momentum_drift_scaled: 0,
    max_com_ballistic_error_scaled: 0, diagnostics_evaluated_at: 'every_accepted_full_step', stop_reason: 'completed' };
}

function payload() {
  return { contract_version: '0.3.1', operation: 'integrate', module_id: 'quanta.pair_dynamics', module_version: '0.1.0',
    particle_ids: ['left', 'right'], masses_kg: [1, 3], primary_refinement_factor: 1, time_kind: 'evolving',
    initial_time_s: 0, physical_validation_status: 'unvalidated', partial: false, legs: [leg()],
    resolution_comparison: { mode: 'none', status: 'not_checked', coarse_pair_scaled_error: null,
      fine_pair_scaled_error: null, comparison_grid: 'every_primary_integer_step',
      interpretation: 'finite_step_agreement_not_physical_validation' } };
}

const approx = (actual, expected, tolerance = 1e-10) => assert.ok(Math.abs(actual - expected) <= tolerance,
  `${actual} differs from independently expected ${expected}`);

test('supported embedded solver payload retains original arrays and signed-zero phase values', () => {
  const source = payload(), model = readDynamicsPayload(source);
  assert.equal(model.payload, source);
  assert.equal(model.ids, source.particle_ids);
  assert.equal(model.masses, source.masses_kg);
  assert.equal(model.legs, source.legs);
  const picked = frameParticle(model, 0, 5, 0);
  assert.equal(picked.position_m, source.legs[0].sampled_frames[5].positions_m[0]);
  assert.equal(picked.velocity_m_per_s, source.legs[0].sampled_frames[5].velocities_m_per_s[0]);
  assert.equal(picked.force_n, source.legs[0].sampled_frames[5].forces_n[0]);
  assert.deepEqual(picked, { id: 'left', mass_kg: 1, position_m: [-.921875, -0, 0],
    velocity_m_per_s: [.125, -0, 0], force_n: [0, -0, 0], time_s: .625, step_index: 5 });
  assert.ok(Object.is(picked.position_m[1], -0));
});

test('generic result version cannot be substituted for the embedded solver contract', () => {
  for (const [key, value] of [['contract_version', '0.4.0'], ['module_version', '0.2.0'],
    ['operation', 'relax'], ['module_id', 'quanta.pair_static'], ['primary_refinement_factor', 2],
    ['time_kind', 'static'], ['initial_time_s', 1], ['physical_validation_status', 'validated'], ['partial', 'false']]) {
    const source = payload(); source[key] = value;
    assert.throws(() => readDynamicsPayload(source), TypeError, key);
  }
});

test('particle count, distinct bounded IDs, positive masses and synchronized shapes are required', () => {
  const changes = [
    p => { p.particle_ids = ['left']; }, p => { p.particle_ids[1] = 'left'; },
    p => { p.particle_ids[1] = '<img>'; }, p => { p.particle_ids = Array(129).fill('x'); },
    p => { p.masses_kg = [1]; }, p => { p.masses_kg[0] = -0; }, p => { p.masses_kg[0] = Infinity; },
    p => { p.legs[0].sampled_frames[1].positions_m.pop(); },
    p => { p.legs[0].sampled_frames[1].forces_n[0].push(0); },
    p => { p.legs[0].sampled_frames[1].velocities_m_per_s[1][2] = NaN; },
  ];
  for (const change of changes) { const p = payload(); change(p); assert.throws(() => readDynamicsPayload(p), TypeError); }
});

test('unknown fields, absent quantities and invalid diagnostic values fail explicitly', () => {
  const changes = [p => { p.extra = 1; }, p => { p.legs[0].extra = 1; },
    p => { p.legs[0].sampled_frames[0].extra = 1; }, p => { delete p.legs[0].sampled_frames[0].forces_n; },
    p => { p.legs[0].sampled_frames[0].kinetic_energy_j = -1; },
    p => { p.legs[0].sampled_frames[0].total_energy_j = Infinity; },
    p => { p.legs[0].sampled_frames[0].linear_momentum_kg_m_per_s = [0, 0]; },
    p => { p.legs[0].max_energy_drift_scaled = -1; },
    p => { p.legs[0].diagnostics_evaluated_at = 'samples_only'; },
    p => { p.resolution_comparison.fine_pair_scaled_error = NaN; }];
  for (const change of changes) { const p = payload(); change(p); assert.throws(() => readDynamicsPayload(p), TypeError); }
});

test('stored clock and step sequence must be finite, increasing, initial and terminal', () => {
  const changes = [p => { p.legs[0].sampled_frames[0].time_s = .1; },
    p => { p.legs[0].sampled_frames[0].step_index = 1; },
    p => { p.legs[0].sampled_frames[1].time_s = 0; },
    p => { p.legs[0].sampled_frames[2].step_index = 1; },
    p => { p.legs[0].sampled_frames[2].time_s = Infinity; },
    p => { p.legs[0].sampled_frames[2].time_s = .3; },
    p => { p.legs[0].sampled_frames.at(-1).step_index = 9; },
    p => { p.legs[0].sampled_frames.pop(); }];
  for (const change of changes) { const p = payload(); change(p); assert.throws(() => readDynamicsPayload(p), TypeError); }
});

test('partial primary failure keeps the accepted terminal sample without claiming final success', () => {
  const p = payload(); p.partial = true;
  Object.assign(p.legs[0], { completed_steps: 2, force_evaluations: 4, completed_force_evaluations: 3,
    sampled_frames: [frame(0), frame(2)], stop_reason: 'domain_error' });
  const model = readDynamicsPayload(p);
  assert.equal(model.partial, true);
  assert.equal(model.legs[0].sampled_frames.at(-1).step_index, 2);
  p.partial = false;
  assert.throws(() => readDynamicsPayload(p), TypeError);
});

test('accepted zero-step partial output remains a single stored initial frame', () => {
  const p = payload(); p.partial = true;
  Object.assign(p.legs[0], { completed_steps: 0, force_evaluations: 1, completed_force_evaluations: 1,
    sampled_frames: [frame(0)], stop_reason: 'resource_limit' });
  const model = readDynamicsPayload(p);
  assert.equal(selectFrameAtFraction(model.legs[0].sampled_frames, 1), 0);
  assert.equal(fractionAtFrame(model.legs[0].sampled_frames, 0), 0);
});

test('h/h2/h4 are ordered, unique and explicitly selected, never auto-promoted', () => {
  const p = payload(); p.resolution_comparison.mode = 'halving_2';
  p.resolution_comparison.status = 'pass'; p.legs = [leg(1), leg(2), leg(4)];
  const model = readDynamicsPayload(p);
  assert.deepEqual(model.legs.map(l => l.refinement_factor), [1, 2, 4]);
  assert.equal(frameParticle(model, 2, 1, 1).step_index, 4);
  p.legs.reverse(); assert.throws(() => readDynamicsPayload(p), TypeError);
});

test('refinement time steps and requested lengths refer to the same physical experiment', () => {
  for (const change of [p => { p.legs[1].dt_s = .05; }, p => { p.legs[1].requested_steps = 15; }]) {
    const p = payload(); p.resolution_comparison.mode = 'halving_2'; p.legs = [leg(1), leg(2), leg(4)];
    change(p); assert.throws(() => readDynamicsPayload(p), TypeError);
  }
});

test('missing later refinement is accepted only as a partial result', () => {
  const p = payload(); p.resolution_comparison.mode = 'halving_2';
  assert.throws(() => readDynamicsPayload(p), TypeError);
  p.partial = true; assert.equal(readDynamicsPayload(p).legs.length, 1);
});

test('incomplete leg cannot precede a later refinement and force-call counts are bounded', () => {
  const p = payload(); p.partial = true; p.resolution_comparison.mode = 'halving_2'; p.legs.push(leg(2));
  p.legs[0].stop_reason = 'engine_failure';
  assert.throws(() => readDynamicsPayload(p), TypeError);
  for (const [key, value] of [['completed_steps', 9], ['requested_steps', 10001], ['force_evaluations', 11],
    ['completed_force_evaluations', 8], ['dt_s', 0]]) {
    const q = payload(); q.legs[0][key] = value; assert.throws(() => readDynamicsPayload(q), TypeError, key);
  }
});

test('total frame bound applies across all refinement legs', () => {
  const p = payload(); p.resolution_comparison.mode = 'halving_2'; p.legs = [leg(1), leg(2), leg(4)];
  for (const l of p.legs) {
    l.requested_steps = l.completed_steps = 200; l.force_evaluations = l.completed_force_evaluations = 201;
    l.sampled_frames = Array.from({ length: 201 }, (_, i) => frame(i, l.dt_s));
  }
  assert.throws(() => readDynamicsPayload(p), TypeError);
});

test('known orthographic x projection and pan/zoom use CSS pixels', () => {
  const frames = [{ positions_m: [[-1, 0, 0], [1, 0, 0]] }];
  const camera = cameraForFrames(frames);
  assert.deepEqual(camera.origin, [0, 0, 0]); assert.equal(camera.scale_m, 1); assert.equal(camera.radius, 1);
  assert.deepEqual(projectPoint([-1, 0, 0], camera, { width: 800, height: 800 }), { x: 64, y: 400, depth: 0 });
  assert.deepEqual(projectPoint([1, 0, 0], camera, { width: 800, height: 800 }), { x: 736, y: 400, depth: 0 });
  assert.deepEqual(projectPoint([1, 0, 0], camera, { width: 800, height: 800, zoom: .5, panX: 10, panY: -5 }),
    { x: 578, y: 395, depth: 0 });
});

test('independent ninety-degree rotations distinguish depth, y-up and yaw/pitch axes', () => {
  const camera = { origin: [0, 0, 0], scale_m: 1, radius: 1 };
  const x = projectPoint([1, 0, 0], camera, { width: 800, height: 800, yaw: Math.PI / 2 });
  approx(x.x, 400); approx(x.y, 400); approx(x.depth, -1);
  const z = projectPoint([0, 0, 1], camera, { width: 800, height: 800, yaw: Math.PI / 2 });
  approx(z.x, 736); approx(z.y, 400); approx(z.depth, 0);
  const y = projectPoint([0, 1, 0], camera, { width: 800, height: 800, pitch: Math.PI / 2 });
  approx(y.x, 400); approx(y.y, 400); approx(y.depth, 1);
});

test('camera encloses the complete leg once, preserving visible ballistic translation', () => {
  const frames = [{ positions_m: [[-1, 0, 0], [1, 0, 0]] }, { positions_m: [[1, 0, 0], [3, 0, 0]] }];
  const camera = cameraForFrames(frames), before = JSON.stringify(camera);
  assert.deepEqual(camera.origin, [1, 0, 0]); assert.equal(camera.scale_m, 2);
  assert.equal(projectPoint(frames[0].positions_m[1], camera, { width: 800, height: 800 }).x, 400);
  assert.equal(projectPoint(frames[1].positions_m[1], camera, { width: 800, height: 800 }).x, 736);
  assert.equal(JSON.stringify(camera), before);
});

test('large shared origin does not erase representable small separations', () => {
  const positions = [[1e16, -1e16, 1e16], [1e16 + 4, -1e16, 1e16]];
  const camera = cameraForFrames([{ positions_m: positions }]);
  assert.equal(camera.scale_m, 2);
  const left = projectPoint(positions[0], camera, { width: 800, height: 800 });
  const right = projectPoint(positions[1], camera, { width: 800, height: 800 });
  assert.equal(left.x, 64); assert.equal(right.x, 736);
});

test('opposite maximum binary64 bounds and multi-axis norm remain finite', () => {
  const max = Number.MAX_VALUE, positions = [[-max, -max, -max], [max, max, max]];
  const camera = cameraForFrames([{ positions_m: positions }]);
  assert.equal(camera.scale_m, max); assert.equal(camera.radius, Math.sqrt(3));
  for (const point of positions) for (const angle of [0, .4, Math.PI / 2]) {
    const p = projectPoint(point, camera, { width: 800, height: 480, yaw: angle, pitch: -.7 });
    assert.ok(Object.values(p).every(Number.isFinite));
    assert.ok(p.x >= 0 && p.x <= 800 && p.y >= 0 && p.y <= 480);
  }
});

test('subnormal distance survives normalization without inventing a physical scale', () => {
  const tiny = Number.MIN_VALUE, positions = [[0, 0, 0], [tiny, 0, 0]];
  const camera = cameraForFrames([{ positions_m: positions }]);
  assert.equal(camera.scale_m, tiny); assert.equal(camera.degenerate, false);
  const a = projectPoint(positions[0], camera), b = projectPoint(positions[1], camera);
  assert.ok(b.x - a.x > 100);
  assert.equal(positions[1][0], tiny);
});

test('coincident display geometry and invalid geometry have explicit behavior', () => {
  const camera = cameraForFrames([{ positions_m: [[2, 2, 2], [2, 2, 2]] }]);
  assert.equal(camera.degenerate, true);
  assert.deepEqual(projectPoint([2, 2, 2], camera), { x: 400, y: 240, depth: 0 });
  for (const frames of [[], [{ positions_m: [[1, 2, 3]] }], [{ positions_m: [[0, 0, 0], [Infinity, 0, 0]] }]]) {
    assert.throws(() => cameraForFrames(frames), TypeError);
  }
  for (const settings of [{ width: 0 }, { zoom: 0 }, { yaw: NaN }, { panY: Infinity }]) {
    assert.throws(() => projectPoint([2, 2, 2], camera, settings), TypeError);
  }
});

test('time selection holds a real prior sample across sparse and nonuniform final intervals', () => {
  const frames = [0, .4, .8, 1].map(time_s => ({ time_s }));
  for (const [fraction, expected] of [[0, 0], [.39, 0], [.4, 1], [.79, 1], [.8, 2], [.9, 2], [1, 3]]) {
    assert.equal(selectFrameAtFraction(frames, fraction), expected);
  }
  assert.equal(fractionAtFrame(frames, 1), .4); assert.equal(fractionAtFrame(frames, 2), .8);
  assert.equal(fractionAtFrame(frames, 3), 1);
});

test('time selector has bounded indices at tiny and huge clocks without uniform-index assumptions', () => {
  for (const magnitude of [Number.MIN_VALUE, 1e-300, 1e300]) {
    const frames = [0, magnitude, 2 * magnitude, 3 * magnitude].map(time_s => ({ time_s }));
    assert.equal(selectFrameAtFraction(frames, 0), 0);
    assert.equal(selectFrameAtFraction(frames, 1), 3);
    assert.equal(fractionAtFrame(frames, 3), 1);
  }
  const offset = [{ time_s: 1e300 }, { time_s: 1.5e300 }];
  assert.equal(selectFrameAtFraction(offset, .5), 0);
  assert.equal(selectFrameAtFraction(offset, 1), 1);
});

test('subnormal physical intervals do not round playback forward into an unelapsed sample', () => {
  const frames = [{ time_s: 0 }, { time_s: Number.MIN_VALUE }];
  assert.equal(selectFrameAtFraction(frames, .9), 0);
  assert.equal(selectFrameAtFraction(frames, 1), 1);
  const largeCommon = [{ time_s: 1e16 }, { time_s: 1e16 + 2 }, { time_s: 1e16 + 4 }];
  assert.equal(selectFrameAtFraction(largeCommon, .49), 0);
  assert.equal(selectFrameAtFraction(largeCommon, .5), 1);
});

test('out-of-range time, indices, absent samples and duplicate clocks are refused', () => {
  const frames = [{ time_s: 0 }, { time_s: 1 }];
  for (const value of [NaN, Infinity, -.1, 1.1, '0.5']) assert.throws(() => selectFrameAtFraction(frames, value), TypeError);
  for (const bad of [[], [{ time_s: 0 }, { time_s: 0 }], [{ time_s: 0 }, { time_s: -1 }]]) {
    assert.throws(() => selectFrameAtFraction(bad, .5), TypeError);
  }
  assert.throws(() => fractionAtFrame(frames, 2), TypeError);
  assert.throws(() => frameParticle(readDynamicsPayload(payload()), 0, 1, 2), TypeError);
});

test('energy and momentum charts return exact raw sample values, not recomputed quantities', () => {
  const p = payload(), l = p.legs[0];
  l.sampled_frames[2].total_energy_j = 4e-240;
  l.sampled_frames[2].angular_momentum_kg_m2_per_s[1] = -8e190;
  assert.equal(dynamicsSeries(l, 'energyE').ys[2], 4e-240);
  assert.equal(dynamicsSeries(l, 'Ly').ys[2], -8e190);
  assert.ok(Object.is(dynamicsSeries(l, 'energyU').ys[2], -0));
  assert.deepEqual(dynamicsSeries(l, 'Px').xs, l.sampled_frames.map(f => f.time_s));
  for (const [key, unit] of [['energyK', 'J'], ['energyU', 'J'], ['energyE', 'J'], ['Px', 'kg·m/s'],
    ['Py', 'kg·m/s'], ['Pz', 'kg·m/s'], ['Lx', 'kg·m²/s'], ['Ly', 'kg·m²/s'], ['Lz', 'kg·m²/s']]) {
    assert.equal(dynamicsSeries(l, key).unit, unit);
  }
  assert.throws(() => dynamicsSeries(l, 'temperature'), TypeError);
  assert.throws(() => dynamicsSeries(l, '__proto__'), TypeError);
  assert.throws(() => dynamicsSeries(l, 'toString'), TypeError);
});
