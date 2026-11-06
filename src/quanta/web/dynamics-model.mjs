/**
 * Scientific presentation boundary for the saved 0.3.1 payload inside a 0.4 run.
 * No integration, unit conversion, interpolation, force evaluation or physical
 * validation happens here. Raw frame quantities are returned without rewriting.
 */

const MAX_FRAMES = 512;
const MAX_PARTICLES = 128;
const VECTOR_FIELDS = ['positions_m', 'velocities_m_per_s', 'forces_n'];
const DRIFTS = ['max_energy_drift_scaled', 'max_momentum_drift_scaled',
  'max_angular_momentum_drift_scaled', 'max_com_ballistic_error_scaled'];
const STOP_REASONS = new Set(['completed', 'domain_error', 'range_error', 'resource_limit', 'cancelled', 'engine_failure']);
const has = (object, key) => Object.hasOwn(object, key);
const finite = value => typeof value === 'number' && Number.isFinite(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;

function refuse(message) {
  throw new TypeError('저장된 동역학 자료를 표시할 수 없습니다. ' + message);
}

function record(value, message) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse(message);
}

function keys(value, expected, message) {
  record(value, message);
  if (expected.some(key => !has(value, key)) || Object.keys(value).some(key => !expected.includes(key))) refuse(message);
}

function vector(value) {
  return Array.isArray(value) && value.length === 3 && value.every(finite);
}

/**
 * Validate only the supported presentation contract and bounded array shape.
 * Server-side synchronized energy/force/clock verification remains authoritative.
 * Returned legs, IDs, masses, frames and numeric values refer to the original
 * decoded payload, preserving binary64 and signed zero. Never mutate them.
 */
export function readDynamicsPayload(payload) {
  keys(payload, ['contract_version', 'operation', 'module_id', 'module_version', 'particle_ids', 'masses_kg',
    'primary_refinement_factor', 'time_kind', 'initial_time_s', 'physical_validation_status', 'partial', 'legs',
    'resolution_comparison'], '지원하는 payload 형식이 아닙니다.');
  if (payload.contract_version !== '0.3.1' || payload.operation !== 'integrate'
      || payload.module_id !== 'quanta.pair_dynamics' || payload.module_version !== '0.1.0'
      || payload.primary_refinement_factor !== 1 || payload.time_kind !== 'evolving'
      || payload.initial_time_s !== 0 || payload.physical_validation_status !== 'unvalidated'
      || typeof payload.partial !== 'boolean') refuse('버전·모형·시각·검증 상태를 확인하세요.');
  const ids = payload.particle_ids, masses = payload.masses_kg;
  if (!Array.isArray(ids) || ids.length < 2 || ids.length > MAX_PARTICLES
      || !ids.every(id => typeof id === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(id))
      || new Set(ids).size !== ids.length || !Array.isArray(masses) || masses.length !== ids.length
      || !masses.every(mass => finite(mass) && mass > 0)) refuse('입자 ID·질량·순서를 확인하세요.');
  const comparison = payload.resolution_comparison;
  keys(comparison, ['mode', 'status', 'coarse_pair_scaled_error', 'fine_pair_scaled_error',
    'comparison_grid', 'interpretation'], '해상도 비교 형식을 확인하세요.');
  if (!['none', 'halving_2'].includes(comparison.mode)
      || !['not_checked', 'pass', 'not_converged'].includes(comparison.status)
      || comparison.comparison_grid !== 'every_primary_integer_step'
      || comparison.interpretation !== 'finite_step_agreement_not_physical_validation'
      || !['coarse_pair_scaled_error', 'fine_pair_scaled_error'].every(key => comparison[key] === null
        || (finite(comparison[key]) && comparison[key] >= 0))) refuse('지원하는 해상도 비교 자료가 아닙니다.');
  const legs = payload.legs;
  if (!Array.isArray(legs) || legs.length < 1 || legs.length > 3
      || (comparison.mode === 'none' && legs.length !== 1)) refuse('궤적 묶음의 수를 확인하세요.');
  let totalFrames = 0;
  for (const [legIndex, leg] of legs.entries()) {
    keys(leg, ['refinement_factor', 'dt_s', 'requested_steps', 'completed_steps', 'force_evaluations',
      'sampled_frames', ...DRIFTS, 'diagnostics_evaluated_at', 'stop_reason', 'completed_force_evaluations'],
    '궤적 묶음의 형식을 확인하세요.');
    if (leg.refinement_factor !== [1, 2, 4][legIndex] || !finite(leg.dt_s) || leg.dt_s <= 0
        || !integer(leg.requested_steps) || leg.requested_steps < 1 || leg.requested_steps > 10000
        || !integer(leg.completed_steps) || leg.completed_steps > leg.requested_steps
        || !integer(leg.force_evaluations) || leg.force_evaluations < 1 || leg.force_evaluations > 10000
        || !integer(leg.completed_force_evaluations) || leg.completed_force_evaluations < leg.completed_steps + 1
        || leg.completed_force_evaluations > leg.force_evaluations
        || leg.force_evaluations > Math.min(leg.completed_steps + 2, leg.requested_steps + 1)
        || !STOP_REASONS.has(leg.stop_reason)
        || leg.diagnostics_evaluated_at !== 'every_accepted_full_step'
        || !DRIFTS.every(key => finite(leg[key]) && leg[key] >= 0)) refuse('계산 간격·완료 길이·진단을 확인하세요.');
    if (legIndex > 0 && (leg.dt_s !== legs[0].dt_s / leg.refinement_factor
        || leg.requested_steps !== legs[0].requested_steps * leg.refinement_factor)) {
      refuse('세분화 간격·요청 길이가 기본 궤적과 일치하지 않습니다.');
    }
    const complete = leg.completed_steps === leg.requested_steps && leg.stop_reason === 'completed';
    if ((leg.stop_reason === 'completed' && !complete) || (!complete && !payload.partial)
        || (!complete && legIndex < legs.length - 1)) refuse('완료·부분 종료 표기가 일치하지 않습니다.');
    const frames = leg.sampled_frames;
    if (!Array.isArray(frames) || frames.length < 1 || frames.length > MAX_FRAMES) refuse('저장 프레임 수를 확인하세요.');
    totalFrames += frames.length;
    if (totalFrames > MAX_FRAMES) refuse('지원하는 전체 저장 프레임 수를 초과했습니다.');
    for (const [index, frame] of frames.entries()) {
      keys(frame, ['step_index', 'time_s', ...VECTOR_FIELDS, 'potential_energy_j', 'kinetic_energy_j',
        'total_energy_j', 'linear_momentum_kg_m_per_s', 'angular_momentum_kg_m2_per_s'], '저장 프레임 형식을 확인하세요.');
      if (!integer(frame.step_index) || frame.step_index > leg.completed_steps
          || !finite(frame.time_s) || frame.time_s < 0
          || frame.time_s !== frame.step_index * leg.dt_s
          || (index === 0 && (frame.step_index !== 0 || frame.time_s !== 0))
          || (index > 0 && (frame.step_index <= frames[index - 1].step_index || frame.time_s <= frames[index - 1].time_s))
          || !VECTOR_FIELDS.every(key => Array.isArray(frame[key]) && frame[key].length === ids.length && frame[key].every(vector))
          || !['potential_energy_j', 'kinetic_energy_j', 'total_energy_j'].every(key => finite(frame[key]))
          || frame.kinetic_energy_j < 0 || !vector(frame.linear_momentum_kg_m_per_s)
          || !vector(frame.angular_momentum_kg_m2_per_s)) refuse('프레임의 순서·유한 수치·입자 배열을 확인하세요.');
    }
    if (frames.at(-1).step_index !== leg.completed_steps) refuse('마지막 수락 상태가 저장 프레임에 없습니다.');
  }
  if (!payload.partial && comparison.mode === 'halving_2' && legs.length !== 3) refuse('해상도 비교 궤적이 완전하지 않습니다.');
  return Object.freeze({ ids, masses, legs, partial: payload.partial, payload });
}

function checkedFrames(frames) {
  if (!Array.isArray(frames) || frames.length < 1 || frames.length > MAX_FRAMES) refuse('저장 프레임을 확인하세요.');
  const count = frames[0]?.positions_m?.length;
  if (!integer(count) || count < 2 || count > MAX_PARTICLES
      || !frames.every(frame => Array.isArray(frame.positions_m) && frame.positions_m.length === count && frame.positions_m.every(vector))) {
    refuse('표시할 입자 좌표를 확인하세요.');
  }
  return frames;
}

function midpoint(a, b) {
  const span = b - a;
  return Number.isFinite(span) ? a + span / 2 : a / 2 + b / 2;
}

function relative(value, origin, scale) {
  const difference = value - origin;
  // Subtract first where possible: common large offsets must not erase an
  // otherwise representable small spacing. Scaled subtraction is overflow-only.
  return Number.isFinite(difference) ? difference / scale : value / scale - origin / scale;
}

/** Fixed origin/normalization/radius enclosing every stored point of one leg. */
export function cameraForFrames(frames) {
  checkedFrames(frames);
  const minimum = [Infinity, Infinity, Infinity], maximum = [-Infinity, -Infinity, -Infinity];
  for (const frame of frames) for (const point of frame.positions_m) for (let axis = 0; axis < 3; axis += 1) {
    minimum[axis] = Math.min(minimum[axis], point[axis]);
    maximum[axis] = Math.max(maximum[axis], point[axis]);
  }
  const origin = minimum.map((value, axis) => midpoint(value, maximum[axis]));
  let scale = 0;
  for (let axis = 0; axis < 3; axis += 1) {
    scale = Math.max(scale, Math.abs(minimum[axis] - origin[axis]), Math.abs(maximum[axis] - origin[axis]));
  }
  const degenerate = scale === 0;
  if (degenerate) scale = 1; // Display-only fallback for coincident stored points.
  let radius = 0;
  for (const frame of frames) for (const point of frame.positions_m) {
    radius = Math.max(radius, Math.hypot(...point.map((value, axis) => relative(value, origin[axis], scale))));
  }
  return Object.freeze({ origin: Object.freeze(origin), scale_m: scale, radius: radius || 1, degenerate });
}

/**
 * Orthographic 3D -> CSS pixels. Right-handed yaw about Y, then pitch about X.
 * panX/panY are CSS pixels; zoom changes display only. Depth is normalized,
 * with larger depth nearer the viewer. No frame-specific recentering occurs.
 */
export function projectPoint(point, camera, {
  width = 800, height = 480, yaw = 0, pitch = 0, zoom = 1, panX = 0, panY = 0,
} = {}) {
  if (!vector(point) || !vector(camera?.origin) || !finite(camera?.scale_m) || camera.scale_m <= 0
      || !finite(camera?.radius) || camera.radius <= 0
      || ![width, height, yaw, pitch, zoom, panX, panY].every(finite)
      || width <= 0 || height <= 0 || width > 1e6 || height > 1e6
      || zoom <= 0 || zoom > 1e4 || Math.abs(panX) > 1e9 || Math.abs(panY) > 1e9) {
    refuse('카메라 표시 조건을 확인하세요.');
  }
  const [x, y, z] = point.map((value, axis) => relative(value, camera.origin[axis], camera.scale_m) / camera.radius);
  const cY = Math.cos(yaw), sY = Math.sin(yaw), cP = Math.cos(pitch), sP = Math.sin(pitch);
  const yawX = cY * x + sY * z, yawZ = -sY * x + cY * z;
  const pitchY = cP * y - sP * yawZ, depth = sP * y + cP * yawZ;
  const pixels = .42 * Math.min(width, height) * zoom;
  const result = { x: width / 2 + pixels * yawX + panX, y: height / 2 - pixels * pitchY + panY, depth };
  if (!Object.values(result).every(finite)) refuse('화면에서 표현할 수 없는 카메라 범위입니다.');
  return result;
}

function timeRange(frames) {
  if (!Array.isArray(frames) || frames.length < 1 || frames.length > MAX_FRAMES
      || !frames.every((frame, index) => finite(frame.time_s) && frame.time_s >= 0
        && (index === 0 || frame.time_s > frames[index - 1].time_s))) refuse('저장 시각의 순서를 확인하세요.');
  return [frames[0].time_s, frames.at(-1).time_s];
}

/** Previous stored sample at a physical-time fraction, never a synthetic frame. */
export function selectFrameAtFraction(frames, fraction) {
  const [first, last] = timeRange(frames);
  if (!finite(fraction) || fraction < 0 || fraction > 1) refuse('재생 위치는0부터1 사이여야 합니다.');
  if (fraction === 0 || first === last) return 0;
  if (fraction === 1) return frames.length - 1;
  // Compare normalized clock differences rather than constructing an absolute
  // target: target = fraction * a subnormal duration could round upward to a
  // future stored sample, and a large common clock can erase a small interval.
  const duration = last - first;
  let low = 0, high = frames.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if ((frames[middle].time_s - first) / duration <= fraction) low = middle + 1;
    else high = middle;
  }
  return Math.max(0, low - 1);
}

/** Physical-time position of an existing frame (not its ordinal spacing). */
export function fractionAtFrame(frames, index) {
  const [first, last] = timeRange(frames);
  if (!integer(index) || index >= frames.length) refuse('저장 프레임 번호를 확인하세요.');
  if (first === last) return 0;
  return (frames[index].time_s - first) / (last - first);
}

const SERIES = Object.freeze({
  energyK: ['kinetic_energy_j', null, 'J', '운동에너지 K'],
  energyU: ['potential_energy_j', null, 'J', '퍼텐셜 에너지 U'],
  energyE: ['total_energy_j', null, 'J', '총에너지 E'],
  Px: ['linear_momentum_kg_m_per_s', 0, 'kg·m/s', '선운동량 Px'],
  Py: ['linear_momentum_kg_m_per_s', 1, 'kg·m/s', '선운동량 Py'],
  Pz: ['linear_momentum_kg_m_per_s', 2, 'kg·m/s', '선운동량 Pz'],
  Lx: ['angular_momentum_kg_m2_per_s', 0, 'kg·m²/s', '각운동량 Lx'],
  Ly: ['angular_momentum_kg_m2_per_s', 1, 'kg·m²/s', '각운동량 Ly'],
  Lz: ['angular_momentum_kg_m2_per_s', 2, 'kg·m²/s', '각운동량 Lz'],
});

/** Exact stored samples; diagnostic maxima across all full steps are separate. */
export function dynamicsSeries(leg, key) {
  const descriptor = typeof key === 'string' && has(SERIES, key) ? SERIES[key] : null;
  if (!descriptor) refuse('지원하지 않는 관측량입니다.');
  timeRange(leg?.sampled_frames);
  const [field, component, unit, label] = descriptor;
  const xs = [], ys = [];
  for (const frame of leg.sampled_frames) {
    const value = component === null ? frame[field] : frame[field]?.[component];
    if (!finite(value)) refuse('관측량의 저장 표본이 유한하지 않습니다.');
    xs.push(frame.time_s); ys.push(value);
  }
  return { xs, ys, unit, label };
}

/** Return exact raw phase values for one selected saved particle/frame. */
export function frameParticle(model, legIndex, frameIndex, particleIndex) {
  if (![legIndex, frameIndex, particleIndex].every(integer)
      || legIndex >= model.legs.length || frameIndex >= model.legs[legIndex].sampled_frames.length
      || particleIndex >= model.ids.length) refuse('선택한 입자·프레임을 확인하세요.');
  const frame = model.legs[legIndex].sampled_frames[frameIndex];
  return { id: model.ids[particleIndex], mass_kg: model.masses[particleIndex],
    position_m: frame.positions_m[particleIndex], velocity_m_per_s: frame.velocities_m_per_s[particleIndex],
    force_n: frame.forces_n[particleIndex], time_s: frame.time_s, step_index: frame.step_index };
}
