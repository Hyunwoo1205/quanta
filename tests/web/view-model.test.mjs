import assert from 'node:assert/strict';
import test from 'node:test';

import {
  terminalStatuses,
  statusLabel,
  formatNumber,
  rawMember,
  formatJSONPreservingNumbers,
  parseDefinition,
  buildRevisionBody,
  buildValidationBody,
  chartPoints,
} from '../../src/quanta/web/view-model.mjs';

const authored = String.raw`{
  "scales": {"length_m": 1.0000e-09, "energy_j": 1E-19},
  "system": {"position_m": [-0.0, 2.500e-9, 0], "message": "brace } and quote \" remain text"},
  "protocol": {"steps": []},
  "literal": "the characters -0 and 1E-19 are a string"
}`;

test('terminal lifecycle states do not include in-progress or numerical statuses', () => {
  assert.deepEqual([...terminalStatuses].sort(), ['CANCELLED', 'FAILED', 'SUCCEEDED']);
  for (const pending of ['QUEUED', 'RUNNING', 'CANCEL_REQUESTED', 'pass', 'not_converged', 'unvalidated']) {
    assert.equal(terminalStatuses.has(pending), false);
  }
});

test('unknown status is not relabelled as success or physical validation', () => {
  const unknown = statusLabel('future_status');
  const success = statusLabel('SUCCEEDED');
  const physical = statusLabel('unvalidated');
  assert.notDeepEqual(unknown, success);
  assert.notDeepEqual(physical, success);
  assert.notDeepEqual(statusLabel('not_converged'), statusLabel('pass'));
});

test('scientific rendering retains tiny nonzero SI quantities and negative zero', () => {
  for (const value of [4e-21, -7.2e-32, 1e-300, 6.23e12]) {
    const rendered = formatNumber(value);
    assert.equal(typeof rendered, 'string');
    assert.ok(Number.isFinite(Number(rendered)));
    assert.notEqual(Number(rendered), 0, `Display lost nonzero ${value}`);
    assert.equal(Math.sign(Number(rendered)), Math.sign(value));
    assert.ok(Math.abs(Number(rendered) / value - 1) < 1e-5);
  }
  assert.equal(formatNumber(-0), '-0');
  assert.equal(formatNumber(0), '0');
});

test('unknown or nonfinite numeric values never appear as a calculated zero', () => {
  for (const value of [undefined, null, NaN, Infinity, -Infinity, '4e-21']) {
    assert.equal(formatNumber(value), '—');
  }
});

test('rawMember extracts the selected top-level member without resampling numbers', () => {
  const wrapper = String.raw`{"before":{"definition":"nested value"},"definition": ${authored},"after":"definition"}`;
  assert.equal(rawMember(wrapper, 'definition'), authored);
  assert.equal(rawMember(wrapper, 'missing'), undefined);
  assert.equal(rawMember('{"x":-0.000e+00}', 'x'), '-0.000e+00');
});

test('rawMember handles escaped property names and nested braces inside strings', () => {
  const source = String.raw`{"def\u0069nition":{"text":"},] \" :","value":[-0,1e-40]},"x":2}`;
  assert.equal(rawMember(source, 'definition'), String.raw`{"text":"},] \" :","value":[-0,1e-40]}`);
});

test('ambiguous repeated top-level member is refused instead of silently choosing one', () => {
  assert.throws(() => rawMember('{"definition":{"x":1},"definition":{"x":2}}', 'definition'), SyntaxError);
  assert.throws(() => rawMember(String.raw`{"definition":1,"def\u0069nition":2}`, 'definition'), SyntaxError);
});

test('formatting preserves authored number lexemes and quoted scientific text', () => {
  const formatted = formatJSONPreservingNumbers(authored);
  assert.notEqual(formatted, '');
  assert.deepEqual(JSON.parse(formatted), JSON.parse(authored));
  assert.ok(Object.is(JSON.parse(formatted).system.position_m[0], -0));
  for (const lexeme of ['1.0000e-09', '1E-19', '-0.0', '2.500e-9']) {
    assert.ok(formatted.includes(lexeme), `Formatter changed scientific token ${lexeme}`);
  }
  assert.equal(JSON.parse(formatted).literal, JSON.parse(authored).literal);
});

test('formatting retains nested authored duplicate keys for server-side validation', () => {
  const formatted = formatJSONPreservingNumbers('{"system":{"x":1,"x":2}}');
  assert.equal((formatted.match(/"x"\s*:/g) || []).length, 2);
});

test('invalid JSON never becomes a corrected or substituted scientific input', () => {
  for (const invalid of ['{', '{"x":NaN}', '{"x":undefined}', '{"x":1,}', '{/* comment */"x":1}']) {
    assert.throws(() => formatJSONPreservingNumbers(invalid));
    assert.throws(() => buildValidationBody(invalid));
    assert.throws(() => buildRevisionBody('Invalid input', invalid));
  }
});

test('parsed definition must remain an object and request builders keep exact raw definition', () => {
  for (const invalid of ['[]', 'null', '1', '"input"', 'true']) {
    assert.throws(() => parseDefinition(invalid), TypeError);
  }
  assert.deepEqual(parseDefinition(authored), JSON.parse(authored));
  const revision = buildRevisionBody('An authored input', authored);
  const validation = buildValidationBody(authored);
  assert.equal(rawMember(revision, 'definition'), authored);
  assert.equal(rawMember(validation, 'definition'), authored);
  assert.equal(JSON.parse(revision).schema_version, '0.2.0');
  assert.equal(JSON.parse(validation).schema_version, '0.2.0');
  assert.equal(JSON.parse(revision).title, 'An authored input');
  assert.ok(Object.is(JSON.parse(revision).definition.system.position_m[0], -0));
});

test('request title and hostile-looking strings remain JSON data', () => {
  const title = '</script><img src=x onerror="alert(1)">\n"quoted"';
  const source = '{"message":"<svg/onload=alert(1)>","__proto__":{"polluted":true}}';
  const revision = buildRevisionBody(title, source);
  assert.equal(JSON.parse(revision).title, title);
  assert.equal(rawMember(revision, 'definition'), source);
  assert.equal({}.polluted, undefined);
});

test('SVG samples preserve independent linear position mapping and endpoint order', () => {
  const chart = chartPoints([-2, 0, 3], [-4, 2, 6], 640, 280, 40);
  assert.equal(chart.empty, false);
  assert.deepEqual(chart.samples.map(sample => [sample.x, sample.y]), [[-2, -4], [0, 2], [3, 6]]);
  assert.equal(chart.left, 40);
  assert.equal(chart.right, 600);
  assert.equal(chart.top, 40);
  assert.equal(chart.bottom, 240);
  for (const sample of chart.samples) {
    const expectedX = chart.left + (sample.x - chart.xMin) * (chart.right - chart.left) / (chart.xMax - chart.xMin);
    const expectedY = chart.bottom - (sample.y - chart.yMin) * (chart.bottom - chart.top) / (chart.yMax - chart.yMin);
    assert.ok(Math.abs(sample.px - expectedX) < 1e-9);
    assert.ok(Math.abs(sample.py - expectedY) < 1e-9);
    assert.ok(sample.px >= chart.left && sample.px <= chart.right);
    assert.ok(sample.py >= chart.top && sample.py <= chart.bottom);
  }
  assert.ok(chart.samples[0].px < chart.samples[1].px && chart.samples[1].px < chart.samples[2].px);
  assert.ok(chart.samples[0].py > chart.samples[1].py && chart.samples[1].py > chart.samples[2].py);
});

test('flat and one-point series keep a finite visible plotting range', () => {
  for (const [xs, ys] of [[[7], [-3]], [[1, 1, 1], [5, 5, 5]], [[0, 1, 2], [0, 0, 0]]]) {
    const chart = chartPoints(xs, ys);
    assert.equal(chart.empty, false);
    assert.ok(chart.xMin < chart.xMax);
    assert.ok(chart.yMin < chart.yMax);
    assert.ok(!/NaN|Infinity/.test(chart.points));
    for (const {px, py} of chart.samples) {
      assert.ok(Number.isFinite(px) && Number.isFinite(py));
    }
  }
});

test('plot excludes nonfinite pairs and never invents a zero for missing data', () => {
  const chart = chartPoints([0, NaN, 2, Infinity, 4], [1, 2, NaN, 4, 5]);
  assert.deepEqual(chart.samples.map(sample => [sample.x, sample.y]), [[0, 1], [4, 5]]);
  assert.ok(!/NaN|Infinity/.test(chart.points));
  for (const [xs, ys] of [[[], []], [[NaN], [0]], [[1], [Infinity]]]) {
    const empty = chartPoints(xs, ys);
    assert.equal(empty.empty, true);
    assert.equal(empty.points, '');
    assert.deepEqual(empty.samples, []);
  }
});

test('zero reference line is mapped only when zero belongs to the plotted range', () => {
  const crossing = chartPoints([0, 1], [-2, 6], 640, 280, 40);
  assert.ok(Math.abs(crossing.zeroY - (crossing.bottom - (0 - crossing.yMin) * (crossing.bottom - crossing.top) / (crossing.yMax - crossing.yMin))) < 1e-9);
  assert.equal(chartPoints([0, 1], [2, 6]).zeroY, null);
  assert.equal(chartPoints([0, 1], [-6, -2]).zeroY, null);
});

test('chart geometry refuses an invalid drawing area rather than emitting invalid SVG', () => {
  for (const args of [[0, 280, 40], [640, 0, 40], [640, 280, 200], [NaN, 280, 40], [640, Infinity, 40], [640, 280, -1]]) {
    assert.throws(() => chartPoints([0, 1], [2, 3], ...args), RangeError);
  }
});
