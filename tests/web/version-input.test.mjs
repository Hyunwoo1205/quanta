import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

import {
  buildRevisionBody,
  buildValidationBody,
  rawMember,
  importDraftJSON,
  supportedExperimentVersions,
} from '../../src/quanta/web/view-model.mjs';

const definition = String.raw`{"system":{"module_id":"quanta.pair_dynamics","x":[-0.000e+00,1.0000e-09,9007199254740993]},"literal":"a } and \" stay data"}`;

function capabilities() {
  return {
    contract_version: '0.2.0',
    supported_experiment_versions: ['0.2.0', '0.4.0'],
    experiment_contracts: {
      '0.2.0': { schema_version: '0.2.0', implemented_operations: {
        'quanta.pair_static@0.1.0': ['energy_forces', 'relax'],
        'quanta.quantum_stationary@0.1.0': ['eigenstates'],
      } },
      '0.4.0': { schema_version: '0.4.0', implemented_operations: {
        'quanta.pair_dynamics@0.1.0': ['integrate'],
      } },
    },
  };
}

test('explicit dynamics builders preserve raw numeric tokens and emit version 0.4.0', () => {
  const revision = buildRevisionBody('Dynamics', definition, '0.4.0');
  const validation = buildValidationBody(definition, '0.4.0');
  for (const body of [revision, validation]) {
    assert.equal(JSON.parse(body).schema_version, '0.4.0');
    assert.equal(rawMember(body, 'definition'), definition);
    assert.ok(Object.is(JSON.parse(body).definition.system.x[0], -0));
    assert.ok(body.includes('9007199254740993'));
  }
  assert.equal(JSON.parse(revision).title, 'Dynamics');
});

test('old default and explicit static requests have byte-identical envelopes', () => {
  assert.equal(buildRevisionBody('Static', definition), buildRevisionBody('Static', definition, '0.2.0'));
  assert.equal(buildValidationBody(definition), buildValidationBody(definition, '0.2.0'));
  assert.equal(JSON.parse(buildValidationBody(definition)).schema_version, '0.2.0');
});

test('unimplemented contracts are refused rather than converted to an experiment contract', () => {
  for (const version of ['0.3.0', '0.3.1', '0.4', '1.0.0', '', null, 4, true, {}, []]) {
    assert.throws(() => buildRevisionBody('No conversion', definition, version), TypeError);
    assert.throws(() => buildValidationBody(definition, version), TypeError);
    assert.throws(() => importDraftJSON(`{"schema_version":${JSON.stringify(version)},"definition":${definition}}`), TypeError);
  }
});

test('a complete versioned draft round-trips its selected contract, title and exact definition', () => {
  const title = '<script>data</script>\n"quoted"';
  const body = buildRevisionBody(title, definition, '0.4.0');
  const imported = importDraftJSON(body);
  assert.deepEqual(imported, { definitionText: definition, schemaVersion: '0.4.0', title });
  assert.equal(buildRevisionBody(imported.title, imported.definitionText, imported.schemaVersion), body);
});

test('actual v0.4 revision fixture imports without changing any number lexeme', () => {
  const raw = readFileSync(new URL('../../contracts/v0.4.0/examples/free_revision.json', import.meta.url), 'utf8');
  const imported = importDraftJSON(raw);
  assert.equal(imported.schemaVersion, '0.4.0');
  assert.equal(imported.title, 'Free particles');
  assert.equal(imported.definitionText, rawMember(raw, 'definition'));
  assert.equal(rawMember(buildValidationBody(imported.definitionText, imported.schemaVersion), 'definition'), imported.definitionText);
});

test('bare input is not assigned a newer contract from its module or operation', () => {
  assert.deepEqual(importDraftJSON(definition), { definitionText: definition, schemaVersion: '0.2.0' });
  const bare = String.raw` {"protocol":{"steps":[{"operation":"integrate"}]},"system":{"x":-0}} `;
  assert.deepEqual(importDraftJSON(bare), { definitionText: bare, schemaVersion: '0.2.0' });
});

test('legacy definition envelopes retain 0.2 default and nested duplicate numbers for server validation', () => {
  const raw = '{"definition":{"system":{"x":-0,"x":1e-009}},"title":"Legacy"}';
  const imported = importDraftJSON(raw);
  assert.equal(imported.schemaVersion, '0.2.0');
  assert.equal(imported.title, 'Legacy');
  assert.equal(imported.definitionText, '{"system":{"x":-0,"x":1e-009}}');
  assert.equal((imported.definitionText.match(/"x":/g) || []).length, 2);
});

test('escaped envelope field names and strings containing braces do not alter import boundaries', () => {
  const raw = String.raw`{"schema_\u0076ersion":"0.4.0","def\u0069nition": {"s":"},] \" :","n":-0.00},"title":"named"}`;
  assert.deepEqual(importDraftJSON(raw), { definitionText: String.raw`{"s":"},] \" :","n":-0.00}`, schemaVersion: '0.4.0', title: 'named' });
});

test('duplicate definition/version/title envelope members are ambiguous even with escaped names', () => {
  const bad = [
    String.raw`{"definition":{},"def\u0069nition":{}}`,
    String.raw`{"definition":{},"schema_version":"0.2.0","schema_\u0076ersion":"0.4.0"}`,
    String.raw`{"definition":{},"title":"a","t\u0069tle":"b"}`,
  ];
  for (const raw of bad) assert.throws(() => importDraftJSON(raw), SyntaxError);
});

test('invalid versioned imports keep their error instead of becoming bare or repaired data', () => {
  for (const raw of [
    '{"schema_version":"0.4.0","system":{}}',
    '{"schema_version":"0.4.0","definition":[]}',
    '{"definition":null}', '{"definition":{},"title":123}',
    '[{"definition":{}}]', 'null', '{', '{"definition":{"x":NaN}}',
  ]) assert.throws(() => importDraftJSON(raw));
});

test('versioned server capabilities expose only known versions and do not mutate declarations', () => {
  const cap = capabilities();
  const before = structuredClone(cap);
  assert.deepEqual(supportedExperimentVersions(cap), ['0.2.0', '0.4.0']);
  assert.deepEqual(cap, before);
  cap.supported_experiment_versions = ['1.0.0', '0.4.0', '0.2.0'];
  cap.experiment_contracts['1.0.0'] = { schema_version: '1.0.0' };
  assert.deepEqual(supportedExperimentVersions(cap), ['0.2.0', '0.4.0']);
  cap.supported_experiment_versions = ['0.4.0'];
  assert.deepEqual(supportedExperimentVersions(cap), ['0.4.0']);
});

test('capabilities cannot advertise a known version without its exact version and implemented operations', () => {
  const mutations = [
    cap => { delete cap.experiment_contracts['0.4.0']; },
    cap => { cap.experiment_contracts['0.4.0'].schema_version = '0.3.1'; },
    cap => { cap.experiment_contracts['0.4.0'].implemented_operations['quanta.pair_dynamics@0.1.0'] = ['energy_forces']; },
    cap => { cap.experiment_contracts['0.2.0'].implemented_operations['quanta.pair_static@0.1.0'] = ['energy_forces']; },
    cap => { cap.supported_experiment_versions = ['0.2.0', '0.2.0']; },
    cap => { cap.supported_experiment_versions = '0.4.0'; },
    cap => { cap.supported_experiment_versions = ['0.4.0', 4]; },
    cap => { cap.experiment_contracts = []; },
    cap => { delete cap.supported_experiment_versions; },
  ];
  for (const mutate of mutations) {
    const cap = capabilities(); mutate(cap);
    assert.throws(() => supportedExperimentVersions(cap), TypeError);
  }
});

test('legacy capabilities expose only their declared 0.2 default, never implicit dynamics', () => {
  assert.deepEqual(supportedExperimentVersions({ contract_version: '0.2.0' }), ['0.2.0']);
  for (const cap of [{ contract_version: '0.4.0' }, {}, { contract_version: '0.3.1' }]) {
    assert.deepEqual(supportedExperimentVersions(cap), []);
  }
  for (const cap of [null, undefined, [], '0.2.0']) assert.throws(() => supportedExperimentVersions(cap), TypeError);
});

test('prototype properties cannot stand in for a declared contract or module operation', () => {
  const cap = capabilities();
  const inherited = cap.experiment_contracts['0.4.0'];
  delete cap.experiment_contracts['0.4.0'];
  Object.setPrototypeOf(cap.experiment_contracts, { '0.4.0': inherited });
  assert.throws(() => supportedExperimentVersions(cap), TypeError);
  const another = capabilities();
  another.experiment_contracts['0.4.0'].implemented_operations = Object.create({ 'quanta.pair_dynamics@0.1.0': ['integrate'] });
  assert.throws(() => supportedExperimentVersions(another), TypeError);
});
