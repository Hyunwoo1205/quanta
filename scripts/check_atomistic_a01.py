"""Check inactive A01 scientific design data, not an electronic-structure solver."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
D = ROOT / 'docs/design/atomistic-a01-v0.1'


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def read(path):
    def invalid(value):
        raise ValueError('nonfinite JSON')
    return json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=invalid)


def finite(value):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError('nonfinite number')
    elif isinstance(value, list):
        for item in value:
            finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            finite(item)
    else:
        raise ValueError('not JSON')


def positions(case):
    return {a['id']: [v * {'m': 1.0, 'angstrom': 1e-10}[case['coordinate_unit']]
                      for v in a['position']] for a in case['atoms']}


def fixture_error(c, profile):
    """Internal fixture consistency only; these are not public runtime API errors."""
    if c['executable'] is not False or c['status'] != 'planned_not_executed':
        return 'DESIGN_STATUS'
    if c['profile_id'] != profile['profile_id']:
        return 'PROFILE_MISMATCH'
    if c['charge_e'] != 0:
        return 'UNSUPPORTED_CHARGE'
    if c['multiplicity'] != 1:
        return 'UNSUPPORTED_SPIN'
    if any(a['element'] not in profile['selected_scope']['elements'] for a in c['atoms']):
        return 'UNSUPPORTED_ELEMENT'
    if c['boundary'] != 'isolated_nonperiodic_3d':
        return 'UNSUPPORTED_BOUNDARY'
    if len({a['id'] for a in c['atoms']}) != len(c['atoms']):
        return 'DUPLICATE_ATOM_ID'
    if c['coordinate_unit'] not in ('m', 'angstrom'):
        return 'UNSUPPORTED_COORDINATE_UNIT'
    if any(a['nuclear_charge'] != profile['selected_scope']['elements'][a['element']]
           or len(a['position']) != 3 for a in c['atoms']):
        return 'NUCLEAR_DEFINITION'
    if c['electron_count'] != sum(a['nuclear_charge'] for a in c['atoms']) - c['charge_e']:
        return 'ELECTRON_COUNT_MISMATCH'
    composition = {}
    for a in c['atoms']:
        composition[a['element']] = composition.get(a['element'], 0) + 1
    if composition not in profile['selected_scope']['reference_compositions']:
        return 'OUTSIDE_REFERENCE_COMPOSITION'
    if len(c['atoms']) == 2:
        p = list(positions(c).values())
        lo, hi = profile['selected_scope']['h2_validation_distance_m']
        if not lo <= math.dist(*p) <= hi:
            return 'NUCLEAR_DISTANCE_OUTSIDE_PROFILE'
    return None


def verify():
    profile, fixtures, plan, refs = [read(D / x) for x in
                                   ('profile.json', 'fixtures.json', 'validation-plan.json', 'reference-data.json')]
    for value in (profile, fixtures, plan, refs):
        finite(value)
    manifest = read(D / 'manifest.json')
    expected_paths = {str((D / n).relative_to(ROOT)) for n in
                      ('profile.json', 'fixtures.json', 'validation-plan.json', 'reference-data.json', 'README.md')}
    expected_paths.add('scripts/check_atomistic_a01.py')
    paths = [entry['path'] for entry in manifest['files']]
    assert set(paths) == expected_paths and len(paths) == len(expected_paths)
    for entry in manifest['files']:
        path = ROOT / entry['path']
        data = path.read_bytes()
        assert len(data) == entry['size_bytes'], entry['path']
        assert hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path']
    assert manifest['hash_scope'] == 'exact_UTF8_file_bytes_not_scientific_state_identity'
    assert profile['executable'] is False and profile['runtime_contract_version'] is None
    assert profile['physical_validation_status'] == 'unvalidated'
    assert profile['model']['electron_treatment'] == 'all_electron'
    assert profile['model']['core_pseudopotential'] is None
    assert profile['density_semantics']['soft_density_allowed_as_total'] is False
    assert profile['density_semantics']['signed_total_charge_density_allowed_as_substitute'] is False
    cases = {c['fixture_id']: c for c in fixtures['valid']}
    assert len(cases) == len(fixtures['valid']) == 7
    for c in cases.values():
        assert fixture_error(c, profile) is None, c['fixture_id']
        assert c['physical_expectations']['absolute_energy_j'] is None
        assert c['physical_expectations']['individual_force_n'] is None
        if c['role'] == 'static':
            assert all('velocity_m_per_s' not in a and 'nuclear_mass_kg' not in a for a in c['atoms'])
    for invalid in fixtures['invalid']:
        c = copy.deepcopy(cases[invalid['base']])
        for mutation in invalid['mutations']:
            target = c
            for key in mutation['path'][:-1]:
                target = target[key]
            target[mutation['path'][-1]] = mutation['value']
        assert fixture_error(c, profile) == invalid['expected_error'], invalid['fixture_id']
    base, transformed = cases['C03-H2-stretched'], cases['C04-H2-rigid-transform']
    R = transformed['equivalence']['rotation']
    shift = transformed['equivalence']['translation_m']
    for i in range(3):
        for j in range(3):
            dot = sum(R[k][i] * R[k][j] for k in range(3))
            assert abs(dot - (1 if i == j else 0)) < 1e-14
    det = (R[0][0]*(R[1][1]*R[2][2]-R[1][2]*R[2][1])
           - R[0][1]*(R[1][0]*R[2][2]-R[1][2]*R[2][0])
           + R[0][2]*(R[1][0]*R[2][1]-R[1][1]*R[2][0]))
    assert abs(det-1) < 1e-14
    for atom_id, p in positions(base).items():
        q = [sum(R[i][j]*p[j] for j in range(3))+shift[i] for i in range(3)]
        assert max(abs(x-y) for x,y in zip(q,positions(transformed)[atom_id])) <= 1e-25
    for name in ('C05-H2-permuted','C06-H2-angstrom'):
        for atom_id, p in positions(base).items():
            assert max(abs(x-y) for x,y in zip(p,positions(cases[name])[atom_id])) <= 1e-25
    expected_re = next(s['value'] for s in refs['sources'] if s['id']=='NIST-H2-RE') * 1e-10
    assert abs(math.dist(*positions(cases['C02-H2-reference']).values())-expected_re) <= 1e-25
    seed = cases['C07-H2-motion-seed']
    assert seed['equivalence']['scope'] == 'nuclear_geometry_only'
    assert seed['role']=='future_P3_seed' and seed['physical_time_s']==0
    mp = refs['constants']['proton_mass_kg']['value']
    for a in seed['atoms']:
        assert a['nuclear_mass_kg'] == mp
        assert math.isclose(math.sqrt(sum(v*v for v in a['velocity_m_per_s'])),100,abs_tol=1e-12)
    momentum = [sum(a['nuclear_mass_kg']*a['velocity_m_per_s'][j] for a in seed['atoms']) for j in range(3)]
    assert max(abs(p) for p in momentum) < 1e-36
    integration = seed['future_integration']
    assert math.isclose(integration['dt_s']*integration['steps'],integration['physical_duration_s'],rel_tol=1e-14)
    source_ids = {s['id'] for s in refs['sources']}
    assert set(profile['sources']) <= source_ids
    assert len({c['id'] for c in plan['checks']}) == len(plan['checks']) == 12
    for c in plan['checks']:
        assert c['status']=='not_executed'
        if 'reference_id' in c:
            assert c['reference_id'] in source_ids
    av = {c['id']:c for c in plan['checks']}
    assert av['AV10']['atol']==0.03 and av['AV11']['rtol']==0.05
    assert av['AV11']['curvature_unit'] == 'J/m^2'
    assert len(plan['bond_distance_scan_angstrom'])==13
    assert all(0.6 <= r <= 1.0 for r in plan['bond_distance_scan_angstrom'])
    data = (D/'manifest.json').read_bytes()
    return {'verification_kind':'inactive_A01_design_consistency','passed':True,
            'engine_executed':False,'numerical_solver_checks_executed':False,
            'physical_validation_status':'unvalidated','valid_fixtures_checked':len(cases),
            'negative_fixtures_rejected':len(fixtures['invalid']),
            'planned_scientific_checks':len(plan['checks']),
            'input_relations_checked':['SI/angstrom mapping','rigid rotation determinant and mapping',
                'permutation by stable ID','reference bond distance','nonzero seed velocities',
                'bare nuclear mass provenance','zero initial momentum','proposed time extent'],
            'file_hashes_checked':len(manifest['files']),
            'manifest_sha256':hashlib.sha256(data).hexdigest(),
            'scientific_results':None}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    report = verify()
    text = json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text)
    print(text,end='')
