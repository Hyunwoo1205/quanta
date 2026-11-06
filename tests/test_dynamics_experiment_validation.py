"""Generic dynamics admission stays force-free and respects both contracts."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from quanta.dynamics_validation import preflight_dynamics_request, validate_dynamics_request
from quanta.registry import ContractRegistry
from quanta.validation import validate_experiment

ROOT=Path(__file__).resolve().parents[1]


def experiment():
    return json.loads((ROOT/'contracts/v0.4.0/examples/free_revision.json').read_text())


def test_generic_validation_performs_no_force_evaluation(monkeypatch):
    from quanta.pair_kernel import PairForceKernel
    def forbidden(*args,**kwargs):
        pytest.fail('Authored experiment admission must not call the AD engine')
    monkeypatch.setattr(PairForceKernel,'evaluate',forbidden)
    report=validate_experiment(experiment())
    assert report['valid'],report['errors']
    assert report['schema_version']=='0.4.0'
    assert any(w['code']=='INITIAL_DYNAMICS_CHECKS_DEFERRED' for w in report['warnings'])


def test_structure_preflight_is_not_standalone_initial_force_validation():
    request=json.loads((ROOT/'contracts/v0.3.1/examples/free.request.json').read_text())
    report=preflight_dynamics_request(request)
    assert report['valid'] and report['scope']=='dynamics_structure_preflight'
    assert report['initial_force_evaluation_performed'] is False
    assert report['initial_state_checks_deferred'] is True
    assert 'initial_state_checks' not in report
    actual=validate_dynamics_request(request)
    assert actual['valid'] and actual['initial_force_evaluation_performed'] is True
    assert actual['dynamics_simulation_executed'] is False


@pytest.mark.parametrize('mutation',[
    lambda d:d['system']['particles'][0].update(mass_kg=0),
    lambda d:d['system']['particles'][0].pop('velocity_m_per_s'),
    lambda d:d['scales'].update(time_s=0),
    lambda d:d['numerics'].update(sample_stride=100),
    lambda d:d['system']['particles'][1].update(id=d['system']['particles'][0]['id']),
    lambda d:d['system']['particles'][1].update(position_m=d['system']['particles'][0]['position_m']),
    lambda d:d['system']['potential'].update(expression={'op':'param','name':'missing'}),
    lambda d:d.update(unregistered=True),
    lambda d:d.update(extensions={'unregistered':True}),
    lambda d:d['protocol']['steps'][0].update(source='previous'),
    lambda d:d['protocol']['steps'][0].update(overrides=[{'path':'/numerics/dt_s','value':.001}]),
    lambda d:d['protocol']['sweep'].update(axes=[{'path':'/numerics/dt_s','values':[.001,.002]}]),
    lambda d:d['protocol']['steps'].append(deepcopy(d['protocol']['steps'][0])),
])
def test_generic_invalid_or_unsupported_inputs_are_explicit(mutation):
    authored=experiment();mutation(authored['definition'])
    report=validate_experiment(authored)
    assert not report['valid'] and report['errors']
    assert report['input_sha256'] is None


def test_old_contract_does_not_enable_dynamics_and_explicit_mismatch_refuses():
    authored=experiment()
    assert not validate_experiment(authored,registry=ContractRegistry())['valid']
    authored['schema_version']='0.2.0'
    assert not validate_experiment(authored)['valid']


def test_generic_lowered_force_budget_is_not_ignored(tmp_path):
    import hashlib,shutil
    target=tmp_path/'contracts';shutil.copytree(ROOT/'contracts/v0.4.0',target)
    path=target/'resource_policy.json';policy=json.loads(path.read_text())
    policy['profiles']['pair_dynamics_cpu']['max_total_force_evaluations']=1
    path.write_text(json.dumps(policy))
    manifest=target/'SHA256SUMS.json';hashes=json.loads(manifest.read_text())
    hashes['resource_policy.json']=hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(hashes))
    registry=ContractRegistry(target,contract_version='0.4.0')
    assert not registry.validate_integrity()
    report=validate_experiment(experiment(),registry=registry)
    assert not report['valid']
    assert any(e['code']=='RESOURCE_LIMIT' for e in report['errors'])
