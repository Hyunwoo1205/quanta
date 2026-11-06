"""Explicit generic dynamics version through normal plan/run/replay commands."""
import json
from pathlib import Path

from quanta.cli import main
from quanta.run_store import read_bundle

ROOT=Path(__file__).resolve().parents[1]


def test_cli_generic_contract_and_plan(capsys):
    assert main(['check-contracts','--contract-version','0.4.0'])==0
    assert json.loads(capsys.readouterr().out)['contract_version']=='0.4.0'
    example=str(ROOT/'contracts/v0.4.0/examples/free_revision.json')
    assert main(['plan',example])==0
    report=json.loads(capsys.readouterr().out)
    assert report['valid'] and report['frozen_plan']['contract_version']=='0.4.0'


def test_cli_runs_stores_and_replays_dynamics(tmp_path,capsys):
    example=str(ROOT/'contracts/v0.4.0/examples/free_revision.json')
    first=tmp_path/'first';second=tmp_path/'replay'
    assert main(['run',example,'--output-dir',str(first),'--format','text'])==0
    assert 'SUCCEEDED' in capsys.readouterr().out
    assert main(['replay',str(first),'--output-dir',str(second),'--format','text'])==0
    assert 'SUCCEEDED' in capsys.readouterr().out
    a=read_bundle(first)['result'];b=read_bundle(second)['result']
    assert a['run_id']!=b['run_id']
    assert a['steps'][0]['payload']==b['steps'][0]['payload']
    assert a['schema_version']==b['schema_version']=='0.4.0'
    assert b['physical_validation_status']=='unvalidated'
