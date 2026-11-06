#!/usr/bin/env python3
"""Measure generic dynamics using authenticated HTTP, SQLite and real children.

This is backend integration evidence, not UI parity, chemical validation,
checkpoint continuation or an OCI deployment probe.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import tempfile

from verify_dynamics import reference, source_record as dynamics_source_record
from verify_service import Measurements
from quanta import __version__
from quanta.environment import environment_report
from quanta.hashing import canonical_bytes
from quanta.job_store import ServiceError
from quanta.registry import ContractRegistry
from quanta.run_store import read_bundle, write_bundle
from quanta.service import ExecutionService
from quanta.worker import JobWorker


def example(name):
    r=ContractRegistry(contract_version='0.4.0')
    return json.loads((r.contract_dir/'examples'/f'{name}_revision.json').read_text())['definition']


def source_record():
    r=dynamics_source_record()
    for name in ['verify_dynamics_workflow.py','verify_service.py']:
        r['files_sha256']['scripts/'+name]=hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
    r['source_set_sha256']=hashlib.sha256(canonical_bytes(r['files_sha256'])).hexdigest()
    generic=ContractRegistry(contract_version='0.4.0')
    r['generic_contract_version']='0.4.0'
    r['generic_contract_files_sha256']={name:hashlib.sha256(raw).hexdigest() for name,raw in generic.raw_bytes.items()}
    r['generic_digest_manifest_sha256']=hashlib.sha256(generic._manifest_path.read_bytes()).hexdigest()
    return r


def difference(a,b):
    if isinstance(a,list):
        if not isinstance(b,(list,tuple)) or len(a)!=len(b):
            raise ValueError('Reference shape mismatch')
        return max((difference(x,y) for x,y in zip(a,b)),default=0)
    if not math.isfinite(a) or not math.isfinite(b):
        raise ValueError('Nonfinite reference comparison')
    return abs(a-b)


def submit(m,definition,key):
    status,exp=m.http('POST','/v1/experiments',{'title':'Dynamics backend verification'})
    if status!=201: raise ValueError('Experiment creation failed')
    status,rev=m.http('POST',f"/v1/experiments/{exp['experiment_id']}/revisions",
        {'schema_version':'0.4.0','title':'Dynamics backend verification','definition':deepcopy(definition)})
    if status!=201: raise ValueError('Revision admission failed: '+str(rev)[:240])
    status,run=m.http('POST','/v1/runs',{'revision_id':rev['revision_id']},key=key)
    if status!=202: raise ValueError('Asynchronous run admission failed: '+str(run)[:240])
    return rev,run


def completed(m,run):
    terminal,samples,elapsed=m.wait(run['run_id'])
    status,result=m.http('GET',f"/v1/runs/{run['run_id']}/result")
    if status!=200: raise ValueError('No published result: '+str(terminal['diagnostics'])[:300])
    return terminal,result,samples,elapsed


def measure(directory):
    m=Measurements(str(directory));cases=[]
    try:
        m.input=example('harmonic')
        before=m.counts()
        unauthorized,_=m.http('GET','/v1/capabilities',authenticated=False)
        cs,cap=m.http('GET','/v1/capabilities')
        vs,val=m.http('POST','/v1/validate',{'schema_version':'0.4.0','definition':m.input})
        checks={'unauthenticated_401':unauthorized==401,'default_contract_preserved':cs==200 and cap['contract_version']=='0.2.0',
            'explicit_dynamics_capability':cap['experiment_contracts']['0.4.0']['implemented_operations']=={'quanta.pair_dynamics@0.1.0':['integrate']},
            'valid_input':vs==200 and val['valid'],'validation_does_not_store':m.counts()==before,
            'initial_force_checks_explicitly_deferred':any(w['code']=='INITIAL_DYNAMICS_CHECKS_DEFERRED' for w in val['warnings'])}
        _,cancel=submit(m,example('free'),'dynamics-queued-cancel')
        status,cancelled=m.http('POST',f"/v1/runs/{cancel['run_id']}/cancel",{})
        checks['queued_cancelled_without_worker']=status==200 and cancelled['execution_status']=='CANCELLED' and not cancelled['artifacts']
        cases.append(m.case('DW01',checks,scope='Authenticated HTTP admission, capability versioning, no storage effects and queued cancellation'))

        revision,run=submit(m,m.input,'dynamics-harmonic-run')
        m.worker=JobWorker(m.service.directory).start()
        terminal,result,samples,elapsed=completed(m,run)
        step=result['steps'][0];payload=step['payload']
        if payload is None: raise ValueError('Harmonic run has no trajectory: '+str(result['errors'])[:300])
        frames=payload['legs'][0]['sampled_frames'];error=0
        for frame in frames:
            t=float(Fraction(m.input['numerics']['dt_s'])*frame['step_index'])
            if frame['time_s']!=t: raise ValueError('Published frame time differs from integer grid')
            positions,velocities=reference(t)
            error=max(error,difference(frame['positions_m'],positions),difference(frame['velocities_m_per_s'],velocities))
        state=next(s for s in result['states'] if s['state_id']==step['state_ref'])
        end=float(Fraction(m.input['numerics']['dt_s'])*int(m.input['numerics']['steps']))
        checks={'actual_child_succeeded':terminal['execution_status']=='SUCCEEDED','result_contract':'0.4.0'==result['schema_version'],
            'closed_form_state_error':error<=1e-6,'actual_time_in_data_and_envelope':state['data']['time_s']==end and state['physical_time']=={'value':end,'unit':'s'},
            'evolving_phase_state':state['time_kind']=='evolving' and state['data']['contract_version']=='0.3.1',
            'force_count':payload['legs'][0]['completed_force_evaluations']==int(m.input['numerics']['steps'])+1,
            'physical_unvalidated':result['physical_validation_status']=='unvalidated'}
        cases.append(m.case('DW02',checks,scope='Real numerical child via HTTP, independent harmonic closed form on every retained frame',
            frames_checked=len(frames),max_position_velocity_error=error,tolerance=1e-6,final_time_s=end,elapsed_seconds=elapsed,progress=samples))

        ms,manifest=m.http('GET',f"/v1/runs/{run['run_id']}/artifacts")
        transfers=[]
        for artifact in manifest['artifacts']:
            status,raw=m.http('GET',f"/v1/artifacts/{artifact['artifact_id']}")
            transfers.append({'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw),
                'passed':status==200 and hashlib.sha256(raw).hexdigest()==artifact['sha256'] and len(raw)==artifact['size_bytes']})
        foreign=False
        try:m.service.request('other-owner','GET',f"/v1/artifacts/{manifest['artifacts'][0]['artifact_id']}")
        except ServiceError as exc:foreign=exc.status==404
        report=m.service.store.get_report('verification-owner',run['run_id'])
        bundle=Path(directory)/'bundle';write_bundle(report,bundle)
        restored=read_bundle(bundle)
        checks={'all_raw_http_transfers_verified':ms==200 and bool(transfers) and all(x['passed'] for x in transfers),
            'foreign_owner_404':foreign,'bundle_roundtrip_exact':restored==report,
            'sqlite_reopen_exact':ExecutionService(m.service.directory).store.get_report('verification-owner',run['run_id'])==report}
        cases.append(m.case('DW03',checks,scope='Actual HTTP artifact bytes, owner separation, validated bundle and durable SQLite reopen',artifacts=transfers))

        status,replay=m.http('POST',f"/v1/runs/{run['run_id']}/replay",{},key='dynamics-replay')
        if status!=202:raise ValueError('Replay rejected: '+str(replay)[:240])
        again,replayed,_,seconds=completed(m,replay)
        checks={'new_run_id':replay['run_id']!=run['run_id'],'real_replay_succeeded':again['execution_status']=='SUCCEEDED',
            'same_payload':replayed['steps'][0]['payload']==payload,
            'same_science_and_execution_hashes':all(replayed[k]==result[k] for k in ['input_sha256','resolved_input_sha256','execution_fingerprint']),
            'new_state_ids':{s['state_id'] for s in result['states']}.isdisjoint({s['state_id'] for s in replayed['states']})}
        cases.append(m.case('DW04',checks,scope='A second actual numerical child replays immutable initial input; no solver checkpoint continuation',elapsed_seconds=seconds))

        _,refined=submit(m,example('harmonic_refinement'),'dynamics-refinement')
        rt,rr,_,seconds=completed(m,refined)
        rp=rr['steps'][0]['payload'];base=example('harmonic_refinement')['numerics']['steps']
        checks={'three_legs_completed':rt['execution_status']=='SUCCEEDED' and [l['refinement_factor'] for l in rp['legs']]==[1,2,4],
            'resolution_pass':rr['resolution_status']=='pass','actual_force_counts':[l['completed_force_evaluations'] for l in rp['legs']]==[base+1,2*base+1,4*base+1]}
        cases.append(m.case('DW05',checks,scope='h/h2/h4 trajectory survives generic API and result verification',resolution_comparison=rp['resolution_comparison'],elapsed_seconds=seconds))

        failed=example('free');particles=failed['system']['particles']
        for i,p in enumerate(particles):p.update(position_m=[-1 if i==0 else 1,0,0],velocity_m_per_s=[2 if i==0 else -2,0,0])
        failed['numerics'].update(dt_s=1,steps=2,sample_stride=1)
        _,bad=submit(m,failed,'dynamics-drift-failure')
        bt,br,_,seconds=completed(m,bad);bs=br['steps'][0];bp=bs['payload']
        checks={'failed_not_successful':bt['execution_status']=='FAILED','no_successful_output_state':bs['state_ref'] is None,
            'only_initial_accepted_frame':bp is not None and bp['partial'] and bp['legs'][0]['completed_steps']==0 and len(bp['legs'][0]['sampled_frames'])==1,
            'no_completed_step_claim':bs['outcome']=='FAILED','unvalidated':br['physical_validation_status']=='unvalidated'}
        cases.append(m.case('DW06',checks,scope='Interior drift crossing rejected by actual child; accepted partial evidence stored without final-state promotion',elapsed_seconds=seconds))
        return cases
    finally:m.close()


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args(argv)
    result={'verification_kind':'generic_dynamics_backend_http_storage_replay','created_at':datetime.now(timezone.utc).isoformat(),
        'package_version':__version__,'contract_version':'0.4.0','solver_contract_version':'0.3.1',
        'physical_validation_status':'unvalidated','full_D07_D11_acceptance_completed':False,
        'not_claimed':['UI trajectory parity','OCI deployment','chemical/physical validation','checkpoint continuation','implicit state conversion'],'cases':[]}
    try:
        result['environment']=environment_report();result['source']=source_record()
        if not result['environment']['valid']:raise ValueError('Locked environment is not valid')
        with tempfile.TemporaryDirectory(prefix='quanta-dynamics-backend-') as directory:result['cases']=measure(directory)
        result['status']='passed' if result['cases'] and all(c['status']=='passed' for c in result['cases']) else 'failed'
    except Exception as exc:result.update(status='failed',error={'type':type(exc).__name__,'message':str(exc)[:600]})
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':result['status'],'cases':{c['id']:c['status'] for c in result['cases']},'error':result.get('error'),'output':str(path)}))
    return 0 if result['status']=='passed' else 2


if __name__=='__main__':raise SystemExit(main())
