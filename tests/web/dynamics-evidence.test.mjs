import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {dynamicsArtifact,verifyDynamicsSource} from '../../src/quanta/web/dynamics-evidence.mjs';
const id='b4eb8bdb-85b8-4898-814a-6573055da6f1';
const raw='{"contract_version":"0.3.1","scope":"standalone_dynamics_integration","module_ref":{"module_id":"quanta.pair_dynamics","module_version":"0.1.0"},"payload":{"positions":[[-0.0,1e-200,2]],"id":"p1"}}';
const meta={artifact_id:id,sha256:createHash('sha256').update(raw).digest('hex'),size_bytes:Buffer.byteLength(raw),mime_type:'application/json',schema_ref:'dynamics_report.schema.json'};
const run={run_id:id,revision_id:id,artifacts:[meta]};
const result={...run,schema_version:'0.4.0'};
test('source selects the exact solver artifact in both recorded manifests',()=>{
  assert.equal(dynamicsArtifact(result,run),meta);
  for(const changed of [{...run,run_id:'wrong'},{...run,revision_id:'other'},{...run,artifacts:[]},{...run,artifacts:[meta,meta]},
    {...run,artifacts:[{...meta,sha256:'a'.repeat(64)}]}]) assert.throws(()=>dynamicsArtifact(result,changed));
  assert.throws(()=>dynamicsArtifact({...result,artifacts:[meta,meta]},run));
});
test('original bytes, decoded payload and signed zero agree before rendering',async()=>{
  const payload=JSON.parse(raw).payload;
  assert.deepEqual(await verifyDynamicsSource(raw,meta,payload),{size_bytes:meta.size_bytes,sha256:meta.sha256});
  const changed=structuredClone(payload);changed.positions[0][0]=0;
  await assert.rejects(verifyDynamicsSource(raw,meta,changed));
  changed.positions[0][0]=-0;changed.positions[0][1]=2e-200;
  await assert.rejects(verifyDynamicsSource(raw,meta,changed));
  await assert.rejects(verifyDynamicsSource(raw+' ',meta,payload));
  await assert.rejects(verifyDynamicsSource(raw,{...meta,sha256:'0'.repeat(64)},payload));
});
test('source identity and bounded byte metadata fail closed',async()=>{
  for(const changed of [{...meta,size_bytes:33554433},{...meta,artifact_id:'../file'},{...meta,mime_type:'text/html'}])
    assert.throws(()=>dynamicsArtifact({...result,artifacts:[changed]},{...run,artifacts:[changed]}));
  const wrong=raw.replace('standalone_dynamics_integration','untrusted_report');
  const m={...meta,size_bytes:Buffer.byteLength(wrong),sha256:createHash('sha256').update(wrong).digest('hex')};
  await assert.rejects(verifyDynamicsSource(wrong,m,JSON.parse(raw).payload));
});
