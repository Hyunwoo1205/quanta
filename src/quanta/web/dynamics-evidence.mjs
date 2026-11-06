/** Bind a rendered trajectory to the server's recorded solver-artifact bytes. */
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const sha = /^[0-9a-f]{64}$/;
function refuse() { throw new TypeError('저장된 동역학 원본과 결과가 일치하지 않습니다. 원본 다운로드와 실행 진단을 확인하세요.'); }

export function dynamicsArtifact(result, run) {
  if (result?.schema_version !== '0.4.0' || result.run_id !== run?.run_id
      || result.revision_id !== run?.revision_id || !Array.isArray(result.artifacts)
      || !Array.isArray(run.artifacts)) refuse();
  const candidates = result.artifacts.filter(a => a.schema_ref === 'dynamics_report.schema.json');
  if (candidates.length !== 1) refuse();
  const a = candidates[0], peers = run.artifacts.filter(b => b.artifact_id === a.artifact_id);
  if (!uuid.test(a.artifact_id) || !sha.test(a.sha256) || !Number.isSafeInteger(a.size_bytes)
      || a.size_bytes < 1 || a.size_bytes > 33554432 || a.mime_type !== 'application/json'
      || peers.length !== 1 || ['sha256','size_bytes','mime_type','schema_ref'].some(k => peers[0][k] !== a[k])) refuse();
  return a;
}

function same(a, b) {
  if (Object.is(a, b)) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every(k => Object.hasOwn(b, k) && same(a[k], b[k]));
}

export async function verifyDynamicsSource(rawText, artifact, payload) {
  if (typeof rawText !== 'string' || rawText.length > 33554432) refuse();
  const bytes = new TextEncoder().encode(rawText);
  if (bytes.byteLength !== artifact.size_bytes || !sha.test(artifact.sha256)) refuse();
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
  if (digest !== artifact.sha256) refuse();
  const report = JSON.parse(rawText);
  if (report?.contract_version !== '0.3.1' || report.scope !== 'standalone_dynamics_integration'
      || report.module_ref?.module_id !== 'quanta.pair_dynamics' || report.module_ref?.module_version !== '0.1.0'
      || !same(report.payload, payload)) refuse();
  return {size_bytes: bytes.byteLength, sha256: digest};
}
