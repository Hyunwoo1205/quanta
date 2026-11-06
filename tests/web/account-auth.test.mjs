import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {authConfiguration,authRequestOptions,accountRequestOptions,accountChallenge,accessResponseNeedsLogin,runExecutionRequest,replayCompatibilityMessage} from '../../src/quanta/web/view-model.mjs';

const csrf='c'.repeat(64);
const principal={id:'c418de89-798b-45ed-a728-494d8121465d',owner:'local',username:'researcher',email:'researcher@example.test',mfa_enabled:true,is_admin:true};
const status={mode:'account',authenticated:true,configured:true,bootstrap_required:false,mail_configured:true,registration:'open',principal,csrf_token:csrf};

test('account discovery retains only public identity and session-bound CSRF metadata',()=>{
  const result=authConfiguration({...status,session_token:'never-return',smtp_password:'never-return',principal:{...principal,password:'never-return'}});
  assert.deepEqual(result,status);
  assert.equal(JSON.stringify(result).includes('never-return'),false);
  assert.notEqual(result.principal,principal);
});

test('anonymous discovery cannot install an injected identity or CSRF token',()=>{
  const result=authConfiguration({...status,authenticated:false,principal:{...principal,is_admin:true},csrf_token:csrf});
  assert.equal(result.principal,null);
  assert.equal(result.csrf_token,null);
  assert.equal(result.authenticated,false);
  assert.equal(result.registration,'open');
});

test('account discovery fails closed on malformed flags, missing identity and malformed CSRF',()=>{
  for(const changed of [
    {...status,authenticated:'true'}, {...status,configured:1}, {...status,mail_configured:null},
    {...status,bootstrap_required:'false'}, {...status,registration:'redirect:https://example.test'},
    {...status,principal:null}, {...status,principal:{...principal,owner:''}},
    {...status,principal:{...principal,username:'name\nheader'}},
    {...status,principal:{...principal,mfa_enabled:'false'}},
    {...status,principal:{...principal,is_admin:1}}, {...status,csrf_token:null},
    {...status,csrf_token:csrf.toUpperCase()}, {...status,csrf_token:'x'.repeat(64)},
  ]) assert.throws(()=>authConfiguration(changed),TypeError);
});

test('account API transport never forwards a bearer secret and uses same-origin cookies',()=>{
  const options=authRequestOptions('account','a-secret-that-must-not-leak');
  assert.equal(options.credentials,'same-origin');
  assert.equal(options.redirect,'error');
  assert.equal(options.cache,'no-store');
  assert.equal(options.headers.Authorization,undefined);
  assert.equal(options.headers.Cookie,undefined);
  assert.equal(options.headers['X-Quanta-CSRF'],undefined);
  assert.equal(JSON.stringify(options).includes('a-secret-that-must-not-leak'),false);
});

test('account API mutations require a well-formed CSRF token while reads and artifacts do not',()=>{
  for(const method of ['POST','PUT','PATCH','DELETE']){
    assert.throws(()=>authRequestOptions('account',null,{method}),TypeError);
    assert.throws(()=>authRequestOptions('account',null,{method,csrfToken:'invalid'}),TypeError);
    const options=authRequestOptions('account',null,{method,csrfToken:csrf});
    assert.equal(options.headers['X-Quanta-CSRF'],csrf);
    assert.equal(options.headers.Authorization,undefined);
  }
  assert.deepEqual(authRequestOptions('account',null,{json:false}).headers,{});
});

test('public login forms use fixed JSON header and bootstrap bearer excludes ambient cookies',()=>{
  const form=accountRequestOptions();
  assert.deepEqual(form.headers,{'Content-Type':'application/json','X-Quanta-Auth':'1'});
  assert.equal(form.credentials,'same-origin');
  const protectedForm=accountRequestOptions(csrf);
  assert.equal(protectedForm.headers['X-Quanta-CSRF'],csrf);
  const bootstrap=accountRequestOptions(null,'b'.repeat(64));
  assert.equal(bootstrap.credentials,'omit');
  assert.equal(bootstrap.headers.Authorization,'Bearer '+'b'.repeat(64));
  assert.throws(()=>accountRequestOptions(null,'invalid'),TypeError);
  assert.throws(()=>accountRequestOptions('invalid'),TypeError);
});

test('email challenge projection never authenticates or retains passwords, codes and session values',()=>{
  const projected=accountChallenge({challenge_id:'a'.repeat(64),expires_in:600,mfa_required:true,
    password:'never-return',code:'123456',session_token:'never-return'});
  assert.deepEqual(projected,{challenge_id:'a'.repeat(64),expires_in:600});
  for(const changed of [null,{...projected,authenticated:true},{...projected,challenge_id:'../escape'},
    {...projected,expires_in:0},{...projected,expires_in:601},{...projected,expires_in:'600'}]){
    assert.throws(()=>accountChallenge(changed),TypeError);
  }
});

test('ordinary account authorization and CSRF refusals are not mislabeled as login expiry',()=>{
  assert.equal(accessResponseNeedsLogin('account',{status:401}),true);
  for(const status of [403,422,429,503]) assert.equal(accessResponseNeedsLogin('account',{status}),false);
  assert.equal(accessResponseNeedsLogin('account',{status:200,contentType:'text/html'}),true);
  assert.equal(accessResponseNeedsLogin('account',{redirected:true}),true);
});

const html=readFileSync(new URL('../../src/quanta/web/index.html',import.meta.url),'utf8');
const app=readFileSync(new URL('../../src/quanta/web/app.js',import.meta.url),'utf8');
test('all literal UI element references exist and authentication fields do not embed initial credentials',()=>{
  const ids=new Set(Array.from(html.matchAll(/\bid="([^"]+)"/g),m=>m[1]));
  for(const match of app.matchAll(/\$\('([^']+)'\)/g)) assert.equal(ids.has(match[1]),true,'Missing element '+match[1]);
  for(const id of ['login-password','signup-password','signup-password-confirm','reset-password','reset-password-confirm','mfa-password','bootstrap-owner-key','bootstrap-gmail-password']){
    const field=html.match(new RegExp('<input\\b[^>]*\\bid="'+id+'"[^>]*>'))?.[0];
    assert.ok(field,id);
    assert.match(field,/type="password"/);
    assert.doesNotMatch(field,/\bvalue=/);
  }
  for(const id of ['login-password','signup-password','reset-password','mfa-password']){
    const field=html.match(new RegExp('<input\\b[^>]*\\bid="'+id+'"[^>]*>'))[0];
    assert.doesNotMatch(field,/maxlength=/,'Do not silently truncate Unicode passwords');
  }
});

test('account forms have browser completion hints and credentials stay out of browser persistence',()=>{
  assert.match(html,/id="login-username"[^>]*autocomplete="username"/);
  assert.match(html,/id="login-password"[^>]*autocomplete="current-password"/);
  assert.match(html,/id="signup-password"[^>]*autocomplete="new-password"/);
  assert.match(html,/id="login-code"[^>]*autocomplete="one-time-code"/);
  assert.doesNotMatch(app,/\b(?:localStorage|sessionStorage)\b|document\.cookie/);
  assert.doesNotMatch(html,/\bonsubmit=|\bonclick=/i);
});

const selectedRun=Object.freeze({run_id:'14c26d5f-f4bf-4ff2-8a47-c5b51e25fcef',revision_id:'7ea8d042-7d50-49b1-a434-e148b58dedec',execution_status:'SUCCEEDED'});
test('strict replay and current-version execution have separate explicit API contracts',()=>{
  assert.deepEqual(runExecutionRequest(selectedRun,'replay'),{path:'/v1/runs/'+selectedRun.run_id+'/replay',body:{}});
  assert.deepEqual(runExecutionRequest(selectedRun,'current'),{path:'/v1/runs',body:{revision_id:selectedRun.revision_id}});
  assert.equal(Object.hasOwn(runExecutionRequest(selectedRun,'current').body,'replay_of'),false);
  assert.equal(selectedRun.execution_status,'SUCCEEDED');
  for(const changed of [{...selectedRun,execution_status:'RUNNING'},{...selectedRun,revision_id:null},{...selectedRun,run_id:'../other'}]){
    assert.throws(()=>runExecutionRequest(changed,'current'),TypeError);
  }
  assert.throws(()=>runExecutionRequest(selectedRun,'automatic-fallback'),TypeError);
});

test('a strict replay version refusal explains a separate action without changing the old error',()=>{
  const error={status:409,data:{errors:[{code:'REGISTRY_SNAPSHOT_UNAVAILABLE',message:'original'}]}};
  assert.equal(replayCompatibilityMessage(error),'저장된 실행과 현재 버전이 다릅니다. 현재 버전으로 새 실행할 수 있습니다.');
  assert.equal(error.data.errors[0].message,'original');
  assert.equal(replayCompatibilityMessage({...error,status:403}),null);
  assert.equal(replayCompatibilityMessage({status:409,data:{errors:[{code:'RUN_NOT_READY'}]}}),null);
});

test('the selected result offers explicit current-version execution alongside same-environment replay',()=>{
  assert.match(html,/id="replay-run"[^>]*>같은 환경 재실행<\/button>/);
  assert.match(html,/id="current-run"[^>]*>현재 버전으로 새 실행<\/button>/);
  assert.match(app,/runExecutionRequest\(source,'replay'\)/);
  assert.match(app,/runExecutionRequest\(source,'current'\)/);
});
