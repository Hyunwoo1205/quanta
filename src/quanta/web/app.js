import {terminalStatuses,runExecutionRequest,replayCompatibilityMessage,statusLabel,formatNumber,rawMember,formatJSONPreservingNumbers,parseDefinition,buildRevisionBody,buildValidationBody,summarizeDefinition,chartPoints,quantumSeries,authConfiguration,authRequestOptions,accountRequestOptions,accountChallenge,isJSONResponse,accessResponseNeedsLogin,importDraftJSON,supportedExperimentVersions} from './view-model.mjs';
import {mountDynamicsViewer} from './dynamics-viewer.mjs';
import {dynamicsArtifact,verifyDynamicsSource} from './dynamics-evidence.mjs';

const $ = id => document.getElementById(id);
const S = {tab:'editor',schemaVersion:'0.2.0',savedSchemaVersion:null,capabilities:null,authMode:'unknown',authentication:null,authState:'checking',principal:null,authCheck:0,token:null,csrfToken:null,accountConfig:null,accountView:'login',accountBusy:false,accountChallenges:{},settingsOpen:false,mfaTarget:null,connected:false,session:0,selection:0,draftVersion:0,busy:0,experiment:null,revision:null,savedDefinition:null,savedTitle:null,examples:[],experimentCursor:null,runsCursor:null,runs:[],run:null,result:null,resultRaw:null,runSelection:0,pollTimer:null,pendingSubmission:null,pendingReplay:null,pendingCurrent:null,artifactExpanded:false,pollRequest:null,runsRequest:0,experimentsRequest:0};
let dynamicsViewer=null,viewerGeneration=0;
function disposeDynamics(){viewerGeneration++;dynamicsViewer?.dispose();dynamicsViewer=null;}
const axisNames = [['execution_status','작업 실행'],['numerical_status','수치 수렴'],['resolution_status','해상도 수렴'],['physical_validation_status','물리적 검증']];
const operationNames = {energy_forces:'에너지·힘 계산',relax:'정적 상태 탐색',eigenstates:'양자 정적 상태',integrate:'입자 동역학'};
function node(tag, className, text) { const element=document.createElement(tag); if(className) element.className=className; if(text!==undefined) element.textContent=String(text); return element; }
function clear(element) { element.replaceChildren(); return element; }
function short(value) { return value ? String(value).slice(0,8) : '—'; }
function color(status) {return ['SUCCEEDED','pass','valid','validated'].includes(status)?'success':['FAILED','not_converged','invalid'].includes(status)?'danger':['RUNNING','QUEUED','CANCEL_REQUESTED'].includes(status)?'info':['CANCELLED','unvalidated'].includes(status)?'warning':'neutral';}
function badge(status) {return node('span','badge '+color(status),statusLabel(status??'not_checked'));}
function notice(message) {$('notice').textContent=message; $('notice').hidden=!message;}
function clearError() {$('error-panel').hidden=true;clear($('error-list'));}
function showError(error) {
  const errors=error?.data?.errors??error?.errors??[{code:error?.code??'CLIENT_REQUEST',message:error?.message??String(error)}];
  clear($('error-list'));
  const flat=[];
  for(const item of errors){flat.push(item);if(Array.isArray(item.details?.errors))flat.push(...item.details.errors);}
  for(const issue of flat.slice(0,20)){const li=node('li','',issue.message??issue.code??'요청을 처리할 수 없습니다.');li.append(node('code','',[issue.code,issue.path].filter(Boolean).join(' · ')));$('error-list').append(li);}
  $('error-panel').hidden=false;
}
function responseInfo(response){return {status:response.status,redirected:response.redirected,type:response.type,contentType:response.headers.get('Content-Type')};}
function connectionLost(session,{loginRequired=false}={}){
  if(session!==S.session||!['access','account'].includes(S.authMode))return;
  disconnect(false);S.authState=loginRequired?'required':'uncertain';renderAuthentication();
  notice(loginRequired?'로그인이 만료되었거나 접근을 확인할 수 없습니다. 작성 중 입력은 유지했습니다. 다시 로그인하기 전에 JSON으로 내보내세요.':'연결 또는 로그인 상태를 확인하지 못했습니다. 작성 중 입력은 유지했습니다. 로그인 상태를 확인한 뒤 실행 기록을 먼저 확인하세요.');
}
async function api(method,path,body=null,options={}) {
  const token=S.token,session=S.session,mode=S.authMode,settings=authRequestOptions(mode,token,{csrfToken:S.csrfToken,method});
  if(options.key)settings.headers['Idempotency-Key']=options.key;
  let response;
  try {response=await fetch(path,{...settings,method,body:body===null?undefined:typeof body==='string'?body:JSON.stringify(body)});}
  catch(cause){connectionLost(session);const error=new Error('서버 응답을 확인하지 못했습니다. 연결 또는 로그인 상태를 확인한 뒤 다시 시도하세요.');error.network=true;error.cause=cause;throw error;}
  if(accessResponseNeedsLogin(mode,responseInfo(response))){connectionLost(session,{loginRequired:true});const error=new Error('로그인을 확인하고 다시 연결해주세요.');error.status=response.status;throw error;}
  let text,data;try{text=await response.text();}catch(cause){connectionLost(session);const error=new Error('서버 응답을 끝까지 확인하지 못했습니다. 연결 상태를 확인하세요.');error.network=true;error.cause=cause;throw error;}
  if(!isJSONResponse(response.headers.get('Content-Type'))){connectionLost(session);throw new Error('서버에서 올바른 응답을 받지 못했습니다. 연결 상태를 확인해주세요.');}
  try{data=text?JSON.parse(text):null;}catch{connectionLost(session);throw new Error('서버에서 읽을 수 없는 응답을 받았습니다.');}
  if(!response.ok){const error=new Error(data?.errors?.[0]?.message??'요청을 처리하지 못했습니다.');error.status=response.status;error.data=data;if(response.status===401&&session===S.session&&S.token===token){disconnect(false);notice('인증을 확인하고 다시 연결해주세요.');}throw error;}
  return options.raw?{data,text}:data;
}
function saved() {return !!S.revision&&$('definition-editor').value===S.savedDefinition&&$('experiment-title').value===S.savedTitle&&S.schemaVersion===S.savedSchemaVersion;}
function syncControls() {
  const ready=S.connected&&S.busy===0;
  const supported=!S.capabilities||supportedExperimentVersions(S.capabilities).includes(S.schemaVersion);
  for(const option of $('schema-version').options)option.disabled=!!S.capabilities&&!supportedExperimentVersions(S.capabilities).includes(option.value);
  $('schema-version').value=S.schemaVersion;
  $('footer-contract').textContent='CONTRACT '+(S.tab==='results'&&S.result?S.result.schema_version:S.schemaVersion);
  $('validate-definition').disabled=!ready||!supported;$('save-revision').disabled=!ready||!supported;$('run-revision').disabled=!ready||!supported||!saved();
  $('run-revision').textContent=S.pendingSubmission&&saved()?'같은 실행 요청 재시도':'▶ 실험 실행';
  $('refresh-runs').disabled=!ready;$('refresh-result').disabled=!ready||!S.run;
  $('cancel-run').disabled=!ready||!S.run||!['RUNNING','QUEUED'].includes(S.run.execution_status);
  $('replay-run').disabled=!ready||!S.run||!terminalStatuses.has(S.run.execution_status);
  $('replay-run').textContent=S.pendingReplay?'같은 재실행 요청 재시도':'같은 환경 재실행';
  $('current-run').disabled=!ready||!S.run||!terminalStatuses.has(S.run.execution_status)||!S.run.revision_id;
  $('current-run').textContent=S.pendingCurrent?'같은 새 실행 요청 재시도':'현재 버전으로 새 실행';
  $('download-result').disabled=!S.resultRaw;
  const state=$('draft-state');state.textContent=saved()?'저장된 입력':S.revision?'저장하지 않은 수정':'새 입력';state.className='badge '+(saved()?'success':S.revision?'warning':'neutral');
}
async function action(task){const session=S.session;clearError();S.busy++;syncControls();try{await task();}catch(error){if(session===S.session)showError(error);}finally{S.busy--;syncControls();}}
function setTab(tab){S.tab=tab;$('footer-contract').textContent='CONTRACT '+(tab==='results'&&S.result?S.result.schema_version:S.schemaVersion);if(tab!=='results')dynamicsViewer?.pause();for(const name of ['editor','runs','results'])$(name+'-view').hidden=name!==tab;document.querySelectorAll('.side-nav-item').forEach(item=>{const active=item.dataset.tab===tab;item.classList.toggle('active',active);if(active)item.setAttribute('aria-current','page');else item.removeAttribute('aria-current');});}
function invalidateRun(){disposeDynamics();S.runSelection++;clearTimeout(S.pollTimer);S.pollTimer=null;S.run=null;S.result=null;S.resultRaw=null;S.pendingReplay=null;S.pendingCurrent=null;renderRun();}
function discardOkay(){return !S.revision||saved()||window.confirm('저장하지 않은 수정이 있습니다. 다른 입력을 불러올까요?');}
function scientificJSON(value){if(typeof value==='number')return Object.is(value,-0)?'-0.0':JSON.stringify(value);if(Array.isArray(value))return '['+value.map(scientificJSON).join(',')+']';if(value&&typeof value==='object')return '{'+Object.entries(value).map(([k,v])=>JSON.stringify(k)+':'+scientificJSON(v)).join(',')+'}';return JSON.stringify(value);}
function setDraft(title,text,{revision=null,experiment=null,schemaVersion=revision?.schema_version??'0.2.0'}={}){
  if(!['0.2.0','0.4.0'].includes(schemaVersion))throw new TypeError('지원하지 않는 실험 계약입니다.');
  S.schemaVersion=schemaVersion;S.savedSchemaVersion=revision?schemaVersion:null;
  S.selection++;S.draftVersion++;S.experiment=experiment;S.revision=revision;S.pendingSubmission=null;
  $('experiment-title').value=title; $('definition-editor').value=text; S.savedTitle=revision?title:null;S.savedDefinition=revision?text:null;
  $('breadcrumb-title').textContent=experiment?.title??'새 실험';resetValidation();updateSummary();renderRevision();syncControls();
}
function resetValidation(){$('validation-state').textContent='검증 전';$('validation-state').className='badge neutral';$('validation-description').textContent='실행 전에 형식·단위·지원 범위와 자원 한도를 확인하세요.';clear($('validation-details'));}
function draftChanged(){S.draftVersion++;S.pendingSubmission=null;resetValidation();updateSummary();syncControls();}
function updateSummary(){
  $('line-count').textContent=$('definition-editor').value.split('\n').length+' lines';clear($('definition-summary'));clear($('protocol-list'));
  try{const definition=parseDefinition($('definition-editor').value),summary=summarizeDefinition(definition);const dl=node('dl');
    const labels=[['계산 모형',summary.module],['조건별 분기',summary.branches+'개'],['전체 계산 단계',summary.expandedSteps+'개']];if(summary.particles!==null)labels.splice(1,0,['입자 수',summary.particles+'개']);
    for(const [label,value]of labels){const row=node('div','summary-row');row.append(node('dt','',label),node('dd',label==='계산 모형'?'module-name':'',value));dl.append(row);}$('definition-summary').append(dl);
    for(const step of definition.protocol?.steps??[]){const li=node('li'),content=node('div','',operationNames[step.operation]??step.operation);content.append(node('small','',step.step_id+' · 출처 '+step.source));li.append(content);$('protocol-list').append(li);}
  }catch{$('definition-summary').append(node('p','muted','JSON 정의를 입력하면 구성을 미리 표시합니다. 정확한 입력 검증은 서버에서 수행합니다.'));}
}
function renderRevision(){clear($('saved-revision-info'));if(!S.revision)return;for(const [label,value]of [['저장한 입력 버전',S.revision.revision_id],['저장 시각',date(S.revision.created_at)]])$('saved-revision-info').append(node('dt','',label),node('dd','',value));}
function date(value){if(!value)return '—';const parsed=new Date(value);return Number.isFinite(parsed.getTime())?parsed.toLocaleString('ko-KR'):value;}
async function loadExamples(){const version=S.draftVersion,session=S.session;try{const response=await fetch('/ui/examples',authRequestOptions(S.authMode,S.token,{json:false}));if(accessResponseNeedsLogin(S.authMode,responseInfo(response))){connectionLost(session,{loginRequired:true});throw new Error();}if(!response.ok||!isJSONResponse(response.headers.get('Content-Type')))throw new Error();const data=await response.json();if(session!==S.session)return;S.examples=Array.isArray(data)?data:data.examples??[];clear($('sample-select'));for(const example of S.examples){const option=node('option','',example.title??example.id);option.value=example.id;$('sample-select').append(option);}if(S.examples.length&&version===S.draftVersion&&!$('definition-editor').value.trim()){const example=S.examples[0];setDraft(example.title,formatJSONPreservingNumbers(example.definition_json??scientificJSON(example.definition)),{schemaVersion:example.schema_version});}else if(!S.examples.length){$('sample-select').append(node('option','','등록된 예제가 없습니다.'));}}catch{if(session!==S.session)return;if(['access','account'].includes(S.authMode)&&S.connected)connectionLost(session);$('sample-select').replaceChildren(node('option','','예제를 불러올 수 없습니다.'));$('definition-editor').placeholder='실험 definition JSON을 붙여넣거나 파일을 가져오세요.';}}
function renderAuthentication(){
  const access=S.authMode==='access',account=S.authMode==='account',ownerKey=S.authMode==='bearer'&&S.authentication==='owner_token',known=S.authMode!=='unknown';
  $('connection-panel').classList.toggle('account-mode',account);$('connection-form').hidden=!known||access||account;$('account-auth').hidden=!account;$('access-actions').hidden=!access;$('check-session').hidden=!(access||account||!known&&S.authState==='uncertain');
  $('access-login').hidden=!access;
  $('connection-description').textContent=account?(S.accountConfig?.configured?'아이디와 비밀번호로 로그인하세요. 이메일 이중 인증을 켠 계정은 인증번호도 확인합니다.':'최초 관리자 설정 후 이메일을 인증하고 계정을 만들 수 있습니다.'):access?(S.authState==='uncertain'?'연결 또는 로그인 상태를 다시 확인하세요. 작성 중 입력은 이 화면에 유지됩니다.':'허용된 이메일로 로그인하면 저장한 실험과 계산 결과를 확인할 수 있어요.'):(ownerKey?'본인용 접근 키를 입력하세요. 키는 현재 화면의 메모리에만 보관하며 연결을 해제하면 지웁니다.':known?'서버 실행 시 설정한 API 토큰을 입력하세요. 토큰은 이 페이지가 열려 있는 동안만 메모리에 보관합니다.':'연결 방식을 확인하고 있습니다.');
  $('connection-heading').textContent=account?'연구 작업 공간에 로그인':access?(S.authState==='required'?'로그인을 확인해주세요.':'연구 작업 공간에 연결하세요.'):ownerKey?'내 작업 공간에 연결하세요.':'계산 환경에 연결하세요.';
  $('api-token-label').textContent=ownerKey?'소유자 접근 키':'API 토큰';$('api-token').placeholder=ownerKey?'본인용 접근 키':'서버의 QUANTA_API_TOKEN';
  $('environment-label').textContent=access||ownerKey||account?'PRIVATE RESEARCH WORKSPACE':'LOCAL RESEARCH ENVIRONMENT';$('workspace-location').textContent=access||ownerKey||account?'비공개 작업 공간':'로컬 작업 공간';
  $('disconnect').title=access||account?'로그아웃':'연결 해제';$('disconnect').setAttribute('aria-label',access||account?'작업 공간 로그아웃':'서버 연결 해제');
  $('access-login').textContent=S.authState==='required'?'다시 로그인':'로그인';
  $('account-settings-open').hidden=!account||!S.connected;
  if(account){renderAccountForms();renderAccountSettings();}
  else $('account-settings').hidden=true;
}
async function finishConnection(session){
  const capability=await api('GET','/v1/capabilities');if(session!==S.session)return;
  S.capabilities=capability;S.connected=true;S.authState='connected';$('connection-panel').hidden=true;$('connection-state').textContent=['access','account'].includes(S.authMode)?(S.principal?.username??S.principal?.email??'로그인됨'):'계산 환경 연결됨';$('environment-dot').classList.add('connected');$('disconnect').hidden=false;$('package-version').textContent='v'+capability.package_version;notice('계산 환경에 연결되었습니다. 입력을 검증하고 저장한 뒤 실행하세요.');renderAuthentication();syncControls();await Promise.all([loadExperiments(),loadRuns(),...((S.authentication==='owner_token'||S.authMode==='account')&&!S.examples.length?[loadExamples()]:[])]);
}
async function connect(event){event.preventDefault();if(S.authMode!=='bearer')return;const token=$('api-token').value;$('api-token').value='';const session=++S.session;S.token=token;clearError();$('connect-button').disabled=true;try{await finishConnection(session);}catch(error){if(session===S.session){S.token=null;S.connected=false;showError(error);}}finally{$('connect-button').disabled=false;syncControls();}}
function disconnect(showNotice=true){S.authCheck++;$('check-session').disabled=false;S.session++;S.selection++;S.experimentsRequest++;S.runsRequest++;S.token=null;S.csrfToken=null;S.connected=false;S.principal=null;S.accountChallenges={};S.settingsOpen=false;S.mfaTarget=null;clearAccountSecrets();$('account-settings').hidden=true;invalidateRun();S.experiment=null;S.revision=null;S.savedDefinition=null;S.savedTitle=null;S.savedSchemaVersion=null;S.capabilities=null;S.pendingSubmission=null;S.runs=[];S.experimentCursor=null;S.runsCursor=null;$('api-token').value='';$('connection-panel').hidden=false;$('disconnect').hidden=true;$('connection-state').textContent='연결 대기';$('environment-dot').classList.remove('connected');$('experiment-list').replaceChildren(node('p','sidebar-empty','다시 연결하면 저장한 실험을 확인할 수 있어요.'));$('more-experiments').hidden=true;$('more-runs').hidden=true;$('run-count').textContent='0';$('breadcrumb-title').textContent='작성 중 입력';for(const id of ['result-metrics','result-visualization','result-tables','artifact-list','run-identity','result-axes','run-diagnostics','step-select'])clear($(id));renderRuns();renderRevision();resetValidation();renderAuthentication();syncControls();if(showNotice)notice(S.authMode==='account'?'로그아웃했습니다. 작성 중 입력은 유지됩니다.':S.authentication==='owner_token'?'연결을 해제하고 메모리의 접근 키와 실행 결과를 지웠습니다. 작성 중 입력은 유지됩니다.':'연결을 해제하고 메모리의 토큰과 실행 결과를 지웠습니다. 작성 중 입력은 유지됩니다.');}
async function discoverAuthentication(){
  const request=++S.authCheck;$('check-session').disabled=true;clearError();
  try{
    const response=await fetch('/ui/auth',{credentials:'same-origin',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer'});
    if(!isJSONResponse(response.headers.get('Content-Type')))throw new Error('로그인 상태를 확인하지 못했습니다.');
    const data=await response.json();if(request!==S.authCheck)return;
    const config=authConfiguration(data);if(config.mode==='account'&&!config.authenticated&&S.connected){disconnect(false);S.authMode='account';S.accountConfig=config;S.authState='required';renderAuthentication();return;}S.authMode=config.mode;S.authentication=config.authentication??null;S.principal=config.principal??null;S.csrfToken=config.csrf_token??null;S.accountConfig=config.mode==='account'?config:null;S.authState=config.authenticated?'checking':'required';renderAuthentication();
    if(!response.ok&&!(config.mode==='access'&&[401,403].includes(response.status)))throw new Error(data?.errors?.[0]?.message??'연결 상태를 확인하지 못했습니다.');
    if(['access','account'].includes(config.mode)&&config.authenticated){const session=++S.session;await finishConnection(session);}
    if(request!==S.authCheck)return;
    if(!S.examples.length&&(config.mode!=='account'||config.authenticated))await loadExamples();
  }catch(error){if(request!==S.authCheck)return;S.authState='uncertain';renderAuthentication();notice('연결 또는 로그인 상태를 확인하지 못했습니다. 작성 중 입력을 유지한 채 상태를 다시 확인할 수 있어요.');showError(error);}finally{if(request===S.authCheck){$('check-session').disabled=false;syncControls();}}
}
function navigateAuthentication(logout=false){
  if(S.authMode!=='access')return;
  if($('definition-editor').value.trim()&&!window.confirm('이동하면 이 화면의 작성 중 입력이 사라집니다. 필요한 입력은 JSON으로 내보낸 뒤 이동하세요. 계속할까요?'))return;
  const target=logout?'/cdn-cgi/access/logout':'/';disconnect(false);location.assign(target);
}
const accountPaths=new Set(['/auth/login','/auth/login/verify','/auth/signup/request','/auth/signup/complete','/auth/logout','/auth/mfa/request','/auth/mfa/confirm','/auth/password/reset/request','/auth/password/reset/complete','/auth/admin/configure']);
const accountErrorMessages={UNAUTHORIZED:'아이디·비밀번호 또는 인증번호를 확인하세요.',AUTH_INPUT:'아이디·이메일·비밀번호·인증번호의 입력 형식을 확인하세요.',AUTH_RATE_LIMIT:'인증 요청이 많거나 재요청 간격이 짧습니다. 잠시 후 다시 시도하세요.',AUTH_BUSY:'비밀번호를 확인 중입니다. 잠시 후 다시 시도하세요.',MAIL_UNAVAILABLE:'인증메일을 보내지 못했습니다. 잠시 후 다시 요청하거나 관리자에게 문의하세요.',AUTH_UNAVAILABLE:'계정 확인을 일시적으로 사용할 수 없습니다. 잠시 후 다시 시도하세요.',OWNER_REQUIRED:'최초 설정에는 기존 소유자 접근 키가 필요합니다.',OWNER_CONFIGURED:'이미 등록한 관리자 이메일과 같은 주소를 입력하세요. 관리자 이메일은 이 화면에서 변경할 수 없습니다.',OWNER_SETUP_REQUIRED:'최초 관리자와 인증메일 설정을 먼저 완료해야 합니다.',ACCOUNT_UNAVAILABLE:'이 아이디 또는 이메일로 가입할 수 없습니다. 입력을 확인하세요.',ACCOUNT_CAPACITY:'현재 새 계정을 등록할 수 없습니다. 관리자에게 문의하세요.'};
const accountForms={'login':'account-login-form','login-code':'account-login-code-form','signup':'account-signup-request-form','signup-complete':'account-signup-complete-form','reset':'account-reset-request-form','reset-complete':'account-reset-complete-form'};
function clearAccountSecrets(){for(const input of document.querySelectorAll('#account-auth input[type="password"],#account-settings input[type="password"],#account-auth input[autocomplete="one-time-code"],#account-settings input[autocomplete="one-time-code"]'))input.value='';}
function accountMessage(message,settings=false){$(settings?'account-settings-message':'account-message').textContent=message;}
function renderAccountForms(){
  for(const [view,id]of Object.entries(accountForms))$(id).hidden=S.accountView!==view;
  for(const item of document.querySelectorAll('.account-tab')){const active=S.accountView.startsWith(item.dataset.authView);item.classList.toggle('active',active);if(active)item.setAttribute('aria-current','page');else item.removeAttribute('aria-current');}
  $('account-mail-note').hidden=S.accountConfig?.mail_configured===true;
  $('account-bootstrap').hidden=false;$('account-bootstrap-summary').textContent=S.accountConfig?.bootstrap_required?'최초 관리자 설정':'소유자 메일 설정 · 복구';
  for(const id of ['account-signup-request-form','account-reset-request-form'])$(id).querySelector('button[type="submit"]').disabled=S.accountBusy||!S.accountConfig?.configured;
}
function setAccountView(view){
  if(!Object.hasOwn(accountForms,view)||S.accountBusy)return;
  clearAccountSecrets();S.accountView=view;
  if(view==='login')delete S.accountChallenges.login;
  if(view==='signup')delete S.accountChallenges.signup;
  if(view==='reset')delete S.accountChallenges.reset;
  accountMessage('');renderAccountForms();$(accountForms[view]).querySelector('input')?.focus();
}
function renderAccountSettings(){
  const available=S.authMode==='account'&&S.connected&&S.principal;
  $('account-settings').hidden=!available||!S.settingsOpen;
  if(!available)return;
  $('account-identity').textContent=S.principal.username+' · '+S.principal.email;
  $('account-mfa-state').textContent=S.principal.mfa_enabled?'이메일 이중 인증이 켜져 있습니다. 로그인할 때 비밀번호와 이메일 인증번호를 확인합니다.':'이메일 이중 인증이 꺼져 있습니다. 설정하면 로그인할 때 이메일 인증번호를 한 번 더 확인합니다.';
  $('account-mfa-request-button').textContent=S.principal.mfa_enabled?'이메일 이중 인증 끄기':'이메일 이중 인증 켜기';
  $('account-mfa-request-form').hidden=!!S.accountChallenges.mfa;
  $('account-mfa-confirm-form').hidden=!S.accountChallenges.mfa;
}
async function accountPost(path,body,{csrf=false,ownerKey=null}={}){
  if(!accountPaths.has(path))throw new Error('지원하지 않는 계정 요청입니다.');
  const response=await fetch(path,{...accountRequestOptions(csrf?S.csrfToken:null,ownerKey),method:'POST',body:JSON.stringify(body)});
  if(response.redirected||response.type==='opaqueredirect'||!isJSONResponse(response.headers.get('Content-Type')))throw new Error('계정 응답을 확인하지 못했습니다. 상태를 다시 확인하세요.');
  const data=await response.json();
  if(!response.ok){const code=data?.errors?.[0]?.code,message=ownerKey!==null&&response.status===401?'기존 소유자 접근 키를 확인하세요.':accountErrorMessages[code]??data?.errors?.[0]?.message??'계정 요청을 처리하지 못했습니다.';const error=new Error(message);error.status=response.status;error.data={errors:[{code:code??'ACCOUNT_REQUEST',message}]};throw error;}
  return data;
}
async function accountAction(task){
  if(S.accountBusy)return;
  const viewBefore=S.accountView,hadMfa=!!S.accountChallenges.mfa;
  S.accountBusy=true;clearError();
  for(const item of document.querySelectorAll('#account-auth input,#account-auth button,#account-settings input,#account-settings button'))item.disabled=true;
  $('disconnect').disabled=true;$('account-settings-open').disabled=true;
  try{await task();}catch(error){showError(error);}finally{
    S.accountBusy=false;
    for(const item of document.querySelectorAll('#account-auth input,#account-auth button,#account-settings input,#account-settings button'))item.disabled=false;
    $('disconnect').disabled=false;$('account-settings-open').disabled=false;
    if(S.authMode==='account'){renderAccountForms();renderAccountSettings();if(!S.connected&&S.accountView!==viewBefore)$(accountForms[S.accountView]).querySelector('input')?.focus();else if(S.settingsOpen&&!!S.accountChallenges.mfa!==hadMfa)$(S.accountChallenges.mfa?'mfa-code':'mfa-password').focus();}
  }
}
function newAccountPassword(id,confirmation){
  const value=$(id).value,repeat=$(confirmation).value;
  $(id).value='';$(confirmation).value='';
  if(value!==repeat)throw new Error('비밀번호 확인이 일치하지 않습니다. 다시 입력하세요.');
  if(Array.from(value).length<15||Array.from(value).length>256)throw new Error('비밀번호는 15~256자로 입력하세요.');
  return value;
}
async function acceptAccountLogin(data){
  if(data?.authenticated!==true)throw new Error('로그인 완료를 확인하지 못했습니다. 로그인 상태를 다시 확인하세요.');
  clearAccountSecrets();S.accountChallenges={};S.accountView='login';accountMessage('');
  await discoverAuthentication();
}
async function logoutAccount(){await accountPost('/auth/logout',{}, {csrf:true});disconnect(false);S.accountView='login';renderAuthentication();notice('로그아웃했습니다. 작성 중 입력은 유지됩니다.');}
function resetMfaChallenge(){delete S.accountChallenges.mfa;S.mfaTarget=null;$('mfa-password').value='';$('mfa-code').value='';accountMessage('',true);renderAccountSettings();}
function listenAccountForm(id,task){$(id).addEventListener('submit',event=>{event.preventDefault();accountAction(task);});}
function bindAccountForms(){
  document.querySelectorAll('[data-auth-view]').forEach(button=>button.addEventListener('click',()=>setAccountView(button.dataset.authView)));
  listenAccountForm('account-login-form',async()=>{
    const username=$('login-username').value,password=$('login-password').value;$('login-password').value='';
    const data=await accountPost('/auth/login',{username,password});
    if(data?.mfa_required===true){S.accountChallenges.login=accountChallenge(data);S.accountView='login-code';accountMessage('등록한 이메일로 인증번호를 보냈습니다. 10분 안에 입력하세요.');renderAccountForms();$('login-code').focus();}
    else await acceptAccountLogin(data);
  });
  listenAccountForm('account-login-code-form',async()=>{
    const challenge=S.accountChallenges.login,code=$('login-code').value;$('login-code').value='';if(!challenge)throw new Error('로그인을 처음부터 다시 시작해주세요.');
    await acceptAccountLogin(await accountPost('/auth/login/verify',{challenge_id:challenge.challenge_id,code}));
  });
  listenAccountForm('account-signup-request-form',async()=>{
    const email=$('signup-email').value;
    S.accountChallenges.signup=accountChallenge(await accountPost('/auth/signup/request',{email}));S.accountView='signup-complete';$('signup-email-summary').textContent=email+' · 이메일 인증 후 가입이 완료됩니다.';accountMessage('인증번호를 받을 수 있는 주소라면 메일이 발송됩니다. 10분 안에 입력하세요.');renderAccountForms();$('signup-code').focus();
  });
  listenAccountForm('account-signup-complete-form',async()=>{
    const challenge=S.accountChallenges.signup,code=$('signup-code').value,username=$('signup-username').value;$('signup-code').value='';const password=newAccountPassword('signup-password','signup-password-confirm');if(!challenge)throw new Error('가입 인증번호를 다시 요청해주세요.');
    await acceptAccountLogin(await accountPost('/auth/signup/complete',{challenge_id:challenge.challenge_id,code,username,password}));
  });
  listenAccountForm('account-reset-request-form',async()=>{
    S.accountChallenges.reset=accountChallenge(await accountPost('/auth/password/reset/request',{email:$('reset-email').value}));S.accountView='reset-complete';accountMessage('등록된 주소라면 인증메일이 발송됩니다. 10분 안에 입력하세요.');renderAccountForms();$('reset-code').focus();
  });
  listenAccountForm('account-reset-complete-form',async()=>{
    const challenge=S.accountChallenges.reset,code=$('reset-code').value;$('reset-code').value='';const new_password=newAccountPassword('reset-password','reset-password-confirm');if(!challenge)throw new Error('재설정 인증번호를 다시 요청해주세요.');
    await accountPost('/auth/password/reset/complete',{challenge_id:challenge.challenge_id,code,new_password});clearAccountSecrets();S.accountChallenges={};S.accountView='login';accountMessage('비밀번호를 재설정했습니다. 새 비밀번호로 로그인하세요.');renderAccountForms();
  });
  listenAccountForm('account-bootstrap-form',async()=>{
    const ownerKey=$('bootstrap-owner-key').value,smtp_password=$('bootstrap-gmail-password').value,initial=S.accountConfig?.bootstrap_required===true;
    const body={smtp_username:$('bootstrap-gmail-username').value,smtp_password,owner_email:$('bootstrap-owner-email').value};
    $('bootstrap-owner-key').value='';$('bootstrap-gmail-password').value='';
    await accountPost('/auth/admin/configure',body,{ownerKey});await discoverAuthentication();S.accountView=initial?'signup':'login';if(initial)$('signup-email').value=body.owner_email;accountMessage(initial?'설정을 저장했습니다. 관리자 이메일을 인증하고 계정을 만드세요.':'메일 설정을 저장했습니다. 기존 계정으로 로그인하거나 이메일 인증을 다시 요청하세요.');$('account-bootstrap').open=false;renderAccountForms();
  });
  $('account-settings-open').addEventListener('click',()=>{S.settingsOpen=!S.settingsOpen;resetMfaChallenge();renderAccountSettings();if(S.settingsOpen)$('mfa-password').focus();});
  $('account-settings-close').addEventListener('click',()=>{S.settingsOpen=false;resetMfaChallenge();renderAccountSettings();});
  $('account-mfa-cancel').addEventListener('click',resetMfaChallenge);
  listenAccountForm('account-mfa-request-form',async()=>{
    const password=$('mfa-password').value,enabled=!S.principal?.mfa_enabled;$('mfa-password').value='';
    S.accountChallenges.mfa=accountChallenge(await accountPost('/auth/mfa/request',{password,enabled},{csrf:true}));S.mfaTarget=enabled;accountMessage('등록한 이메일로 보낸 인증번호를 입력하면 이중 인증 설정이 변경됩니다.',true);renderAccountSettings();$('mfa-code').focus();
  });
  listenAccountForm('account-mfa-confirm-form',async()=>{
    const challenge=S.accountChallenges.mfa,code=$('mfa-code').value,enabled=S.mfaTarget;$('mfa-code').value='';if(!challenge)throw new Error('이중 인증 설정을 처음부터 다시 시작해주세요.');
    await acceptAccountLogin(await accountPost('/auth/mfa/confirm',{challenge_id:challenge.challenge_id,code},{csrf:true}));S.settingsOpen=true;accountMessage(enabled?'이메일 이중 인증을 켰습니다.':'이메일 이중 인증을 껐습니다.',true);renderAccountSettings();
  });
}

async function loadExperiments(append=false){if(!S.connected)return;const session=S.session,request=++S.experimentsRequest,cursor=append?S.experimentCursor:null;const page=await api('GET','/v1/experiments?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''));if(session!==S.session||request!==S.experimentsRequest)return;if(!append)clear($('experiment-list'));for(const experiment of page.items){const button=node('button','experiment-item'+(S.experiment?.experiment_id===experiment.experiment_id?' active':''),experiment.title);button.type='button';button.dataset.experimentId=experiment.experiment_id;button.addEventListener('click',()=>action(()=>selectExperiment(experiment.experiment_id)));$('experiment-list').append(button);}if(!page.items.length&&!append)$('experiment-list').append(node('p','sidebar-empty','첫 실험을 저장해보세요.'));S.experimentCursor=page.next_cursor;$('more-experiments').hidden=!S.experimentCursor;}
async function selectExperiment(id){if(!discardOkay())return;const session=S.session,selection=++S.selection,version=S.draftVersion;const experiment=await api('GET','/v1/experiments/'+encodeURIComponent(id));if(session!==S.session||selection!==S.selection||version!==S.draftVersion)return;invalidateRun();if(experiment.revision_ids.length){await loadRevision(experiment.revision_ids.at(-1),experiment,selection,session);}else{setDraft(experiment.title,$('definition-editor').value,{experiment,schemaVersion:S.schemaVersion});}if(session!==S.session)return;await Promise.all([loadExperiments(),loadRuns()]);setTab('editor');}
async function loadRevision(id,experiment,selection=S.selection,session=S.session){const version=S.draftVersion;const revision=await api('GET','/v1/revisions/'+encodeURIComponent(id),null,{raw:true});if(session!==S.session||selection!==S.selection||version!==S.draftVersion)return;setDraft(revision.data.title,formatJSONPreservingNumbers(rawMember(revision.text,'definition')),{revision:revision.data,experiment});const select=node('select','revision-selector');select.setAttribute('aria-label','저장한 입력 버전');for(const revId of experiment.revision_ids){const option=node('option','','입력 버전 · '+short(revId));option.value=revId;option.selected=revId===id;select.append(option);}select.addEventListener('change',()=>action(async()=>{if(!discardOkay()){select.value=S.revision.revision_id;return;}const nextSelection=++S.selection;await loadRevision(select.value,S.experiment,nextSelection,S.session);}));$('saved-revision-info').append(select);}
async function validateCurrent(snapshot=null){const version=snapshot?.version??S.draftVersion,text=snapshot?.text??$('definition-editor').value,session=S.session,schemaVersion=snapshot?.schemaVersion??S.schemaVersion;if(!supportedExperimentVersions(S.capabilities).includes(schemaVersion))throw new Error('현재 서버가 지원하지 않는 실험 계약입니다.');const report=await api('POST','/v1/validate',buildValidationBody(text,schemaVersion));if(session!==S.session||version!==S.draftVersion){notice('입력이 변경되었습니다. 현재 입력을 다시 검증해주세요.');return null;}$('validation-state').textContent=report.valid?'검증 통과':'입력 확인';$('validation-state').className='badge '+(report.valid?'success':'danger');$('validation-description').textContent=report.valid?'형식·단위·지원 범위와 자원 한도를 확인했습니다. 계산 결과의 정확도 검증과는 별도입니다.':'아래 오류를 확인하고 입력을 수정해주세요.';clear($('validation-details'));for(const warning of report.warnings??[])$('validation-details').append(node('p','validation-detail',warning.message));if(!report.valid)showError(report);return report;}
async function saveRevision(){const snapshot={version:S.draftVersion,text:$('definition-editor').value,title:$('experiment-title').value,schemaVersion:S.schemaVersion},session=S.session,selection=S.selection;const body=buildRevisionBody(snapshot.title,snapshot.text,snapshot.schemaVersion);const validation=await validateCurrent(snapshot);if(!validation?.valid)return;if(session!==S.session||selection!==S.selection)return;let experiment=S.experiment;if(!experiment){experiment=await api('POST','/v1/experiments',{title:snapshot.title});if(session!==S.session||selection!==S.selection)return;S.experiment=experiment;}
  const revision=await api('POST','/v1/experiments/'+encodeURIComponent(experiment.experiment_id)+'/revisions',body);if(session!==S.session||selection!==S.selection)return;S.revision=revision;S.savedTitle=snapshot.title;S.savedDefinition=snapshot.text;S.savedSchemaVersion=snapshot.schemaVersion;S.pendingSubmission=null;S.experiment=experiment;$('breadcrumb-title').textContent=experiment.title;renderRevision();notice(saved()?'새 입력 버전을 저장했습니다. 이제 실험을 실행할 수 있어요.':'이전 입력을 저장했습니다. 현재 수정 내용은 새 입력으로 다시 저장해주세요.');await Promise.all([loadExperiments(),loadRuns()]);}
async function submitRun(){if(!saved())throw new Error('현재 입력을 새 버전으로 저장한 뒤 실행하세요.');const session=S.session,selection=S.selection,revision=S.revision.revision_id;if(!S.pendingSubmission||S.pendingSubmission.revision!==revision)S.pendingSubmission={revision,key:crypto.randomUUID()};const pending=S.pendingSubmission;try{const run=await api('POST','/v1/runs',{revision_id:revision},{key:pending.key});if(session!==S.session||selection!==S.selection)return;S.pendingSubmission=null;notice('실행 요청을 저장했습니다. 진행 상태는 실제 계산 단계에 따라 갱신됩니다.');await selectRun(run);await loadRuns();}catch(error){if(error.network&&session===S.session)notice('실행 요청의 응답을 확인하지 못했습니다. 다시 누르면 같은 키로 동일한 실행을 확인합니다.');throw error;}}
async function loadRuns(append=false){if(!S.connected)return;const session=S.session,selection=S.selection,request=++S.runsRequest,experiment=S.experiment?.experiment_id,cursor=append?S.runsCursor:null;const params=new URLSearchParams({limit:'50'});if(experiment)params.set('experiment_id',experiment);if(cursor)params.set('cursor',cursor);const page=await api('GET','/v1/runs?'+params.toString());if(session!==S.session||selection!==S.selection||request!==S.runsRequest)return;S.runs=append?[...S.runs,...page.items]:page.items;S.runsCursor=page.next_cursor;$('more-runs').hidden=!S.runsCursor;$('run-count').textContent=String(S.runs.length)+(S.runsCursor?'+':'');renderRuns();}
function renderRuns(){clear($('run-list'));if(!S.runs.length){const empty=node('div','empty-state card');empty.append(node('span','empty-symbol','◷'),node('h2','','아직 실행 기록이 없어요.'),node('p','','실험을 저장하고 실행하면 이곳에 표시됩니다.'));$('run-list').append(empty);return;}for(const run of S.runs){const button=node('button','run-row'+(S.run?.run_id===run.run_id?' active':''));const label=node('div');label.append(node('span','run-row-name',(run.replay_of?'재실행':'실행')+' · '+short(run.run_id)),node('span','run-row-id','입력 버전 '+run.revision_id));const meta=node('div','run-row-meta');meta.append(badge(run.execution_status),node('div','',date(run.created_at)),node('div','',(run.progress?.completed_steps??0)+' / '+(run.progress?.total_steps??0)+' 단계'));button.append(label,meta,node('span','run-row-arrow','→'));button.addEventListener('click',()=>action(()=>selectRun(run)));$('run-list').append(button);}}
async function selectRun(run){disposeDynamics();const sequence=++S.runSelection;clearTimeout(S.pollTimer);S.run=run;S.result=null;S.resultRaw=null;S.pendingReplay=null;S.pendingCurrent=null;S.artifactExpanded=false;renderRun();renderRuns();setTab('results');await refreshRun(sequence);}
async function refreshRun(sequence=S.runSelection){const key=String(sequence)+':'+S.run?.run_id;if(S.pollRequest?.key===key)return S.pollRequest.promise;clearTimeout(S.pollTimer);const promise=refreshRunInner(sequence).finally(()=>{if(S.pollRequest?.key===key)S.pollRequest=null;});S.pollRequest={key,promise};return promise;}
async function refreshRunInner(sequence=S.runSelection){if(!S.connected||!S.run)return;const session=S.session,id=S.run.run_id;try{const run=await api('GET','/v1/runs/'+encodeURIComponent(id));if(session!==S.session||sequence!==S.runSelection)return;S.run=run;renderRun();if(terminalStatuses.has(run.execution_status)){try{const result=await api('GET','/v1/runs/'+encodeURIComponent(id)+'/result',null,{raw:true});if(session!==S.session||sequence!==S.runSelection)return;S.result=result.data;S.resultRaw=result.text;renderResult();}catch(error){if(session!==S.session||sequence!==S.runSelection)return;if(error.status!==409)throw error;S.result=null;S.resultRaw=null;renderResult();}await loadRuns();}else{clearTimeout(S.pollTimer);S.pollTimer=setTimeout(()=>refreshRun(sequence),1000);}}catch(error){if(session===S.session&&sequence===S.runSelection){showError(error);if(S.connected){clearTimeout(S.pollTimer);S.pollTimer=setTimeout(()=>refreshRun(sequence),2500);}}}syncControls();}
function renderRun(){$('result-empty').hidden=!!S.run;$('result-content').hidden=!S.run;if(!S.run){syncControls();return;}$('active-run-title').textContent=statusLabel(S.run.execution_status);$('run-identity').textContent='RUN '+S.run.run_id+' · 입력 '+S.run.revision_id;clear($('result-axes'));for(const [field,label]of axisNames){const card=node('div','axis-card');card.append(node('p','',label),node('strong','',statusLabel(S.run[field]??'not_checked')));$('result-axes').append(card);}const progress=S.run.progress??{};$('run-progress').max=Math.max(progress.total_steps??1,1);$('run-progress').value=progress.completed_steps??0;$('progress-label').textContent=(progress.completed_steps??0)+' / '+(progress.total_steps??0)+' 단계 처리';$('active-step-label').textContent=progress.active_step?'현재 '+progress.active_step+' · 분기 '+(progress.active_branch??0):terminalStatuses.has(S.run.execution_status)?'실행 종료':'계산 준비 중';clear($('run-diagnostics'));for(const error of S.run.diagnostics??[])$('run-diagnostics').append(node('div','',(error.code?error.code+' · ':'')+(error.message??'')));renderArtifacts();renderResult();syncControls();}
function renderResult(){const result=S.result;if(!result)disposeDynamics();$('numerical-content').hidden=!result;$('result-unavailable').hidden=!!result;const pending=S.run&&!terminalStatuses.has(S.run.execution_status);$('result-unavailable-text').textContent=pending?'실행이 끝나면 검증된 결과를 이곳에서 확인할 수 있어요.':'검증된 수치 결과가 없는 실행입니다. 실행 상태와 종료 사유, 저장한 입력을 확인해주세요.';if(!result){syncControls();return;}const prior=$('step-select').value;clear($('step-select'));for(const [index,step]of result.steps.entries()){const option=node('option','','분기 '+step.branch_index+' · '+step.step_id+' · '+(operationNames[step.payload?.operation]??step.payload?.operation??statusLabel(step.outcome)));option.value=String(index);$('step-select').append(option);}if(prior&&Number(prior)<result.steps.length)$('step-select').value=prior;renderStep();syncControls();}
function metric(label,value,unit=''){const card=node('div','metric-card'),number=node('span','metric-value',value);if(unit)number.append(node('span','metric-unit',unit));card.append(node('span','metric-label',label),number);return card;}
function table(parent,title,headers,rows){parent.append(node('h2','',title));const wrapper=node('div','table-scroll'),element=node('table'),head=node('thead'),tr=node('tr');for(const h of headers)tr.append(node('th','',h));head.append(tr);const body=node('tbody');for(const row of rows){const t=node('tr');for(const value of row)t.append(node('td','',value));body.append(t);}element.append(head,body);wrapper.append(element);parent.append(wrapper);}
function chart(parent,title,xs,ys,{xLabel='x',yLabel='y',caption=''}={}){const heading=node('div','chart-heading');heading.append(node('h2','',title));parent.append(heading);const model=chartPoints(xs,ys,700,290,48);if(model.empty){parent.append(node('p','muted','표시할 유한한 데이터가 없습니다.'));return;}const NS='http://www.w3.org/2000/svg',svg=document.createElementNS(NS,'svg');svg.setAttribute('viewBox','0 0 700 290');svg.setAttribute('class','chart-svg');svg.setAttribute('role','img');svg.setAttribute('aria-label',title+' · '+xLabel+' / '+yLabel);const make=(name,attrs,text)=>{const element=document.createElementNS(NS,name);for(const [k,v]of Object.entries(attrs))element.setAttribute(k,String(v));if(text!==undefined)element.textContent=text;svg.append(element);return element;};for(let i=0;i<=4;i++){const y=model.top+(model.bottom-model.top)*i/4;make('line',{x1:model.left,y1:y,x2:model.right,y2:y,class:'chart-grid'});make('text',{x:model.left-8,y:y+3,'text-anchor':'end',class:'chart-label'},formatNumber(model.yMax-(model.yMax-model.yMin)*i/4,3));}if(model.zeroY!==null)make('line',{x1:model.left,y1:model.zeroY,x2:model.right,y2:model.zeroY,class:'chart-zero'});make('line',{x1:model.left,y1:model.bottom,x2:model.right,y2:model.bottom,class:'chart-axis'});make('polyline',{points:model.points,class:'chart-line'});for(const i of [0,1,2,3,4]){const x=model.left+(model.right-model.left)*i/4;make('text',{x,y:model.bottom+19,'text-anchor':'middle',class:'chart-label'},formatNumber(model.xMin+(model.xMax-model.xMin)*i/4,3));}make('text',{x:350,y:285,'text-anchor':'middle',class:'chart-label'},xLabel);make('text',{x:model.left,y:16,class:'chart-label'},yLabel);parent.append(svg);if(caption)parent.append(node('p','chart-caption',caption));}
function renderStep(){disposeDynamics();clear($('result-metrics'));clear($('result-visualization'));clear($('result-tables'));const step=S.result?.steps?.[Number($('step-select').value)];if(!step)return;$('step-outcome').className='badge '+color(step.outcome);$('step-outcome').textContent=statusLabel(step.outcome)+(step.partial?' · 부분 결과':'');const p=step.payload;if(!p){$('result-metrics').append(metric('단계 상태',statusLabel(step.outcome)));$('result-visualization').append(node('h2','','계산 payload 없음'),node('p','muted','이 단계는 수치 결과를 공개하지 않았습니다. 실행 진단을 확인해주세요.'));$('result-tables').hidden=true;return;}$('result-tables').hidden=false;
  if(p.operation==='integrate'){if(S.result.schema_version!=='0.4.0'||step.module_id!=='quanta.pair_dynamics'||step.module_version!=='0.1.0'){showError(new Error('동역학 결과의 계약 또는 모형을 확인할 수 없습니다. 원본 결과를 확인하세요.'));return;}renderDynamicsStep(step);return;}
  if(p.operation==='eigenstates'){renderQuantum(p);renderChecks(p);return;}const forces=p.forces_n??[],maximum=forces.length?Math.max(...forces.map(f=>Math.hypot(...f))):null;$('result-metrics').append(metric('총에너지',formatNumber(p.energy_j),'J'),metric('최대 합력',formatNumber(maximum),'N'),metric(p.operation==='relax'?'자유 좌표 기울기':'평가한 입자',p.operation==='relax'?formatNumber(p.free_gradient_inf):String(p.final_positions_m?.length??0),p.operation==='relax'?'무차원':'개'));
  if(p.operation==='relax'&&p.optimization_history?.length){const history=p.optimization_history;const xs=history.map((v,i)=>v.iteration??i),ys=history.map(v=>v.energy_j);chart($('result-visualization'),'정적 탐색의 에너지 변화',xs,ys,{xLabel:'수락한 반복',yLabel:'에너지 (J)',caption:'최적화의 계산 반복입니다. 실제 시간이 흐르는 운동 궤적을 뜻하지 않습니다.'});}else{const positions=p.final_positions_m??[];chart($('result-visualization'),'최종 배치 · x 좌표',positions.map((_,i)=>i+1),positions.map(v=>v[0]),{xLabel:'입자 순번',yLabel:'x (m)',caption:'입자 순번에 따른 x 좌표입니다. y·z 좌표와 각 축의 힘은 아래 원본 수치에서 확인하세요.'});}
  const initial=S.result.states?.find(v=>v.producer?.kind==='initial'&&v.data?.particles);const ids=initial?.data?.particles?.map(v=>v.id)??[];table($('result-tables'),'입자별 최종 좌표와 힘',['입자','x (m)','y (m)','z (m)','Fx (N)','Fy (N)','Fz (N)'],(p.final_positions_m??[]).map((v,i)=>[ids[i]??String(i+1),...v.map(x=>formatNumber(x)),...(forces[i]??[null,null,null]).map(x=>formatNumber(x))]));if(p.operation==='relax')$('result-tables').append(node('p','chart-caption','종료 사유: '+(p.stop_reason??'—')+' · 수락 반복 '+p.iterations+' · 함수 평가 '+p.evaluations+' · 전역 최솟값 또는 최소점의 보증과는 별도입니다.'));renderChecks(p);
}
async function renderDynamicsStep(step){
  const generation=viewerGeneration,session=S.session,result=S.result,run=S.run;
  $('result-visualization').append(node('p','muted','저장된 궤적의 원본 근거를 확인하고 있습니다.'));
  try{
    const artifact=dynamicsArtifact(result,run);
    const raw=await readArtifactBytes(artifact,session);
    const receipt=await verifyDynamicsSource(new TextDecoder('utf-8',{fatal:true}).decode(raw),artifact,step.payload);
    if(generation!==viewerGeneration||session!==S.session||result!==S.result||run.run_id!==S.run?.run_id)return;
    clear($('result-visualization'));
    dynamicsViewer=mountDynamicsViewer({payload:step.payload,host:$('result-visualization'),tableHost:$('result-tables'),metricsHost:$('result-metrics')});
    $('result-visualization').append(node('p','chart-caption','원본 궤적 근거 확인 · '+receipt.size_bytes.toLocaleString()+' bytes · SHA-256 '+receipt.sha256));
  }catch(error){if(generation!==viewerGeneration||session!==S.session)return;clear($('result-visualization'));$('result-visualization').append(node('h2','','궤적을 표시할 수 없습니다.'),node('p','muted',error.message));showError(error);}
}
async function readArtifactBytes(artifact,session=S.session){
  let response;
  try{response=await fetch('/v1/artifacts/'+encodeURIComponent(artifact.artifact_id),authRequestOptions(S.authMode,S.token,{json:false}));}
  catch(error){connectionLost(session);throw error;}
  if(accessResponseNeedsLogin(S.authMode,responseInfo(response))){connectionLost(session,{loginRequired:true});throw new Error('로그인을 확인한 뒤 원본 궤적을 다시 여세요.');}
  if(!response.ok||/^text\/html/i.test(response.headers.get('Content-Type')??''))throw new Error('원본 산출물을 읽을 수 없습니다.');
  const declared=response.headers.get('Content-Length');
  if(declared!==null&&Number(declared)!==artifact.size_bytes)throw new Error('원본 산출물의 전송 크기가 기록과 다릅니다.');
  const bytes=await response.arrayBuffer();
  if(bytes.byteLength!==artifact.size_bytes||bytes.byteLength>33554432)throw new Error('원본 산출물 크기가 기록과 다릅니다.');
  return bytes;
}
function renderChecks(p){const checks=p.diagnostics?.checks;if(!Array.isArray(checks)||!checks.length)return;const display=value=>value===undefined||value===null?'—':typeof value==='number'?formatNumber(value):typeof value==='string'?value:JSON.stringify(value);const block=node('section');block.className='diagnostic-checks';table(block,'계산 기준과 실제 검사값',['기준','판정','실제값','허용오차'],checks.map(check=>[check.id??'—',statusLabel(check.status),display(check.value),display(check.tolerance)]));$('result-tables').append(block);}
function renderQuantum(p){$('result-metrics').append(metric('가장 낮은 에너지',formatNumber(p.energies_j?.[0]),'J'),metric('계산한 상태',String(p.energies_j?.length??0),'개'),metric('공간 격자',String(p.x_m?.length??0),'점'));const visualization=$('result-visualization'),heading=node('div','chart-heading');heading.append(node('h2','','파동함수와 확률밀도'));const controls=node('div'),stateSelect=node('select'),kindSelect=node('select');stateSelect.setAttribute('aria-label','양자 상태 선택');kindSelect.setAttribute('aria-label','양자 결과 표시 종류');for(let i=0;i<(p.energies_j?.length??0);i++){const option=node('option','','상태 '+(i+1));option.value=String(i);stateSelect.append(option);}for(const [value,text]of [...(p.density_per_m?[['density','확률밀도']]:[]),...(p.states?.real?[['wave','파동함수']]:[])]){const option=node('option','',text);option.value=value;kindSelect.append(option);}controls.append(stateSelect,kindSelect);heading.append(controls);visualization.append(heading);const plot=node('div');visualization.append(plot);function draw(){clear(plot);const index=Number(stateSelect.value),density=kindSelect.value==='density',series=quantumSeries(p,index,density?'density':'wave');chart(plot,series.label+' · 상태 '+(index+1),series.xs,series.ys,{xLabel:'위치 x (m)',yLabel:series.unit,caption:'유한한 1차원 구간 · 양 끝 파동함수 0 · 계산한 실제 격자 값을 표시합니다.'});}stateSelect.addEventListener('change',draw);kindSelect.addEventListener('change',draw);draw();table($('result-tables'),'가능한 에너지 상태',['상태','에너지 (J)','위치 기댓값 (m)'],(p.energies_j??[]).map((value,i)=>[String(i+1),formatNumber(value),formatNumber(p.x_mean_m?.[i])]));}
function renderArtifacts(){clear($('artifact-list'));const artifacts=S.run?.artifacts??[];if(!artifacts.length){$('artifact-list').append(node('p','muted','공개된 산출물이 아직 없습니다.'));return;}for(const artifact of artifacts.slice(0,S.artifactExpanded?undefined:8)){const row=node('div','artifact-row'),label=node('div');label.append(node('span','artifact-name',(artifact.kind==='config'?'구조화된 근거':'실행 근거')+' · '+short(artifact.artifact_id)+' · '+artifact.size_bytes.toLocaleString()+' bytes'),node('span','artifact-hash','SHA-256 '+artifact.sha256));const button=node('button','button secondary small','다운로드');button.addEventListener('click',()=>action(()=>downloadArtifact(artifact)));row.append(label,button);$('artifact-list').append(row);}if(artifacts.length>8&&!S.artifactExpanded){const more=node('button','text-button','산출물 '+artifacts.length+'개 모두 보기');more.addEventListener('click',()=>{S.artifactExpanded=true;renderArtifacts();});$('artifact-list').append(more);}}
async function downloadArtifact(artifact){const session=S.session,mode=S.authMode;let response;try{response=await fetch('/v1/artifacts/'+encodeURIComponent(artifact.artifact_id),authRequestOptions(mode,S.token,{json:false}));}catch(cause){connectionLost(session);const error=new Error('산출물의 응답을 확인하지 못했습니다. 연결 또는 로그인 상태를 확인하세요.');error.network=true;error.cause=cause;throw error;}if(accessResponseNeedsLogin(mode,responseInfo(response))){connectionLost(session,{loginRequired:true});throw new Error('로그인을 확인한 뒤 산출물을 다시 내려받으세요.');}if(!response.ok){if(response.status===401&&session===S.session){disconnect(false);notice('인증을 확인하고 다시 연결해주세요.');}throw new Error('산출물을 다운로드할 수 없습니다.');}if(/^text\/html/i.test(response.headers.get('Content-Type')??''))throw new Error('산출물 대신 다른 응답을 받았습니다.');let bytes;try{bytes=await response.arrayBuffer();}catch(cause){connectionLost(session);const error=new Error('산출물을 끝까지 내려받지 못했습니다. 연결 상태를 확인하세요.');error.network=true;error.cause=cause;throw error;}if(session!==S.session)return;const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))).map(x=>x.toString(16).padStart(2,'0')).join('');if(session!==S.session)return;if(digest!==artifact.sha256||bytes.byteLength!==artifact.size_bytes)throw new Error('산출물 크기 또는 SHA-256이 기록과 다릅니다.');download(new Blob([bytes],{type:artifact.mime_type}),'quanta-'+artifact.artifact_id+(artifact.mime_type?.startsWith('application/json')?'.json':'.txt'));}
function download(blob,filename){const href=URL.createObjectURL(blob),a=node('a');a.href=href;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(href),1000);}

bindAccountForms();
$('connection-origin').textContent='연결 주소 · '+location.origin;
$('connection-form').addEventListener('submit',connect);
$('disconnect').addEventListener('click',()=>S.authMode==='account'?accountAction(logoutAccount):S.authMode==='access'?navigateAuthentication(true):disconnect());
$('access-login').addEventListener('click',()=>navigateAuthentication());
$('check-session').addEventListener('click',discoverAuthentication);
$('dismiss-error').addEventListener('click',clearError);
document.querySelectorAll('[data-tab]').forEach(button=>button.addEventListener('click',()=>setTab(button.dataset.tab)));
$('schema-version').addEventListener('change',()=>{S.schemaVersion=$('schema-version').value;draftChanged();});
$('experiment-title').addEventListener('input',draftChanged);$('definition-editor').addEventListener('input',draftChanged);
$('new-experiment').addEventListener('click',()=>{if(!discardOkay())return;invalidateRun();setDraft('새 실험',$('definition-editor').value,{schemaVersion:S.schemaVersion});S.runs=[];renderRuns();setTab('editor');if(S.connected)action(()=>loadRuns());});
$('load-sample').addEventListener('click',()=>{if(!discardOkay())return;const example=S.examples.find(v=>v.id===$('sample-select').value);if(!example)return;invalidateRun();setDraft(example.title,formatJSONPreservingNumbers(example.definition_json??scientificJSON(example.definition)),{schemaVersion:example.schema_version});S.runs=[];renderRuns();setTab('editor');notice('예제 입력을 불러왔습니다. 값을 수정하거나 검증을 시작하세요.');});
$('format-json').addEventListener('click',()=>{try{$('definition-editor').value=formatJSONPreservingNumbers($('definition-editor').value);draftChanged();}catch(error){showError(error);}});
$('export-draft').addEventListener('click',()=>{try{download(new Blob([buildRevisionBody($('experiment-title').value,$('definition-editor').value,S.schemaVersion)],{type:'application/json'}),'quanta-draft.json');}catch(error){showError(error);}});
$('import-file').addEventListener('change',async event=>{const file=event.target.files?.[0];event.target.value='';if(!file||!discardOkay())return;try{if(file.size>1048576)throw new Error('JSON 파일은 1 MiB 이하여야 합니다.');const version=S.draftVersion,selection=S.selection;const raw=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());if(version!==S.draftVersion||selection!==S.selection)return;const imported=importDraftJSON(raw);invalidateRun();setDraft(imported.title??file.name.replace(/\.json$/i,''),formatJSONPreservingNumbers(imported.definitionText),{schemaVersion:imported.schemaVersion});notice('파일을 편집 가능한 새 입력으로 불러왔습니다. 서버 입력 검증 후 저장하세요.');}catch(error){showError(error);}});
$('validate-definition').addEventListener('click',()=>action(()=>validateCurrent()));
$('save-revision').addEventListener('click',()=>action(saveRevision));
$('run-revision').addEventListener('click',()=>action(submitRun));
$('refresh-runs').addEventListener('click',()=>action(()=>loadRuns()));
$('more-runs').addEventListener('click',()=>action(()=>loadRuns(true)));
$('more-experiments').addEventListener('click',()=>action(()=>loadExperiments(true)));
$('refresh-result').addEventListener('click',()=>action(()=>refreshRun()));
$('cancel-run').addEventListener('click',()=>action(async()=>{const id=S.run?.run_id,session=S.session,sequence=S.runSelection;if(!id)return;const run=await api('POST','/v1/runs/'+encodeURIComponent(id)+'/cancel',{});if(session!==S.session||sequence!==S.runSelection)return;S.run=run;notice('취소 요청을 확인했습니다. 완료 여부는 서버가 확정한 실행 상태를 따릅니다.');await refreshRun(sequence);}));
$('replay-run').addEventListener('click',()=>action(async()=>{
  const source=S.run,session=S.session,sequence=S.runSelection;if(!source)return;
  const request=runExecutionRequest(source,'replay');
  if(!S.pendingReplay||S.pendingReplay.source!==source.run_id)S.pendingReplay={source:source.run_id,key:crypto.randomUUID()};
  try{const run=await api('POST',request.path,request.body,{key:S.pendingReplay.key});if(session!==S.session||sequence!==S.runSelection)return;S.pendingReplay=null;notice('같은 입력과 환경의 재실행을 시작했습니다.');await selectRun(run);await loadRuns();}
  catch(error){const compatibility=replayCompatibilityMessage(error);if(compatibility&&session===S.session){notice(compatibility);error.message=compatibility;error.data={errors:[{code:'REGISTRY_SNAPSHOT_UNAVAILABLE',message:compatibility}]};}else if(error.network&&session===S.session)notice('재실행 응답을 확인하지 못했습니다. 다시 누르면 같은 요청 키를 유지합니다.');throw error;}
}));
$('current-run').addEventListener('click',()=>action(async()=>{
  const source=S.run,session=S.session,sequence=S.runSelection;if(!source)return;
  const request=runExecutionRequest(source,'current');
  if(!S.pendingCurrent||S.pendingCurrent.source!==source.run_id||S.pendingCurrent.revision!==source.revision_id)S.pendingCurrent={source:source.run_id,revision:source.revision_id,key:crypto.randomUUID()};
  try{const run=await api('POST',request.path,request.body,{key:S.pendingCurrent.key});if(session!==S.session||sequence!==S.runSelection)return;if(run.revision_id!==source.revision_id||run.run_id===source.run_id||run.replay_of)throw new Error('새 실행의 입력 연결을 확인하지 못했습니다. 실행 기록을 확인하세요.');S.pendingCurrent=null;notice('저장한 입력을 현재 계산 버전으로 새 실행했습니다. 이전 실행은 그대로 보존됩니다.');await selectRun(run);await loadRuns();}
  catch(error){if(error.network&&session===S.session)notice('새 실행 응답을 확인하지 못했습니다. 다시 누르면 같은 요청 키를 유지합니다.');throw error;}
}));
$('step-select').addEventListener('change',renderStep);
$('download-result').addEventListener('click',()=>{if(S.resultRaw)download(new Blob([S.resultRaw],{type:'application/json'}),'quanta-result-'+S.run.run_id+'.json');});
window.addEventListener('beforeunload',event=>{if(S.revision&&!saved()){event.preventDefault();event.returnValue='';}});
discoverAuthentication();syncControls();

window.addEventListener('pagehide',disposeDynamics);
