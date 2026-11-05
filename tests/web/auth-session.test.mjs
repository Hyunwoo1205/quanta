import test from 'node:test';
import assert from 'node:assert/strict';
import {authConfiguration,authRequestOptions,isJSONResponse,accessResponseNeedsLogin} from '../../src/quanta/web/view-model.mjs';

const access = {mode:'access',authenticated:true,principal:{email:'researcher@example.test',owner:'local'},login_url:'/',logout_url:'/cdn-cgi/access/logout'};

test('access transport carries same-origin session cookies and never a bearer token',()=>{
  const options=authRequestOptions('access','a-secret-that-must-not-leak');
  assert.equal(options.credentials,'same-origin');
  assert.equal(options.redirect,'error');
  assert.equal(options.cache,'no-store');
  assert.equal(options.referrerPolicy,'no-referrer');
  assert.equal(options.headers.Authorization,undefined);
  assert.equal(JSON.stringify(options).includes('a-secret-that-must-not-leak'),false);
});

test('bearer transport preserves local authorization and excludes browser cookies',()=>{
  const options=authRequestOptions('bearer','local-token');
  assert.equal(options.headers.Authorization,'Bearer local-token');
  assert.equal(options.credentials,'omit');
  assert.equal(options.redirect,'error');
});

test('artifact downloads use the same authentication boundary without declaring a JSON body',()=>{
  const accessDownload=authRequestOptions('access',null,{json:false});
  assert.deepEqual(accessDownload.headers,{});
  assert.equal(accessDownload.credentials,'same-origin');
  const localDownload=authRequestOptions('bearer','local-token',{json:false});
  assert.deepEqual(localDownload.headers,{Authorization:'Bearer local-token'});
  assert.equal(localDownload.credentials,'omit');
  assert.throws(()=>authRequestOptions('unknown','token'),TypeError);
});

test('discovery accepts only the known session configuration and fixed local navigation routes',()=>{
  assert.deepEqual(authConfiguration(access),access);
  assert.deepEqual(authConfiguration({mode:'bearer',authenticated:true,principal:{email:'ignore'}}),{mode:'bearer',authenticated:false});
  const unauthenticated=authConfiguration({...access,authenticated:false,principal:{email:'untrusted',owner:'other'}});
  assert.equal(unauthenticated.principal,null);
  assert.equal(unauthenticated.authenticated,false);
});

test('owner-token discovery requires manual key entry and accepts no identity or navigation routes',()=>{
  const owner={mode:'bearer',authenticated:false,authentication:'owner_token'};
  assert.deepEqual(authConfiguration(owner),owner);
  assert.deepEqual(authConfiguration({...owner,authenticated:true,principal:{email:'ignore',owner:'other'},
    login_url:'https://attacker.example/',logout_url:'javascript:alert(1)'}),owner);
  assert.deepEqual(authConfiguration({mode:'bearer',authenticated:false,authentication:'https://attacker.example/'}),
    {mode:'bearer',authenticated:false});
});

test('owner key requests keep bearer transport with cookies omitted for APIs and downloads',()=>{
  const configuration=authConfiguration({mode:'bearer',authenticated:false,authentication:'owner_token'});
  for(const json of [true,false]){
    const options=authRequestOptions(configuration.mode,'owner-key',{json});
    assert.equal(options.credentials,'omit');
    assert.equal(options.redirect,'error');
    assert.equal(options.headers.Authorization,'Bearer owner-key');
    assert.equal(options.headers.Cookie,undefined);
  }
});

test('discovery cannot introduce an external login/logout destination or malformed identity',()=>{
  for(const changed of [
    {...access,login_url:'https://attacker.example/'},
    {...access,login_url:'//attacker.example/'},
    {...access,logout_url:'/cdn-cgi/access/logout?redirect=https://attacker.example/'},
    {...access,logout_url:'javascript:alert(1)'},
    {...access,principal:null},
    {...access,principal:{email:'x',owner:''}},
    {...access,authenticated:'true'},
    {...access,mode:'public'},
  ])assert.throws(()=>authConfiguration(changed),TypeError);
});

test('explicit Access rejection, HTML login page, or redirect is never a scientific API response',()=>{
  for(const response of [
    {status:401,contentType:'application/json'},
    {status:403,contentType:'application/json'},
    {status:200,contentType:'text/html; charset=UTF-8'},
    {status:200,redirected:true,contentType:'application/json'},
    {type:'opaqueredirect'},
  ])assert.equal(accessResponseNeedsLogin('access',response),true);
});

test('ordinary network uncertainty and scientific validation failures are not labelled as login expiry',()=>{
  for(const response of [undefined,{status:0},{status:422,contentType:'application/json'},{status:503,contentType:'application/json'},{status:200,contentType:'application/octet-stream'}]){
    assert.equal(accessResponseNeedsLogin('access',response),false);
  }
  assert.equal(accessResponseNeedsLogin('bearer',{status:401}),false);
});

test('JSON response detection accepts parameters and structured JSON but rejects login HTML',()=>{
  for(const type of ['application/json','application/json; charset=utf-8','Application/Problem+JSON; charset=UTF-8'])assert.equal(isJSONResponse(type),true);
  for(const type of [null,'text/html','text/json','application/jsonp','application/json evil'])assert.equal(isJSONResponse(type),false);
});
