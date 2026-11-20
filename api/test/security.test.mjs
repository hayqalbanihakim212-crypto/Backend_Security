import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, generateKeyPairSync, sign, createHash } from 'node:crypto';
import express from 'express';
import { requireQxPassport } from '../../sdk/qx-passport-verifier.js';

const origin = 'http://127.0.0.1:5173';
const evil = 'https://unauthorized.example';
const admin = randomBytes(48).toString('base64');
const coreKey = randomBytes(48).toString('base64');
const root = mkdtempSync(join(tmpdir(), 'qx-gate-test-'));
mkdirSync(join(root, 'data')); mkdirSync(join(root, 'logs'));
writeFileSync(join(root,'data','tenants.json'), '{"tenants":[]}\n');
writeFileSync(join(root,'data','users.json'), '{"users":[]}\n');
const keys = generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url');
const json = (res, code, val) => { res.writeHead(code, {'content-type':'application/json'});res.end(JSON.stringify(val)); };
const sha = (v) => createHash('sha256').update(String(v)).digest('base64url');
const bsh = (v) => createHash('sha256').update(JSON.stringify(v)).digest('base64url');

let coreServer, api, apiPort, corePort, clientServer, clientPort;
async function portOf(server) { await new Promise(r=>server.listen(0,'127.0.0.1',r));return server.address().port; }
const req = async (path,body,{originHeader=origin,siteKey,gateToken,adminKey,method='POST',port=apiPort}={}) => {
  const headers = {'content-type':'application/json', ...(originHeader ? {origin:originHeader}:{}),
    ...(siteKey ? {'x-qx-site-key':siteKey}:{}),...(gateToken?{'x-qx-gate-token':gateToken}:{}),
    ...(adminKey?{'x-qx-admin-key':adminKey}:{})};
  const response = await fetch(`http://127.0.0.1:${port}${path}`,{method,headers,...(body===undefined?{}:{body:JSON.stringify(body)})});
  return {status:response.status, data:await response.json().catch(()=>({})), headers:response.headers};
};
const pause=(ms)=>new Promise(r=>setTimeout(r,ms));

async function start() {
  coreServer = createServer(async (request,response)=>{
    if(request.url==='/healthz')return json(response,200,{ok:true});
    if(request.headers['x-core-key']!==coreKey)return json(response,401,{error:'unauthorized'});
    if(request.url==='/v1/passport/public-key')return json(response,200,{public_key_b64:pub,alg:'EdDSA'});
    let buf='';for await(const part of request)buf+=part;
    const d=buf?JSON.parse(buf):{};
    if(request.url==='/v1/password/hash')return json(response,200,{hash:sha('secret:'+d.password)});
    if(request.url==='/v1/password/verify')return json(response,200,{valid:d.hash===sha('secret:'+d.password)});
    if(request.url==='/v1/challenge/new')return json(response,200,{rotations:Array.from({length:d.length},(_,i)=>i%3+1)});
    if(request.url==='/v1/challenge/verify')return json(response,200,{ok:d.initial.every((n,i)=>(n+d.taps[i])%4===0),wrong:d.initial.map((n,i)=>(n+d.taps[i])%4!==0)});
    if(request.url==='/v1/passport/sign'){
      const now=Math.floor(Date.now()/1000);
      const h=Buffer.from(JSON.stringify({alg:'EdDSA',typ:'JWT'})).toString('base64url');
      const claims={iss:'qx-gatekeeper',aud:d.site_key,org:d.origin,pth:d.target_path,mth:d.method,bsh:d.body_sha256,
        sub:d.subject,chk:d.checks_passed,iat:now,nbf:now,exp:now+d.ttl_sec,jti:randomBytes(24).toString('base64url')};
      const p=Buffer.from(JSON.stringify(claims)).toString('base64url');
      const signed=sign(null,Buffer.from(`${h}.${p}`),keys.privateKey).toString('base64url');
      return json(response,200,{passport:`${h}.${p}.${signed}`,expires_at:claims.exp});
    }
    json(response,404,{error:'missing'});
  });
  corePort=await portOf(coreServer);
  const temp=createServer();apiPort=await portOf(temp);await new Promise(r=>temp.close(r));
  api=spawn(process.execPath,['src/server.js'],{cwd:new URL('../',import.meta.url),env:{...process.env,
    NODE_ENV:'test',QX_DATA_DIR:join(root,'data'),QX_LOG_DIR:join(root,'logs'),QX_CORE_KEY:coreKey,
    QX_ADMIN_KEY:admin,QX_CORE_URL:`http://127.0.0.1:${corePort}`,PORT:String(apiPort),HOST:'127.0.0.1',
    CHALLENGE_MIN_SOLVE_MS:'300'}});
  let stderr='';api.stderr.on('data',b=>stderr+=b.toString());
  let ready=false;
  for(let i=0;i<90;i++){
    if(api.exitCode!==null)break;
    try {const r=await fetch(`http://127.0.0.1:${apiPort}/healthz`);if(r.status===200){ready=true;break;}} catch{}
    await pause(50);
  }
  assert.ok(ready,`API did not start: ${stderr}`);
}
async function stop() {
  if(clientServer)await new Promise(r=>clientServer.close(r));
  if(api && api.exitCode===null){api.kill('SIGTERM');await new Promise(r=>api.once('exit',r));}
  if(coreServer)await new Promise(r=>coreServer.close(r));
  rmSync(root,{recursive:true,force:true});
}

test('qX zero-data backend — security regression and integration',async(t)=>{
  await start();
  t.after(stop);
  assert.deepEqual(JSON.parse(readFileSync(join(root,'data','tenants.json'))).tenants,[]);
  assert.deepEqual(JSON.parse(readFileSync(join(root,'data','users.json'))).users,[]);

  let r=await req('/api/gate/tenants/register',{name:'Tenant',allowedOrigins:[origin]});
  assert.equal(r.status,403,'Public registration MUST be forbidden');
  r=await req('/api/gate/tenants/register',{name:'Tenant',allowedOrigins:['*']},{adminKey:admin});
  assert.equal(r.status,400,'Wildcard must be blocked');
  r=await req('/api/gate/tenants/register',{name:'Tenant',allowedOrigins:[evil]},{adminKey:admin});
  assert.equal(r.status,201);const siteKeyEvil=r.data.siteKey;
  r=await req('/api/gate/tenants/register',{name:'Client A',allowedOrigins:[origin]},{adminKey:admin});
  assert.equal(r.status,201);const siteKey=r.data.siteKey;
  assert.equal(JSON.parse(readFileSync(join(root,'data','tenants.json'))).tenants.length,2);

  let options=await fetch(`http://127.0.0.1:${apiPort}/api/gate/preflight`,{
    method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST',
      'Access-Control-Request-Headers':'content-type,x-qx-site-key'}});
  assert.equal(options.status,204,'Browser preflight has no Site Key value');
  options=await fetch(`http://127.0.0.1:${apiPort}/api/gate/preflight`,{
    method:'OPTIONS',headers:{Origin:evil,'Access-Control-Request-Method':'POST'}});
  assert.equal(options.status,204,'Origin authorized for a separate tenant can preflight');
  options=await fetch(`http://127.0.0.1:${apiPort}/api/gate/preflight`,{
    method:'OPTIONS',headers:{Origin:'https://attacker.invalid','Access-Control-Request-Method':'POST'}});
  assert.equal(options.status,403,'Unknown origin preflight blocked');

  const transfer={destination:'recipient-42',amount:50};
  const pre={targetPath:'/api/transfer',method:'POST',payloadSample:transfer,
    telemetry:{webdriver:false,pointerMoves:10,timeOnPageMs:2000}};
  r=await req('/api/gate/preflight',pre,{siteKey,originHeader:evil});
  assert.equal(r.status,403,'Tenant A must not accept tenant B origin');
  r=await req('/api/gate/preflight',{targetPath:'/api/transfer',method:'POST'},{siteKey});
  assert.equal(r.status,400,'Missing payload sample blocked');
  r=await req('/api/gate/preflight',{...pre,targetPath:'//host'},{siteKey});
  assert.equal(r.status,400,'Noncanonical path blocked');
  r=await req('/api/gate/preflight',{...pre,payloadSample:{x:'<script>alert(1)</script>'}},{siteKey});
  assert.equal(r.status,403,'WAF blocks obvious script payload');
  r=await req('/api/gate/preflight',pre,{siteKey});
  assert.equal(r.status,200);assert.equal(r.data.status,'2FA_REQUIRED');
  const token=r.data.gateToken;
  r=await req('/api/gate/verify-2fa',{username:'existing',securityCode:'made-up-long-code'},{siteKey,gateToken:token});
  assert.equal(r.status,401,'Unknown user cannot auto-enroll');
  assert.deepEqual(JSON.parse(readFileSync(join(root,'data','users.json'))).users,[]);

  r=await req('/api/gate/tenants/users/provision',{
    siteKey,username:'existing',securityCode:'this-is-a-long-test-only-secret'},{adminKey:admin});
  assert.equal(r.status,201,'Trusted admin can provision user');
  r=await req('/api/gate/tenants/users/provision',{
    siteKey,username:'existing',securityCode:'overwriting-code-should-fail'},{adminKey:admin});
  assert.equal(r.status,409,'Enrolled user cannot be overwritten');

  r=await req('/api/gate/verify-2fa',{username:'existing',securityCode:'this-is-a-long-test-only-secret'},
    {siteKey:siteKeyEvil,originHeader:evil,gateToken:token});
  assert.equal(r.status,401,'Cross tenant flow reuse blocked');
  r=await req('/api/gate/verify-2fa',{username:'existing',securityCode:'this-is-a-long-test-only-secret'},
    {siteKey,gateToken:token});
  assert.equal(r.status,200);assert.equal(r.data.status,'ALLOW');
  const passport=r.data.passport;
  r=await req('/api/gate/verify-2fa',{username:'existing',securityCode:'this-is-a-long-test-only-secret'},
    {siteKey,gateToken:token});
  assert.equal(r.status,401,'Flow is single use');

  const app=express();app.use(express.json());app.use((rq,_rs,next)=>{rq.user={id:"existing"};next();});
  app.post('/api/transfer',requireQxPassport({expectedSiteKey:siteKey,expectedPublicKeyB64:pub,expectedOrigin:origin,
    requiredChecks:['waf','2fa_verified'],getAuthenticatedSubject:(rq)=>rq.user?.id}),(rq,rs)=>rs.json({ok:true,sub:rq.qxSecurity.sub}));
  app.post('/api/other',requireQxPassport({expectedSiteKey:siteKey,expectedPublicKeyB64:pub,expectedOrigin:origin,requiredChecks:["waf"]}),
    (rq,rs)=>rs.json({ok:true}));
  clientServer=createServer(app);clientPort=await portOf(clientServer);
  const clientReq=(path,body,pass)=>fetch(`http://127.0.0.1:${clientPort}${path}`,{
    method:'POST',headers:{Origin:origin,'Content-Type':'application/json',"X-QX-Passport":pass},body:JSON.stringify(body)});
  assert.equal((await clientReq('/api/transfer',{amount:51,destination:'recipient-42'},passport)).status,403,'Body tampering blocked');
  assert.equal((await clientReq('/api/other',transfer,passport)).status,403,'Path tampering blocked');
  let good=await clientReq('/api/transfer',transfer,passport);
  assert.equal(good.status,200);assert.equal((await good.json()).sub,'existing');
  assert.equal((await clientReq('/api/transfer',transfer,passport)).status,403,'Replay blocked');
  assert.equal(JSON.parse(readFileSync(join(root,'data','users.json'))).users.length,1);
});
