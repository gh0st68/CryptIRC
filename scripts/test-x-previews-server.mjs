// Real-binary smoke for a FRESH install (no X provider flags set): base-path integration of
// the served app.js / sw.js, the /tweet routes' auth + cache headers, provider_disabled
// answers, and that the generic path is untouched. Run the binary under
// `strace -f -e trace=connect` (see INSTALL/verification docs) to prove it makes no
// outbound connection at all. Usage:
//   CRYPTIRC_BIN=target/debug/cryptirc node scripts/test-x-previews-server.mjs
// Optional: CRYPTIRC_TEST_PORT_BASE (default 28400), CRYPTIRC_TEST_WRAP="strace -f -e trace=connect -o /tmp/trace"
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';

const bin=process.env.CRYPTIRC_BIN;
if(!bin)throw new Error('Set CRYPTIRC_BIN to the built cryptirc web binary.');
const portBase=Number(process.env.CRYPTIRC_TEST_PORT_BASE||28400);
const wrap=(process.env.CRYPTIRC_TEST_WRAP||'').split(' ').filter(Boolean);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const checks=[];const ok=(name,value)=>{checks.push({name,pass:!!value});console.error((value?'ok   ':'FAIL ')+name);assert(value,name);};

for(const [i,basePath] of ['/cryptirc','/chat/nested','/'].entries()){
  const data=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-x-server-'));
  // The most permissive admin policy: with no provider flag set it must still change nothing.
  await fs.writeFile(path.join(data,'admin_settings.json'),JSON.stringify({registration_open:true,captcha_enabled:false,link_preview_mode:'all'}));
  const port=portBase+i,bp=basePath==='/'?'':basePath,origin=`http://127.0.0.1:${port}`;
  const env={...process.env,CRYPTIRC_DATA:data,CRYPTIRC_BASE_PATH:basePath,CRYPTIRC_PORT:String(port),CRYPTIRC_HSTS:'off',RUST_LOG:'warn'};
  for(const k of Object.keys(env))if(k.startsWith('CRYPTIRC_X_'))delete env[k];
  // Optional wrapper (e.g. strace); an "-o FILE" gets a per-base-path suffix.
  const args=wrap.slice(1).map((a,n,all)=>all[n-1]==='-o'?`${a}.${i}`:a);
  // Own process group, so cleanup also stops the server when a wrapper (strace) is in front.
  const child=wrap.length?spawn(wrap[0],[...args,bin],{env,stdio:['ignore','ignore','pipe'],detached:true}):spawn(bin,[],{env,stdio:['ignore','ignore','pipe'],detached:true});
  let stderr='';child.stderr.on('data',d=>{stderr+=d;});
  try{
    let up=false;
    for(let n=0;n<200&&!up;n++){try{up=(await fetch(`${origin}${bp}/auth/status`)).ok;}catch{await sleep(100);}}
    ok(`${basePath}: server up`,up);
    const appJs=await(await fetch(`${origin}${bp}/app.js`)).text();
    ok(`${basePath}: app.js X routes rewritten to the base path`,appJs.includes(`'${bp}/tweet/config'`)&&appJs.includes(`'${bp}/tweet/media/sign'`)&&appJs.includes(`\`${bp}/tweet/\${task.operation}`));
    ok(`${basePath}: no stray /cryptirc/tweet in a non-default base`,bp==='/cryptirc'||!appJs.includes('/cryptirc/tweet'));
    const sw=await(await fetch(`${origin}${bp}/sw.js`)).text();
    ok(`${basePath}: sw.js passes ${bp}/tweet through`,sw.includes(`'${bp}/tweet'`));
    const json={'content-type':'application/json'};
    const reg=await fetch(`${origin}${bp}/auth/register`,{method:'POST',headers:json,body:JSON.stringify({username:'smoker',password:'Correct1!horse'})});
    ok(`${basePath}: register`,reg.ok);
    const login=await(await fetch(`${origin}${bp}/auth/login`,{method:'POST',headers:json,body:JSON.stringify({username:'smoker',password:'Correct1!horse'})})).json();
    ok(`${basePath}: login`,typeof login.token==='string');
    const auth={authorization:'Bearer '+login.token};
    const config=await fetch(`${origin}${bp}/tweet/config`);
    ok(`${basePath}: /tweet/config needs a session`,config.status===401&&config.headers.get('cache-control')==='private, no-store');
    const caps=await fetch(`${origin}${bp}/tweet/config`,{headers:auth});
    const offered=await caps.json();
    ok(`${basePath}: fresh install offers nothing`,offered.schema_version===1&&offered.preview===false&&offered.thread===false&&Object.keys(offered).length===3&&caps.headers.get('vary')==='Authorization');
    for(const op of ['preview','thread']){
      const r=await fetch(`${origin}${bp}/tweet/${op}?url=${encodeURIComponent('https://x.com/a/status/123')}`,{headers:auth});
      const body=await r.json();
      ok(`${basePath}: /tweet/${op} answers provider_disabled locally`,r.status===200&&body.availability?.reason==='provider_disabled'&&r.headers.get('cache-control')==='private, no-store');
    }
    const sign=await fetch(`${origin}${bp}/tweet/media/sign`,{method:'POST',headers:{...auth,...json},body:JSON.stringify({urls:['https://pbs.twimg.com/media/a.jpg']})});
    ok(`${basePath}: media signing refused with no provider`,sign.status===403);
    const media=await fetch(`${origin}${bp}/tweet/media?url=x&exp=1&a=b&sig=c`);
    ok(`${basePath}: forged media URL refused`,media.status===403);
    const bad=await fetch(`${origin}${bp}/tweet/preview?url=${encodeURIComponent('https://evil.test/a/status/1')}`,{headers:auth});
    ok(`${basePath}: invalid URL is 400`,bad.status===400);
    // (Generic /preview is deliberately not called: it would resolve a public host, and
    // this run must show zero outbound attempts. Its client side is covered by
    // test-x-previews-parity.mjs, its server code is unchanged.)
  }finally{
    const exited=new Promise(resolve=>child.once('exit',resolve));
    try{process.kill(-child.pid,'SIGTERM');}catch{}
    await Promise.race([exited,sleep(5000)]);try{process.kill(-child.pid,'SIGKILL');}catch{}
    if(stderr.match(/panicked/))console.error(stderr);
    await fs.rm(data,{recursive:true,force:true});
  }
}
console.log(JSON.stringify({checks},null,2));
