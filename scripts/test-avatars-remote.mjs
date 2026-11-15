// Real-binary test for avatars ACROSS CryptIRC instances (avatar/remote.rs): two separate
// instances (web + irc_core each, own data dir and port) on ONE local ircd with message-tags
// and draft/metadata-2 (Ergo), raw IRC clients, a hostile HTTP server and Chromium.
//
// - Join discovery: alice (instance A) is in #x; bob (instance B) joins — both nick lists
//   show the other's avatar within seconds, with no message, menu or WHOIS (invisible
//   TAGMSGs: join announce, welcome, answer to a peer's announce).
// - A plain client (no CAP) in #x sees nothing at all: no TAGMSG, no CTCP, no line from them.
// - A 30-client join flood gets a bounded number of welcome TAGMSGs.
// - The announce tag on speech: the first DM to a target carries it, the second does not;
//   a raw client's tagged message is learned like a CryptIRC user's.
// - Hostile announces (SVG, HTML-as-PNG, 3 MB, 20000² header, redirect, slow, private IP,
//   our own instance's URL) never show, each URL is fetched at most once, redirects are
//   never followed.
// - Invalidation: NICK (an impostor taking the old nick gets nothing), QUIT (same), PART
//   (same for a nick held while out of sight), rejoin re-announces.
// - A viewer's own settings never stop them seeing others: no avatar, sharing and "show my
//   avatar" off, an avatar an admin removed. A viewer behind a bouncer gets no remote
//   avatars at all; a sharer behind a bouncer never answers CTCP AVATAR.
// - Withdraw during an outage: sharing turned off while the web was down reaches IRC
//   (the metadata value is deleted) when it comes back.
// - CTCP AVATAR (networks without message-tags): an explicit look asks once (cooldown);
//   member lists never do; an opted-out owner never answers; KVIrc-style queries are answered.
// - draft/metadata-2: a member's avatar arrives with the join sync and goes away when the
//   owner stops sharing; the public link then 404s.
//
// Usage (the ircd must listen on 127.0.0.1 at IRC_PORT, e.g. Ergo):
//   CRYPTIRC_BIN=target/debug/cryptirc CRYPTIRC_CORE_BIN=target/debug/irc_core IRC_PORT=28667 \
//     node scripts/test-avatars-remote.mjs
// Debug binaries only (CRYPTIRC_AVATAR_TEST_LOOPBACK lets them fetch http from loopback).
// Optional: REMOTE_PORT_BASE (default 28651: A, B, hostile server, bouncer proxy), CDP_PORT_BASE (28640),
//   CRYPTIRC_BASE_PATH (/cryptirc), CHROMIUM (/usr/bin/chromium).
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import net from 'node:net';
import http from 'node:http';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';

const bin=process.env.CRYPTIRC_BIN, coreBin=process.env.CRYPTIRC_CORE_BIN, ircPort=Number(process.env.IRC_PORT||0);
if(!bin||!coreBin||!ircPort)throw new Error('Set CRYPTIRC_BIN, CRYPTIRC_CORE_BIN and IRC_PORT.');
const portBase=Number(process.env.REMOTE_PORT_BASE||28651), cdpBase=Number(process.env.CDP_PORT_BASE||28640);
const basePath=process.env.CRYPTIRC_BASE_PATH||'/cryptirc', bp=basePath==='/'?'':basePath.replace(/\/$/,'');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const checks=[];
const ok=(name,value,extra)=>{checks.push({name,pass:!!value});console.error((value?'ok   ':'FAIL ')+name+(value||extra==null?'':' :: '+String(extra).slice(0,600)));
  if(!value) for(const c of children) console.error('--- '+c.label+' (avatar log lines)\n'+c.stderrText.split('\n').filter(l=>/avatars:/.test(l)).slice(-40).join('\n'));
  assert(value,name);};
const until=async(fn,ms=15000,every=300)=>{const end=Date.now()+ms;while(Date.now()<end){let v=null;try{v=await fn();}catch{}if(v)return v;await sleep(every);}return null;};
const json={'content-type':'application/json'};

// ── PNG encoder (from the v1 test) ──
function crc32(buf){let c=~0;for(const b of buf){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^(0xEDB88320&-(c&1));}return (~c)>>>0;}
function chunk(type,data){const len=Buffer.alloc(4);len.writeUInt32BE(data.length);const td=Buffer.concat([Buffer.from(type),data]);const crc=Buffer.alloc(4);crc.writeUInt32BE(crc32(td));return Buffer.concat([len,td,crc]);}
function png(w,h,fn){
  const raw=Buffer.alloc((w*3+1)*h);
  for(let y=0;y<h;y++)for(let x=0;x<w;x++){const o=y*(w*3+1)+1+x*3;const [r,g,b]=fn(x,y);raw[o]=r;raw[o+1]=g;raw[o+2]=b;}
  const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(w,0);ihdr.writeUInt32BE(h,4);ihdr[8]=8;ihdr[9]=2;
  return Buffer.concat([Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);
}
const picture=(bg,fg)=>png(160,160,(x,y)=>{const d=Math.hypot(x-80,y-80);return d>30&&d<46?fg:bg;});
function hugeHeaderPng(){
  const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(20000,0);ihdr.writeUInt32BE(20000,4);ihdr[8]=8;ihdr[9]=2;
  return Buffer.concat([Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(Buffer.alloc(1000))),chunk('IEND',Buffer.alloc(0))]);
}

const children=[], chromes=[], browsers=[], raws=[], tmpdirs=[];
let hostile=null, bouncer=null;
const start=(file,env,label)=>{const c=spawn(file,[],{env,stdio:['ignore','pipe','pipe'],detached:true});c.stderrText='';const keep=d=>{c.stderrText+=d;if(c.stderrText.length>400000)c.stderrText=c.stderrText.slice(-200000);};c.stdout.on('data',keep);c.stderr.on('data',keep);c.label=label;children.push(c);return c;};

async function instance(name,port){
  const data=await fs.mkdtemp(path.join(os.tmpdir(),`cryptirc-remote-${name}-`));
  tmpdirs.push(data);
  await fs.writeFile(path.join(data,'admin_settings.json'),JSON.stringify({registration_open:true,captcha_enabled:false}));
  const origin=`http://127.0.0.1:${port}`;
  const env={...process.env,CRYPTIRC_DATA:data,CRYPTIRC_BASE_PATH:basePath,CRYPTIRC_PORT:String(port),CRYPTIRC_HSTS:'off',RUST_LOG:process.env.REMOTE_RUST_LOG||'warn',
    CRYPTIRC_BASE_URL:`${origin}${bp}`,CRYPTIRC_AVATAR_TEST_LOOPBACK:'1'};
  start(coreBin,env,name+':irc_core');
  for(let i=0;i<100;i++){try{await fs.stat(path.join(data,'irc-core.sock'));break;}catch{await sleep(100);}}
  start(bin,env,name+':web');
  let up=false;
  for(let i=0;i<300&&!up;i++){try{up=(await fetch(`${origin}${bp}/auth/status`)).ok;}catch{await sleep(100);}}
  ok(`${name}: up`,up);
  return {name,port,origin,data,env};
}
// Restart one instance's web only (irc-core keeps the IRC sessions); `between` runs while it is down.
async function restartWeb(inst,between){
  const web=children.find(c=>c.label===inst.name+':web');
  const exited=new Promise(r=>web.once('exit',r));
  process.kill(-web.pid,'SIGTERM');
  await Promise.race([exited,sleep(10000)]);
  children.splice(children.indexOf(web),1);
  if(between) await between();
  start(bin,inst.env,inst.name+':web');
  let up=false;
  for(let i=0;i<300&&!up;i++){try{up=(await fetch(`${inst.origin}${bp}/auth/status`)).ok;}catch{await sleep(100);}}
  return up;
}

const wsClient=(inst,token)=>new Promise((resolve,reject)=>{
  const ws=new WebSocket(`ws://127.0.0.1:${inst.port}${bp}/ws`);
  const events=[],waiters=[];
  ws.onmessage=e=>{const ev=JSON.parse(e.data);events.push(ev);if(events.length>5000)events.splice(0,2500);for(const w of [...waiters])if(w.pred(ev)){waiters.splice(waiters.indexOf(w),1);w.resolve(ev);}};
  ws.onerror=reject;
  ws.onopen=()=>{ws.send(JSON.stringify({type:'auth',token,e2e:2}));resolve({ws,events,
    send:o=>ws.send(JSON.stringify(o)),
    wait:(pred,ms=20000)=>new Promise((res,rej)=>{const hit=events.find(pred);if(hit)return res(hit);const w={pred,resolve:res};waiters.push(w);setTimeout(()=>rej(new Error('timed out waiting for an event')),ms);}),
  });};
});

// A CryptIRC account on `inst`, with an avatar (`share` false: opted out), connected as `nick`.
async function account(inst,name,{nick=name,channels=[],disabled=[],avatar=true,share=true,visible=true,port=ircPort,color=[[90,90,90],[200,200,200]]}={}){
  const password='Remote-test-'+name+'-1!';
  const reg=await fetch(`${inst.origin}${bp}/auth/register`,{method:'POST',headers:json,body:JSON.stringify({username:name,password})});
  ok(`${inst.name}/${name}: register`,reg.ok);
  const u={inst,name,nick,password};
  u.token=(await(await fetch(`${inst.origin}${bp}/auth/login`,{method:'POST',headers:json,body:JSON.stringify({username:name,password})})).json()).token;
  u.ws=await wsClient(inst,u.token);
  await u.ws.wait(e=>e.type==='auth_ok');
  u.ws.send({type:'unlock_vault',passphrase:'vault passphrase for '+name+' 123'});
  await u.ws.wait(e=>e.type==='vault_unlocked',60000);
  if(avatar){
    // A first avatar is shared only with consent (?share=1, what the app sends after asking).
    const r=await fetch(`${inst.origin}${bp}/api/avatar/me${share?'?share=1':''}`,{method:'POST',headers:{authorization:'Bearer '+u.token,'content-type':'image/png'},body:picture(...color)});
    const me=await r.json();
    if(share) ok(`${inst.name}/${name}: avatar uploaded and shared (consent given)`,r.ok&&me.share===true&&typeof me.public_url==='string');
    else ok(`${inst.name}/${name}: avatar uploaded without sharing (no consent): not public`,r.ok&&me.share===false&&me.public_url==null);
    if(!visible){
      const s=await(await fetch(`${inst.origin}${bp}/api/avatar/me`,{method:'PUT',headers:{authorization:'Bearer '+u.token,...json},body:JSON.stringify({visible:false})})).json();
      ok(`${inst.name}/${name}: hides the avatar ("show my avatar" off)`,s.visible===false);
    }
    u.publicUrl=(await(await fetch(`${inst.origin}${bp}/api/avatar/me`,{headers:{authorization:'Bearer '+u.token}})).json()).public_url;
  }
  const label='Net '+name;
  u.ws.send({type:'add_network',network:{id:'',label,server:'127.0.0.1',port,tls:false,tls_accept_invalid_certs:false,
    nick,realname:nick,username:nick,password:null,sasl_plain:null,sasl_external:false,client_cert_id:null,auto_join:channels,auto_reconnect:true,disabled_caps:disabled}});
  const st=await u.ws.wait(e=>e.type==='state'&&(e.networks||[]).some(n=>n.config.label===label));
  u.conn=st.networks.find(n=>n.config.label===label).config.id;
  u.ws.send({type:'connect',id:u.conn});
  await u.ws.wait(e=>e.type==='connected'&&e.conn_id===u.conn,30000);
  for(const ch of channels) await u.ws.wait(e=>e.type==='irc_names'&&e.conn_id===u.conn&&e.channel.toLowerCase()===ch,30000);
  return u;
}
const lookup=(u,nicks,probe=[])=>fetch(`${u.inst.origin}${bp}/api/avatar/lookup`,{method:'POST',headers:{...json,authorization:'Bearer '+u.token},body:JSON.stringify({conn_id:u.conn,nicks,probe})}).then(r=>r.json());
const say=(u,raw)=>u.ws.send({type:'send',conn_id:u.conn,raw});

// A raw IRC client (`tags`: negotiates message-tags) — every line it receives is kept.
function raw(nick,{tags=false,channels=[]}={}){
  return new Promise((resolve,reject)=>{
    const s=net.connect(ircPort,'127.0.0.1');
    const c={nick,lines:[],s,waiters:[],send:l=>s.write(l+'\r\n'),
      wait:(re,ms=10000)=>new Promise((res,rej)=>{const hit=c.lines.find(l=>re.test(l));if(hit)return res(hit);const w={re,res};c.waiters.push(w);setTimeout(()=>rej(new Error(nick+': timed out on '+re)),ms);})};
    let buf='';
    s.on('data',d=>{buf+=d;let i;while((i=buf.indexOf('\n'))>=0){const l=buf.slice(0,i).replace(/\r$/,'');buf=buf.slice(i+1);c.lines.push(l);if(/^PING /.test(l))c.send('PONG '+l.slice(5));for(const w of [...c.waiters])if(w.re.test(l)){c.waiters.splice(c.waiters.indexOf(w),1);w.res(l);}}});
    s.on('error',reject);
    s.on('connect',()=>{if(tags){c.send('CAP LS 302');c.send('CAP REQ :message-tags');}c.send('NICK '+nick);c.send('USER '+nick.replace(/[^a-z0-9]/gi,'x').slice(0,9)+' 0 * :'+nick);if(tags)c.send('CAP END');});
    c.wait(/ 001 /,15000).then(async()=>{for(const ch of channels){c.send('JOIN '+ch);await c.wait(new RegExp(` 366 \\S+ ${ch.replace(/[#]/g,'\\#')} `,'i'),10000);}raws.push(c);resolve(c);}).catch(reject);
  });
}
const tagged=l=>/^@\S*\+cryptirc\.com\/avatar=/.test(l);

// ── Chromium (one per account checked through the UI) ──
async function openBrowser(u){
  const profile=path.join(u.inst.data,'chrome-'+u.name), cdpPort=cdpBase+chromes.length;
  const chrome=spawn(process.env.CHROMIUM||'/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-address=127.0.0.1','--remote-debugging-port='+cdpPort,'--user-data-dir='+profile,'--no-first-run','about:blank'],{stdio:'ignore',detached:true});
  chromes.push(chrome);
  let tabs=null;
  for(let i=0;i<150&&!tabs;i++){try{tabs=await(await fetch('http://127.0.0.1:'+cdpPort+'/json')).json();}catch{await sleep(100);}}
  if(!tabs)throw new Error('Chromium unavailable; set CHROMIUM.');
  const socket=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);
  await new Promise(r=>socket.onopen=r);
  let seq=0;const pending=new Map(),requests=[],errors=[];
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
  socket.onmessage=event=>{
    const m=JSON.parse(event.data);
    if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p?.reject(new Error(JSON.stringify(m.error))):p?.resolve(m.result);}
    if(m.method==='Network.requestWillBeSent')requests.push(m.params.request.url);
    if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails);
  };
  const ev=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
  await send('Runtime.enable');await send('Page.enable');await send('Network.enable');
  await send('Emulation.setDeviceMetricsOverride',{width:1280,height:800,deviceScaleFactor:1,mobile:false});
  await send('Page.navigate',{url:`${u.inst.origin}${bp}/auth/status`});
  await sleep(300);
  await ev(`localStorage.setItem('cryptirc_token',${JSON.stringify(u.token)});localStorage.setItem('cryptirc_user',${JSON.stringify(u.name)});localStorage.setItem('cryptirc_data_owner',${JSON.stringify(u.name)});true`);
  await send('Page.navigate',{url:`${u.inst.origin}${bp}/`});
  await until(()=>ev("typeof avatarFor==='function'&&!!sessionToken&&Array.isArray(networks)&&networks.some(n=>n.connected)"),30000);
  const b={u,send,ev,requests,errors,socket,chrome};
  browsers.push(b);
  return b;
}
const show=(b,target)=>b.ev(`(()=>{document.getElementById('vault-overlay')?.classList.remove('show');setActive(${JSON.stringify(b.u.conn)},${JSON.stringify(target)});return true;})()`);
// The nick-list avatar of `nick`: 'missing' (no entry), 'none', or the picture id ('r…' = remote).
const listAv=(b,nick)=>b.ev(`(()=>{const e=[...document.querySelectorAll('#nick-list .nick-entry[data-nick]')].find(x=>x.dataset.nick.toLowerCase()===${JSON.stringify(nick.toLowerCase())});if(!e)return 'missing';const i=e.querySelector('img.nick-av');return i&&i.complete&&i.naturalWidth>0?i.dataset.av:'none';})()`);

try{
  // ── hostile HTTP server ──
  const hits=[];
  const good=picture([30,160,60],[250,250,120]);
  const handler=(req,res)=>{
    hits.push(req.url);
    const p=req.url;
    const send=(ct,body)=>{res.writeHead(200,{'content-type':ct,'content-length':body.length});res.end(body);};
    if(p==='/good.png') return send('image/png',good);
    if(p==='/svg') return send('image/svg+xml',Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'));
    if(p==='/html') return send('image/png',Buffer.from('<!doctype html><title>x</title>'));
    if(p==='/big'){const b=Buffer.alloc(3*1024*1024);good.copy(b);return send('image/png',b);}
    if(p==='/huge') return send('image/png',hugeHeaderPng());
    if(p==='/redir'){res.writeHead(302,{location:'/good2.png'});return res.end();}
    if(p==='/slow'){res.writeHead(200,{'content-type':'image/png','content-length':100000});const t=setInterval(()=>{if(!res.write('x'))return;},500);res.on('close',()=>clearInterval(t));setTimeout(()=>{clearInterval(t);res.destroy();},40000);return;}
    res.writeHead(404);res.end();
  };
  // Loopback only, both families ("localhost" may resolve to either).
  hostile=[http.createServer(handler),http.createServer(handler)];
  await new Promise(r=>hostile[0].listen(portBase+2,'127.0.0.1',r));
  await new Promise(r=>hostile[1].listen(portBase+2,'::1',r));
  const H=`http://localhost:${portBase+2}`;

  const A=await instance('A',portBase), B=await instance('B',portBase+1);
  const noMeta=['draft/metadata-2'];

  // ── 1. join discovery: bob (B) joins #x where alice (A) already is ──
  const plain=await raw('plain1',{channels:['#x']});
  const tagwatch=await raw('tagwatch',{tags:true,channels:['#x']});
  const alice=await account(A,'alice',{channels:['#x'],disabled:noMeta,color:[[220,70,60],[255,220,120]]});
  ok('A/alice: her join is announced to #x with an invisible TAGMSG',await until(()=>tagwatch.lines.find(l=>tagged(l)&&/ TAGMSG #x$/.test(l)&&/:alice!/.test(l)),8000),tagwatch.lines.slice(-5).join(' | '));
  const aliceB=await openBrowser(alice);
  await show(aliceB,'#x');
  await sleep(10500);   // past alice's own join burst (no welcomes then)
  const bob=await account(B,'bob',{channels:['#x'],disabled:noMeta,color:[[40,90,220],[160,220,255]]});
  const bobB=await openBrowser(bob);
  await show(bobB,'#x');
  const t0=Date.now();
  const bobSeesAlice=await until(async()=>{const v=await listAv(bobB,'alice');return /^r/.test(v)?v:null;},15000);
  ok(`bob (B) sees alice's avatar (A) in his nick list without any message, menu or WHOIS (${Date.now()-t0} ms)`,bobSeesAlice,await listAv(bobB,'alice'));
  const aliceSeesBob=await until(async()=>{const v=await listAv(aliceB,'bob');return /^r/.test(v)?v:null;},15000);
  ok("alice (A) sees bob's avatar (B) the same way",aliceSeesBob,await listAv(aliceB,'bob'));
  ok('no WHOIS / probe was needed (no CTCP AVATAR or METADATA GET sent)',!tagwatch.lines.some(l=>/AVATAR/.test(l))&&!plain.lines.some(l=>/AVATAR/.test(l)));
  ok('the menu hint names the other server',await (async()=>{
    await bobB.ev(`(()=>{const e=[...document.querySelectorAll('#nick-list .nick-entry[data-nick]')].find(x=>x.dataset.nick==='alice');e.dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,clientX:200,clientY:200}));e.click();return true;})()`);
    const t=await until(()=>bobB.ev(`(()=>{const h=document.querySelector('.nick-ctx-head .nick-ctx-av-from');return h?h.textContent:'';})()`),5000);
    await bobB.ev(`document.body.dispatchEvent(new MouseEvent('click',{bubbles:true}));true`);
    return /via 127\.0\.0\.1/.test(t||'');
  })());

  // ── 2. a plain client sees nothing ──
  const cryptircLines=l=>/^(@\S+ )?:(alice|bob|dave)!/.test(l);
  // Anything a plain client must never see from this feature (its own lines aside).
  const leak=l=>/^(@\S+ )?:\S+ TAGMSG /.test(l)||/\x01/.test(l)||/cryptirc\.com\/avatar/.test(l);
  ok('the plain client (no CAP) received no TAGMSG, no CTCP and no line from them but JOIN',!plain.lines.some(leak)&&!plain.lines.filter(cryptircLines).some(l=>!/ JOIN /.test(l)),plain.lines.filter(l=>leak(l)||cryptircLines(l)).join(' | '));

  // ── 3. a 30-client join flood gets a bounded number of welcomes ──
  const flood=[];
  for(let i=0;i<30;i++) flood.push(raw('fl'+i,{tags:true,channels:['#x']}));
  const flooders=await Promise.all(flood);
  await sleep(8000);
  const welcomes=flooders.flatMap(c=>c.lines.filter(l=>tagged(l)&&new RegExp(` TAGMSG ${c.nick}$`).test(l)));
  ok(`a 30-user join flood got ${welcomes.length} welcome TAGMSGs (bounded: at most 5 per member per channel per minute)`,welcomes.length>=1&&welcomes.length<=10,welcomes.length);
  ok('the plain client still sees nothing',!plain.lines.some(leak),plain.lines.filter(leak).join(' | '));

  // ── 4. the tag on speech ──
  say(alice,'PRIVMSG tagwatch :hello one');
  say(alice,'PRIVMSG tagwatch :hello two');
  await tagwatch.wait(/PRIVMSG tagwatch :hello two/);
  const dms=tagwatch.lines.filter(l=>/:alice!\S+ PRIVMSG tagwatch :hello/.test(l));
  ok("alice's first DM to a target carries the announce tag, the second does not",dms.length===2&&tagged(dms[0])&&!tagged(dms[1]),dms.join(' | '));

  // ── 5. raw announces: one good, the rest hostile ──
  const own=bob.publicUrl;   // B's own URL: B's viewers must ignore it
  const announces={kv:`${H}/good.png`,mal1:`${H}/svg`,mal2:`${H}/html`,mal3:`${H}/big`,mal4:`${H}/huge`,mal5:`${H}/redir`,mal6:`${H}/slow`,mal7:'http://10.0.0.1/x.png',mal8:own};
  const announcers={};
  for(const [n,u] of Object.entries(announces)){
    announcers[n]=await raw(n,{tags:true,channels:['#x']});
  }
  await sleep(1500);
  for(let k=0;k<3;k++) for(const [n,u] of Object.entries(announces)) announcers[n].send(`@+cryptirc.com/avatar=${u} PRIVMSG #x :hi ${k}`);
  const kvAv=await until(async()=>{const v=await listAv(bobB,'kv');return /^r/.test(v)?v:null;},20000);
  ok("a raw client's tagged message is learned like a CryptIRC user's (kv's avatar shows for bob)",kvAv,await listAv(bobB,'kv'));
  await sleep(6000);
  const malShown=[];
  for(const n of Object.keys(announces).filter(n=>n!=='kv')){const v=await listAv(bobB,n);if(v!=='none')malShown.push(n+'='+v);}
  ok('no hostile announce shows anything',malShown.length===0,malShown.join(','));
  const count=p=>hits.filter(h=>h===p).length;
  // Both instances have a viewer in #x (alice on A, bob on B): at most one fetch per instance.
  ok('each announced URL was fetched at most once per viewing instance despite repeated announces',['/svg','/html','/big','/huge','/redir','/slow','/good.png'].every(p=>count(p)<=2),JSON.stringify(hits));
  ok('a redirect is never followed',count('/good2.png')===0);
  ok('private addresses and our own instance are never fetched',!hits.some(h=>/10\.0\.0\.1/.test(h)));
  const st=await lookup(bob,['alice','kv']);
  ok("B still answers lookups (alice's and kv's pictures)",st.avatars?.alice?.r&&st.avatars?.kv?.r,JSON.stringify(st));

  // ── 6. invalidation ──
  const dave=await account(A,'dave',{channels:['#x'],disabled:noMeta,color:[[120,40,160],[230,200,255]]});
  ok("bob sees dave's avatar after dave joins",await until(async()=>/^r/.test(await listAv(bobB,'dave')),15000),await listAv(bobB,'dave'));
  // NICK: alice → alice_x; the new nick shows again (re-announce), an impostor on "alice" gets nothing.
  say(alice,'NICK alice_x');
  ok("after alice's nick change, bob sees alice_x's avatar (re-announced)",await until(async()=>/^r/.test(await listAv(bobB,'alice_x')),15000),await listAv(bobB,'alice_x'));
  const fakeAlice=await raw('alice',{channels:['#x']});
  await sleep(4000);
  ok('an impostor taking the old nick "alice" gets no avatar',await listAv(bobB,'alice')==='none',await listAv(bobB,'alice'));
  // QUIT: dave quits; an impostor on "dave" gets nothing.
  dave.ws.send({type:'disconnect',id:dave.conn});
  await until(async()=>(await listAv(bobB,'dave'))==='missing',10000);
  const fakeDave=await raw('dave',{channels:['#x']});
  fakeDave.send('PRIVMSG #x :i am dave');
  await sleep(4000);
  ok('an impostor taking "dave" after he quit gets no avatar',await listAv(bobB,'dave')==='none',await listAv(bobB,'dave'));
  // PART: alice_x leaves #x and renames out of sight; an impostor on "alice_x" gets nothing.
  say(alice,'PART #x');
  await until(async()=>(await listAv(bobB,'alice_x'))==='missing',10000);
  say(alice,'NICK alice_y');
  await sleep(1500);
  const fakeAx=await raw('alice_x',{channels:['#x']});
  await sleep(4000);
  ok('after a PART, a nick that changed hands out of sight gets no avatar',await listAv(bobB,'alice_x')==='none',await listAv(bobB,'alice_x'));
  // Rejoin: announced again.
  say(alice,'JOIN #x');
  ok('alice_y rejoining #x is announced again (bob sees her avatar)',await until(async()=>/^r/.test(await listAv(bobB,'alice_y')),15000),await listAv(bobB,'alice_y'));
  // bob leaves and rejoins: alice's server answers his announce privately.
  say(bob,'PART #x');
  await sleep(1500);
  say(bob,'JOIN #x');
  await show(bobB,'#x');
  const rejoinSeen=await until(async()=>/^r/.test(await listAv(bobB,'alice_y')),15000);
  if(!rejoinSeen) console.error('rejoin diagnostics:',JSON.stringify({bobLookup:await lookup(bob,['alice_y']),aliceLookup:await lookup(alice,['bob']),bobAnnounces:tagwatch.lines.filter(l=>/:bob!\S+ TAGMSG/.test(l)),hints:bob.ws.events.filter(e=>e.type==='avatar_hint').slice(-6)}));
  ok('after bob leaves and rejoins, he sees alice_y again (her server answers his announce)',rejoinSeen,await listAv(bobB,'alice_y'));
  ok('the plain client saw no TAGMSG, CTCP or announce through all of it',!plain.lines.some(leak),plain.lines.filter(leak).join(' | '));

  // ── 6b. a viewer's own settings never stop them seeing others ──
  // nora: no avatar; olga: sharing AND "show my avatar" off; pete: avatar removed by an admin;
  // quinn: no avatar, behind a bouncer (a proxy adding ZNC's znc.in/batch to CAP LS).
  bouncer=net.createServer(client=>{
    const up=net.connect(ircPort,'127.0.0.1');
    let buf='';
    up.on('data',d=>{buf+=d.toString('latin1');let i;while((i=buf.indexOf('\n'))>=0){let line=buf.slice(0,i+1);buf=buf.slice(i+1);
      if(/^(@\S+ )?(:\S+ )?CAP \S+ LS /.test(line))line=line.replace(/\r?\n$/,' znc.in/batch\r\n');client.write(Buffer.from(line,'latin1'));}});
    client.on('data',d=>up.write(d));client.on('error',()=>up.destroy());up.on('error',()=>client.destroy());client.on('close',()=>up.destroy());up.on('close',()=>client.destroy());
  });
  await new Promise(r=>bouncer.listen(portBase+3,'127.0.0.1',r));
  await sleep(11000);   // past alice_y's own join burst
  const nora=await account(B,'nora',{channels:['#x'],disabled:noMeta,avatar:false});
  const olga=await account(B,'olga',{channels:['#x'],disabled:noMeta,share:false,visible:false});
  const pete=await account(B,'pete',{channels:['#x'],disabled:noMeta});
  // An admin of B removes pete's avatar (admin rights as makeadmin.sh grants them: the record's flag).
  const bobRec=path.join(B.data,'users','bob.json');
  const rec=JSON.parse(await fs.readFile(bobRec,'utf8'));rec.admin=true;await fs.writeFile(bobRec,JSON.stringify(rec));
  const rm=await fetch(`${B.origin}${bp}/admin/user/pete/avatar`,{method:'DELETE',headers:{authorization:'Bearer '+bob.token}});
  ok('B/pete: an admin removed his avatar',rm.ok&&!(await(await fetch(`${B.origin}${bp}/api/avatar/me`,{headers:{authorization:'Bearer '+pete.token}})).json()).avatar,rm.status);
  const quinn=await account(B,'quinn',{channels:['#x'],disabled:noMeta,avatar:false,port:portBase+3});
  for(const [v,why] of [[nora,'with no avatar'],[olga,'with sharing and "show my avatar" off'],[pete,'whose avatar an admin removed']]){
    const got=await until(async()=>{const x=await lookup(v,['alice_y']);return x.avatars?.alice_y?.r?x:null;},15000);
    ok(`a viewer ${why} (${v.name}) sees alice_y's avatar from the other server`,got,JSON.stringify(await lookup(v,['alice_y'])));
  }
  // A viewer behind a bouncer (or not classified) gets NO remote avatars at all, like v1's
  // bouncer exclusion: no tag, no TAGMSG welcome, and no explicit look either (a bouncer's
  // playback looks live — codex astra re-checks).
  await sleep(8000);
  const qBefore=await lookup(quinn,['alice_y']);
  ok('the bouncer viewer (quinn) ignored the welcome TAGMSG',!qBefore.avatars?.alice_y,JSON.stringify(qBefore));
  const qProbe=await lookup(quinn,['alice_y'],['alice_y']);
  ok('…and an explicit look asks nothing',!(qProbe.pending||[]).length&&!qProbe.avatars?.alice_y,JSON.stringify(qProbe));
  await sleep(4000);
  const qAfter=await lookup(quinn,['alice_y']);
  ok('…so no remote avatar ever shows on a connection through a bouncer',!qAfter.avatars?.alice_y,JSON.stringify(qAfter));
  const qb=await lookup(quinn,['bob']);
  ok('…while v1 still never matches a same-instance user for the bouncer viewer (bob)',!qb.avatars?.bob,JSON.stringify(qb));
  // A sharing user behind a bouncer still announces (live sends) but never answers CTCP AVATAR.
  const rita=await account(B,'rita',{channels:['#x'],disabled:noMeta,port:portBase+3,color:[[160,20,120],[255,200,240]]});
  ok("rita (behind a bouncer) still announces her own join with a TAGMSG",await until(()=>tagwatch.lines.find(l=>tagged(l)&&/:rita!\S+ TAGMSG #x$/.test(l)),8000));
  const asker=await raw('asker',{channels:['#x']});
  asker.send('PRIVMSG rita :\x01AVATAR\x01');
  await sleep(4000);
  ok('…but never answers a CTCP AVATAR on that connection',!asker.lines.some(l=>/:rita!\S+ NOTICE asker :\x01AVATAR/.test(l)),asker.lines.filter(l=>/rita/.test(l)).join(' | '));

  // ── 7. CTCP AVATAR (no message-tags, no metadata) ──
  const watcher=await raw('watcher',{channels:['#ctcp']});
  const erin=await account(B,'erin',{channels:['#ctcp'],disabled:['message-tags','draft/metadata-2'],color:[[200,120,20],[255,240,200]]});
  const grace=await account(B,'grace',{channels:['#ctcp'],disabled:['message-tags','draft/metadata-2'],share:false});
  const frank=await account(A,'frank',{channels:['#ctcp'],disabled:noMeta,avatar:false});
  await sleep(1500);
  const ctcpAt=c=>c.lines.filter(l=>/PRIVMSG \S+ :\x01AVATAR\x01/.test(l));
  let d=await lookup(frank,['erin','grace','watcher']);
  await sleep(2000);
  ok('a member-list lookup sends no CTCP to anyone (watcher got none) and finds nothing yet',ctcpAt(watcher).length===0&&!d.avatars?.erin,JSON.stringify(d));
  d=await lookup(frank,['erin'],['erin']);
  ok('an explicit look at erin is pending (CTCP sent)',(d.pending||[]).includes('erin'),JSON.stringify(d));
  const erinAv=await until(async()=>{const x=await lookup(frank,['erin']);return x.avatars?.erin?.r?x:null;},15000);
  ok("frank (A) gets erin's avatar (B) through CTCP AVATAR",erinAv,JSON.stringify(await lookup(frank,['erin'])));
  await lookup(frank,['watcher'],['watcher']);
  await until(()=>ctcpAt(watcher).length>=1,5000);
  await lookup(frank,['watcher'],['watcher']);
  await sleep(2500);
  ok('an explicit look at a plain user sends exactly one CTCP (cooldown)',ctcpAt(watcher).length===1,ctcpAt(watcher).length);
  await lookup(frank,['grace'],['grace']);
  await sleep(4000);
  ok('an opted-out owner never answers (grace: no avatar)',!(await lookup(frank,['grace'])).avatars?.grace);
  watcher.send('PRIVMSG erin :\x01AVATAR\x01');
  watcher.send('PRIVMSG grace :\x01AVATAR\x01');
  const ans=await watcher.wait(/:erin!\S+ NOTICE watcher :\x01AVATAR /,8000).catch(()=>null);
  ok('a KVIrc-style CTCP AVATAR to a sharing user is answered with her public URL',ans&&ans.includes(erin.publicUrl),ans);
  await sleep(3000);
  ok('an opted-out user never answers it',!watcher.lines.some(l=>/:grace!\S+ NOTICE/.test(l)));
  const pubOk=await fetch(erin.publicUrl);
  ok('the public link serves a PNG with nosniff and a short public cache',pubOk.status===200&&pubOk.headers.get('content-type')==='image/png'&&pubOk.headers.get('x-content-type-options')==='nosniff'&&/public, max-age=300/.test(pubOk.headers.get('cache-control')||''));

  // ── 8. draft/metadata-2 (no message-tags) ──
  const helen=await account(B,'helen',{channels:['#meta'],disabled:['message-tags'],color:[[20,160,160],[220,255,255]]});
  await sleep(1500);
  const ivan=await account(A,'ivan',{channels:['#meta'],disabled:['message-tags'],avatar:false});
  const helenAv=await until(async()=>{const x=await lookup(ivan,['helen']);return x.avatars?.helen?.r?x:null;},15000);
  ok("ivan (A) gets helen's avatar (B) from the metadata sync on join — no message, no query",helenAv,JSON.stringify(await lookup(ivan,['helen'])));
  // Withdraw during an outage: helen's sharing is turned off while B's web is down (so no
  // deletion could be sent then); when the web is back, metadata-2 is active again and the
  // current state is synced — the value is deleted (codex astra re-check 2).
  for(const b of [...browsers]) if(b.u.inst===B){try{b.socket.close();}catch{}try{process.kill(-b.chrome.pid,'SIGKILL');}catch{}browsers.splice(browsers.indexOf(b),1);}
  const back=await restartWeb(B,async()=>{
    const f=path.join(B.data,'users','helen','avatar.json');
    const m=JSON.parse(await fs.readFile(f,'utf8'));m.share=false;delete m.pub_id;
    await fs.writeFile(f,JSON.stringify(m));
  });
  ok("B's web is back (irc-core kept the IRC sessions)",back);
  const gone=await until(async()=>{const x=await lookup(ivan,['helen']);return !x.avatars?.helen;},25000);
  ok("helen's withdrawal made during the outage reaches IRC: her avatar disappears for ivan (METADATA deleted)",gone,JSON.stringify(await lookup(ivan,['helen'])));
  ok('her public link now 404s',(await fetch(helen.publicUrl)).status===404);

  // ── 9. the app asks before a FIRST avatar becomes public (codex astra M app.js:9931) ──
  await fetch(`${A.origin}${bp}/api/avatar/me`,{method:'DELETE',headers:{authorization:'Bearer '+alice.token}});
  const uploadFirst=async(choice)=>{
    await aliceB.ev(`(async()=>{await showProfilePanel();return true;})()`);
    await until(()=>aliceB.ev(`!!document.getElementById('profile-avatar-file')`),10000);
    return aliceB.ev(`(async()=>{
      window.__log=[];
      const oc=window.customConfirm, of=window.fetch;
      window.customConfirm=async(m)=>{__log.push(['confirm',m]);return ${choice};};
      window.fetch=(u,o)=>{if(String(u).includes('/api/avatar/me')&&o&&o.method==='POST')__log.push(['post',String(u)]);return of(u,o);};
      try{
        const cv=document.createElement('canvas');cv.width=cv.height=64;const g=cv.getContext('2d');g.fillStyle='#c33';g.fillRect(0,0,64,64);
        const blob=await new Promise(r=>cv.toBlob(r,'image/png'));
        const dt=new DataTransfer();dt.items.add(new File([blob],'a.png',{type:'image/png'}));
        const inp=document.getElementById('profile-avatar-file');inp.files=dt.files;inp.dispatchEvent(new Event('change'));
        for(let i=0;i<100&&!__log.some(x=>x[0]==='post');i++) await new Promise(r=>setTimeout(r,100));
        await new Promise(r=>setTimeout(r,1500));
        return JSON.stringify(__log);
      }finally{window.customConfirm=oc;window.fetch=of;}
    })()`);
  };
  const meOf=async()=>(await fetch(`${A.origin}${bp}/api/avatar/me`,{headers:{authorization:'Bearer '+alice.token}})).json();
  let log=JSON.parse(await uploadFirst(false));
  let me=await meOf();
  ok('a first upload asks about sharing BEFORE uploading (the question says public)',log.length>=2&&log[0][0]==='confirm'&&/PUBLIC/.test(log[0][1])&&log[1][0]==='post',JSON.stringify(log));
  ok('"This server only": uploaded, not shared, no public link',me.avatar&&me.share===false&&me.public_url==null&&!/share=1/.test(log[1][1]),JSON.stringify(me));
  await fetch(`${A.origin}${bp}/api/avatar/me`,{method:'DELETE',headers:{authorization:'Bearer '+alice.token}});
  log=JSON.parse(await uploadFirst(true));
  me=await meOf();
  ok('"Share it publicly": uploaded with consent and shared',me.avatar&&me.share===true&&typeof me.public_url==='string'&&/share=1/.test(log[1][1]),JSON.stringify(me));

  ok('no page errors',browsers.every(b=>b.errors.length===0)||(console.error(JSON.stringify(browsers.map(b=>b.errors))),false));
  const panics=children.filter(c=>/panicked/.test(c.stderrText));
  ok('no panics',panics.length===0,panics.map(c=>c.label+': '+c.stderrText.slice(-2000)).join('\n'));
}finally{
  for(const b of browsers){try{b.socket.close();}catch{}}
  for(const c of chromes){try{process.kill(-c.pid,'SIGKILL');}catch{}}
  for(const c of raws){try{c.s.destroy();}catch{}}
  for(const h of hostile||[]){try{h.closeAllConnections?.();h.close();}catch{}}
  if(bouncer){try{bouncer.close();}catch{}}
  for(const c of children.reverse()){try{process.kill(-c.pid,'SIGTERM');}catch{}}
  await sleep(1500);
  for(const c of children){try{process.kill(-c.pid,'SIGKILL');}catch{}}
  for(const d of tmpdirs) await fs.rm(d,{recursive:true,force:true});
}
console.log(JSON.stringify({checks},null,2));
