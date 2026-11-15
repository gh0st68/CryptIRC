// Real-binary browser test for avatars: the web binary + irc_core + a local IRC server +
// Chromium. Three accounts join #avtest on ONE local ircd: alice and bob dial it as
// 127.0.0.1, carol dials the very same ircd as "localhost" (another host alias). alice and
// bob see each other's avatars in the nick list, the WHOIS view and the nick menu; carol
// sees only her own, and nobody sees carol's. Also: hide-others setting, opt-out, NICK
// change (also with the nick menu open), no Referer on picture requests, nothing in
// CacheStorage, split view (each pane's own connection), WebSocket re-auth drops cached
// answers, failed loads are retried, keyboard upload, and finally an account behind a
// bouncer (a proxy that adds ZNC's znc.in/batch to CAP LS) is never matched — while the
// plain connections on the same host keep matching — and a web-only restart (irc-core keeps
// the IRC sessions: same WHOIS signon) keeps both: bob matched again, dave still excluded. Screenshots (dark,
// light, phone).
//
// Usage (the ircd must listen on 127.0.0.1 AND [::1] at IRC_PORT and take a 2200-line burst
// from one client, e.g. Ergo with fakelag disabled):
//   CRYPTIRC_BIN=target/debug/cryptirc CRYPTIRC_CORE_BIN=target/debug/irc_core IRC_PORT=28667 \
//     node scripts/test-avatars-browser.mjs
// Optional: CRYPTIRC_TEST_PORT (default 28610), CDP_PORT_BASE (default 28620; three DevTools
//   ports from there), CRYPTIRC_BASE_PATH (default /cryptirc), CHROMIUM (default
//   /usr/bin/chromium), AVATAR_SHOTS (directory for screenshots).
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import assert from 'node:assert/strict';
import net from 'node:net';
import {spawn} from 'node:child_process';

const bin=process.env.CRYPTIRC_BIN, coreBin=process.env.CRYPTIRC_CORE_BIN, ircPort=Number(process.env.IRC_PORT||0);
if(!bin||!coreBin||!ircPort)throw new Error('Set CRYPTIRC_BIN, CRYPTIRC_CORE_BIN and IRC_PORT.');
const port=Number(process.env.CRYPTIRC_TEST_PORT||28610), cdpBase=Number(process.env.CDP_PORT_BASE||28620);
const bncPort=Number(process.env.BNC_PORT||28668);
const basePath=process.env.CRYPTIRC_BASE_PATH||'/cryptirc', bp=basePath==='/'?'':basePath.replace(/\/$/,'');
const origin=`http://127.0.0.1:${port}`;
const shots=process.env.AVATAR_SHOTS||'';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const checks=[];
const ok=(name,value)=>{checks.push({name,pass:!!value});console.error((value?'ok   ':'FAIL ')+`[${basePath}] `+name);assert(value,name);};

// ── a tiny PNG encoder (solid colour + a ring, so the pictures are told apart) ──
function crc32(buf){let c=~0;for(const b of buf){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^(0xEDB88320&-(c&1));}return (~c)>>>0;}
function chunk(type,data){const len=Buffer.alloc(4);len.writeUInt32BE(data.length);const td=Buffer.concat([Buffer.from(type),data]);const crc=Buffer.alloc(4);crc.writeUInt32BE(crc32(td));return Buffer.concat([len,td,crc]);}
function png(w,h,fn){
  const raw=Buffer.alloc((w*3+1)*h);
  for(let y=0;y<h;y++)for(let x=0;x<w;x++){const o=y*(w*3+1)+1+x*3;const [r,g,b]=fn(x,y);raw[o]=r;raw[o+1]=g;raw[o+2]=b;}
  const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(w,0);ihdr.writeUInt32BE(h,4);ihdr[8]=8;ihdr[9]=2;
  return Buffer.concat([Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);
}
const picture=(bg,fg)=>png(240,160,(x,y)=>{const d=Math.hypot(x-120,y-80);return d>34&&d<52?fg:bg;});

const data=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-avatars-'));
await fs.writeFile(path.join(data,'admin_settings.json'),JSON.stringify({registration_open:true,captcha_enabled:false}));
const env={...process.env,CRYPTIRC_DATA:data,CRYPTIRC_BASE_PATH:basePath,CRYPTIRC_PORT:String(port),CRYPTIRC_HSTS:'off',RUST_LOG:'warn'};
const children=[];
const start=(file,name)=>{const c=spawn(file,[],{env,stdio:['ignore','ignore','pipe'],detached:true});c.stderrText='';c.stderr.on('data',d=>{c.stderrText+=d;});c.label=name;children.push(c);return c;};
const browsers=[], chromes=[];
let bouncer=null;
try{
  start(coreBin,'irc_core');
  for(let i=0;i<100;i++){try{await fs.stat(path.join(data,'irc-core.sock'));break;}catch{await sleep(100);}}
  start(bin,'web');
  let up=false;
  for(let i=0;i<300&&!up;i++){try{up=(await fetch(`${origin}${bp}/auth/status`)).ok;}catch{await sleep(100);}}
  ok('server up',up);

  // ── accounts, vaults, networks (over the same HTTP + WebSocket API the apps use) ──
  const json={'content-type':'application/json'};
  const users={alice:{host:'127.0.0.1',color:[[220,70,60],[255,220,120]]},bob:{host:'127.0.0.1',color:[[40,90,220],[160,220,255]]},carol:{host:'localhost',color:[[40,170,90],[230,255,200]]}};
  const wsClient=token=>new Promise((resolve,reject)=>{
    const ws=new WebSocket(`ws://127.0.0.1:${port}${bp}/ws`);
    const events=[],waiters=[];
    ws.onmessage=e=>{const ev=JSON.parse(e.data);events.push(ev);for(const w of [...waiters])if(w.pred(ev)){waiters.splice(waiters.indexOf(w),1);w.resolve(ev);}};
    ws.onerror=reject;
    ws.onopen=()=>{ws.send(JSON.stringify({type:'auth',token,e2e:2}));resolve({ws,events,
      send:o=>ws.send(JSON.stringify(o)),
      wait:(pred,ms=20000)=>new Promise((res,rej)=>{const hit=events.find(pred);if(hit)return res(hit);const w={pred,resolve:res};waiters.push(w);setTimeout(()=>rej(new Error('timed out waiting for an event')),ms);}),
    });};
  });
  const addNetwork=async(u,label,host,nick,ircPortOverride)=>{
    u.ws.send({type:'add_network',network:{id:'',label,server:host,port:ircPortOverride||ircPort,tls:false,tls_accept_invalid_certs:false,
      nick,realname:nick,username:nick,password:null,sasl_plain:null,sasl_external:false,client_cert_id:null,auto_join:['#avtest'],auto_reconnect:true}});
    const st=await u.ws.wait(e=>e.type==='state'&&(e.networks||[]).some(n=>n.config.label===label));
    const id=st.networks.find(n=>n.config.label===label).config.id;
    u.ws.send({type:'connect',id});
    await u.ws.wait(e=>e.type==='connected'&&e.conn_id===id,30000);
    await u.ws.wait(e=>e.type==='irc_names'&&e.conn_id===id&&/avtest/i.test(e.channel),30000);
    return id;
  };
  for(const [name,u] of Object.entries(users)){
    const password='Avatar-test-'+name+'-1!';
    const reg=await fetch(`${origin}${bp}/auth/register`,{method:'POST',headers:json,body:JSON.stringify({username:name,password})});
    ok(`${name}: register`,reg.ok);
    const login=await(await fetch(`${origin}${bp}/auth/login`,{method:'POST',headers:json,body:JSON.stringify({username:name,password})})).json();
    u.token=login.token;
    ok(`${name}: login`,typeof u.token==='string');
    u.ws=await wsClient(u.token);
    await u.ws.wait(e=>e.type==='auth_ok');
    u.ws.send({type:'unlock_vault',passphrase:'vault passphrase for '+name+' 123'});
    await u.ws.wait(e=>e.type==='vault_unlocked',60000);
    u.conn=await addNetwork(u,'AvTest '+name,u.host,name);
    // alice is also on the same ircd as "localhost" (split-view case: another host there).
    if(name==='alice') u.conn2=await addNetwork(u,'AvTest alice via localhost','localhost','alice2');
    const [bg,fg]=u.color;
    const up=await fetch(`${origin}${bp}/api/avatar/me`,{method:'POST',headers:{authorization:'Bearer '+u.token,'content-type':'image/png'},body:picture(bg,fg)});
    const me=await up.json();
    ok(`${name}: avatar uploaded`,up.ok&&/^[0-9a-f]{32}$/.test(me.avatar?.t||''));
    u.avatar=me.avatar;
  }
  await sleep(1500);   // let the last JOIN reach everyone's member list

  // ── one Chromium per account (separate profiles: separate cookies and storage) ──
  const openBrowser=async(name,u)=>{
    const profile=path.join(data,'chrome-'+name), cdpPort=cdpBase+chromes.length;
    const chrome=spawn(process.env.CHROMIUM||'/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-address=127.0.0.1','--remote-debugging-port='+cdpPort,'--user-data-dir='+profile,'--no-first-run','about:blank'],{stdio:'ignore',detached:true});
    chromes.push(chrome);
    // (Chromium writes no DevToolsActivePort file for a fixed port: poll the port itself.)
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
      if(m.method==='Network.requestWillBeSent')requests.push({url:m.params.request.url,headers:m.params.request.headers,method:m.params.request.method});
      if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails);
    };
    const ev=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
    const wait=async(expression,ms=15000)=>{const end=Date.now()+ms;while(Date.now()<end){try{if(await ev(expression))return true;}catch{}await sleep(100);}throw new Error(`[${name}] timed out: ${expression}`);};
    await send('Runtime.enable');await send('Page.enable');await send('Network.enable');
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:800,deviceScaleFactor:1,mobile:false});
    await send('Page.navigate',{url:`${origin}${bp}/auth/status`});
    await sleep(300);
    await ev(`localStorage.setItem('cryptirc_token',${JSON.stringify(u.token)});localStorage.setItem('cryptirc_user',${JSON.stringify(name)});localStorage.setItem('cryptirc_data_owner',${JSON.stringify(name)});true`);
    await send('Page.navigate',{url:`${origin}${bp}/`});
    await wait("typeof avatarFor==='function'&&!!sessionToken&&Array.isArray(networks)&&networks.some(n=>n.connected)",30000);
    const b={name,u,send,ev,wait,requests,errors,socket};
    browsers.push(b);
    return b;
  };
  const show=async(b,target)=>{
    // The vault is already unlocked server-side; a per-device E2E prompt may still be up.
    await b.ev(`(()=>{document.getElementById('vault-overlay')?.classList.remove('show');setActive(${JSON.stringify(b.u.conn)},${JSON.stringify(target)});return true;})()`);
  };
  const entryAvatar=(b,nick)=>b.ev(`(()=>{const e=document.querySelector('#nick-list .nick-entry[data-nick=${JSON.stringify(nick)}]');if(!e)return 'missing';const i=e.querySelector('img.nick-av');return i?JSON.stringify({src:i.getAttribute('src'),av:i.dataset.av,size:i.dataset.avSize,alt:i.alt,rp:i.referrerPolicy,loaded:i.complete&&i.naturalWidth>0,w:i.naturalWidth}):'none';})()`);
  const lookups=b=>b.requests.filter(r=>r.url.includes('/api/avatar/lookup')).length;
  // Close a nick menu the way a user does (a click elsewhere), so the app's one-shot
  // "next click closes the menu" listener is used up and can't close the next menu.
  const closeMenu=async b=>{await sleep(150);await b.ev(`document.body.dispatchEvent(new MouseEvent('click',{bubbles:true}));true`);await b.wait(`!document.querySelector('.nick-ctx')`);};
  const pictureRequests=b=>b.requests.filter(r=>new URL(r.url).pathname.startsWith(`${bp}/avatar/`));
  const shot=async(b,file)=>{if(!shots)return;const s=await b.send('Page.captureScreenshot',{format:'png'});await fs.mkdir(shots,{recursive:true});await fs.writeFile(path.join(shots,(bp?bp.replaceAll('/','_'):'_root')+'-'+file),Buffer.from(s.data,'base64'));};

  const alice=await openBrowser('alice',users.alice);
  const bob=await openBrowser('bob',users.bob);
  const carol=await openBrowser('carol',users.carol);
  for(const b of [alice,bob,carol])await show(b,'#avtest');

  // ── alice: bob's and her own avatar, none for carol (other host alias) ──
  await alice.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`);
  let a=JSON.parse(await entryAvatar(alice,'bob'));
  ok('alice: bob has an avatar in the nick list',a.loaded&&a.w===48);
  ok('alice: it is bob\'s picture (token, version, 48 px), shown from memory',a.av===`${users.bob.avatar.t}.${users.bob.avatar.v}`&&a.size==='48'&&a.src.startsWith('blob:'));
  ok('alice: alt text is the nick, no referrer',a.alt==='bob'&&a.rp==='no-referrer');
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="alice"] img.nick-av')`);
  ok('alice: her own avatar shows next to her nick',JSON.parse(await entryAvatar(alice,'alice')).av.startsWith(users.alice.avatar.t));
  await sleep(1200);
  ok('alice: carol (dials the same ircd as "localhost") has no avatar',await entryAvatar(alice,'carol')==='none');
  ok('alice: no picture of carol was ever requested',!pictureRequests(alice).some(r=>r.url.includes(users.carol.avatar.t)));
  // (CDP lists an empty "Referer" entry when none is sent.)
  const pics=pictureRequests(alice), noReferer=r=>!Object.entries(r.headers).some(([k,v])=>k.toLowerCase()==='referer'&&v!=='');
  if(!(pics.length>0&&pics.every(r=>r.url.startsWith(origin)&&noReferer(r))))console.error(JSON.stringify(pics,null,1));
  ok('alice: picture requests are same-origin with no Referer',pics.length>0&&pics.every(r=>r.url.startsWith(origin)&&noReferer(r)));
  ok('alice: picture requests carry the session header',pics.every(r=>Object.keys(r.headers).some(k=>k.toLowerCase()==='authorization')));
  ok('alice: her own avatar is not shown on her other connection\'s nick (another host)',await entryAvatar(alice,'alice2')==='none');
  ok('alice: no avatar response is in CacheStorage',await alice.ev(`(async()=>{for(const k of await caches.keys()){for(const r of await (await caches.open(k)).keys())if(r.url.includes('/avatar/'))return false;}return true;})()`));
  ok('alice: the nick list rows keep their height',await alice.ev(`(()=>{const rows=[...document.querySelectorAll('#nick-list .nick-entry')];const h=rows.map(r=>Math.round(r.getBoundingClientRect().height));return h.length>=3&&new Set(h).size===1;})()`));
  await shot(alice,'nicklist-dark.png');

  // ── bob and carol ──
  await bob.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="alice"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`);
  ok('bob: alice has her avatar',JSON.parse(await entryAvatar(bob,'alice')).av.startsWith(users.alice.avatar.t));
  await carol.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="carol"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`);
  await sleep(1200);
  ok('bob: carol has none',await entryAvatar(bob,'carol')==='none');
  ok('carol: sees her own avatar',JSON.parse(await entryAvatar(carol,'carol')).av.startsWith(users.carol.avatar.t));
  ok('carol: alice and bob have none on her "localhost" connection',await entryAvatar(carol,'alice')==='none'&&await entryAvatar(carol,'bob')==='none');
  ok('carol: never requested bob\'s picture',!pictureRequests(carol).some(r=>r.url.includes(users.bob.avatar.t)));
  await carol.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="alice2"] img.nick-av')`);
  ok('carol: alice\'s avatar shows next to "alice2" — alice\'s own connection via "localhost", carol\'s host',JSON.parse(await entryAvatar(carol,'alice2')).av.startsWith(users.alice.avatar.t));

  // ── nick menu ──
  await alice.ev(`(()=>{const e=document.querySelector('#nick-list .nick-entry[data-nick="bob"]');e.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:1000,clientY:200}));return true;})()`);
  await alice.wait(`(()=>{const i=document.querySelector('.nick-ctx .nick-ctx-head img.nick-ctx-av');return i&&i.complete&&i.naturalWidth===128;})()`);
  ok('alice: the nick menu shows bob\'s larger avatar',await alice.ev(`document.querySelector('.nick-ctx-head span').textContent==='bob'`));
  await shot(alice,'nick-menu.png');
  await closeMenu(alice);
  await alice.ev(`(()=>{const e=document.querySelector('#nick-list .nick-entry[data-nick="carol"]');e.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:1000,clientY:200}));return true;})()`);
  await alice.wait(`!!document.querySelector('.nick-ctx')`);
  ok('alice: no avatar header in carol\'s nick menu',await alice.ev(`!document.querySelector('.nick-ctx .nick-ctx-head')`));
  await closeMenu(alice);

  // ── WHOIS (typed, through the real command path) ──
  const whois=async(b,nick)=>{
    // The app's command handler (what Enter calls), as if typed.
    await b.ev(`handleInput('/whois ${nick}').then(()=>true)`);
    try{ await b.wait(`active&&active.target.toLowerCase()===${JSON.stringify(nick)}&&!!document.querySelector('.whois-head[data-whois-nick]')`); }
    catch(e){ console.error(await b.ev(`JSON.stringify({active,sendLock:_sendLock,input:document.getElementById('msg-input').value,rows:[...document.querySelectorAll('#chat-area .msg-row')].slice(-8).map(r=>r.textContent),pending:window._pendingWhois})`)); throw e; }
  };
  await whois(alice,'bob');
  await alice.wait(`(()=>{const i=document.querySelector('.whois-head[data-whois-nick="bob"] img.whois-av');return i&&i.complete&&i.naturalWidth===128;})()`);
  ok('alice: the WHOIS view shows bob\'s avatar (128 px)',await alice.ev(`document.querySelector('.whois-head img.whois-av').dataset.av===${JSON.stringify(`${users.bob.avatar.t}.${users.bob.avatar.v}`)}`));
  await shot(alice,'whois.png');
  // (From the channel: a line typed in bob's DM waits for the E2E handshake between two
  // CryptIRC users, which is outside this test.)
  await show(alice,'#avtest');
  await whois(alice,'carol');
  await sleep(1500);
  ok('alice: no avatar in carol\'s WHOIS view',await alice.ev(`!!document.querySelector('.whois-head[data-whois-nick="carol"]')&&!document.querySelector('.whois-head img.whois-av')`));
  await show(alice,'#avtest');

  // ── "Show other people's avatars" off ──
  await alice.ev(`setAvatarsShown(false);renderNickPanel(networks.find(n=>n.config.id===active.conn_id).channels.find(c=>_sameChan(c.name,'#avtest')).names);true`);
  const before=lookups(alice);
  await sleep(1500);
  ok('alice: hidden — no avatars in the list',await alice.ev(`!document.querySelector('#nick-list img.nick-av')`));
  ok('alice: hidden — no lookups are made',lookups(alice)===before);
  await alice.ev(`setAvatarsShown(true);renderNickPanel(networks.find(n=>n.config.id===active.conn_id).channels.find(c=>_sameChan(c.name,'#avtest')).names);true`);
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`);
  ok('alice: shown again after turning it back on',true);

  // ── bob opts out, then back in ──
  const vis=async on=>(await fetch(`${origin}${bp}/api/avatar/me`,{method:'PUT',headers:{authorization:'Bearer '+users.bob.token,'content-type':'application/json'},body:JSON.stringify({visible:on})})).ok;
  ok('bob: opts out',await vis(false));
  const sentBefore=lookups(alice);
  await alice.ev(`avatarForgetAll();avatarRefreshActive();true`);
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="alice"] img.nick-av')`);
  ok('alice: a fresh lookup was made',lookups(alice)>sentBefore);
  ok('alice: her own still shows; bob\'s is gone after he opts out',await alice.ev(`!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`));
  const direct=await alice.ev(`fetch(${JSON.stringify(`${bp}/avatar/${users.bob.avatar.t}?v=${users.bob.avatar.v}`)},{cache:'no-store',headers:{Authorization:'Bearer '+sessionToken}}).then(r=>r.status)`);
  ok('alice: bob\'s picture URL now answers 404',direct===404);
  ok('bob: opts back in',await vis(true));
  await alice.ev(`avatarForgetAll();avatarRefreshActive();true`);
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`);

  // ── bob changes nick: the avatar follows his CURRENT nick; an open menu drops it ──
  await alice.ev(`(()=>{const e=document.querySelector('#nick-list .nick-entry[data-nick="bob"]');e.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:1000,clientY:200}));return true;})()`);
  await alice.wait(`!!document.querySelector('.nick-ctx .nick-ctx-head img.nick-ctx-av')`);
  users.bob.ws.send({type:'send',conn_id:users.bob.conn,raw:'NICK bobby'});
  await alice.wait(`!!nickCtx&&!nickCtx.querySelector('.nick-ctx-head img')`);
  ok('alice: the open nick menu drops bob\'s avatar when "bob" changes hands',await alice.ev(`!!document.querySelector('.nick-ctx')`));
  await closeMenu(alice);
  await alice.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="bobby"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`);
  ok('alice: bob\'s avatar follows him to "bobby"',!(await alice.ev(`!!document.querySelector('#nick-list .nick-entry[data-nick="bob"]')`)));
  users.bob.ws.send({type:'send',conn_id:users.bob.conn,raw:'NICK bob'});
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`);

  // ── split view: each pane's rows belong to their own connection ──
  users.bob.ws.send({type:'send',conn_id:users.bob.conn,raw:'PRIVMSG #avtest :hello from bob'});
  await alice.wait(`!!document.querySelector('#chat-area .msg-nick[data-nick="bob"]')`);
  await alice.ev(`(()=>{if(!_splitActive)toggleSplitView();_splitTarget=${JSON.stringify(users.alice.conn2+'/#avtest')};renderSplitChat();return true;})()`);
  await alice.wait(`!!document.querySelector('#split-panel .msg-nick[data-nick="bob"]')`);
  await alice.ev(`(()=>{const n=document.querySelector('#split-panel .msg-nick[data-nick="bob"]');n.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:900,clientY:300}));return true;})()`);
  await alice.wait(`!!document.querySelector('.nick-ctx')`);
  await sleep(1200);
  ok('split view: bob in the pane of alice\'s "localhost" connection gets no avatar in the menu',await alice.ev(`!document.querySelector('.nick-ctx .nick-ctx-head img')`));
  await closeMenu(alice);
  await alice.ev(`(()=>{const n=document.querySelector('#chat-area .msg-nick[data-nick="bob"]');n.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:600,clientY:300}));return true;})()`);
  await alice.wait(`!!document.querySelector('.nick-ctx .nick-ctx-head img.nick-ctx-av')`);
  ok('split view: bob in the main pane (alice\'s 127.0.0.1 connection) still gets it',true);
  await closeMenu(alice);await alice.ev(`toggleSplitView();true`);

  // ── PART of the last shared channel drops the answer; the nick menu asks again ──
  // (carol's view of alice2 — alice's own connection on carol's host. Carol WHOISes alice2
  // first: a WHOIS makes a nick eligible for a lookup, it doesn't keep an old answer.)
  users.alice.ws.send({type:'send',conn_id:users.alice.conn2,raw:'PRIVMSG #avtest :hello from alice2'});
  await carol.wait(`!!document.querySelector('#chat-area .msg-nick[data-nick="alice2"]')`);
  await carol.ev(`handleInput('/whois alice2').then(()=>true)`);
  await carol.wait(`active&&active.target.toLowerCase()==='alice2'&&!!document.querySelector('.whois-head[data-whois-nick]')`);
  await show(carol,'#avtest');
  await carol.wait(`!!document.querySelector('#chat-area .msg-nick[data-nick="alice2"]')`);
  await carol.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="alice2"] img.nick-av')`);
  users.alice.ws.send({type:'part_channel',conn_id:users.alice.conn2,channel:'#avtest'});
  await carol.wait(`!document.querySelector('#nick-list .nick-entry[data-nick="alice2"]')`);
  ok('PART: the answer for alice2 is dropped once she leaves carol\'s last shared channel (even freshly WHOIS\'d)',await carol.ev(`avatarFor(${JSON.stringify(users.carol.conn)},'alice2')===null`));
  await carol.ev(`(()=>{const n=document.querySelector('#chat-area .msg-nick[data-nick="alice2"]');n.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:600,clientY:300}));return true;})()`);
  await carol.wait(`!!document.querySelector('.nick-ctx')`);
  await sleep(1500);
  ok('PART: carol\'s nick menu shows no avatar for a nick she no longer sees',await carol.ev(`!document.querySelector('.nick-ctx .nick-ctx-head img')`));
  await closeMenu(carol);
  // The menu asked the server again; within the WHOIS window the server still vouches, so an
  // answer is cached — yet it is never rendered for a nick outside the shared channels.
  await carol.wait(`avatarFor(${JSON.stringify(users.carol.conn)},'alice2')!==null`,15000);
  await carol.ev(`(()=>{const n=document.querySelector('#chat-area .msg-nick[data-nick="alice2"]');n.dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:600,clientY:300}));return true;})()`);
  await carol.wait(`!!document.querySelector('.nick-ctx')`);
  await sleep(800);
  ok('PART: a cached answer is never shown in the menu for a nick outside the shared channels',await carol.ev(`!document.querySelector('.nick-ctx .nick-ctx-head img')`));
  await closeMenu(carol);
  users.alice.ws.send({type:'join_channel',conn_id:users.alice.conn2,channel:'#avtest',key:null});
  await carol.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="alice2"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`,20000);
  ok('PART: the avatar is back once alice2 shares a channel again',true);

  // ── the WebSocket drops and re-authenticates: cached answers are dropped ──
  const forgotBefore=await alice.ev(`_AV.forgot.get('*')||0`);
  await alice.ev(`ws.close();true`);
  await alice.wait(`(_AV.forgot.get('*')||0)>${forgotBefore}&&_wsAuthed===true`,30000);
  await show(alice,'#avtest');
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`,20000);
  ok('re-auth: answers were dropped and asked again',true);

  // ── a failed picture load is retried (backoff), not given up for good ──
  const failed=await alice.ev(`_avLoad({t:'0'.repeat(32),v:'0'.repeat(16)},48).then(u=>{const r=_AVIMG.get('0'.repeat(32)+'.'+'0'.repeat(16)+'.48');return JSON.stringify({u,state:r.state,wait:r.retryAt-Date.now()});})`);
  const f1=JSON.parse(failed);
  ok('retry: a failed load backs off (about 30 s)',f1.u===null&&f1.state==='fail'&&f1.wait>20000&&f1.wait<=30000);
  await alice.ev(`(()=>{const k=${JSON.stringify(`${users.bob.avatar.t}.${users.bob.avatar.v}.48`)};const r=_AVIMG.get(k);try{URL.revokeObjectURL(r.url);}catch(_){}_AVIMG.set(k,{state:'fail',fails:1,retryAt:Date.now()+600000,url:null});document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')?.remove();_avApplyAll();return true;})()`);
  ok('retry: while backing off, no picture',await alice.ev(`!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`));
  await alice.ev(`(()=>{_AVIMG.get(${JSON.stringify(`${users.bob.avatar.t}.${users.bob.avatar.v}.48`)}).retryAt=0;_avApplyAll();return true;})()`);
  await alice.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`);
  ok('retry: loaded again once the backoff is over',true);

  // ── Settings ▸ Profile ▸ Avatar ──
  await alice.ev(`showProfilePanel();true`);
  await alice.wait(`(()=>{const i=document.querySelector('#profile-avatar-preview img');return i&&i.complete&&i.naturalWidth===128;})()`);
  ok('profile: the avatar card shows the picture and both switches',await alice.ev(`!!document.getElementById('profile-avatar-visible')&&!!document.getElementById('profile-avatar-others')&&!!document.getElementById('profile-avatar-file')`));
  ok('profile: Upload/Replace is a focusable button that opens the file picker',await alice.ev(`(()=>{const b=document.getElementById('profile-avatar-pick'),f=document.getElementById('profile-avatar-file');let opened=0;const orig=f.click;f.click=()=>{opened++;};b.focus();const focused=document.activeElement===b;b.click();f.click=orig;return b.tagName==='BUTTON'&&b.tabIndex>=0&&focused&&opened===1;})()`));
  await shot(alice,'profile-dark.png');
  await alice.ev(`closeProfilePanel();true`);

  // ── light theme and a phone ──
  await alice.ev(`(()=>{const c=loadAppearance();c.theme='light';localStorage.setItem('cryptirc_appear',JSON.stringify(c));invalidateAppearCache();applyThemeCSS(loadAppearance());return true;})()`);
  await sleep(300);
  await shot(alice,'nicklist-light.png');
  await alice.ev(`showProfilePanel();true`);
  await alice.wait(`!!document.querySelector('#profile-avatar-preview img')`);
  await shot(alice,'profile-light.png');
  await alice.ev(`closeProfilePanel();true`);
  await alice.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:2,mobile:true});
  await sleep(400);
  await alice.ev(`(()=>{const np=document.getElementById('nick-panel');np.classList.add('open');return true;})()`);
  await sleep(300);
  ok('phone: avatars in the nick list are 24 px and loaded',await alice.ev(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av');if(!i)return false;const r=i.getBoundingClientRect();return Math.round(r.width)===24&&i.naturalWidth>0;})()`));
  ok('phone: no horizontal overflow in the nick list',await alice.ev(`(()=>{const l=document.getElementById('nick-list');return l.scrollWidth<=l.clientWidth+1;})()`));
  await shot(alice,'nicklist-phone-light.png');

  // ── last: dave is behind a bouncer on 127.0.0.1 (a proxy adding ZNC's znc.in/batch to CAP LS) ──
  await alice.send('Emulation.setDeviceMetricsOverride',{width:1280,height:800,deviceScaleFactor:1,mobile:false});
  const bnc=net.createServer(client=>{
    const up=net.connect(ircPort,'127.0.0.1');
    let buf='';
    up.on('data',d=>{buf+=d.toString('latin1');let i;while((i=buf.indexOf('\n'))>=0){let line=buf.slice(0,i+1);buf=buf.slice(i+1);
      if(/^(@\S+ )?(:\S+ )?CAP \S+ LS /.test(line))line=line.replace(/\r?\n$/,' znc.in/batch\r\n');client.write(Buffer.from(line,'latin1'));}});
    client.on('data',d=>up.write(d));client.on('error',()=>up.destroy());up.on('error',()=>client.destroy());client.on('close',()=>up.destroy());up.on('close',()=>client.destroy());
  });
  await new Promise(r=>bnc.listen(bncPort,'127.0.0.1',r));
  bouncer=bnc;
  const dave={};
  const dpw='Avatar-test-dave-1!';
  await fetch(`${origin}${bp}/auth/register`,{method:'POST',headers:json,body:JSON.stringify({username:'dave',password:dpw})});
  dave.token=(await(await fetch(`${origin}${bp}/auth/login`,{method:'POST',headers:json,body:JSON.stringify({username:'dave',password:dpw})})).json()).token;
  dave.ws=await wsClient(dave.token);await dave.ws.wait(e=>e.type==='auth_ok');
  dave.ws.send({type:'unlock_vault',passphrase:'vault passphrase for dave 123'});await dave.ws.wait(e=>e.type==='vault_unlocked',60000);
  const daveConn=await addNetwork(dave,'AvTest dave via bouncer','127.0.0.1','dave',bncPort);
  const dup=await fetch(`${origin}${bp}/api/avatar/me`,{method:'POST',headers:{authorization:'Bearer '+dave.token,'content-type':'image/png'},body:picture([120,60,200],[255,255,255])});
  ok('dave: avatar uploaded',dup.ok);
  await sleep(1000);
  await alice.ev(`avatarForgetAll();avatarRefreshActive();true`);
  await alice.wait(`!!document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av')`);
  await sleep(1500);
  ok('bouncer: dave (behind a bouncer) gets no avatar in alice\'s nick list',await entryAvatar(alice,'dave')==='none');
  ok('bouncer: bob, a plain connection on the same host, keeps his',JSON.parse(await entryAvatar(alice,'bob')).av.startsWith(users.bob.avatar.t));
  const asAlice=await(await fetch(`${origin}${bp}/api/avatar/lookup`,{method:'POST',headers:{...json,authorization:'Bearer '+users.alice.token},body:JSON.stringify({conn_id:users.alice.conn,nicks:['bob','dave']})})).json();
  ok('bouncer: the server vouches for bob, not for dave',!!asAlice.avatars?.bob&&!asAlice.avatars?.dave);
  const asDave=await(await fetch(`${origin}${bp}/api/avatar/lookup`,{method:'POST',headers:{...json,authorization:'Bearer '+dave.token},body:JSON.stringify({conn_id:daveConn,nicks:['bob','alice','dave']})})).json();
  ok('bouncer: nothing is vouched for to a viewer behind a bouncer',Object.keys(asDave.avatars||{}).length===0);

  // ── web-only restart: irc-core keeps every IRC session ──
  // WHOIS signon time of a nick, asked by a throwaway plain IRC client.
  let probeN=0;
  const signon=nick=>new Promise((resolve,reject)=>{
    const sock=net.connect(ircPort,'127.0.0.1'),me='avprobe'+(++probeN);let buf='';
    const t=setTimeout(()=>{sock.destroy();reject(new Error('whois probe timed out'));},15000);
    sock.on('data',d=>{buf+=d.toString();let i;while((i=buf.indexOf('\n'))>=0){const line=buf.slice(0,i).trim();buf=buf.slice(i+1);const w=line.split(' ');
      if(w[0]==='PING')sock.write('PONG '+w.slice(1).join(' ')+'\r\n');
      if(w[1]==='001')sock.write('WHOIS '+nick+'\r\n');
      if(w[1]==='317'&&w[3]===nick){clearTimeout(t);sock.write('QUIT\r\n');sock.end();resolve(w[5]);}
      if(w[1]==='401'){clearTimeout(t);sock.end();reject(new Error('no such nick '+nick));}}});
    sock.write('NICK '+me+'\r\nUSER '+me+' 0 * :probe\r\n');
  });
  // Push the registration lines (CAP LS …) out of every connection's irc-core replay ring
  // (2000 lines), as on a busy production network: after the restart the replay alone can't
  // reclassify anyone, only the per-connection records can. (The test ircd runs without fakelag.)
  for(const [u,conns] of [[users.alice,[users.alice.conn,users.alice.conn2]],[users.bob,[users.bob.conn]],[users.carol,[users.carol.conn]],[dave,[daveConn]]])
    for(const c of conns) u.ws.send({type:'join_channel',conn_id:c,channel:'#avflood',key:null});
  await sleep(2500);
  await new Promise((resolve,reject)=>{
    const sock=net.connect(ircPort,'127.0.0.1');let buf='',sent=false;
    const t=setTimeout(()=>{sock.destroy();reject(new Error('flood timed out'));},60000);
    sock.on('data',d=>{buf+=d.toString();let i;while((i=buf.indexOf('\n'))>=0){const line=buf.slice(0,i).trim();buf=buf.slice(i+1);const w=line.split(' ');
      if(w[0]==='PING')sock.write('PONG '+w.slice(1).join(' ')+'\r\n');
      if(w[1]==='001')sock.write('JOIN #avflood\r\n');
      if(w[1]==='366'&&!sent){sent=true;let out='';for(let n=0;n<2200;n++)out+='PRIVMSG #avflood :flood line '+n+'\r\n';sock.write(out+'PING :done\r\n');}
      if(w[1]==='PONG'&&/:?done$/.test(line)){clearTimeout(t);sock.write('QUIT\r\n');sock.end();resolve();}}});
    sock.write('NICK avflooder\r\nUSER avflooder 0 * :flood\r\n');
  });
  // irc-core reads inbound lines through a token bucket (1024 burst, 64/s): 2200 lines are
  // taken within ~35 s even from an empty bucket. (Not awaited as WebSocket events: the
  // server drops events for a lagging socket by design, and 2200 can overflow its buffer.)
  await sleep(40000);
  const bobSignon=await signon('bob'), daveSignon=await signon('dave');
  const web=children.find(c=>c.label==='web');
  const exited=new Promise(r=>web.once('exit',r));
  process.kill(-web.pid,'SIGTERM');
  await Promise.race([exited,sleep(10000)]);
  children.splice(children.indexOf(web),1);
  start(bin,'web');
  let back=false;
  for(let i=0;i<300&&!back;i++){try{back=(await fetch(`${origin}${bp}/auth/status`)).ok;}catch{await sleep(100);}}
  ok('restart: the web came back (irc-core untouched)',back);
  const relogin=async(name,pw)=>(await(await fetch(`${origin}${bp}/auth/login`,{method:'POST',headers:json,body:JSON.stringify({username:name,password:pw})})).json()).token;
  const aliceToken=await relogin('alice','Avatar-test-alice-1!'), daveToken=await relogin('dave',dpw);
  const ask=(token,conn,nicks)=>fetch(`${origin}${bp}/api/avatar/lookup`,{method:'POST',headers:{...json,authorization:'Bearer '+token},body:JSON.stringify({conn_id:conn,nicks})}).then(r=>r.json());
  let afterAlice={};
  for(let i=0;i<60;i++){afterAlice=await ask(aliceToken,users.alice.conn,['bob','dave']);if(afterAlice.avatars?.bob)break;await sleep(500);}
  ok('restart: bob\'s avatar is matched again without an IRC reconnect',!!afterAlice.avatars?.bob);
  ok('restart: the IRC sessions really stayed up (same WHOIS signon)',await signon('bob')===bobSignon&&await signon('dave')===daveSignon);
  ok('restart: dave, behind a bouncer, stays excluded',!afterAlice.avatars?.dave);
  const afterDave=await ask(daveToken,daveConn,['bob','alice','dave']);
  ok('restart: a viewer behind a bouncer still gets nothing',Object.keys(afterDave.avatars||{}).length===0);
  await alice.ev(`localStorage.setItem('cryptirc_token',${JSON.stringify(aliceToken)});true`);
  await alice.send('Page.navigate',{url:`${origin}${bp}/`});
  await alice.wait("typeof avatarFor==='function'&&!!sessionToken&&Array.isArray(networks)&&networks.some(n=>n.connected)",30000);
  await show(alice,'#avtest');
  await alice.wait(`(()=>{const i=document.querySelector('#nick-list .nick-entry[data-nick="bob"] img.nick-av');return i&&i.complete&&i.naturalWidth>0;})()`,30000);
  ok('restart: alice\'s nick list shows bob\'s avatar again',true);
  ok('restart: and not dave\'s',await entryAvatar(alice,'dave')==='none');

  ok('no page errors',browsers.every(b=>b.errors.length===0)||(console.error(JSON.stringify(browsers.map(b=>b.errors))),false));
}finally{
  for(const b of browsers){try{b.socket.close();}catch{}}
  for(const c of chromes){try{process.kill(-c.pid,'SIGKILL');}catch{}}
  if(bouncer)bouncer.close();
  for(const c of children.reverse()){try{process.kill(-c.pid,'SIGTERM');}catch{}}
  await sleep(1500);
  for(const c of children){try{process.kill(-c.pid,'SIGKILL');}catch{}if(/panicked/.test(c.stderrText))console.error(c.label+': '+c.stderrText);}
  await fs.rm(data,{recursive:true,force:true});
}
console.log(JSON.stringify({basePath,checks},null,2));
