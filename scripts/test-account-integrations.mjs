// Runs a fresh CryptIRC web + irc_core against an already-running local testnet.
// CRYPTIRC_BIN, CRYPTIRC_CORE_BIN, IRC_PORT and optionally IRC_LEAF_PORT are required.
// CRYPTIRC_TEST_E2E=1, CRYPTIRC_TEST_LEGACY_SIGNAL_HANDOFF=1 and CRYPTIRC_LEGACY_BIN
// exercise a running v2 browser before and after its account moves to recovery.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {checkSettingsSearch} from './settings-search-checks.mjs';
import {checkTranslation, startTranslator} from './translation-checks.mjs';
import {checkCrossInstanceE2e, checkE2eChat, checkLegacyMigration, login, seedLegacyE2e, setUpRecovery} from './e2e-chat-checks.mjs';
import {checkChannelList} from './channel-list-checks.mjs';
import {checkLegacyReactionMenu, checkOrdinaryClientReactions, checkPlainReactions, checkReactionEchoDurability, checkReactionHistory, checkReactionMidpoint} from './reaction-checks.mjs';

const {CRYPTIRC_BIN, CRYPTIRC_CORE_BIN, IRC_PORT, IRC_LEAF_PORT, CHROMIUM} = process.env;
assert(CRYPTIRC_BIN && CRYPTIRC_CORE_BIN && Number(IRC_PORT), 'Set the test binaries and local IRC testnet port');
const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-integrations-'));
const children=[];
const sockets=[];
const tcpSockets=[];
const fixtureServers=[];
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const check=(message,value)=>{assert(value,message);console.log('ok '+message);};
const stamp=randomBytes(3).toString('hex');
const owner='pka'+stamp;
const other='pkb'+stamp;
const password='TestOnly-Password-91!';
const vault='TestOnly-Vault-92!';
const channel='#mcp-'+stamp;
const translationEnabled=process.env.CRYPTIRC_TEST_TRANSLATION==='1';
const e2eEnabled=process.env.CRYPTIRC_TEST_E2E==='1';
const composerEncryption=process.env.CRYPTIRC_TEST_COMPOSER_ENCRYPTION==='1';
const legacyBin=process.env.CRYPTIRC_LEGACY_BIN;
const legacySignalHandoff=process.env.CRYPTIRC_TEST_LEGACY_SIGNAL_HANDOFF==='1';
if(legacySignalHandoff)assert(e2eEnabled&&legacyBin,'The cached-browser test needs the real previous browser release');
const reactionMidpoint=process.env.CRYPTIRC_TEST_REACTION_MIDPOINT==='1';
let translator;
let reactionWindowEnds=0;

async function waitFor(checkFn, name, timeout=20000) {
  const stop=Date.now()+timeout;
  while(Date.now()<stop){
    const result=await checkFn();
    if(result)return result;
    await pause(100);
  }
  throw new Error('Timed out: '+name);
}

function start(file,args,env) {
  const child=spawn(file,args,{env,stdio:['ignore','ignore','pipe'],detached:true});
  child.logs='';
  child.stderr.on('data',chunk=>{child.logs=(child.logs+chunk).slice(-12000);});
  children.push(child);
  return child;
}

const allocatePort=()=>new Promise((resolve,reject)=>{
  const server=net.createServer();
  server.once('error',reject);
  server.listen(0,'127.0.0.1',()=>{
    const {port}=server.address();
    server.close(err=>err?reject(err):resolve(port));
  });
});
const port=await allocatePort();
const origin='http://localhost:'+port;
const base=origin+'/cryptirc';
const env={...process.env,CRYPTIRC_DATA:tmp,CRYPTIRC_BASE_PATH:'/cryptirc',
  CRYPTIRC_BASE_URL:base,CRYPTIRC_PORT:String(port),CRYPTIRC_HSTS:'off',RUST_LOG:'warn'};
if(translationEnabled)env.CRYPTIRC_AI_ALLOW_PRIVATE='1';

async function request(route,{method='GET',body,token,headers={},endpoint=base}={}) {
  const res=await fetch(endpoint+route,{method,body:body===undefined?undefined:JSON.stringify(body),headers:{
    ...(body===undefined?{}:{'Content-Type':'application/json'}),
    ...(token?{Authorization:'Bearer '+token}:{}),...headers
  }});
  const data=await res.json().catch(()=>null);
  return {status:res.status,data,headers:res.headers};
}

async function connectWebsocket(token, endpoint=base) {
  const socket=new WebSocket(endpoint.replace('http','ws')+'/ws');
  sockets.push(socket);
  const events=[];
  socket.onmessage=e=>events.push(JSON.parse(e.data));
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
  const send=message=>socket.send(JSON.stringify(message));
  send({type:'auth',token,e2e:2});
  const wait=(pred,name)=>waitFor(()=>events.find(pred),name);
  await wait(e=>e.type==='auth_ok','WebSocket authentication');
  return {events,send,wait};
}

async function ordinaryIrcClient(port, nick, messageTags=false) {
  const socket=net.createConnection(Number(port),'127.0.0.1');
  tcpSockets.push(socket);
  const lines=[];
  const send=line=>socket.write(line+'\r\n');
  let input='';
  socket.setEncoding('utf8');
  socket.on('data',chunk=>{
    input+=chunk;
    const received=input.split('\r\n');
    input=received.pop();
    for(const line of received){
      lines.push(line);
      if(line.startsWith('PING '))send('PONG '+line.slice(5));
    }
  });
  await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
  if(messageTags) send('CAP REQ :message-tags');
  send('NICK '+nick);
  send(`USER ${nick} 0 * :Ordinary IRC fixture`);
  if(messageTags){
    await waitFor(()=>lines.some(line=>line.includes(' ACK :message-tags')),'ordinary IRC client negotiated message tags');
    send('CAP END');
  }
  await waitFor(()=>lines.some(line=>line.includes(` 001 ${nick} `)),'ordinary IRC client registered');
  return {lines,send,close:()=>socket.end('QUIT :Test complete\r\n')};
}

async function reactionIpcGate(corePath,webPath){
  const gate={held:null,replay:null,match:null};
  let heldSocket;
  const server=net.createServer(browserSocket=>{
    const coreSocket=net.createConnection(corePath);
    tcpSockets.push(browserSocket,coreSocket);
    browserSocket.pipe(coreSocket);
    browserSocket.on('error',()=>coreSocket.destroy());
    coreSocket.on('error',()=>browserSocket.destroy());
    browserSocket.on('close',()=>coreSocket.destroy());
    coreSocket.on('close',()=>browserSocket.destroy());
    let pending=Buffer.alloc(0);
    let delayed=null;
    coreSocket.on('data',chunk=>{
      pending=Buffer.concat([pending,chunk]);
      while(pending.length>=4){
        const length=pending.readUInt32BE(0);
        assert(length<=65536,'the fixture received an IPC frame of the expected size');
        if(pending.length<length+4)return;
        const frame=pending.subarray(0,length+4);
        pending=pending.subarray(length+4);
        if(delayed){delayed.push(frame);continue;}
        // Later frames must stay behind the held frame so a cumulative process
        // acknowledgement cannot mark the held echo as delivered to old web.
        if(browserSocket===heldSocket)continue;
        const event=JSON.parse(frame.subarray(4));
        if(event.type==='raw_line'&&gate.delayOwnEcho?.(event)){
          gate.delayOwnEcho=null;delayed=[frame];
          const receivedAt=Date.now();
          setTimeout(()=>{
            gate.delayedMs=Date.now()-receivedAt;
            if(!browserSocket.destroyed)for(const queued of delayed)browserSocket.write(queued);
            delayed=null;
          },17000);
          continue;
        }
        if(event.type==='raw_line'&&gate.match?.(event)){
          if(!gate.held&&!event.replayed){gate.held=event;heldSocket=browserSocket;continue;}
          if(gate.held&&event.replayed)gate.replay=event;
        }
        browserSocket.write(frame);
      }
    });
  });
  fixtureServers.push(server);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(webPath,resolve);});
  return gate;
}

async function checkPrivacyClock(fast, slow, observer, connection) {
  const quote=JSON.stringify, first='policyfirst'+stamp, second='policysecond'+stamp;
  const edit=(page,fastClock)=>page.evaluate(`(async()=>{
    const now=Date.now, fast=${fastClock}, first=${quote(first)}, next=${quote(fastClock?first:second)};
    const click=(selector,wanted)=>{
      const button=document.querySelector(selector);
      if(!button)throw Error('Missing protection control '+selector);
      if(button.classList.contains('on')===wanted)button.click();
      button.click();
    };
    try {
      if(fast)Date.now=()=>now()+300000;
      setActive(${quote(connection)},${quote(channel)});
      await handleInput('/ignore '+next);
      if(fast)addPmAllow(first,null);else removePmAllow(first,null);
      showPmProtectionPanel();
      click('#pm-prot-enable',!fast);
      const scope=document.querySelector('#pm-prot-scope');scope.value=${quote(connection)};
      scope.dispatchEvent(new Event('change',{bubbles:true}));
      const override=document.querySelector('#pm-prot-override');
      if(!override.classList.contains('on'))override.click();
      click('#pm-prot-notify',!fast);
      // Both devices dismiss different reminders. The network description is a
      // local test fixture; the dismissal itself is saved by the real UI.
      const close=document.querySelector('#pm-prot-scope').closest('div[style*="position:fixed"]')?.querySelector('[data-ov-close]');
      if(close)close.click();
      else document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
      _showTlsVerifyPopup([{config:{id:next,label:next,server:'127.0.0.1',tls:true,tls_accept_invalid_certs:true}}],false);
      Array.from(document.querySelectorAll('#tls-verify-popup button')).find(b=>b.textContent==='Not now').click();
      flushPrefsToServer();
    } finally {Date.now=now;}
  })()`);
  const stored=(at,accept)=>waitFor(()=>{
    for(const e of observer.events.slice(at)){
      if(e.type!=='preferences'||!e.prefs)continue;
      const prefs=JSON.parse(e.prefs);
      if(accept(prefs))return prefs;
    }
  },'the account receives the actual protection settings save');
  const hasSettings=(p,fastClock)=>p.ignoreList?.includes(fastClock?first:second)&&p.pmAllow?.includes(first)===fastClock&&
    p.pmBlock===!fastClock&&p.pmNet?.[connection]?.notify===!fastClock&&p.tlsVerify?.dismissed?.includes(fastClock?first:second);
  const local=(page,fastClock)=>page.evaluate(`({
    ignored:ignoreList.has(${quote(fastClock?first:second)}),allow:pmAllowList.has(${quote(first)})===${fastClock},
    block:(localStorage.getItem('cryptirc_block_pms')==='true')===${!fastClock},
    network:loadPmNet()[${quote(connection)}]?.notify===${!fastClock},
    certificateReminder:_tlsIdSet(_TLS_DISMISS_KEY).has(${quote(fastClock?first:second)})
  })`);
  let at=observer.events.length;
  await edit(fast,true);
  await stored(at,p=>hasSettings(p,true));
  await waitFor(async()=>Object.values(await local(slow,true)).every(Boolean),'the second device receives the fast clock’s settings');
  at=observer.events.length;
  await edit(slow,false);
  await stored(at,p=>hasSettings(p,false));
  await waitFor(async()=>Object.values(await local(fast,false)).every(Boolean),'the faster device applies the slower device’s privacy edits',5000).catch(()=>false);
  const applied=await local(fast,false);
  at=observer.events.length;
  await fast.evaluate("document.getElementById('topic-menu-btn').click();[...document.querySelectorAll('#topic-menu button')].find(b=>b.textContent==='☆ Favorite').click()");
  const saved=await stored(at,p=>p.favorites?.some(f=>f.key===connection+'/'+channel));
  console.log('PROTECTION-CLOCK '+JSON.stringify({applied,retained:hasSettings(saved,false)}));
  check('the slower device’s ignore, removed PM allowance, enabled PM protection, network setting and certificate reminder survive an unrelated Favorite',
    Object.values(applied).every(Boolean)&&hasSettings(saved,false));
}

// Hold only the ordinary Favorite button's actual serialized WebSocket frame.
// The second account device edits its settings while that frame is in transit.
async function checkConcurrentPreferenceSave({token, ownerWs, networkA, browser}) {
  const tab=await chromium('concurrent-preferences');
  const ev=tab.evaluate;
  await ev("document.getElementById('l-user').value="+JSON.stringify(owner)+";document.getElementById('l-pass').value="+JSON.stringify(password)+";doLogin()");
  await waitFor(()=>ev('!!sessionToken&&_wsReady()&&_prefsSeen'),'second preference browser signed in');
  await ev("document.getElementById('vault-pass').value="+JSON.stringify(vault)+";doUnlock()");
  await waitFor(()=>ev('E2E._vaultUp&&_prefsSeen'),'second preference browser unlocked');
  if(process.env.CRYPTIRC_TEST_PROTECTION_CLOCK==='1')return checkPrivacyClock(tab,browser,ownerWs,networkA);
  const patch=settings=>tool(token,'cryptirc_settings',{section:'preferences',settings});
  const read=()=>tool(token,'cryptirc_settings',{section:'preferences'});
  const fixtureKey='disposable-favorite-'+stamp;
  const favoriteKey=networkA+'/'+channel;
  const hasFavorite=prefs=>prefs.favorites?.some(f=>f.key===favoriteKey)??false;
  const delayFavoriteEcho=process.env.CRYPTIRC_TEST_FAVORITE_PENDING_ECHO==='1';
  await ev('setActive('+JSON.stringify(networkA)+','+JSON.stringify(channel)+')');
  for(const adding of [true,false]){
    const rating=adding?'pg':'g';
    const updatedRating=adding?'g':'pg';
    const initialKey=adding?'':fixtureKey;
    const updatedKey=adding?fixtureKey:'';
    await patch({giphyKey:initialKey,giphyRating:rating,autoRejoin:adding});
    const hasLocal=(key,contentRating,rejoin)=>ev(
      "(localStorage.getItem('cryptirc_giphy_key')||'')==="+JSON.stringify(key)+
      "&&localStorage.getItem('cryptirc_giphy_rating')==="+JSON.stringify(contentRating)+
      "&&(localStorage.getItem('cryptirc_autorejoin')!=='false')==="+JSON.stringify(rejoin));
    await waitFor(()=>hasLocal(initialKey,rating,adding),'browser applied the initial preferences');
    await ev(`(()=>{
      const socket=ws, original=socket.send;
      window.heldFavorite=null;
      socket.send=function(frame){
        const message=JSON.parse(frame);
        if(message.type==='save_preferences'){
          const prefs=JSON.parse(message.prefs), included=prefs.favorites?.some(f=>f.key===${JSON.stringify(favoriteKey)});
          if(included===${adding}){
            socket.send=original;
            window.heldFavorite={stamp:prefs._favsTs,base:message.base,release:()=>original.call(socket,frame)};
            return;
          }
        }
        return original.call(socket,frame);
      };
      document.getElementById('topic-menu-btn').click();
      const button=[...document.querySelectorAll('#topic-menu button')].find(b=>b.textContent===${JSON.stringify(adding?'☆ Favorite':'★ Unfavorite')});
      if(!button)throw Error('Favorite menu action unavailable');
      button.click();
    })()`);
    const favStamp=await waitFor(()=>ev('window.heldFavorite?.stamp'),'ordinary Favorite button submitted a preference frame');
    if(delayFavoriteEcho&&!adding){
      const count=await ev("favoriteEchoGate.events.length");
      // The client loads preferences again on vault unlock. This real request
      // reaches storage while the previous Favorite echo is still in transit.
      await ev("wsend({type:'load_preferences'})");
      await waitFor(()=>ev("favoriteEchoGate.events.length>"+count),'the user’s reload receives the saved Favorite');
      check('Unfavorite was queued before this browser applied its own Favorite echo',await ev(
        "favoriteEchoGate.events.every(e=>JSON.parse(e.prefs)._prefsRevision>heldFavorite.base)"));
      await ev('favoriteEchoGate.release();delete window.favoriteEchoGate');
    }
    await patch({giphyKey:updatedKey,giphyRating:updatedRating,autoRejoin:!adding});
    const before=(await read()).settings;
    check('concurrent settings reached storage before '+(adding?'Favorite':'Unfavorite'),
      before.giphyRating===updatedRating&&before.autoRejoin===!adding&&!Object.hasOwn(before,'giphyKey'));
    await waitFor(()=>hasLocal(updatedKey,updatedRating,!adding),'browser applied the independent change');
    if(delayFavoriteEcho&&adding)await ev(`(()=>{
      const dispatch=handleEvent,events=[];
      window.favoriteEchoGate={events,release:()=>{handleEvent=dispatch;events.forEach(dispatch);}};
      handleEvent=e=>{
        if(e.type==='preferences'&&e.prefs&&JSON.parse(e.prefs).favorites?.some(f=>f.key===${JSON.stringify(favoriteKey)})){
          events.push(e);return;
        }
        return dispatch(e);
      };
    })()`);
    const from=ownerWs.events.length;
    await ev('window.heldFavorite.release();window.heldFavorite=null');
    const saved=await waitFor(()=>{
      for(const event of ownerWs.events.slice(from)){
        if(event.type!=='preferences'||!event.prefs)continue;
        const p=JSON.parse(event.prefs);
        if(p._favsTs===favStamp&&hasFavorite(p)===adding)return p;
      }
    },'independent browser observed the delayed Favorite save');
    const after=(await read()).settings;
    check(adding?'a delayed Favorite preserves independent settings and their credential':
      'a delayed Unfavorite cannot restore a cleared credential',
      saved.giphyRating===updatedRating&&saved.autoRejoin===!adding&&saved.giphyKey===updatedKey&&
      after.giphyRating===updatedRating&&after.autoRejoin===!adding&&hasFavorite(after)===adding&&
      !Object.hasOwn(after,'giphyKey')&&!Object.hasOwn(after,'_prefsFieldVersions'));
    await waitFor(()=>hasLocal(updatedKey,updatedRating,!adding),'originating browser converged after the delayed write');
    await waitFor(()=>browser.evaluate('isFavorite('+JSON.stringify(networkA)+','+JSON.stringify(channel)+')==='+adding+
      "&&Number(localStorage.getItem('cryptirc_favs_ts'))==="+favStamp),'sibling applied the Favorite list and its timestamp together');
  }

  // Real browsers decide whether to adopt channel keys using the last local
  // device timestamp. The fast browser creates the key and the slow one clears
  // it normally. Only the first browser's clock, not its messages, is adjusted.
  const keyPresent=page=>page.evaluate('Boolean(loadChanKeys()['+JSON.stringify(favoriteKey)+'])');
  const observed=(from,accept)=>waitFor(()=>{
    for(const event of ownerWs.events.slice(from)){
      if(event.type!=='preferences'||!event.prefs)continue;
      const prefs=JSON.parse(event.prefs);
      if(accept(prefs))return prefs;
    }
  },'account observer received the channel-key preferences');
  let from=ownerWs.events.length;
  await tab.evaluate(`(async()=>{
    const original=Date.now;
    try{
      Date.now=()=>original()+300000;
      await handleInput(${JSON.stringify('/key '+channel+' disposable-clock-key')});
      flushPrefsToServer();
    }finally{Date.now=original;}
  })()`);
  const first=await observed(from,p=>!!p.channelKeys?.[favoriteKey]);
  await waitFor(()=>keyPresent(browser),'second browser received the known channel key');
  await browser.evaluate('setActive('+JSON.stringify(networkA)+','+JSON.stringify(channel)+')');
  from=ownerWs.events.length;
  await browser.evaluate('(async()=>{await handleInput('+JSON.stringify('/key '+channel)+');flushPrefsToServer()})()');
  const cleared=await observed(from,p=>Object.hasOwn(p,'channelKeys')&&!p.channelKeys?.[favoriteKey]);
  check('a channel key cleared from a slower clock has a revision every cached browser can apply',
    cleared._channelKeysTs>=first._channelKeysTs);
  await waitFor(async()=>!await keyPresent(tab),'fast browser applied the other device’s channel-key clear');
  from=ownerWs.events.length;
  await tab.evaluate("document.getElementById('topic-menu-btn').click();[...document.querySelectorAll('#topic-menu button')].find(b=>b.textContent==='☆ Favorite').click()");
  const after=await observed(from,hasFavorite);
  check('an unrelated Favorite on a fast device cannot restore a cleared channel key',
    !after.channelKeys?.[favoriteKey]&&!Object.hasOwn((await read()).settings,'channelKeys'));
}

async function chromium(profile='chrome', endpoint=base, clockOffsetMs=0) {
  const chrome=start(CHROMIUM||'/usr/bin/chromium',[
    '--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-port=0',
    '--user-data-dir='+tmp+'/'+profile,'--no-first-run','about:blank'
  ],process.env);
  const cdpPort=await waitFor(async()=>{
    if(chrome.exitCode!==null)throw new Error('Chromium exited: '+chrome.logs);
    return Number((await fs.readFile(path.join(tmp,profile,'DevToolsActivePort'),'utf8').catch(()=>'' )).split('\n')[0]);
  },'Chromium DevTools');
  const targets=await (await fetch('http://127.0.0.1:'+cdpPort+'/json')).json();
  const socket=new WebSocket(targets.find(x=>x.type==='page').webSocketDebuggerUrl);
  sockets.push(socket);
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
  let id=0;
  const pending=new Map();
  const errors=[];
  const frames=[];
  const deliveryNotices=[];
  socket.onmessage=e=>{
    const m=JSON.parse(e.data);
    if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.text);
    if((e2eEnabled||composerEncryption||reactionMidpoint||process.env.CRYPTIRC_TEST_REACTION_DURABILITY==='1')&&m.method==='Network.webSocketFrameSent')
      frames.push(m.params.response.payloadData);
    if(legacySignalHandoff&&m.method==='Network.webSocketFrameReceived'){
      const event=JSON.parse(m.params.response.payloadData);
      if(event.type==='irc_delivery_warning'||(event.type==='irc_message'&&event.from==='*'))deliveryNotices.push(event);
    }
    if(!pending.has(m.id))return;
    const {resolve,reject}=pending.get(m.id);
    pending.delete(m.id);
    if(m.error)reject(new Error(m.error.message));else resolve(m.result);
  };
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    const commandId=++id;
    const timeout=setTimeout(()=>{
      pending.delete(commandId);
      reject(new Error('Chromium did not answer '+method));
    },45000);
    pending.set(commandId,{
      resolve:value=>{clearTimeout(timeout);resolve(value);},
      reject:error=>{clearTimeout(timeout);reject(error);},
    });
    try{socket.send(JSON.stringify({id:commandId,method,params}));}
    catch(error){pending.delete(commandId);clearTimeout(timeout);reject(error);}
  });
  const evaluate=async expression=>{
    const result=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true,userGesture:true});
    if(result.exceptionDetails)throw new Error(result.exceptionDetails.exception?.description||result.exceptionDetails.text);
    return result.result.value;
  };
  await send('Runtime.enable');
  await send('Network.enable');
  await send('Network.setBypassServiceWorker',{bypass:true});
  await send('Network.setBlockedURLs',{urls:['https://*','wss://*']});
  await send('Page.enable');
  if(clockOffsetMs)await send('Page.addScriptToEvaluateOnNewDocument',{source:
    `(()=>{const now=Date.now;Date.now=()=>now()+${Number(clockOffsetMs)};})()`});
  await send('Page.addScriptToEvaluateOnNewDocument',{source:
    "window.scriptPolicyViolations=[];document.addEventListener('securitypolicyviolation',e=>{if(e.effectiveDirective.startsWith('script-src'))window.scriptPolicyViolations.push(e.effectiveDirective);});"});
  await send('Page.navigate',{url:endpoint+'/'});
  await waitFor(()=>evaluate("document.readyState==='complete' && typeof doPasskeyLogin==='function'"),'CryptIRC login page');
  await send('WebAuthn.enable');
  const {authenticatorId}=await send('WebAuthn.addVirtualAuthenticator',{options:{
    protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,
    automaticPresenceSimulation:true,isUserVerified:true
  }});
  const close=async()=>{
    process.kill(-chrome.pid,'SIGTERM');
    await waitFor(()=>chrome.exitCode!==null||chrome.signalCode!==null,'browser exited before reopening its profile');
    children.splice(children.indexOf(chrome),1);
    await fs.rm(path.join(tmp,profile,'DevToolsActivePort'),{force:true});
  };
  const reopen=(clockOffsetMs=0)=>chromium(profile,endpoint,clockOffsetMs);
  const relaunch=async()=>{await close();return reopen();};
  return {send,evaluate,authenticatorId,errors,frames,deliveryNotices,chrome,close,reopen,relaunch};
}

async function checkComposerEncryption(browser, id, observer) {
  const {evaluate:ev,send:cdp}=browser;
  const q=JSON.stringify, view=`${q(id)},${q(channel)}`;
  const field="document.getElementById('msg-input')";
  const panel="document.getElementById('composer-encryption-status')";
  const shown=`${panel}.classList.contains('show')`;
  const status="document.getElementById('composer-encryption-status-text').textContent";
  const action="document.getElementById('composer-encryption-action')";
  const inputDrafts=`${shown}&&${field}.value===`;
  const simulatePhone=send=>send('Emulation.setDeviceMetricsOverride',{
    width:390,height:844,deviceScaleFactor:1,mobile:true,
  });
  const tap=async({evaluate,send},selector)=>{
    const point=await evaluate(`(()=>{const r=${selector}.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);
    await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[point]});
    await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
  };
  const draft='held for encryption check '+stamp;
  const wire=()=>browser.frames.map(JSON.parse).filter(f=>f.type==='send'&&f.raw?.includes(draft));
  const received=()=>observer.events.filter(e=>e.type==='irc_message'&&e.text===draft);
  const holdSettings=async()=>ev(`window.composerGate={before:ws,events:[],handle:e2eHandleEvent};
    e2eHandleEvent=async event=>{
      if(event.type==='e2e_keyring'){composerGate.events.push(event);return;}
      return composerGate.handle(event);
    };
    ws.close();`);
  const releaseSettings=async()=>ev(`(async()=>{
    e2eHandleEvent=composerGate.handle;
    for(const event of composerGate.events) await e2eHandleEvent(event);
    delete window.composerGate;
  })()`);
  await simulatePhone(cdp);
  await holdSettings();
  await waitFor(()=>ev('ws!==composerGate.before&&_wsReady()&&E2E._vaultUp&&!E2E._krReceived'),
    'browser reconnects before receiving encryption settings');
  await ev(`setActive(${view});${field}.value=${q(draft)}`);
  const sendButton="document.getElementById('send-btn')";
  await tap(browser,sendButton);
  await waitFor(()=>ev(`${inputDrafts}${q(draft)}&&${status}===${q(`Checking encryption settings for ${channel}…`)}`),
    'mobile composer shows the encryption check below the draft');
  await waitFor(()=>ev('composerGate.events.length>0'),'real test server replies to the keyring request');
  await ev(`${field}.dispatchEvent(new InputEvent('beforeinput',{inputType:'insertLineBreak',bubbles:true,cancelable:true}))`);
  check('repeated mobile Send keeps one inline status and no IRC traffic or error rows',
    await ev(`${inputDrafts}${q(draft)}&&
      ${panel}.getBoundingClientRect().top>=${field}.getBoundingClientRect().bottom&&
      !getBuf(${view}).some(m=>String(m.text).includes('E2E status for this account is not known'))`)&&
    !wire().length&&!received().length);
  await waitFor(()=>ev(`${inputDrafts}${q(draft)}&&${status}.startsWith('Encryption check timed out.')&&${action}.textContent==='Retry'`),
    'timed out check keeps the same draft and shows Retry',12000);
  check('the timeout leaves the draft private and shows a phone-sized Retry button',
    !wire().length&&!received().length&&await ev(`${action}.getBoundingClientRect().height>=44`));
  await releaseSettings();
  await waitFor(()=>ev('E2E._krReceived'),'encryption settings finish loading');
  check('a late keyring reply does not automatically send the timed-out draft',!wire().length&&!received().length);
  await tap(browser,action);
  await waitFor(()=>received().length>0&&wire().length>0,
    'Retry sends the saved draft and DevTools records its frame');
  check('Retry delivered the draft once and cleared the inline status',wire().length===1&&
    await ev(`!${shown}&&${field}.value===''`));

  const sending='one confirmed send '+stamp;
  await waitFor(()=>ev('!_sendLock'),'Retry has finished processing');
  await ev(`window.composerSendGate={prepare:_prepChatPart,calls:0};
    _prepChatPart=async (...args)=>{
      if(args[2]===${q(sending)}&&++composerSendGate.calls===1)
        await new Promise(resolve=>{composerSendGate.resume=resolve;});
      return composerSendGate.prepare(...args);
    };
    ${field}.value=${q(sending)};${sendButton}.click();`);
  await waitFor(()=>ev('composerSendGate.calls===1'),'the composer is preparing an ordinary IRC send');
  await ev(`${field}.dispatchEvent(new InputEvent('beforeinput',{inputType:'insertLineBreak',bubbles:true,cancelable:true}))`);
  check('keyboard Send cannot resubmit the same draft while a tap is still pending',await ev('composerSendGate.calls===1'));
  await ev(`setActive(${q(id)},'status');setActive(${view});
    ${field}.dispatchEvent(new InputEvent('beforeinput',{inputType:'insertLineBreak',bubbles:true,cancelable:true}));`);
  check('switching away and back does not allow a second send of an in-flight draft',await ev('composerSendGate.calls===1'));
  await ev(`setActive(${q(id)},'status');
    _prepChatPart=composerSendGate.prepare;composerSendGate.resume();`);
  await waitFor(()=>observer.events.some(e=>e.type==='irc_message'&&e.text===sending),
    'the first send reaches the original channel after navigation');
  check('a completed send clears its old draft after switching conversations',
    await ev(`${field}.value===''&&active.target==='status'`));

  const slot=`_e2eScopedPskSlot(${q(channel)},${q(id)})`;
  await ev('void e2ePromptDeviceUnlock()');
  const recoveryCode=await setUpRecovery(browser,waitFor,check);

  const reconnectDraft='held during encryption resync '+stamp;
  const frameCount=browser.frames.length;
  await holdSettings();
  await waitFor(()=>ev('ws!==composerGate.before&&_wsReady()&&E2E.keyReady&&E2E._resyncPending'),
    'previously unlocked device reconnects with encryption resync pending');
  await ev(`setActive(${view});${field}.value=${q(reconnectDraft)};${sendButton}.click()`);
  await waitFor(()=>ev(`${inputDrafts}${q(reconnectDraft)}&&${status}.startsWith('Checking encryption settings')&&composerGate.events.length`),
    'unlocked device shows Checking while reconnecting');
  await ev(`setActive(${q(id)},'status');setActive(${view})`);
  check('switching conversations clears the status without discarding the draft',
    await ev(`!${shown}&&${field}.value===${q(reconnectDraft)}`));
  await waitFor(()=>ev('!_sendLock'),'touch send guard has cleared');
  await ev(`${sendButton}.click()`);
  await waitFor(()=>ev(shown),'trying again opens a new inline check');
  await ev(`${field}.value+=' edited';${field}.dispatchEvent(new InputEvent('input',{bubbles:true}));`);
  await releaseSettings();
  await waitFor(()=>ev('E2E.keyReady&&!E2E._resyncPending'),'ready device completes its real reconnect');
  check('editing while waiting cancels the old status and sends neither version of the draft',
    await ev(`!${shown}&&${field}.value===${q(reconnectDraft+' edited')}`)&&
    !browser.frames.slice(frameCount).map(JSON.parse).some(f=>f.type==='send'&&f.raw?.startsWith('PRIVMSG '+channel+' :')));

  const requestNick='verify'+stamp, requestKey=`_e2eDmKey(${q(requestNick)},${q(id)})`;
  const mobilePm='one mobile tap to plaintext '+stamp;
  await cdp('Emulation.setTouchEmulationEnabled',{enabled:true});
  await ev(`setActive(${q(id)},'status');${field}.value='';${field}.blur();openSidebar();
    window.mobileTrust={result:null};
    void _e2eAskIdentity(${requestKey},'test-fingerprint','Verify test identity',false,${q(id)})
      .then(answer=>mobileTrust.result=answer);`);
  check('the initial identity question is visible while the mobile drawer is open',
    await ev("!!document.getElementById('e2e-id-dialog')&&document.getElementById('sidebar').classList.contains('open')"));
  await ev(`setActive(${q(id)},${q(other)});${field}.value=${q(mobilePm)};${field}.focus()`);
  check('opening a different private chat leaves Send reachable and preserves the pending trust decision',
    await ev(`(()=>{const r=${sendButton}.getBoundingClientRect();
      return ${sendButton}.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2))&&
      !document.getElementById('e2e-id-dialog')&&!document.getElementById('sidebar').classList.contains('open')&&
      mobileTrust.result===null&&!E2E.trustStore[${requestKey}];})()`));
  await tap(browser,sendButton);
  await waitFor(()=>observer.events.some(e=>e.type==='irc_message'&&e.text===mobilePm),
    'one touch sends the ordinary PM over IRC');
  check('the touch sends plaintext exactly once and clears the composer',
    browser.frames.map(JSON.parse).filter(f=>f.type==='send'&&f.raw===`PRIVMSG ${other} :${mobilePm}`).length===1&&
    await ev(`${field}.value===''&&!${shown}&&mobileTrust.result===null`));
  await ev(`setActive(${q(id)},${q(requestNick)});document.getElementById('e2e-id-cancel').click()`);
  await waitFor(()=>ev('mobileTrust.result===false'),'the original trust request is reviewable in its own PM');
  check('Cancel leaves the original identity untrusted',await ev(`!E2E.trustStore[${requestKey}]`));

  const channelRequest='channelverify'+stamp;
  await ev(`setActive(${view});${field}.value='unfinished channel message';${field}.focus();
    mobileTrust.channelResult=null;
    void _e2eAskIdentity(_e2eDmKey(${q(channelRequest)},${q(id)}),'other-fingerprint','Review in PM',false,${q(id)})
      .then(answer=>mobileTrust.channelResult=answer);`);
  check('an incoming identity request leaves a channel draft and its focus intact',
    await ev(`!document.getElementById('e2e-id-dialog')&&document.activeElement===${field}&&mobileTrust.channelResult===null`));
  await ev(`setActive(${q(id)},${q(channelRequest)});document.getElementById('e2e-id-cancel').click();${field}.value=''`);
  await waitFor(()=>ev('mobileTrust.channelResult===false'),'the deferred channel-time request can be reviewed in its PM');

  await ev(`(async()=>{const generated=await generateChannelKey();
    await storeChannelKey(${slot},generated.key,generated.keyB64);})()`);
  await waitFor(()=>ev(`_e2eReq({type:'e2e_load_keyring'},'e2e_keyring').then(event=>event?.channels?.includes(${slot}))`),
    'the test server has recorded the shared channel key');
  const locked=await chromium('composer-without-cached-key');
  await simulatePhone(locked.send);
  await locked.evaluate(`window.composerCache={read:_e2eIdbGetKey,started:false};
    _e2eIdbGetKey=async (...args)=>{
      composerCache.started=true;
      await new Promise(resolve=>{composerCache.resume=resolve;});
      return composerCache.read(...args);
    };`);
  await login(locked,owner,password,waitFor);
  await locked.evaluate(`if(!E2E._vaultUp){document.getElementById('vault-pass').value=${q(vault)};doUnlock();}`);
  const restoring=()=>locked.evaluate(`({lookup:composerCache.started,inventory:E2E._krReceived,
    key:E2E._serverHints?.channels.includes(${slot}),network:networks.some(n=>n.config.id===${q(id)}&&n.connected),phase:E2E._bootPhase})`);
  try{
    await waitFor(async()=>{const s=await restoring();return s.lookup&&s.inventory&&s.key&&s.network;},
      'fresh browser is restoring its saved key');
  }catch(error){throw new Error(error.message+' '+JSON.stringify(await restoring()));}
  const encryptedDraft='held for saved channel key '+stamp;
  const count=observer.events.length;
  await locked.evaluate(`setActive(${view});${field}.value=${q(encryptedDraft)};${sendButton}.click()`);
  check('a known encrypted channel shows Loading while the device key lookup is pending',await locked.evaluate(
    `${inputDrafts}${q(encryptedDraft)}&&${status}==='Loading your encryption key…'&&${action}.hidden`));
  await locked.evaluate(`_e2eIdbGetKey=composerCache.read;composerCache.resume();`);
  await waitFor(()=>locked.evaluate(`${inputDrafts}${q(encryptedDraft)}&&${status}==='Unlock encrypted chats to send.'&&${action}.textContent==='Unlock'`),
    'a fresh device with no cached key offers Unlock');
  check('a locked encrypted channel keeps the draft out of IRC',
    !observer.events.slice(count).some(e=>e.type==='irc_message'&&e.from===owner&&e.target===channel));
  await locked.evaluate(`insertEmoji('🙂')`);
  check('using the emoji picker changes the draft and dismisses its old Unlock status',
    await locked.evaluate(`!${shown}&&${field}.value.includes('🙂')`));
  await waitFor(()=>locked.evaluate('!_sendLock'),'the locked composer has finished processing Send');
  await locked.evaluate(`${field}.value=${q(encryptedDraft)};${sendButton}.click()`);
  await waitFor(()=>locked.evaluate(`${inputDrafts}${q(encryptedDraft)}&&${action}.textContent==='Unlock'`),
    'sending the current draft offers Unlock again');
  await tap(locked,action);
  await waitFor(()=>locked.evaluate("document.getElementById('custom-prompt-overlay').classList.contains('open')&&document.getElementById('custom-prompt-msg').textContent.includes('Enter your E2E recovery code')"),
    'Unlock opens the recovery code prompt');
  await locked.evaluate(`document.getElementById('custom-prompt-input').value=${q(recoveryCode)};
    document.getElementById('custom-prompt-ok').click();`);
  await waitFor(()=>locked.evaluate(`E2E._bootPhase==='ready'&&e2eTargetState(${q(channel)},{conn_id:${q(id)}}).mode==='psk'`),
    'unlock restores the actual shared channel key');
  check('Unlock leaves the encrypted channel draft in the composer',await locked.evaluate(`${field}.value===${q(encryptedDraft)}`));
  await tap(locked,sendButton);
  await waitFor(()=>observer.events.slice(count).some(e=>e.type==='irc_message'&&e.from===owner&&e.target===channel&&e.text?.startsWith('sd8~')),
    'sending after unlock relays a shared-key ciphertext to the IRC peer');
  check('sending after unlock clears the draft, with no cleartext on the IRC relay',
    await locked.evaluate(`${field}.value===''&&!${shown}`)&&
    !observer.events.slice(count).some(e=>e.type==='irc_message'&&e.text===encryptedDraft));
  check('no unhandled browser errors during encryption status tests',!(browser.errors.length||locked.errors.length));
}

let rpcId=0;
const rpc=(token,method,params={},headers={})=>request('/mcp',{method:'POST',token,headers:{
  Accept:'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25',...headers
},body:{jsonrpc:'2.0',id:++rpcId,method,params}});

async function tool(token,name,args={},wantError=false) {
  const res=await rpc(token,'tools/call',{name,arguments:args});
  assert.equal(res.status,200,name);
  const result=res.data.result;
  assert(result,name+' returned a JSON-RPC error');
  assert.equal(!!result.isError,wantError,name+': '+(result.isError?result.content[0].text:'unexpected success'));
  return wantError?result.content[0].text:result.structuredContent;
}

async function legacyObserver(nick) {
  const login=await request('/auth/login',{method:'POST',body:{username:nick,password}});
  assert.equal(login.status,200);
  return connectWebsocket(login.data.token);
}

async function legacyContact(browser,nick,identity) {
  const observer=await legacyObserver(nick);
  const label='Legacy Signal testnet';
  observer.send({type:'add_network',network:{id:crypto.randomUUID(),label,server:'127.0.0.1',port:Number(IRC_PORT),
    tls:false,tls_accept_invalid_certs:false,nick,username:nick,realname:'Legacy Signal fixture',
    auto_join:[],sasl_external:false,auto_reconnect:false}});
  const state=await observer.wait(e=>e.type==='state'&&e.networks.some(n=>n.config.label===label),'old browser IRC network');
  const id=state.networks.find(n=>n.config.label===label).config.id;
  observer.send({type:'connect',id});
  await observer.wait(e=>e.type==='connected'&&e.conn_id===id,'old browser IRC registration');
  await waitFor(()=>browser.evaluate(`networks.some(n=>n.config.id===${JSON.stringify(id)})`),'old browser sees connected IRC network');
  const origin=await browser.evaluate('performance.timeOrigin');
  return {browser,nick,identity,observer,id,origin};
}

async function legacyCompose(from,to,text) {
  await from.browser.evaluate(`setActive(${JSON.stringify(from.id)},${JSON.stringify(to.nick)});
    document.getElementById('msg-input').focus();document.getElementById('msg-input').value=${JSON.stringify(text)};`);
  await from.browser.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await from.browser.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
}

async function legacyAccept(from,to) {
  await waitFor(()=>from.browser.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"),'old browser identity confirmation');
  const verified=await from.browser.evaluate(`(async()=>{
    const fp=await computeIdentityFingerprint(...${JSON.stringify(to.identity)});
    const dialog=document.getElementById('e2e-id-dialog');
    if(!dialog.textContent.includes(fp)||!dialog.textContent.includes(${JSON.stringify(to.nick)}))return false;
    dialog.querySelector('#e2e-id-accept').click();return true;
  })()`);
  check('the previous release confirms the other real browser identity',verified);
}

const legacyRow=(device,peer,text)=>device.browser.evaluate(
  `getBuf(${JSON.stringify(device.id)},${JSON.stringify(peer.nick)}).some(m=>m.text===${JSON.stringify(text)})`);
const legacyWire=(frame,nick)=>frame.type==='send'&&frame.raw.startsWith('PRIVMSG '+nick+' :[e2edm2]')
  ?frame.raw.slice(frame.raw.indexOf(' :')+2):null;

async function checkLegacyDelivery(from,to,text) {
  const sent=from.browser.frames.length,received=to.observer.events.length,notices=from.browser.deliveryNotices.length;
  await legacyCompose(from,to,text);
  const wire=await waitFor(()=>from.browser.frames.slice(sent).map(f=>legacyWire(JSON.parse(f),to.nick)).find(Boolean),
    'previous browser hands an ordinary encrypted PM to its authenticated web socket');
  const seen=event=>event.type==='irc_message'&&event.conn_id===to.id&&event.from===from.nick;
  const refusal=()=>from.browser.deliveryNotices.slice(notices).find(e=>e.conn_id===from.id&&e.target===to.nick&&/not sent|blocked/i.test(e.text));
  await waitFor(()=>to.observer.events.slice(received).some(e=>seen(e)&&e.text===wire)||refusal(),
    'actual IRC relay or a specific delivery refusal');
  const delivered=to.observer.events.slice(received).filter(e=>seen(e)&&e.text===wire).length;
  const clear=to.observer.events.slice(received).some(e=>seen(e)&&e.text===text);
  const opened=delivered>0&&await waitFor(()=>legacyRow(to,from,text),'old peer reads the genuine ciphertext');
  console.log('LEGACY-SIGNAL-HANDOFF',JSON.stringify({text,delivered,clear,opened:!!opened,refused:!!refusal(),reason:refusal()?.text}));
  check('one genuine old-browser Signal message reaches its peer and opens',delivered===1&&opened&&!clear);
}

async function prepareLegacyHandoff(browser,nick,legacy) {
  const peerNick='plp'+stamp;
  check('second old-release account registered',(await request('/auth/register',{method:'POST',body:{username:peerNick,password}})).status===200);
  const peerBrowser=await chromium('e2e-old-peer');
  const peerLegacy=await seedLegacyE2e({browser:peerBrowser,waitFor,check,tmp,user:peerNick,password,vault,channel});
  const sender=await legacyContact(browser,nick,legacy.identity),peer=await legacyContact(peerBrowser,peerNick,peerLegacy.identity);
  await legacyCompose(sender,peer,'/encrypt on '+peer.nick);
  await legacyAccept(sender,peer);
  await waitFor(()=>browser.evaluate('Object.values(E2E.dmSessions).some(session=>!!session?.RK)'),
    'genuine legacy outgoing ratchet');
  const first='archived browser handshake '+stamp;
  await legacyCompose(sender,peer,first);
  await legacyAccept(peer,sender);
  await waitFor(()=>legacyRow(peer,sender,first),'genuine encrypted handshake reaches the old peer');
  await checkLegacyDelivery(peer,sender,'archived browser encrypted reply '+stamp);
  for(const device of [sender,peer])device.beforeRestart=device.browser.frames.length;
  return {sender,peer};
}

async function stageLegacyHandoff({sender,peer}) {
  for(const device of [sender,peer]){
    const connected=()=>device.browser.frames.slice(device.beforeRestart).map(f=>JSON.parse(f)).some(m=>m.type==='auth'&&m.e2e===2);
    const status=()=>device.browser.evaluate(`({same:performance.timeOrigin===${device.origin},ready:_wsReady(),identity:!!E2E.identityReady,
      phase:E2E._bootPhase,signIn:getComputedStyle(document.getElementById('auth-screen')).display!=='none'})`);
    try {
      await waitFor(async()=>{const s=await status();return connected()&&(s.ready||s.signIn);},'cached browser reconnect or sign-in form',30000);
      if(!(await status()).ready){
        await device.browser.evaluate(`document.getElementById('l-user').value=${JSON.stringify(device.nick)};
          document.getElementById('l-pass').value=${JSON.stringify(password)};doLogin()`);
        await waitFor(async()=>(await status()).ready,'the same old document signs back in');
      }
      check('cached browser reconnected with its old protocol and original document',(await status()).same);
      await device.browser.evaluate(`document.getElementById('vault-pass').value=${JSON.stringify(vault)};doUnlock()`);
      await waitFor(async()=>(await status()).identity,'previously unlocked legacy identity is ready after reconnection');
    }catch(error){console.error('LEGACY-RECONNECT',await status(),{oldAuth:connected()});throw error;}
    device.observer=await legacyObserver(device.nick);
  }
  await checkLegacyDelivery(sender,peer,'replacement web before account recovery '+stamp);
  // Delay one fully formed browser frame at its final transport boundary.
  // The same authenticated socket will hand it to the web process after migration.
  await sender.browser.evaluate(`(()=>{
    const socket=ws,write=socket.send;
    socket.send=function(data){
      const frame=JSON.parse(data);
      if(frame.type==='send'&&frame.raw.startsWith(${JSON.stringify('PRIVMSG '+peer.nick+' :[e2edm2]')})){
        socket.send=write;
        window.releaseLegacySignal=()=>{
          if(ws!==socket||socket.readyState!==WebSocket.OPEN)return false;
          write.call(socket,data);return true;
        };
        return;
      }
      return write.call(socket,data);
    };
  })()`);
  await legacyCompose(sender,peer,'old pending message across recovery '+stamp);
  await waitFor(()=>sender.browser.evaluate("typeof window.releaseLegacySignal==='function'"),'the cached client has a genuine pending encrypted send');
}

async function checkMigratedHandoff({sender,peer}) {
  const before=sender.browser.frames.length,notices=sender.browser.deliveryNotices.length,received=peer.observer.events.length;
  check('the sender still has its original document and socket',await sender.browser.evaluate(
    `performance.timeOrigin===${sender.origin}&&_wsReady()`));
  check('the authenticated socket from before migration is still open',await sender.browser.evaluate(
    '(()=>{const sent=window.releaseLegacySignal();delete window.releaseLegacySignal;return sent;})()'));
  const wire=await waitFor(()=>sender.browser.frames.slice(before).map(f=>legacyWire(JSON.parse(f),peer.nick)).find(Boolean),
    'the same old browser submits the genuine held ciphertext after migration');
  const refusal=await waitFor(()=>sender.browser.deliveryNotices.slice(notices).find(e=>e.conn_id===sender.id&&e.target===peer.nick&&
    /reload cryptirc to use encrypted chat/i.test(e.text)),'old sender receives the conversation-specific reload instruction');
  const barrier=await ordinaryIrcClient(IRC_PORT,'plb'+stamp);
  const mark='after old browser refusal '+stamp;
  barrier.send('PRIVMSG '+peer.nick+' :'+mark);
  await peer.observer.wait(e=>e.type==='irc_message'&&e.from==='plb'+stamp&&e.text===mark,'IRC recipient receives a subsequent independent message');
  barrier.close();
  const arrivals=peer.observer.events.slice(received).filter(e=>e.type==='irc_message'&&e.conn_id===peer.id&&e.from===sender.nick);
  check('the authenticated old browser is refused after upgrade and the IRC peer receives neither wire nor cleartext',
    refusal&&arrivals.every(e=>e.text!==wire&&e.text!=='old pending message across recovery '+stamp)&&
    !await legacyRow(peer,sender,'old pending message across recovery '+stamp));
}

async function runIntegration() {
  if(translationEnabled)translator=await startTranslator();
  await fs.writeFile(path.join(tmp,'admin_settings.json'),JSON.stringify({registration_open:true,captcha_enabled:false}));
  const core=start(CRYPTIRC_CORE_BIN,[],env);
  await waitFor(()=>fs.stat(path.join(tmp,'irc-core.sock')).catch(()=>null),'isolated IRC core');
  if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='divergent-web-upgrade'){
    const {checkDivergentWebUpgrade}=await import('./signal-upgrade-checks.mjs');
    const stop=async child=>{
      process.kill(-child.pid,'SIGTERM');
      await waitFor(()=>child.exitCode!==null||child.signalCode!==null,'disposable process exited');
      children.splice(children.indexOf(child),1);
    };
    await checkDivergentWebUpgrade({core,base,env,tmp,owner,other,password,vault,stamp,start,stop,allocatePort,
      request,chromium,connectWebsocket,waitFor,check});
    return;
  }
  const fixtureIpcPath=path.join(tmp,'reaction-gate.sock');
  const delayOwnEcho=process.env.CRYPTIRC_TEST_SIGNAL_ECHO_DELAY==='1';
  const reactionGate=reactionMidpoint||delayOwnEcho?await reactionIpcGate(path.join(tmp,'irc-core.sock'),fixtureIpcPath):null;
  const webEnv=reactionGate?{...env,CRYPTIRC_IPC_SOCK:fixtureIpcPath}:env;
  const waitWeb=()=>waitFor(()=>fetch(base+'/auth/status').then(r=>r.ok).catch(()=>false),'isolated web server');
  const legacyUser='pkl'+stamp;
  let legacy,legacyPair;
  if(e2eEnabled&&legacyBin){
    const oldWeb=start(legacyBin,[],env);
    await waitWeb();
    check('legacy migration fixture account registered',(await request('/auth/register',{
      method:'POST',body:{username:legacyUser,password}
    })).status===200);
    const oldBrowser=await chromium('e2e-old-release');
    legacy=await seedLegacyE2e({browser:oldBrowser,waitFor,check,tmp,user:legacyUser,password,vault,channel});
    if(legacySignalHandoff)legacyPair=await prepareLegacyHandoff(oldBrowser,legacyUser,legacy);
    for(const child of (legacyPair?[oldWeb]:[oldBrowser.chrome,oldWeb])){
      process.kill(-child.pid,'SIGTERM');
      await waitFor(()=>child.exitCode!==null||child.signalCode!==null,'old test process exited');
      children.splice(children.indexOf(child),1);
    }
  }
  let web=start(CRYPTIRC_BIN,[],webEnv);
  await waitWeb();
  const checkPagePolicy=async route=>{
    const response=await fetch(base+route);
    const scriptPolicy=response.headers.get('content-security-policy').split(';').map(v=>v.trim()).find(v=>v.startsWith('script-src '));
    const nonce=scriptPolicy.match(/'nonce-([^']+)'/)[1];
    const html=await response.text();
    check('protected page has a nonce and disallows inline handlers '+route,
      !scriptPolicy.includes("'unsafe-inline'") &&
      response.headers.get('content-security-policy').includes("script-src-attr 'none'") &&
      html.includes('<script nonce="'+nonce+'">'));
    return nonce;
  };
  const mainNonce=await checkPagePolicy('/');
  check('page script nonce changes across responses',mainNonce!==await checkPagePolicy('/'));
  await checkPagePolicy('/auth/reset?token=fixture');
  if(legacy){
    if(legacyPair)await stageLegacyHandoff(legacyPair);
    const migrationBrowser=await chromium('e2e-migration');
    await checkLegacyMigration({browser:migrationBrowser,waitFor,check,tmp,user:legacyUser,password,vault,channel,legacy});
    if(legacyPair){await checkMigratedHandoff(legacyPair);return;}
  }
  for(const username of [owner,other]){
    const res=await request('/auth/register',{method:'POST',body:{username,password}});
    check('disposable test account registered',res.status===200);
  }
  if(e2eEnabled){
    const record=path.join(tmp,'users',owner+'.json');
    const account=JSON.parse(await fs.readFile(record,'utf8'));
    await fs.writeFile(record,JSON.stringify({...account,can_upload:true}),{mode:0o600});
  }
  const browser=await chromium();
  const {evaluate:ev,send:cdp}=browser;
  const fill=(id,value)=>ev('document.getElementById('+JSON.stringify(id)+').value='+JSON.stringify(value));
  await fill('l-user',owner);
  await fill('l-pass',password);
  check('all static page controls have native handlers',await ev(`Array.from(document.querySelectorAll('*')).every(control=>
    control.getAttributeNames().every(attr=>!attr.startsWith('data-cryptirc-')||
      typeof control['on'+attr.slice('data-cryptirc-'.length)]==='function'))`));
  await ev("document.getElementById('login-btn').click()");
  await waitFor(()=>ev('sessionToken'),'login button under script CSP');
  let ownerSession=await ev('sessionToken');
  check('normal login works alongside passkeys',!!ownerSession);
  const fileName='download-fixture.txt';
  await fs.writeFile(path.join(tmp,'uploads',fileName),'download fixture');
  const fileUrl=base+'/files/'+fileName;
  check('downloads refuse URL session tokens',
    (await fetch(fileUrl+'?token='+encodeURIComponent(ownerSession))).status===401);
  for(const headers of [{Authorization:'Bearer '+ownerSession},{Cookie:'cryptirc_token='+ownerSession}]){
    const download=await fetch(fileUrl,{headers});
    check('downloads accept '+Object.keys(headers)[0]+' authentication',
      download.ok && await download.text()==='download fixture');
  }
  check('passkey sign-in button is available',await ev("!document.getElementById('passkey-login-btn').hidden"));
  await ev("(()=>{const real=window.fetch.bind(window);window.testPasskeyRequests={};window.fetch=(url,opt)=>{const u=String(url);if(u.includes('/passkeys/')&&u.endsWith('/finish'))window.testPasskeyRequests[u.split('/').at(-2)]=JSON.parse(opt.body);return real(url,opt);};})()");
  await waitFor(()=>ev("_wsReady() && !document.getElementById('vault-unlock-banner').hidden"),'initial WebSocket vault state');
  check('a cold vault shows an unlock button without opening a password prompt',
    await ev("!document.getElementById('vault-overlay').classList.contains('show')"));
  await ev("document.querySelector('[data-cryptirc-click=openEncryptionSettings]').click();"+
    "document.querySelector('#encrypt-panel-body [data-encrypt-cmd=unlock]').click()");
  check('Encryption settings can explicitly request a cold vault unlock',
    await ev("document.getElementById('vault-overlay').classList.contains('show') && !document.getElementById('vault-unlock-later').hidden"));
  await ev("document.getElementById('vault-unlock-later').click();closeEncryptPanel()");
  check('choosing Later leaves the vault locked and returns to the app',
    await ev("_vaultNeedsUnlock && !document.getElementById('vault-overlay').classList.contains('show')"));
  check('an explicit vault unlock is in front of Encryption when Later is unavailable', await ev(`(() => {
    const overlay = document.getElementById('vault-overlay');
    const wasUnlocked = _vaultWasUnlocked;
    try {
      _vaultWasUnlocked = true;
      document.querySelector('[data-cryptirc-click=openEncryptionSettings]').click();
      document.querySelector('#encrypt-panel-body [data-encrypt-cmd=unlock]').click();
      const input = document.getElementById('vault-pass');
      const {x, y, width, height} = input.getBoundingClientRect();
      return document.getElementById('vault-unlock-later').hidden &&
        document.activeElement === input && document.elementFromPoint(x+width/2, y+height/2) === input;
    } finally {
      overlay.classList.remove('show', 'on-demand');
      closeEncryptPanel();
      _vaultWasUnlocked = wasUnlocked;
      _vaultUnlockForEncryption = false;
    }
  })()`));
  await ev('showProfilePanel()');
  await waitFor(()=>ev("!!document.getElementById('profile-passkey-add')"),'passkey profile card');
  const ownHeaders={Origin:origin};
  const denied=await request('/auth/passkeys/register/start',{method:'POST',token:ownerSession,
    headers:{Origin:'https://unrelated.example'},body:{name:'bad',password}});
  check('cross-origin passkey registration denied',denied.status===403);
  check('passkey enrollment requires the real password',(await request('/auth/passkeys/register/start',{
    method:'POST',token:ownerSession,headers:ownHeaders,body:{name:'bad',password:'wrong'}
  })).status===401);
  await fill('profile-passkey-name','Arch virtual passkey');
  await fill('profile-passkey-password',password);
  await ev("document.getElementById('profile-passkey-add').click()");
  await waitFor(()=>ev("!!document.querySelector('[data-passkey-id]')"),'register passkey from profile');
  const passkeys=await request('/auth/passkeys',{token:ownerSession});
  check('profile stores one named passkey',passkeys.data.passkeys.length===1 && passkeys.data.passkeys[0].name==='Arch virtual passkey');
  const registered=await ev('window.testPasskeyRequests.register');
  check('registration challenge replay refused',(await request('/auth/passkeys/register/finish',{
    method:'POST',token:ownerSession,headers:ownHeaders,body:registered
  })).status===400);

  await waitFor(()=>ev("!!document.getElementById('profile-mcp-create')"),'MCP profile card');
  await fill('profile-mcp-password',password);
  await ev("document.getElementById('profile-mcp-create').click()");
  const token=await waitFor(()=>ev("document.querySelector('#profile-mcp input[value^=cryptirc_mcp_]')?.value"),'MCP token creation');
  check('web session is rejected at MCP endpoint',(await rpc(ownerSession,'ping')).status===401);
  check('MCP token cannot sign in to the web app',(await request('/auth/me',{token})).status===401);
  check('MCP rejects cross-origin browser requests',(await rpc(token,'ping',{},{Origin:'https://unrelated.example'})).status===403);
  check('MCP rejects unknown protocol versions',(await rpc(token,'ping',{}, {'MCP-Protocol-Version':'1'})).status===400);
  check('stateless MCP offers only POST',(await request('/mcp',{token})).status===405);
  const initial=await rpc(token,'initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'arch-test',version:'1'}});
  check('MCP negotiates supported version and tools',initial.data.result.protocolVersion==='2025-11-25'&&!!initial.data.result.capabilities.tools);
  const notification=await request('/mcp',{method:'POST',token,body:{jsonrpc:'2.0',method:'notifications/initialized'}});
  check('MCP accepts initialized notification without body',notification.status===202&&notification.data===null);
  if(process.env.MCP_SDK_ESM){
    const entry=pathToFileURL(process.env.MCP_SDK_ESM+'/');
    const {Client}=await import(new URL('client/index.js',entry));
    const {StreamableHTTPClientTransport}=await import(new URL('client/streamableHttp.js',entry));
    const client=new Client({name:'arch-sdk-test',version:'1'});
    const transport=new StreamableHTTPClientTransport(new URL(base+'/mcp'),{
      requestInit:{headers:{Authorization:'Bearer '+token}}
    });
    try {
      await client.connect(transport);
      check('official MCP SDK discovers tools',(await client.listTools()).tools.length===11);
      check('official MCP SDK calls a tool',(await client.callTool({name:'irc_state',arguments:{}})).structuredContent.account===owner);
    } finally {
      await client.close();
    }
  }
  const available=(await rpc(token,'tools/list')).data.result.tools;
  check('MCP advertises all eleven tools with schemas',available.length===11&&available.every(t=>t.inputSchema.type==='object'));
  check('MCP rejects unknown method',(await rpc(token,'not_a_method')).data.error.code===-32601);
  check('MCP exposes a locked vault as locked',(await tool(token,'irc_state')).vault_unlocked===false);
  check('MCP encrypted note does not unlock the vault',/unlock/i.test(await tool(token,'cryptirc_notepad',{},true)));
  check('MCP preferences follow the vault lock',/unlock/i.test(await tool(token,'cryptirc_settings',{section:'preferences'},true)));

  // Return the actual browser to the login screen and select the resident passkey
  // with the username field blank. Keep the CDP WebAuthn authenticator attached.
  await request('/auth/logout',{method:'POST',token:ownerSession});
  await ev("localStorage.removeItem('cryptirc_token');localStorage.removeItem('cryptirc_user');document.cookie='cryptirc_token=;path=/cryptirc;max-age=0';");
  const originTime=await ev('performance.timeOrigin');
  await cdp('Page.reload',{ignoreCache:true});
  await waitFor(async()=>{
    try{
      return await ev(`performance.timeOrigin>${originTime} && document.readyState==='complete' &&
        typeof doPasskeyLogin==='function' && !document.getElementById('passkey-login-btn')?.hidden`);
    }catch(error){
      if(/Inspected target navigated|Execution context was destroyed|Cannot find context/.test(error.message))return false;
      throw error;
    }
  },'passkey login page');
  await ev("(()=>{const real=window.fetch.bind(window);window.fetch=(url,opt)=>{if(String(url).endsWith('/passkeys/login/finish'))window.lastAssertion=JSON.parse(opt.body);return real(url,opt);};})()");
  await ev("document.getElementById('passkey-login-btn').click()");
  ownerSession=await waitFor(()=>ev("typeof sessionToken!=='undefined' && sessionToken"),'resident passkey sign-in');
  check('passkey signs in with an empty username field',await ev('currentUser=== '+JSON.stringify(owner)));
  const assertion=await ev('window.lastAssertion');
  check('assertion replay is refused',(await request('/auth/passkeys/login/finish',{
    method:'POST',headers:ownHeaders,body:assertion
  })).status===401);
  check('passkey sign-in leaves the IRC vault locked',(await tool(token,'irc_state')).vault_unlocked===false);
  check('MCP key survives an ordinary web sign-out',(await rpc(token,'ping')).status===200);

  const second=await request('/auth/login',{method:'POST',body:{username:other,password}});
  let otherSession=second.data.token;
  const otherKeyRes=await request('/api/mcp/token',{method:'POST',headers:ownHeaders,token:otherSession,body:{password}});
  const otherKey=otherKeyRes.data.token;
  check('separate account can issue its own key',!!otherKey&&otherKey!==token);
  let ownerWs=await connectWebsocket(ownerSession);
  let otherWs=await connectWebsocket(otherSession);
  for(const ws of [ownerWs,otherWs]){
    ws.send({type:'unlock_vault',passphrase:vault});
    await ws.wait(e=>e.type==='vault_unlocked','test vault unlock');
  }

  const network=async (key,nick,port,label)=>{
    await tool(key,'irc_network',{action:'add',settings:{server:'127.0.0.1',port:Number(port),nick,
      label,tls:false,username:nick,realname:'CryptIRC test',auto_reconnect:false}});
    const state=await tool(key,'irc_state');
    const {id}=state.networks.find(n=>n.label===label);
    return id;
  };
  const networkA=await network(token,owner,IRC_PORT,'Hub');
  const networkB=await network(otherKey,other,IRC_LEAF_PORT||IRC_PORT,'Peer');
  const testPassword='dummy-network-secret-'+stamp;
  await tool(token,'irc_network',{action:'update',network:networkA,settings:{
    label:'Renamed hub',server:'localhost',realname:'MCP network settings test',
    password:testPassword,quit_message:'Testnet disconnect'
  }});
  check('MCP network edits appear in state',(await tool(token,'irc_state')).networks[0].label==='Renamed hub');
  const {settings:savedNetwork}=await tool(token,'irc_network',{action:'get',network:networkA});
  check('MCP reads edited network settings with credentials omitted',
    savedNetwork.server==='localhost'&&savedNetwork.realname==='MCP network settings test'&&
    savedNetwork.quit_message==='Testnet disconnect'&&!Object.hasOwn(savedNetwork,'password'));
  check('MCP cannot redirect inherited network credentials',/clear saved credentials/i.test(await tool(token,'irc_network',{
    action:'update',network:networkA,settings:{server:'127.0.0.1'}
  },true)));
  await tool(token,'irc_network',{action:'update',network:networkA,settings:{server:'127.0.0.1',password:null}});
  check('MCP cannot see a second account’s network',(await tool(token,'irc_state')).networks.every(n=>n.id!==networkB));
  check('MCP cannot read a second account’s history',/unknown network/i.test(await tool(token,'irc_history',{network:networkB,target:channel},true)));
  check('MCP cannot disconnect a second account',/unknown network/i.test(await tool(token,'irc_network',{action:'disconnect',network:networkB},true)));
  await tool(token,'irc_network',{action:'connect',network:networkA});
  await tool(otherKey,'irc_network',{action:'connect',network:networkB});
  await ownerWs.wait(e=>e.type==='connected'&&e.conn_id===networkA,'hub registration');
  await otherWs.wait(e=>e.type==='connected'&&e.conn_id===networkB,'peer registration');
  await tool(token,'irc_join',{network:networkA,channel});
  await ownerWs.wait(e=>['irc_join','irc_join_ex'].includes(e.type)&&e.channel===channel,'MCP join on hub');
  await tool(otherKey,'irc_join',{network:networkB,channel});
  await otherWs.wait(e=>['irc_join','irc_join_ex'].includes(e.type)&&e.channel===channel,'MCP join on peer');
  const phrase='MCP linked testnet '+stamp;
  for(const [target,text,kind] of [[channel,phrase,'message'],[other,'direct '+stamp,'notice'],[channel,'action '+stamp,'action']]){
    await tool(token,'irc_send',{network:networkA,target,text,kind});
    await otherWs.wait(e=>e.type==='irc_message'&&e.text.includes(text),kind+' received by a real IRC peer');
    check('MCP '+kind+' reached the IRC peer',true);
  }
  await ev("closeProfilePanel();document.getElementById('vault-pass').value="+JSON.stringify(vault)+";doUnlock()");
  await waitFor(()=>ev(`networks.some(n=>n.config.id===${JSON.stringify(networkA)}&&n.connected) &&
    !document.getElementById('vault-overlay').classList.contains('show')`),'browser websocket and vault');
  if(process.env.CRYPTIRC_TEST_INBOX_RECOVERY==='1'){
  await waitFor(()=>ev("E2E._krReceived&&E2E._vaultUp"),'test browser has encryption metadata');
  await ev("void e2ePromptDeviceUnlock()");
  await setUpRecovery(browser,waitFor,check);
  const q=JSON.stringify;
  const onlineNick='pml'+stamp, offlineNick='pmo'+stamp;
  const live=await ordinaryIrcClient(IRC_PORT,onlineNick);
  const absent=await ordinaryIrcClient(IRC_PORT,offlineNick);
  const inbox=(device,nick)=>device.evaluate(`_msgsConversations().some(c=>c.conn_id===${q(networkA)}&&c.lc===${q(nick)})`);
  const liveText='fresh PM while browser is connected '+stamp;
  const offlineText='fresh PM while browser is closed '+stamp;
  await ev("localStorage.setItem('cryptirc_block_pms','true');localStorage.setItem('cryptirc_pm_deliver_first','true');setActive(MSGS_CONN,MSGS_TARGET)");
  live.send('PRIVMSG '+owner+' :'+liveText);
  await waitFor(()=>inbox(browser,onlineNick),'first incoming PM adds its thread to Messages while online');
  check('a first live inbound PM created the thread with PM Protection enabled',await inbox(browser,onlineNick));
  const plainReply='two-way plaintext reply '+stamp;
  await ev(`setActive(${q(networkA)},${q(onlineNick)});document.getElementById('msg-input').focus();document.getElementById('msg-input').value=${q(plainReply)};`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  await waitFor(()=>live.lines.some(line=>line.endsWith(' :'+plainReply)),'ordinary IRC peer receives the live plaintext reply');
  check('plaintext PMs moved both ways before the disconnect',true);
  live.close();
  await pause(450);
  const draft='reply after peer quits '+stamp;
  const mark=browser.frames.length;
  await ev(`setActive(${q(networkA)},${q(onlineNick)});document.getElementById('msg-input').focus();document.getElementById('msg-input').value=${q(draft)};`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  const offlineReported=await waitFor(()=>ev(`getBuf(${q(networkA)},${q(onlineNick)}).some(m=>m.text===${q(onlineNick+' is offline.')})`),
    'online peer quit, then CryptIRC reports the nick offline',15000).catch(()=>false);
  if(!offlineReported)console.log('TEST OFFLINE DIAGNOSTIC',JSON.stringify({
    frames:browser.frames.slice(mark).map(JSON.parse).filter(f=>f.username===onlineNick||f.raw?.includes(onlineNick)).map(f=>f.type),
    reply:ownerWs.events.filter(e=>e.type==='e2e_bundle_missing').slice(-2).map(e=>e.reason),
    browser:await ev(`({ready:E2E.keyReady,reason:E2E.lastBlockReason,
      chat:getBuf(${q(networkA)},${q(onlineNick)}).filter(m=>m.kind==='error').map(m=>m.text),
      composer:document.getElementById('composer-encryption-status-text').textContent})`)
  }));
  const keptAfterDisconnect=offlineReported&&
    await ev(`document.getElementById('msg-input').value===${q(draft)}`)&&
    !browser.frames.slice(mark).map(JSON.parse).some(f=>f.type==='send'&&f.raw?.includes(draft));
  console.log('DISCONNECTED REPLY '+JSON.stringify({notice:offlineReported,draftKept:keptAfterDisconnect}));
  await ev("localStorage.setItem('cryptirc_block_pms','false');savePrefsToServer();flushPrefsToServer()");
  await waitFor(()=>ev("_prefsPendingSince===0"),'PM protection change queued before browser closes');
  await browser.close();
  absent.send('PRIVMSG '+owner+' :'+offlineText);
  await ownerWs.wait(e=>e.type==='irc_message'&&e.from===offlineNick&&e.text===offlineText,'Frozen-equivalent web receives a PM while the browser is closed');
  const returned=await browser.reopen();
  await waitFor(()=>returned.evaluate(`_wsReady()&&networks.some(n=>n.config.id===${q(networkA)}&&n.connected)&&
    !document.getElementById('vault-overlay').classList.contains('show')`),'browser reconnects while the IRC core stays connected');
  await returned.evaluate("setActive(MSGS_CONN,MSGS_TARGET)");
  await waitFor(()=>inbox(returned,offlineNick),'Messages recovers the new conversation without opening its query');
  const present=await inbox(returned,offlineNick);
  check('the first PM received while the browser was closed is listed in Messages',present);
  await returned.evaluate(`setActive(${q(networkA)},${q(offlineNick)});`);
  await waitFor(()=>returned.evaluate(`getBuf(${q(networkA)},${q(offlineNick)}).some(m=>m.text===${q(offlineText)})`),
    'opening the known IRC nick directly retrieves its saved first PM');
  console.log('INBOX RECOVERY '+JSON.stringify({threadRecoveredAutomatically:present, historyRetrieved:true}));
  absent.close();
  check('a reply after the peer disconnects stays in the composer and sends no PRIVMSG',keptAfterDisconnect);
  return;
  }
  if(composerEncryption){
    await checkComposerEncryption(browser,networkA,otherWs);
    return;
  }
  const noticeNetwork=await network(token,'pkc'+stamp,IRC_PORT,'Other network');
  await tool(token,'irc_network',{action:'connect',network:noticeNetwork});
  await ownerWs.wait(e=>e.type==='connected'&&e.conn_id===noticeNetwork,'second viewer network');
  await waitFor(()=>ev(`networks.some(n=>n.config.id===${JSON.stringify(noticeNetwork)})`),'browser second network');
  if(reactionMidpoint||process.env.CRYPTIRC_TEST_REACTION_DURABILITY==='1'){
    const profile='reaction-durability';
    const q=JSON.stringify;
    const signIn=async device=>{
      const state=await waitFor(()=>device.evaluate(`_wsReady()?'connected':
        document.getElementById('auth-screen').style.display==='flex'?'login':null`),
      'the reaction fixture browser is connected or offers login');
      if(state==='login') await device.evaluate(`document.getElementById('l-user').value=${q(owner)};
        document.getElementById('l-pass').value=${q(password)};doLogin()`);
      await waitFor(()=>device.evaluate('!!sessionToken&&_wsReady()'),'reaction fixture browser signed in');
    };
    const ready=device=>waitFor(()=>device.evaluate(`window._appShown&&_wsReady()&&
      reactionEnabled(${JSON.stringify(networkA)})&&!document.getElementById('vault-overlay').classList.contains('show')`).catch(()=>false),
    'reaction fixture browser is authenticated on the existing IRC route');
    const close=async device=>{
      if(device.chrome.exitCode===null&&device.chrome.signalCode===null){
        await device.send('Browser.close');
        await waitFor(()=>device.chrome.exitCode!==null||device.chrome.signalCode!==null,'the reaction browser process closed');
      }
      await fs.rm(path.join(tmp,profile,'DevToolsActivePort'),{force:true});
    };
    let actor=await chromium(profile);
    try{
      await signIn(actor);
      await actor.evaluate(`document.getElementById('vault-pass').value=${q(vault)};doUnlock()`);
      await ready(actor);
      const reopen=async(previous,restartWeb)=>{
        await close(previous);
        if(restartWeb){
          const corePid=core.pid;
          process.kill(-web.pid,reactionMidpoint?'SIGKILL':'SIGTERM');
          await waitFor(()=>web.exitCode!==null||web.signalCode!==null,'disposable reaction web exited');
          children.splice(children.indexOf(web),1);
          web=start(CRYPTIRC_BIN,[],webEnv);
          await waitWeb();
          process.kill(corePid,0);
          check('the reaction fixture web restarted with the original IRC core PID',
            core.pid===corePid&&core.exitCode===null&&core.signalCode===null);
          const freshToken=async username=>{
            const {status,data}=await request('/auth/login',{method:'POST',body:{username,password}});
            assert.equal(status,200,'reaction observer login after the web restart');
            return data.token;
          };
          ownerSession=await freshToken(owner);
          otherSession=await freshToken(other);
          ownerWs=await connectWebsocket(ownerSession);
          otherWs=await connectWebsocket(otherSession);
          for(const [observer,network] of [[ownerWs,networkA],[otherWs,networkB]]){
            observer.send({type:'unlock_vault',passphrase:vault});
            await observer.wait(event=>event.type==='vault_unlocked','reaction observer unlocked after web restart');
            let last=0;
            await waitFor(()=>{
              const online=observer.events.some(event=>event.type==='state'&&event.networks.some(net=>net.config.id===network&&net.connected));
              if(!online&&Date.now()-last>=500){ last=Date.now();observer.send({type:'get_state'}); }
              return online;
            },'existing reaction observer route reattached');
          }
        }
        actor=await chromium(profile);
        await signIn(actor);
        await ready(actor);
        return {browser:actor,ownerWs,otherWs};
      };
      const dateReceipt=async(device,receipt,observer)=>{
        const elapsed=14*60*60*1000;
        const ledger=path.join(tmp,'users',owner,'reaction-receipts.json');
        const rows=JSON.parse(await fs.readFile(ledger,'utf8'));
        const order=row=>row.order??row.expires_at;
        assert(rows.some(row=>row.conn_id===networkA&&row.request_id===receipt.request_id&&order(row)===order(receipt)),
          'the genuine IRC receipt is in the disposable account ledger');
        // Shift this idle fixture's prior timestamps together so the existing
        // confirmed Like, Heart and removal keep their true ordering.
        for(const row of rows){
          if(Number.isSafeInteger(row.order)) row.order-=elapsed;
          else row.expires_at-=elapsed;
        }
        await fs.writeFile(ledger+'.dated',JSON.stringify(rows),{mode:0o600});
        await fs.rename(ledger+'.dated',ledger);
        await device.evaluate(`(async()=>{
          const slot=reactionHistorySlot(false), key='receipt:'+${q(receipt.request_id)};
          const records=await readReactionHistory(slot,null), pending=records.get(key);
          if(!pending)throw new Error('the actual pending removal is missing');
          for(const [id,entry] of records){
            if(id.startsWith('receipt:')) entry.until=Number.isFinite(entry.until)?entry.until-${elapsed}:Date.now()-${elapsed};
            else if(entry.ownOrder) for(const emoji of Object.keys(entry.ownOrder))entry.ownOrder[emoji]-=${elapsed};
          }
          await _e2eIdbOp('readwrite',store=>store.put([...records],slot),2000);
        })()`);
        const at=observer.events.length;
        observer.send({type:'get_reaction_receipts',conn_id:networkA,request_ids:[receipt.request_id]});
        const reply=await waitFor(()=>observer.events.slice(at).find(event=>event.type==='reaction_receipts'&&event.conn_id===networkA),
          'the actual server answers the aged reaction receipt lookup');
        return {elapsedHours:14,serverStillConfirms:reply.receipts.some(row=>row.request_id===receipt.request_id)};
      };
      if(reactionGate){
        const witness=await ordinaryIrcClient(IRC_LEAF_PORT||IRC_PORT,'pkw'+stamp);
        try{
          witness.send('CAP REQ :message-tags');
          await waitFor(()=>witness.lines.some(line=>line.includes(' ACK ')&&line.includes('message-tags')),
            'independent IRC witness negotiated message tags');
          witness.send('JOIN '+channel);
          await waitFor(()=>witness.lines.some(line=>line.includes(' JOIN ')&&line.includes(channel)),
            'independent IRC witness joined the durability channel');
          await checkReactionMidpoint({browser:actor,reopen,gate:reactionGate,witness,ownerWs,otherWs,check,waitFor,
            networkA,networkB,channel,owner,stamp});
        }finally{witness.close();}
      }else{
        await checkReactionEchoDurability({browser:actor,reopen,dateReceipt,ownerWs,otherWs,check,waitFor,networkA,networkB,channel,owner,stamp});
      }
      await signIn(browser);
      await waitFor(()=>ev(`window._appShown&&_wsReady()&&reactionEnabled(${q(networkA)})`),'the original browser returned after the optional reaction web restart');
    }finally{ await close(actor); }
  }
  if(process.env.CRYPTIRC_TEST_REACTION_HISTORY==='1'){
    await checkReactionHistory({browser,check,waitFor,otherWs,networkA,networkB,channel,stamp});
  }
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
    const unsupportedNick='pkr'+stamp;
    const unsupportedNetwork=await network(token,unsupportedNick,process.env.IRC_UNSUPPORTED_PORT,'No reaction capability');
    const unsupportedSender=await network(otherKey,other,process.env.IRC_UNSUPPORTED_PORT,'Compatibility test sender');
    await tool(token,'irc_network',{action:'connect',network:unsupportedNetwork});
    await tool(otherKey,'irc_network',{action:'connect',network:unsupportedSender});
    await ownerWs.wait(e=>e.type==='connected'&&e.conn_id===unsupportedNetwork,'unsupported reaction IRC server');
    await otherWs.wait(e=>e.type==='connected'&&e.conn_id===unsupportedSender,'unsupported reaction sender');
    await waitFor(()=>ev(`reactionEnabled(${JSON.stringify(networkA)})&&reactionAllows(${JSON.stringify(networkA)},'👎')&&networks.some(n=>n.config.id===${JSON.stringify(unsupportedNetwork)})`),'browser capability sync');
    await checkPlainReactions({ev,cdp,check,waitFor,ownerWs,otherWs,owner,other,networkA,networkB,channel,stamp,unsupportedNetwork,unsupportedSender,unsupportedNick});
    const plainNick='pkrx'+stamp;
    const plain=await ordinaryIrcClient(IRC_LEAF_PORT||IRC_PORT,plainNick);
    const reactionViewer=await chromium('reaction-viewer');
    try {
      const peer=reactionViewer.evaluate;
      const q=JSON.stringify;
      await peer(`document.getElementById('l-user').value=${q(other)};document.getElementById('l-pass').value=${q(password)};doLogin()`);
      await waitFor(()=>peer('!!sessionToken&&_wsReady()'),'second CryptIRC reaction viewer signed in');
      await peer(`document.getElementById('vault-pass').value=${q(vault)};doUnlock()`);
      await waitFor(()=>peer(`reactionEnabled(${q(networkB)})&&!document.getElementById('vault-overlay').classList.contains('show')`),
        'second CryptIRC reaction viewer ready');
      await checkOrdinaryClientReactions({ev:peer,peer:ev,check,waitFor,plain,plainNick,owner:other,
        networkA:networkB,networkB:networkA,channel,stamp});
      if(process.env.IRC_LEGACY_REACTIONS_PORT){
        const legacyNick='pkrm'+stamp;
        const legacyNetwork=await network(otherKey,legacyNick,process.env.IRC_LEGACY_REACTIONS_PORT,'Legacy reactions');
        await tool(otherKey,'irc_network',{action:'connect',network:legacyNetwork});
        await otherWs.wait(e=>e.type==='connected'&&e.conn_id===legacyNetwork,'legacy reaction fixture registration');
        const legacyPlain='pkrn'+stamp;
        const legacySender=await ordinaryIrcClient(process.env.IRC_LEGACY_REACTIONS_PORT,legacyPlain);
        try {
          await checkLegacyReactionMenu({ev:peer,check,waitFor,ownerWs:otherWs,legacyNetwork,legacyNick,legacyPlain,legacySender,stamp});
        } finally {
          legacySender.close();
          await tool(otherKey,'irc_network',{action:'disconnect',network:legacyNetwork});
          await tool(otherKey,'irc_network',{action:'remove',network:legacyNetwork});
        }
      }
    } finally {
      plain.close();
      process.kill(-reactionViewer.chrome.pid,'SIGTERM');
    }
    await tool(token,'irc_network',{action:'disconnect',network:unsupportedNetwork});
    await tool(otherKey,'irc_network',{action:'disconnect',network:unsupportedSender});
    await tool(token,'irc_network',{action:'remove',network:unsupportedNetwork});
    await tool(otherKey,'irc_network',{action:'remove',network:unsupportedSender});
    reactionWindowEnds=Date.now()+61000;
  }
  const sendLag=ms=>ev(`handleEvent({type:'lag_update',conn_id:${JSON.stringify(networkA)},ms:${ms}})`);
  await ev(`setActive(${JSON.stringify(noticeNetwork)},'status')`);
  await sendLag(463);
  check('high latency never appears on the other network',await ev(`!document.getElementById('chat-area').textContent.includes('High latency on Renamed hub')`));
  for(const command of ['VERSION','FINGER']){
    otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${owner} :\x01${command}\x01`});
    await ownerWs.wait(e=>e.type==='ctcp_request'&&e.command===command&&e.conn_id===networkA,`${command} event`);
    check(`private CTCP ${command} appears in the viewer's other network tab`,await waitFor(()=>ev(
      `document.getElementById('chat-area').textContent.includes(${JSON.stringify(`CTCP ${command} detected from ${other} on Renamed hub.`)})`),`${command} notice`));
  }
  const leakedCtcp=otherWs.events.filter(e=>
    (e.type==='ctcp_request'&&e.conn_id===networkA&&e.from===other&&['VERSION','FINGER'].includes(e.command))||
    ['VERSION','FINGER'].some(command=>e.text?.includes(`CTCP ${command} detected from ${other}`)));
  check('the IRC peer receives no private CTCP notices',!leakedCtcp.length);
  check('CTCP alerts are absent from the viewer network history',!(await tool(token,'irc_history',{network:noticeNetwork,target:'status'})).lines.some(l=>l.text.includes('CTCP VERSION detected')));
  await sendLag(463);
  await ev(`setActive(${JSON.stringify(networkA)},${JSON.stringify(channel)})`);
  check('latency appears when the affected network is viewed',await waitFor(()=>ev(
    `document.getElementById('chat-area').textContent.includes('High latency on Renamed hub (463 ms).')`),'network-local latency message'));
  await sendLag(483);
  check('repeated high latency is quiet until the connection recovers',await ev(`!document.getElementById('chat-area').textContent.includes('483 ms')`));
  await sendLag(120);
  await sendLag(523);
  check('a later latency spike is reported after recovery',await ev(`document.getElementById('chat-area').textContent.includes('High latency on Renamed hub (523 ms).')`));
  check('latency alerts are absent from shared IRC traffic and server history',!otherWs.events.some(e=>e.text?.includes('High latency on Renamed hub')) &&
    !(await tool(token,'irc_history',{network:networkA,target:channel})).lines.some(l=>l.text.includes('High latency on Renamed hub')));
  const alertControls=await ev(`(async()=>{
    await showNotifModal();
    return ['notif-ctcp-version','notif-ctcp-finger','notif-latency'].every(id=>document.getElementById(id).checked)
      && document.getElementById('notif-latency-threshold').value==='300';
  })()`);
  check('private alert settings default to VERSION, FINGER, and 300 ms latency alerts',alertControls);
  const clickAlert=id=>ev(`document.getElementById(${JSON.stringify(id)}).click()`);
  const setAlertThreshold=value=>ev(`(()=>{const input=document.getElementById('notif-latency-threshold');input.value=${JSON.stringify(value)};input.dispatchEvent(new Event('change',{bubbles:true}));return input.value;})()`);
  const noticeCount=(id,target,text)=>ev(`getBuf(${JSON.stringify(id)},${JSON.stringify(target)}).filter(m=>m.text?.includes(${JSON.stringify(text)})).length`);
  const sendCtcp=async command=>{
    const from=ownerWs.events.length;
    otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${owner} :\x01${command}\x01`});
    await waitFor(()=>ownerWs.events.slice(from).some(e=>e.type==='ctcp_request'&&e.command===command&&e.conn_id===networkA),
      `new ${command} event`);
  };
  await ev(`setActive(${JSON.stringify(noticeNetwork)},'status')`);
  await clickAlert('notif-ctcp-version');
  const beforeVersion=await noticeCount(noticeNetwork,'status','CTCP VERSION detected');
  const beforeFinger=await noticeCount(noticeNetwork,'status','CTCP FINGER detected');
  const replyFrom=otherWs.events.length;
  await pause(2100);
  await sendCtcp('VERSION');
  await sendCtcp('FINGER');
  await waitFor(async()=>await noticeCount(noticeNetwork,'status','CTCP FINGER detected')>beforeFinger,'FINGER still displays');
  check('disabling VERSION only hides VERSION alerts',await noticeCount(noticeNetwork,'status','CTCP VERSION detected')===beforeVersion);
  check('disabling the VERSION alert still allows the protocol reply',await waitFor(()=>otherWs.events.slice(replyFrom).some(e=>
    e.type==='irc_message'&&e.kind==='Notice'&&e.text?.includes('VERSION CryptIRC v')),'VERSION protocol reply'));
  await clickAlert('notif-ctcp-finger');
  await clickAlert('notif-ctcp-version');
  const fingerMutedAt=await noticeCount(noticeNetwork,'status','CTCP FINGER detected');
  const timeBefore=await noticeCount(noticeNetwork,'status','CTCP TIME detected');
  await sendCtcp('FINGER');
  await sendCtcp('TIME');
  await waitFor(async()=>await noticeCount(noticeNetwork,'status','CTCP TIME detected')>timeBefore,'TIME still displays');
  check('disabling FINGER leaves other incoming CTCP alerts visible',await noticeCount(noticeNetwork,'status','CTCP FINGER detected')===fingerMutedAt);
  await ev(`setActive(MSGS_CONN,MSGS_TARGET);handleEvent({type:'ctcp_request',conn_id:${JSON.stringify(networkA)},command:'VERSION',from:${JSON.stringify(other)}})`);
  check('VERSION is queued while a non-chat tab is active',await ev("pendingCtcpNotices.some(n=>n.command==='VERSION')"));
  await clickAlert('notif-ctcp-version');
  check('turning off VERSION discards the already queued alert',await ev("!pendingCtcpNotices.some(n=>n.command==='VERSION')"));

  await sendLag(100);
  check('the threshold keeps the last valid value when an out-of-range value is entered',
    await setAlertThreshold('450')==='450' && await setAlertThreshold('9000')==='450');
  await ev(`setActive(${JSON.stringify(noticeNetwork)},'status')`);
  await sendLag(470);
  check('custom latency warnings stay on the affected connection',await noticeCount(noticeNetwork,'status','(470 ms)')===0);
  await sendLag(430);
  await ev(`setActive(${JSON.stringify(networkA)},${JSON.stringify(channel)})`);
  check('latency below the custom threshold stays quiet',await noticeCount(networkA,channel,'(430 ms)')===0);
  await sendLag(470);
  check('latency above the custom threshold warns in chat',await noticeCount(networkA,channel,'(470 ms)')===1);
  await setAlertThreshold('460');
  await setAlertThreshold('450');
  check('editing the threshold does not repeat an ongoing latency warning',await noticeCount(networkA,channel,'(470 ms)')===1);
  await sendLag(420);
  await sendLag(null);
  await sendLag(480);
  check('a small dip or missing sample does not duplicate latency warnings',await noticeCount(networkA,channel,'(480 ms)')===0);
  await sendLag(365);
  await sendLag(490);
  check('custom latency warnings resume after recovery',await noticeCount(networkA,channel,'(490 ms)')===1);
  await setAlertThreshold('100');
  await sendLag(80);
  await sendLag(120);
  check('a low threshold re-arms after a proportional recovery',await noticeCount(networkA,channel,'(120 ms)')===1);
  await ev("const thresholdForClose=document.getElementById('notif-latency-threshold');thresholdForClose.focus();thresholdForClose.value='450';closeNotifModal()");
  await waitFor(()=>ev('_popSkipCount===0'),'settings history entry closed');
  await ev('showNotifModal()');
  check('closing the settings saves a valid unfinished threshold edit',await ev("loadIrcAlertPrefs().threshold===450"));
  await clickAlert('notif-latency');
  await sendLag(100);
  await sendLag(800);
  check('latency alerts can be disabled without hiding the latency indicator',
    await noticeCount(networkA,channel,'(800 ms)')===0 && await ev("document.getElementById('lag-mobile-val').textContent==='800ms'"));
  await ev('ircAlertPrefs=loadIrcAlertPrefs();renderIrcAlertPrefs()');
  check('saved alert settings are restored from local storage',await ev(`
    ['notif-ctcp-version','notif-ctcp-finger','notif-latency'].every(id=>!document.getElementById(id).checked)
      && document.getElementById('notif-latency-threshold').disabled
      && document.getElementById('notif-latency-threshold').value==='450'`));
  await sendLag(100);
  await clickAlert('notif-ctcp-version');
  await clickAlert('notif-ctcp-finger');
  await clickAlert('notif-latency');
  await setAlertThreshold('300');
  await ev('closeNotifModal()');
  await tool(token,'irc_network',{action:'disconnect',network:noticeNetwork});
  await tool(token,'irc_network',{action:'remove',network:noticeNetwork});
  if(process.env.CRYPTIRC_TEST_CHANNEL_LIST==='1'){
    const directoryChannel=channel+'-directory';
    const directoryPeer=await network(otherKey,other+'d',IRC_PORT,'Directory peer');
    await tool(otherKey,'irc_network',{action:'connect',network:directoryPeer});
    await otherWs.wait(e=>e.type==='connected'&&e.conn_id===directoryPeer,'directory peer registration');
    for(const id of [networkB,directoryPeer]){
      await tool(otherKey,'irc_join',{network:id,channel:directoryChannel});
      await otherWs.wait(e=>['irc_join','irc_join_ex'].includes(e.type)&&e.conn_id===id&&e.channel===directoryChannel,'directory fixture channel');
    }
    await checkChannelList({ev,cdp,waitFor,check,network:networkA,channel:directoryChannel});
    await ev(`setActive(${JSON.stringify(networkA)},${JSON.stringify(channel)})`);
  }
  if(process.env.CRYPTIRC_TEST_SETTINGS_SEARCH==='1'){
    const grantAdmin=async admin=>{
      const record=path.join(tmp,'users',owner+'.json');
      const data=JSON.parse(await fs.readFile(record,'utf8'));
      const temporary=record+'.settings-search-test';
      await fs.writeFile(temporary,JSON.stringify({...data,admin}),{mode:0o600});
      await fs.rename(temporary,record);
    };
    await checkSettingsSearch({ev,cdp,check,waitFor,pause,network:'Renamed hub',grantAdmin});
  }
  const composerText='browser composer '+stamp;
  await ev(`setActive(${JSON.stringify(networkA)},${JSON.stringify(channel)});
   const composer=document.getElementById('msg-input');
   composer.focus();composer.value=${JSON.stringify(composerText)};`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  check('desktop browser composer sent a message on the real testnet',!!await otherWs.wait(e=>
    e.type==='irc_message'&&e.text.includes(composerText),'browser composer send'));
  const mobileText='mobile composer '+stamp;
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await cdp('Emulation.setTouchEmulationEnabled',{enabled:true,maxTouchPoints:1});
  await ev(`document.getElementById('msg-input').value=${JSON.stringify(mobileText)};
   document.getElementById('msg-input').dispatchEvent(new InputEvent('beforeinput',{
     inputType:'insertLineBreak',bubbles:true,cancelable:true
   }));`);
  check('mobile Send action reached the IRC peer',!!await otherWs.wait(e=>
    e.type==='irc_message'&&e.text.includes(mobileText),'mobile composer send'));
  if(translator)await checkTranslation({
    ev,cdp,check,waitFor,pause,request,tmp,owner,other,ownerSession,otherSession,ownerWs,otherWs,networkA,networkB,channel,translator,
  });
  await tool(token,'irc_command',{network:networkA,line:'TOPIC '+channel+' :test topic'});
  check('MCP standard IRC command reached the peer',!!await otherWs.wait(e=>e.type==='irc_topic'&&e.topic==='test topic','topic update'));
  const history=await tool(token,'irc_history',{network:networkA,target:channel});
  check('MCP history includes the actual sent message',history.lines.some(l=>l.text===phrase));
  check('MCP searches real IRC history',(await tool(token,'irc_search',{network:networkA,target:channel,query:stamp})).lines.some(l=>l.text===phrase));
  check('MCP rejects multi-command injection',/invalid text/i.test(await tool(token,'irc_send',{
    network:networkA,target:channel,text:'hello\r\nJOIN #unexpected'
  },true)));
  const rawText='raw IRC '+stamp;
  await tool(token,'irc_command',{network:networkA,line:'@+test=1 PRIVMSG '+channel+' :'+rawText});
  check('MCP IRCv3 raw message reached the peer',!!await otherWs.wait(e=>
    e.type==='irc_message'&&e.text===rawText,'tagged raw IRC message'));
  check('MCP raw IRC rejects multiple commands',/invalid line/i.test(await tool(token,'irc_command',{
    network:networkA,line:'PING test\nQUIT'
  },true)));
  const beforeMotd=ownerWs.events.length;
  await tool(token,'irc_command',{network:networkA,line:'/MOTD'});
  await waitFor(()=>ownerWs.events.slice(beforeMotd).some(e=>
    e.type==='irc_message'&&e.target==='status'&&/motd|Message of the Day/i.test(e.text)
  ),'raw MOTD response');
  check('MCP runs an IRC verb outside the old allowlist',true);
  ownerWs.send({type:'e2e_store_channel_key',channel,blob:'e2e2.test-only opaque key'});
  await ownerWs.wait(e=>e.type==='e2e_channel_key'&&e.channel===channel,'E2E-protected channel fixture');
  check('MCP refuses plaintext to an E2E channel',/end-to-end/i.test(await tool(token,'irc_send',{
    network:networkA,target:channel,text:'this must never appear'
  },true)));
  check('MCP raw IRC honors E2E protection for tagged multi-target sends',/end-to-end/i.test(await tool(token,'irc_command',{
    network:networkA,line:'@+test=1 NOTICE '+other+','+channel+' :this must never appear'
  },true)));
  check('E2E refusal produced no IRC message',!otherWs.events.some(e=>e.text?.includes('this must never appear')));
  const brokenSlot=path.join(tmp,'e2e',owner,'channels','broken~fixture.enc');
  await fs.writeFile(brokenSlot,'isolated unreadable key metadata');
  check('MCP fails closed when E2E metadata is unreadable',/verify.+encryption/i.test(await tool(token,'irc_send',{
    network:networkA,target:other,text:'fail closed test'
  },true)));
  await fs.rm(brokenSlot);
  if(e2eEnabled){
    // Plain and sealed reactions share the per-account budget. Start the
    // sealed checks in a fresh window with the normal limit in effect.
    if(reactionWindowEnds>Date.now()) await pause(reactionWindowEnds-Date.now());
    ownerWs.send({type:'e2e_delete_channel_key',channel,v:2});
    await waitFor(async()=>{
      const files=await fs.readdir(path.join(tmp,'e2e',owner,'channels'));
      return !files.some(name=>name.endsWith('.enc'));
    },'test plaintext policy fixture removed');
    const ownerCode=await checkE2eChat({browser,chromium,check,waitFor,pause,owner,other,password,vault,tmp,ownerWs,otherWs,
      networkA,networkB,channel,stamp,request,ownerSession,echoGate:delayOwnEcho?reactionGate:null});
    if(process.env.CRYPTIRC_TEST_E2E_BRIDGE==='1'){
      const ordinaryFirst=['first-account-plain','first-account-shared-consent'].includes(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT);
      const peerPort=Number(ordinaryFirst?process.env.IRC_UNSUPPORTED_PORT:IRC_LEAF_PORT);
      assert(peerPort,ordinaryFirst?'Set IRC_UNSUPPORTED_PORT for the ordinary first-account check':'Set IRC_LEAF_PORT for bridge tests');
      const remote='pkx'+stamp;
      const remotePort=await allocatePort();
      const endpoint=`http://localhost:${remotePort}/cryptirc`;
      const remoteData=await fs.mkdtemp(path.join(tmp,'remote-'));
      const remoteEnv={...env,CRYPTIRC_DATA:remoteData,CRYPTIRC_PORT:String(remotePort),CRYPTIRC_BASE_URL:endpoint};
      await fs.writeFile(path.join(remoteData,'admin_settings.json'),JSON.stringify({registration_open:true,captcha_enabled:false}));
      start(process.env.CRYPTIRC_PEER_CORE_BIN||CRYPTIRC_CORE_BIN,[],remoteEnv);
      await waitFor(()=>fs.stat(path.join(remoteData,'irc-core.sock')).catch(()=>null),'separate IRC core');
      const peerWeb=start(process.env.CRYPTIRC_PEER_BIN||CRYPTIRC_BIN,[],remoteEnv);
      await waitFor(()=>fetch(endpoint+'/auth/status').then(r=>r.ok).catch(()=>false),'separate CryptIRC instance');
      const createRemote=async nick=>{
        check('second CryptIRC instance registers its own account',(await request('/auth/register',{method:'POST',endpoint,body:{username:nick,password}})).status===200);
        const login=await request('/auth/login',{method:'POST',endpoint,body:{username:nick,password}});
        const observer=await connectWebsocket(login.data.token,endpoint);
        observer.send({type:'unlock_vault',passphrase:vault});
        await observer.wait(e=>e.type==='vault_unlocked','second instance vault');
        const label='Second CryptIRC instance';
        observer.send({type:'add_network',network:{id:crypto.randomUUID(),label,server:'127.0.0.1',port:peerPort,
          tls:false,tls_accept_invalid_certs:false,nick,username:nick,realname:'CryptIRC bridge fixture',
          auto_join:[],sasl_external:false,auto_reconnect:false}});
        const state=await observer.wait(e=>e.type==='state'&&e.networks.some(n=>n.config.label===label),'second instance network');
        const id=state.networks.find(n=>n.config.label===label).config.id;
        observer.send({type:'connect',id});
        await observer.wait(e=>e.type==='connected'&&e.conn_id===id,'second instance linked IRC registration');
        return {observer,id,device:await chromium('encrypted-bridge-'+nick,endpoint)};
      };
      const {observer:remoteWs,id:remoteNetwork,device:bridgePeer}=await createRemote(remote);
      const ordinary='pkn'+stamp;
      const silentTagged=!ordinaryFirst&&!['bridge-ordinary','bridge-ordinary-cold'].includes(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT);
      const irc=await ordinaryIrcClient(peerPort,ordinary,silentTagged);
      await checkCrossInstanceE2e({browser,peer:bridgePeer,createRemote,chromium,ownerCode,check,waitFor,
        owner,ownerWs,remote,password,vault,networkA,remoteNetwork,remoteWs,stamp,otherWs,ownerData:tmp,remoteData,peerWeb,ordinary,ordinaryLines:irc.lines,ordinarySend:irc.send});
      irc.close();
      // These audits fully close the original browser before reopening its profile.
      if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='identity-reset'&&
         ['1','on'].includes(process.env.CRYPTIRC_TEST_IDENTITY_CLOSED_SIBLING)&&
         process.env.CRYPTIRC_TEST_DEVICE_HISTORY_SYNC==='1')return;
      if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='offline-restart-history')return;
    }
  }
  await tool(token,'cryptirc_appearance',{settings:{theme:'arctic'}});
  check('MCP appearance can be updated and read',(await tool(token,'cryptirc_appearance')).settings.theme==='arctic');
  if(process.env.CRYPTIRC_TEST_PREFERENCE_CONCURRENCY==='1')await checkConcurrentPreferenceSave({token,ownerWs,networkA,browser});
  const browserPrefCount=ownerWs.events.length;
  await tool(token,'cryptirc_settings',{section:'preferences',settings:{
    giphyRating:'g',giphyKey:'test-only-gif-key'
  }});
  await waitFor(()=>ev("localStorage.getItem('cryptirc_giphy_rating')==='g'&&localStorage.getItem('cryptirc_giphy_key')==='test-only-gif-key'"),
    'browser applied the first MCP preference patch');
  const browserSaveTs=await ev("localStorage.setItem('cryptirc_highlight_words_ts',String(Date.now()-1000));_lastFlushTs='mcp-test-browser-save';_lastFlushTs");
  await tool(token,'cryptirc_settings',{section:'preferences',settings:{
    autoRejoin:false,highlightWords:[stamp],_saveTs:browserSaveTs
  }});
  await waitFor(()=>ev("JSON.parse(localStorage.getItem('cryptirc_highlight_words')||'[]').includes("+JSON.stringify(stamp)+")"),
    'browser applied an MCP preference with an existing local timestamp');
  check('MCP preference updates are applied by the browser',true);
  const {settings:mcpPrefs}=await tool(token,'cryptirc_settings',{section:'preferences'});
  check('MCP patches encrypted preferences without returning saved keys',
    mcpPrefs.giphyRating==='g'&&mcpPrefs.autoRejoin===false&&!Object.hasOwn(mcpPrefs,'giphyKey'));
  await waitFor(()=>ownerWs.events.slice(browserPrefCount).some(e=>{
    if(e.type!=='preferences'||!e.prefs)return false;
    const prefs=JSON.parse(e.prefs);
    return prefs.giphyRating==='g'&&prefs.autoRejoin===false&&prefs.giphyKey==='test-only-gif-key';
  }),'browser received synced preferences with stored credentials');
  const notifications=await tool(token,'cryptirc_settings',{section:'notifications',settings:{enabled:true,dnd:true}});
  check('MCP writes notifications through the normal API',notifications.settings.enabled&&
    (await request('/push/settings',{token:ownerSession})).data.dnd===true);
  const {settings:savedBots}=await tool(token,'cryptirc_settings',{section:'bots'});
  await tool(token,'cryptirc_settings',{section:'bots',settings:{...savedBots,enabled:false}});
  check('MCP reads saved bot settings',(await tool(token,'cryptirc_settings',{section:'bots'})).settings.enabled===false);
  check('MCP requires the admin role for server settings',/administrator/i.test(await tool(otherKey,'cryptirc_settings',{
    section:'admin',settings:{max_upload_mb:17}
  },true)));
  const ownerRecord=path.join(tmp,'users',owner+'.json');
  const ownerData=JSON.parse(await fs.readFile(ownerRecord,'utf8'));
  const stagedOwner=ownerRecord+'.mcp-admin-test';
  await fs.writeFile(stagedOwner,JSON.stringify({...ownerData,admin:true}),{mode:0o600});
  await fs.rename(stagedOwner,ownerRecord);
  await tool(token,'cryptirc_settings',{section:'admin',settings:{max_upload_mb:17}});
  check('MCP admin changes are visible to the normal admin API',
    (await request('/admin/settings',{token:ownerSession})).data.max_upload_mb===17);
  await ev('showAdminPanel()');
  const invite='fixture-'+stamp;
  await fill('admin-reg-code',invite);
  await ev("document.getElementById('admin-reg-code-set').click()");
  await waitFor(()=>ev("document.getElementById('admin-reg-code').placeholder==='Code set'"),'invite code saved by admin UI');
  const {settings:inviteSettings}=await tool(token,'cryptirc_settings',{section:'admin'});
  const httpInviteSettings=(await request('/admin/settings',{token:ownerSession})).data;
  check('admin HTTP and MCP return only whether the invite code is set',
    [inviteSettings,httpInviteSettings].every(s=>s.registration_code_set===true &&
      !('registration_code' in s) && !JSON.stringify(s).includes(invite)));
  for(const registration_code of ['', 'undefined']){
    const legacyWrite=await request('/admin/settings',{method:'PUT',token:ownerSession,
      body:{registration_open:false,captcha_enabled:true,registration_code}});
    check('old admin clients get an explicit invite-code conflict',legacyWrite.status===409);
  }
  const signupPolicy=(await request('/auth/status')).data;
  check('old admin clients can still close registration and enable captcha',
    !signupPolicy.registration_open && signupPolicy.captcha_enabled && signupPolicy.requires_code);
  assert.equal((await request('/admin/settings',{method:'PUT',token:ownerSession,
    body:{registration_open:true,captcha_enabled:false}})).status,200);
  for(const settings of [{registration_code:'legacy'},{new_registration_code:''},{new_registration_code:' '},
    {new_registration_code:'replacement',clear_registration_code:true}]){
    await tool(token,'cryptirc_settings',{section:'admin',settings},true);
  }
  const signup=await request('/auth/register',{method:'POST',
    body:{username:'invite'+stamp,password,code:invite}});
  check('invalid HTTP and MCP updates preserve the original invite code',signup.status===200);
  await ev("document.getElementById('admin-reg-code-clear').click()");
  await waitFor(()=>ev("document.getElementById('admin-reg-code').placeholder==='No code set'"),'invite code cleared explicitly');
  check('admin UI can clear the invite code',
    (await request('/admin/settings',{token:ownerSession})).data.registration_code_set===false);
  await ev('closeAdminPanel()');
  assert.equal((await request('/admin/settings',{method:'PUT',token:ownerSession,
    body:{registration_open:false}})).status,200);
  const closedSignup=await chromium('closed-signup');
  await waitFor(()=>closedSignup.evaluate("document.getElementById('tab-register').style.display==='none'"),
    'closed registration hides the signup tab');
  check('closed registration hides the signup tab under strict CSP',true);
  const {settings:previewPolicy}=await tool(token,'cryptirc_settings',{section:'link_previews'});
  await tool(token,'cryptirc_settings',{section:'link_previews',settings:{...previewPolicy,mode:'off'}});
  check('MCP link-preview updates share the admin policy',
    (await request('/admin/link-preview',{token:ownerSession})).data.mode==='off');
  await tool(token,'cryptirc_notepad',{text:'Arch isolated note'});
  check('MCP reads and writes encrypted notepad data',(await tool(token,'cryptirc_notepad')).text==='Arch isolated note');
  check('MCP notepad is isolated by account',(await tool(otherKey,'cryptirc_notepad')).text==='');
  await tool(token,'irc_part',{network:networkA,channel});
  check('MCP part reached IRC',!!await otherWs.wait(e=>e.type==='irc_part'&&e.nick===owner&&e.channel===channel,'MCP part'));
  await tool(token,'irc_network',{action:'disconnect',network:networkA});
  await ownerWs.wait(e=>e.type==='disconnected'&&e.conn_id===networkA,'MCP disconnect');
  await tool(token,'irc_network',{action:'remove',network:networkA});
  check('MCP removes the selected test network',(await tool(token,'irc_state')).networks.length===0);
  check('MCP token is never stored in plaintext',!(await fs.readFile(path.join(tmp,'users',owner+'.json'),'utf8')).includes(token));

  const rotated=await request('/api/mcp/token',{method:'POST',headers:ownHeaders,token:ownerSession,body:{password}});
  check('replacement token invalidates original',(await rpc(token,'ping')).status===401&&(await rpc(rotated.data.token,'ping')).status===200);
  await request('/api/mcp/token',{method:'DELETE',headers:ownHeaders,token:ownerSession});
  check('explicit token revocation takes effect',(await rpc(rotated.data.token,'ping')).status===401);
  check('revoking one account leaves the second account alone',(await rpc(otherKey,'ping')).status===200);

  const begin=await request('/auth/passkeys/login/start',{method:'POST',headers:ownHeaders,body:{}});
  const staleAssertion=await ev(`(async()=>{const item=${JSON.stringify(begin.data)};const credential=await navigator.credentials.get(passkeyOptions(item.options));return {id:item.id,username:'',credential:passkeyResponse(credential)};})()`);
  await request('/auth/passkeys',{method:'DELETE',headers:ownHeaders,token:ownerSession,body:{id:passkeys.data.passkeys[0].id}});
  check('passkey removal is reflected in account settings',(await request('/auth/passkeys',{token:ownerSession})).data.passkeys.length===0);
  check('removing a passkey invalidates an in-flight assertion',(await request('/auth/passkeys/login/finish',{
    method:'POST',headers:ownHeaders,body:staleAssertion
  })).status===401);
  let keepNetwork, keepNick;
  if(process.env.CRYPTIRC_TEST_KEEPNICK==='1'){
    const fallback='pkf'+stamp, label='KeepNick fixture';
    keepNick='pkk'+stamp;
    const network={id:crypto.randomUUID(),label,server:'127.0.0.1',port:Number(IRC_PORT),
      tls:false,tls_accept_invalid_certs:false,nick:fallback,username:fallback,realname:'KeepNick fixture',
      auto_join:[],sasl_external:false,auto_reconnect:false};
    ownerWs.send({type:'add_network',network});
    const state=await ownerWs.wait(e=>e.type==='state'&&e.networks.some(n=>n.config.label===label),'KeepNick fixture network');
    keepNetwork=state.networks.find(n=>n.config.label===label).config.id;
    const waitOwner=(from,pred,name)=>waitFor(()=>ownerWs.events.slice(from).find(pred),name);
    let from=ownerWs.events.length;
    ownerWs.send({type:'connect',id:keepNetwork});
    await waitOwner(from,e=>e.type==='connected'&&e.conn_id===keepNetwork,'KeepNick fallback registered');
    const holdFrom=otherWs.events.length;
    otherWs.send({type:'send',conn_id:networkB,raw:'NICK '+keepNick});
    await waitFor(()=>otherWs.events.slice(holdFrom).find(e=>e.type==='irc_nick'&&e.new===keepNick),'other fixture holds desired nick');
    await waitFor(()=>ev(`networks.some(n=>n.config.id===${JSON.stringify(keepNetwork)})`),'browser sees KeepNick network');
    from=ownerWs.events.length;
    ownerWs.send({type:'keep_nick',conn_id:keepNetwork,nick:'a'.repeat(64)});
    check('KeepNick honors the testnet nickname length',
      /^KeepNick: This network allows nicknames up to /.test((await waitOwner(from,e=>e.type==='error','server nick length validation')).message));
    from=ownerWs.events.length;
    await ev(`setActive(${JSON.stringify(keepNetwork)},'status');handleInput(${JSON.stringify('/keepnick '+keepNick)})`);
    check('/keepnick saves the chosen nick even while another client holds it',
      (await waitOwner(from,e=>e.type==='keep_nick_updated'&&e.conn_id===keepNetwork,'KeepNick saved')).nick===keepNick);
    await ev(`handleInput(${JSON.stringify('/keepnick stop  '+fallback)})`);
    await waitFor(()=>ev(`document.body.textContent.includes('That nickname is not being kept on this network.')`),'a mismatched KeepNick stop is explained');
    from=ownerWs.events.length;
    await ev(`handleInput(${JSON.stringify('/unkeepnick '+keepNick)})`);
    check('/unkeepnick stops the chosen nick',
      (await waitOwner(from,e=>e.type==='keep_nick_updated'&&e.conn_id===keepNetwork,'KeepNick removed')).nick===null);
    from=ownerWs.events.length;
    await ev(`handleInput(${JSON.stringify('/keepnick '+keepNick)})`);
    await waitOwner(from,e=>e.type==='keep_nick_updated'&&e.conn_id===keepNetwork&&e.nick===keepNick,'KeepNick restored for restart');
    from=ownerWs.events.length;
    ownerWs.send({type:'update_network',network:{...network,id:keepNetwork,label:'Renamed KeepNick fixture'}});
    const edited=await waitOwner(from,e=>e.type==='state'&&e.networks.some(n=>n.config.label==='Renamed KeepNick fixture'),'network edit');
    check('an older network edit preserves KeepNick',edited.networks.find(n=>n.config.id===keepNetwork).config.keep_nick===keepNick);
    from=ownerWs.events.length;
    ownerWs.send({type:'disconnect',id:keepNetwork});
    await waitOwner(from,e=>e.type==='disconnected'&&e.conn_id===keepNetwork,'KeepNick fixture disconnect');
    from=ownerWs.events.length;
    ownerWs.send({type:'connect',id:keepNetwork});
    await waitOwner(from,e=>e.type==='connected'&&e.conn_id===keepNetwork,'KeepNick fallback reconnects');
    ownerWs.send({type:'get_state'});
    check('KeepNick survives disconnect and reconnect',
      (await waitOwner(from,e=>e.type==='state'&&e.networks.some(n=>n.config.id===keepNetwork&&n.connected),'reconnected KeepNick state')).networks.find(n=>n.config.id===keepNetwork).config.keep_nick===keepNick);

    const clearAt=Date.now();
    const savePrefs=prefs=>ownerWs.send({type:'save_preferences',prefs:JSON.stringify(prefs)});
    savePrefs({mentions:[],_mentionsTs:clearAt,_mentionsClearTs:clearAt});
    await ownerWs.wait(e=>e.type==='preferences'&&JSON.parse(e.prefs||'{}')._mentionsClearTs===clearAt,'Clear saved');
    const staleNotice={type:'mention',conn_id:keepNetwork,from:other,target:channel,text:'stale notice',ts:Math.floor(clearAt/1000)-1};
    savePrefs({mentions:[staleNotice],_mentionsTs:clearAt+1,_saveTs:'older-tab',unrelatedFixtureSetting:true});
    const repaired=await ownerWs.wait(e=>e.type==='preferences'&&JSON.parse(e.prefs||'{}').unrelatedFixtureSetting,'stale tab settings save');
    const prefs=JSON.parse(repaired.prefs);
    check('a stale preferences save preserves Clear and saves other settings',
      prefs._mentionsClearTs===clearAt&&prefs.mentions.length===0&&!prefs._saveTs);
    savePrefs({mentions:[staleNotice],_mentionsTs:clearAt-1,_mentionsClearTs:clearAt,earlierNoticeRevision:true});
    const older=await ownerWs.wait(e=>e.type==='preferences'&&JSON.parse(e.prefs||'{}').earlierNoticeRevision,'older notice revision saved');
    check('an older notice revision in the same Clear generation is ignored',
      JSON.parse(older.prefs).mentions.length===0);
  }
  check('Chromium produced no unhandled JavaScript exceptions',browser.errors.length===0);
  check('Chromium reported no script CSP violations during the UI checks',await ev('window.scriptPolicyViolations.length===0'));
  const htmlPaste=await request('/paste',{method:'POST',token:ownerSession,
    body:{content:'<p>Isolated HTML fixture</p>',language:'html',content_type:'html'}});
  assert.equal(htmlPaste.status,200);
  const pasteRoute='/paste/'+htmlPaste.data.id;
  await checkPagePolicy(pasteRoute);
  const appFrame=await fetch(base+pasteRoute+'/app');
  const appPolicy=appFrame.headers.get('content-security-policy');
  check('HTML paste frame still has an opaque script sandbox',
    appFrame.ok && appPolicy.startsWith('sandbox allow-scripts ') && !appPolicy.includes('allow-same-origin'));
  await cdp('Page.navigate',{url:base+pasteRoute});
  await waitFor(()=>ev("!!document.getElementById('tab-src')"),'HTML paste shell rendered');
  await ev("document.getElementById('tab-src').click()");
  check('the HTML paste Source tab works with strict CSP',
    await ev("getComputedStyle(document.getElementById('pane-src')).display==='block'"));
  if(keepNetwork){
    process.kill(-web.pid,'SIGTERM');
    await waitFor(()=>web.exitCode!==null||web.signalCode!==null,'fixture web exited');
    children.splice(children.indexOf(web),1);
    web=start(CRYPTIRC_BIN,[],env);
    await waitWeb();
    check('the original IRC core survived the CryptIRC web restart',core.exitCode===null&&core.signalCode===null);
    const fixtureSession=async username=>{
      const {status,data}=await request('/auth/login',{method:'POST',body:{username,password}});
      assert.equal(status,200,'fixture login after web restart');
      return connectWebsocket(data.token);
    };
    const reattached=async(ws,id)=>{
      let requested=0;
      return waitFor(()=>{
        const state=ws.events.find(e=>e.type==='state'&&e.networks.some(n=>n.config.id===id&&n.connected));
        if(!state&&Date.now()-requested>=500){ws.send({type:'get_state'});requested=Date.now();}
        return state;
      },'IRC session reattached');
    };
    const observer=await fixtureSession(other);
    await reattached(observer,networkB);
    const afterRestart=await fixtureSession(owner);
    const state=await reattached(afterRestart,keepNetwork);
    check('KeepNick survives a web restart and IRC core reattach',state.networks.find(n=>n.config.id===keepNetwork).config.keep_nick===keepNick);
    observer.send({type:'send',conn_id:networkB,raw:'NICK '+other});
    await observer.wait(e=>e.type==='irc_nick'&&e.old===keepNick&&e.new===other,'other client released desired nick');
    await waitFor(()=>afterRestart.events.find(e=>e.type==='irc_nick'&&e.conn_id===keepNetwork&&e.new===keepNick),
      'server reclaims KeepNick after release',75000);
    check('KeepNick reclaimed the released nick with the browser closed',true);
    afterRestart.send({type:'keep_nick',conn_id:keepNetwork,nick:keepNick.toUpperCase(),stop:true});
    check('stopping KeepNick matches the configured nick case-insensitively',
      (await afterRestart.wait(e=>e.type==='keep_nick_updated'&&e.conn_id===keepNetwork,'KeepNick stopped')).nick===null);
    afterRestart.send({type:'keep_nick',conn_id:keepNetwork,nick:keepNick,import:true});
    afterRestart.send({type:'get_state'});
    const stopped=await waitFor(()=>afterRestart.events.slice(afterRestart.events.indexOf(state)+1).find(e=>e.type==='state'&&
      e.networks.some(n=>n.config.id===keepNetwork&&n.config.keep_nick===null&&n.config.keep_nick_managed)), 'KeepNick stays stopped');
    check('an old browser’s import cannot restore an explicitly stopped nick',!!stopped);
  }
}
try {
  await runIntegration();
} catch (error) {
  for(const child of children.slice(0,2))if(child.logs)console.error(child.logs);
  throw error;
} finally {
  translator?.close();
  for(const server of fixtureServers)server.close();
  for(const socket of sockets)socket.close();
  for(const socket of tcpSockets)socket.destroy();
  for(const child of children)try{ process.kill(-child.pid,'SIGTERM'); }catch {}
  await pause(500);
  await fs.rm(tmp,{recursive:true,force:true,maxRetries:4,retryDelay:100});
}
