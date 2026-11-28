// End-to-end upgrade from an actual released web that holds two divergent
// conversations. Both durable IRC cores keep their original connections.
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {acceptIdentity,compose,login,setUpRecovery,unlockVault} from './e2e-chat-checks.mjs';

const q=JSON.stringify;
const assetHash=async url=>createHash('sha256').update(await (await fetch(url+'/e2e.js')).text()).digest('hex');

export async function checkDivergentWebUpgrade({core,base,env,tmp,owner,other,password,vault,stamp,start,stop,allocatePort,
  request,chromium,connectWebsocket,waitFor,check}){
  const opts=process.env,old=opts.CRYPTIRC_TEST_UPGRADE_OLD_BIN,next=opts.CRYPTIRC_BIN;
  assert(old&&next&&old!==next,'Set distinct old and replacement web binary paths');
  assert.equal(opts.CRYPTIRC_TEST_E2E,'1','Enable CRYPTIRC_TEST_E2E to observe actual outbound IRC messages');
  assert(Number(opts.IRC_PORT)&&Number(opts.IRC_LEAF_PORT)&&opts.IRC_PORT!==opts.IRC_LEAF_PORT,'Set two distinct linked test IRC ports');
  const cold=opts.CRYPTIRC_TEST_UPGRADE_COLD==='1',unanswered=opts.CRYPTIRC_TEST_UPGRADE_UNANSWERED==='1';
  const restartBy=opts.CRYPTIRC_TEST_UPGRADE_RESTART_BY||'original';
  const firstRole=opts.CRYPTIRC_TEST_UPGRADE_FIRST||'original';
  assert(['original','restarting'].includes(firstRole)&&['original','restarting'].includes(restartBy));
  const secondPort=await allocatePort(),remoteUrl='http://localhost:'+secondPort+'/cryptirc';
  const secondData=await fs.mkdtemp(path.join(tmp,'upgrade-peer-'));
  const remoteEnv={...env,CRYPTIRC_DATA:secondData,CRYPTIRC_PORT:String(secondPort),CRYPTIRC_BASE_URL:remoteUrl};
  await fs.writeFile(path.join(secondData,'admin_settings.json'),JSON.stringify({registration_open:true,captcha_enabled:false}));
  const remoteCore=start(opts.CRYPTIRC_PEER_CORE_BIN||opts.CRYPTIRC_CORE_BIN,[],remoteEnv);
  await waitFor(()=>fs.stat(path.join(secondData,'irc-core.sock')).catch(()=>null),'second isolated core is ready');
  const services=[
    {url:base,env,core,old,port:Number(opts.IRC_PORT),nick:owner,profile:'upgrade-one'},
    {url:remoteUrl,env:remoteEnv,core:remoteCore,old:opts.CRYPTIRC_TEST_UPGRADE_OLD_PEER_BIN||old,
      port:Number(opts.IRC_LEAF_PORT),nick:other,profile:'upgrade-two'},
  ];
  const pids=services.map(s=>s.core.pid);
  const serve=async(s,binary)=>{
    s.web=start(binary,[],s.env);
    await waitFor(()=>fetch(s.url+'/auth/status').then(r=>r.ok).catch(()=>false),'separate web is serving');
    return assetHash(s.url);
  };
  const attach=async s=>{
    const fresh=await request('/auth/login',{method:'POST',endpoint:s.url,body:{username:s.nick,password}});
    assert.equal(fresh.status,200);
    s.observer=await connectWebsocket(fresh.data.token,s.url);
  };
  for(const s of services){
    s.oldHash=await serve(s,s.old);
    check('old web registered its independent test account',(await request('/auth/register',{
      method:'POST',endpoint:s.url,body:{username:s.nick,password}})).status===200);
    s.page=await chromium(s.profile,s.url);
    await login(s.page,s.nick,password,waitFor);await unlockVault(s.page,vault);
    await waitFor(()=>s.page.evaluate('E2E._vaultUp&&E2E._krReceived'),'old account vault is ready');
    await s.page.evaluate('void e2ePromptDeviceUnlock()');
    s.recovery=await setUpRecovery(s.page,waitFor,check);
    await attach(s);
    const label='Archived linked IRC '+s.profile;
    s.observer.send({type:'add_network',network:{id:randomUUID(),label,server:'127.0.0.1',port:s.port,tls:false,
      tls_accept_invalid_certs:false,nick:s.nick,username:s.nick,realname:'Synthetic upgrade test',auto_join:[],sasl_external:false,auto_reconnect:false}});
    const st=await s.observer.wait(e=>e.type==='state'&&e.networks.some(n=>n.config.label===label),'old instance saved its linked network');
    s.cid=st.networks.find(n=>n.config.label===label).config.id;s.observer.send({type:'connect',id:s.cid});
    await s.observer.wait(e=>e.type==='connected'&&e.conn_id===s.cid,'old instance registered on IRC');
    await waitFor(()=>s.page.evaluate('networks.some(n=>n.config.id==='+q(s.cid)+'&&n.connected)'),'browser sees its IRC connection');
    s.publicKey=await s.page.evaluate("exportPub(E2E.identityKeys.dhKeyPair.publicKey,'ECDH')");
    s.origin=await s.page.evaluate('performance.timeOrigin');
    s.oldVersion=await s.page.evaluate('CRYPTIRC_VERSION');
  }
  const [a,b]=[...services].sort((x,y)=>Buffer.compare(Buffer.from(x.publicKey,'base64'),Buffer.from(y.publicKey,'base64')));
  const slot=(s,o)=>`_e2eDmKey(${q(o.nick)},${q(s.cid)})`;
  const state=(s,o)=>s.page.evaluate(`(()=>{const k=${slot(s,o)},v=E2E.dmSessions[k],t=E2E.trustStore[k];
    return {start:v?.startEph,pending:!!v?.x3dhPending,previous:v?.restartPrev?.until||0,alt:!!E2E._glareAlt?.[k],
      pin:t?.fingerprint,changed:!!t?.keyChanged};})()`);
  const visible=(s,o,text)=>s.page.evaluate(`getBuf(${q(s.cid)},${q(o.nick)}).some(m=>m.encrypted&&m.text===${q(text)})`);
  const restoredHistory=(s,o)=>s.page.evaluate(`(()=>{
    const v=E2E.dmSessions[${slot(s,o)}],nick=${q(s.nick)},peer=${q(o.nick)};
    const rows=getBuf(${q(s.cid)},peer).filter(r=>r.encrypted&&r._dmHistoryWire?.startsWith(E2E_DM_PREFIX))
      .slice().sort((left,right)=>left.ts-right.ts||(left.id||0)-(right.id||0));
    let currentChainSent=0,readableIncoming=0,incomingAfterCurrentSend=0;
    for(const r of rows){
      if(r._dmHistoryState!=='ready')continue;
      if(r.from===nick){try{
        const envelope=JSON.parse(atob(r._dmHistoryWire.slice(E2E_DM_PREFIX.length)));
        if(v?.DHs?.pub&&envelope.h?.d===v.DHs.pub)currentChainSent++;
      }catch{} }
      if(r.from===peer){readableIncoming++;if(currentChainSent)incomingAfterCurrentSend++;}
    }
    return {loadedRows:rows.length,currentChainSent,readableIncoming,incomingAfterCurrentSend,
      session:!!v,receiveChain:!!v?.CKr,pending:!!v?.x3dhPending,
      priorOffers:Array.isArray(v?.priorEstablishEphs)?v.priorEstablishEphs.length:0,
      previousReceive:!!v?.restartPrev,explicitPredecessor:!!v?.x3dhPending?.restart_sig};
  })()`);
  const send=async(s,o,text)=>{
    const index=s.page.frames.length,mark=o.observer.events.length;
    await compose(s.page,s.cid,o.nick,text);
    const outgoing=()=>s.page.frames.slice(index).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===s.cid&&e.raw?.startsWith('PRIVMSG '+o.nick+' :'));
    const received=()=>o.observer.events.slice(mark).filter(e=>e.type==='irc_message'&&e.conn_id===o.cid&&e.from===s.nick);
    const wires=()=>outgoing().map(e=>e.raw.split(' :')[1]).filter(body=>body.startsWith('[e2edm2]'));
    const relays=()=>received().filter(e=>wires().includes(e.text)).length;
    const relayed=await waitFor(()=>relays()>0,'the independent peer receives an encrypted PM',16000).catch(()=>false);
    const opened=relayed&&await waitFor(()=>visible(o,s,text),'the peer opens the exact encrypted PM',18000).catch(()=>false);
    return {opened:!!opened,submitted:wires().length,relayed:relays(),
      clear:outgoing().some(e=>e.raw.endsWith(' :'+text))||received().some(e=>e.text===text)};
  };
  const good=r=>r.opened&&r.submitted===1&&r.relayed===1&&!r.clear;
  const exchange=async(s,o,label)=>[await send(s,o,label+' A '+stamp),await send(o,s,label+' B '+stamp)];
  for(const [s,o] of [[a,b],[b,a]])await s.page.evaluate('setActive('+q(s.cid)+','+q(o.nick)+')');
  await compose(a.page,a.cid,b.nick,'/encrypt on '+b.nick);await acceptIdentity(a.page,waitFor);
  await waitFor(async()=>(await state(a,b)).pending,'old original user creates an initial Signal offer');
  const original='old initial '+stamp;
  await compose(a.page,a.cid,b.nick,original);await acceptIdentity(b.page,waitFor);
  await waitFor(()=>visible(b,a,original),'old peer opens the first PM');
  if(!unanswered){
    const prior=await state(b,a);
    await compose(b.page,b.cid,a.nick,'/encrypt restart '+a.nick);
    await waitFor(async()=>{const s=await state(b,a);return s.pending&&s.start!==prior.start&&s.previous;},'old peer explicitly starts a replacement');
    check('original author receives the genuine new offer over linked IRC',good(await send(b,a,'old replacement '+stamp)));
  }
  const [left,right]=await Promise.all([state(a,b),state(b,a)]);
  if(unanswered){
    const responses=b.page.frames.map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===b.cid&&e.raw?.startsWith('PRIVMSG '+a.nick+' :[e2edm2]'));
    check('recipient read the original message and sent zero encrypted replies before upgrading',
      left.pending&&!right.pending&&left.start===right.start&&!left.alt&&!right.previous&&!responses.length);
  }else{
    check('old users demonstrably hold separate canonical sessions while both read chat',
      left.start!==right.start&&left.pending&&right.pending&&left.alt&&right.previous&&!left.changed&&!right.changed&&
      (await exchange(a,b,'before update')).every(good));
  }
  if(cold){
    if(!unanswered)await waitFor(async()=>Date.now()>right.previous&&!(await state(b,a)).previous,'the actual previous receive window expires',340000);
    for(const s of services){
      await stop(s.page.chrome);
      await fs.rm(path.join(tmp,s.profile,'DevToolsActivePort'),{force:true});
    }
    check('both original browsers exited before upgrading either web',services.every(s=>s.page.chrome.exitCode!==null||s.page.chrome.signalCode!==null));
  }
  for(const s of services)await stop(s.web);
  for(const s of services)s.newHash=await serve(s,next);
  check('both served E2E assets changed while both original linked IRC cores kept running',
    services[0].oldHash===services[1].oldHash&&services[0].newHash===services[1].newHash&&services.every((s,i)=>
      s.newHash!==s.oldHash&&(!opts.CRYPTIRC_TEST_UPGRADE_OLD_E2E_SHA||opts.CRYPTIRC_TEST_UPGRADE_OLD_E2E_SHA===s.oldHash)&&
      (!opts.CRYPTIRC_TEST_UPGRADE_NEW_E2E_SHA||opts.CRYPTIRC_TEST_UPGRADE_NEW_E2E_SHA===s.newHash)&&
      s.core.pid===pids[i]&&s.core.exitCode===null&&s.core.signalCode===null));
  for(const [s,o] of [[a,b],[b,a]]){
    if(cold)s.page=await chromium(s.profile,s.url);
    else await s.page.send('Page.reload');
    await waitFor(()=>s.page.evaluate('performance.timeOrigin!=='+s.origin+
      "&&typeof doLogin==='function'&&(_wsReady()||getComputedStyle(document.getElementById('auth-screen')).display!=='none')").catch(()=>false),'replacement page ready');
    if(!(await s.page.evaluate('_wsReady()')))await login(s.page,s.nick,password,waitFor);
    await unlockVault(s.page,vault);
    await waitFor(()=>s.page.evaluate('E2E._vaultUp&&E2E._krReceived'),'remembered account vault loaded');
    s.recoveryNeeded=!await waitFor(()=>s.page.evaluate('E2E.keyReady&&E2E.identityReady'),'remembered encryption unlock',10000).catch(()=>false);
    if(s.recoveryNeeded){
      await s.page.evaluate('void e2ePromptDeviceUnlock()');
      await waitFor(()=>s.page.evaluate("document.getElementById('custom-prompt-overlay').classList.contains('open')"),'ordinary device recovery prompt');
      await s.page.evaluate("document.getElementById('custom-prompt-input').value="+q(s.recovery)+";document.getElementById('custom-prompt-ok').click()");
      await waitFor(()=>s.page.evaluate('E2E.identityReady'),'recovered original device identity');
    }
    await attach(s);
    await s.page.evaluate('_sidebarActivate('+q(s.cid)+','+q(o.nick)+')');
  }
  const restored=await Promise.all([[a,b],[b,a]].map(async([s,o])=>{
    await waitFor(async()=>{
      const h=await restoredHistory(s,o);return unanswered?h.loadedRows>=1&&(s===a||h.readableIncoming>=1):h.loadedRows>=4&&h.readableIncoming>=2;
    },'the remembered profile finishes loading its prior authenticated rows',12000).catch(()=>false);
    return restoredHistory(s,o);
  }));
  console.log('BEFORE-FIRST-UPGRADED-PM '+JSON.stringify({cold,unanswered,firstRole,original:restored[0],peer:restored[1]}));
  if(unanswered)check('recipient still reads the originally unanswered PM after the web upgrade',await visible(b,a,original));
  const foregroundRace=opts.CRYPTIRC_TEST_FOREGROUND_LEGACY_RACE;
  if(foregroundRace){
    assert(unanswered && ['preflight','bundle'].includes(foregroundRace));
    const duringBundle=foregroundRace==='bundle';
    const key=slot(a,b), before=await state(a,b);
    check('phone restored an original unconfirmed offer from the earlier release',before.pending&&
      await a.page.evaluate(`!!_e2eLegacyPendingStart(E2E.dmSessions[${key}])`));
    await a.page.evaluate(`(()=>{
      const run=_e2eRunEncryptCommand, handle=e2eHandleEvent, connect=connectWs;
      window.foregroundRace={resume:()=>{connectWs=connect;_onResume();},finish:async()=>{
        _e2eRunEncryptCommand=run;e2eHandleEvent=handle;
        await foregroundRace.release();
      }};
      if(${duringBundle}) e2eHandleEvent=event=>{
        const pending=E2E._pendingOn?.[${key}];
        if(event.type==='e2e_bundle'&&pending?.migration&&event.req===pending.req){
          foregroundRace.release=()=>handle(event);
          return Promise.resolve();
        }
        return handle(event);
      };
      else _e2eRunEncryptCommand=async(...args)=>{
        if(args[4]) await new Promise(resolve=>{foregroundRace.release=resolve;});
        return run(...args);
      };
      connectWs=()=>{};ws.close();
    })()`);
    await waitFor(()=>a.page.evaluate('!_wsReady()'),'the phone WebSocket closes in the background');
    await a.page.evaluate('foregroundRace.resume()');
    await waitFor(()=>a.page.evaluate('_wsReady() && !E2E._resyncPending'),'the foregrounded phone reconnects');
    const draft='resume '+stamp, reply='reply '+stamp;
    const from=a.page.frames.length, observed=b.observer.events.length;
    await compose(a.page,a.cid,b.nick,draft);
    await waitFor(()=>a.page.evaluate('!!foregroundRace.release'),'automatic migration waits at '+foregroundRace);
    await compose(b.page,b.cid,a.nick,reply);
    await waitFor(()=>visible(a,b,reply),'the phone reads the real first reply during migration');
    await waitFor(()=>a.page.evaluate(`E2E.dmSessions[${key}]?.CKr&&!E2E.dmSessions[${key}]?.x3dhPending`),
      'the authenticated reply confirms the original ratchet');
    if(!duringBundle) await a.page.evaluate('foregroundRace.finish()');
    const opened=await waitFor(()=>visible(b,a,draft),'the peer reads the new draft without a restart',5500).catch(()=>false);
    if(duringBundle) await a.page.evaluate('foregroundRace.finish()');
    const events=b.observer.events.slice(observed).filter(e=>e.type==='irc_message'&&e.from===a.nick);
    const frames=a.page.frames.slice(from).map(JSON.parse);
    const after=await state(a,b);
    check('the confirmed session delivers the foreground draft once and ignores a redundant restart',opened&&
      after.start===before.start&&after.pin===before.pin&&!after.pending&&
      frames.filter(e=>e.type==='e2e_fetch_bundle').length===Number(duringBundle)&&
      events.filter(e=>e.text?.startsWith('[e2edm2]')).length===1&&!events.some(e=>e.text===draft));
    return;
  }
  const [sender,recipient]=firstRole==='original'?[a,b]:[b,a];
  const firstText='new first '+stamp,replyText='new reply '+stamp;
  const first=await send(sender,recipient,firstText),reply=await send(recipient,sender,replyText);
  const followup=await exchange(sender,recipient,'next');
  const eventual=[await visible(recipient,sender,firstText),await visible(sender,recipient,replyText)];
  let manual=null;
  if(![first,reply,...followup].every(good)){
    const [from,to]=restartBy==='original'?[a,b]:[b,a];
    await waitFor(()=>from.page.evaluate(`!_sendLock&&Date.now()-(_e2eRestartRequested.get(JSON.stringify([_e2eUser(),${slot(from,to)}]))||0)>=15100`),
      'first explicit restart is available',30000);
    await compose(from.page,from.cid,to.nick,'/encrypt restart '+to.nick);
    await waitFor(()=>from.page.evaluate(`!_sendLock&&!E2E._pendingOn?.[${slot(from,to)}]`),'one explicit restart finishes',45000);
    manual={by:restartBy,exchange:await exchange(from,to,'after one restart')};
  }
  const [nowA,nowB]=await Promise.all([state(a,b),state(b,a)]);
  const pins=!!left.pin&&!!right.pin&&nowA.pin===left.pin&&nowB.pin===right.pin&&!nowA.changed&&!nowB.changed;
  console.log('DIVERGENT-WEB-UPGRADE '+JSON.stringify({oldVersion:a.oldVersion,oldAsset:a.oldHash,newAsset:a.newHash,
    cold,unanswered,firstRole,first,reply,eventual,followup,manual,pins,recoveryEntries:services.filter(s=>s.recoveryNeeded).length}));
  check('first protected message and first reply each reach the intended displayed conversation exactly once',good(first)&&good(reply));
  check('both follow-up messages open once and the original trust pins survive the web-only upgrade',followup.every(good)&&pins);
}
