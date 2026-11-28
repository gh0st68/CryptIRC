import fs from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {checkFirstSignalReaction,checkReactionDuringSignalSetup,checkRestartedSignalReaction,checkSealedReaction,prepareResumeReaction,checkResumeReaction,reactionButton,reactionRow} from './reaction-checks.mjs';

const q = JSON.stringify;
const promptOpen = "document.getElementById('custom-prompt-overlay').classList.contains('open')";
const promptText = "document.getElementById('custom-prompt-msg').textContent";
const input = "document.getElementById('custom-prompt-input')";
const acceptPrompt = "document.getElementById('custom-prompt-ok').click()";
const cancelPrompt = "document.getElementById('custom-prompt-cancel').click()";
const openEncryptionSettings = "document.querySelector('[data-cryptirc-click=openEncryptionSettings]').click();"+
  "document.querySelector('#encrypt-panel-body [data-encrypt-cmd=unlock]').click()";
const setupText = 'Copy this E2E recovery code';
const unlockText = 'Enter your E2E recovery code';
const panelUnlock = '#encrypt-panel-body [data-encrypt-cmd=unlock]';
const setupButton = '#chat-area .e2e-setup-button';
const plainPrompt = "Array.from(document.querySelectorAll('button')).find(button=>['Send unencrypted','Allow unencrypted'].includes(button.textContent)&&button.offsetWidth)";

const fillPrompt = (browser, value) => browser.evaluate(input + '.value=' + q(value) + ';' + acceptPrompt);
const waitPrompt = (browser, waitFor, text) => waitFor(
  () => browser.evaluate(promptOpen + '&&' + promptText + '.includes(' + q(text) + ')'), text);

export async function unlockVault(browser, vault) {
  await browser.evaluate("document.getElementById('vault-pass').value=" + q(vault) + ';doUnlock()');
}

export async function login(browser, user, password, waitFor) {
  await browser.evaluate("document.getElementById('l-user').value=" + q(user) +
    ";document.getElementById('l-pass').value=" + q(password) + ';doLogin()');
  await waitFor(() => browser.evaluate('!!sessionToken&&_wsReady()'), 'browser connected for '+user);
}

async function reopen(browser, waitFor, ready, description) {
  const oldDocument = await browser.evaluate('performance.timeOrigin');
  await browser.send('Page.reload');
  await waitFor(() => browser.evaluate(`performance.timeOrigin!==${oldDocument} &&
    document.readyState==='complete' && (${ready})`).catch(()=>false), description);
}

export async function setUpRecovery(browser, waitFor, check) {
  try { await waitPrompt(browser, waitFor, setupText); }
  catch(error){
    const state=await browser.evaluate(`({phase:E2E._bootPhase,vault:E2E._vaultUp,socket:_wsReady(),
      deviceLocked:encryptionDeviceLocked(),discovered:E2E._krReceived,interactive:!!E2E._interactiveUnlock,
      promptOpen:${promptOpen},setupControl:document.querySelector('.e2e-setup-button')?.textContent||null})`);
    throw new Error(error.message+' '+JSON.stringify(state));
  }
  const code = await browser.evaluate(input + '.value');
  check('browser generated a 256-bit recovery code', /^[A-Za-z0-9_-]{43}$/.test(code));
  await browser.evaluate(acceptPrompt);
  await waitPrompt(browser, waitFor, 'Paste your saved E2E recovery code');
  await fillPrompt(browser, code);
  await waitFor(() => browser.evaluate("E2E._bootPhase==='ready'&&E2E.identityReady"), 'recovery keyring and identity ready', 35000);
  check('browser clears the recovery input after setup', await browser.evaluate(input + ".value===''"));
  check('recovery code stays out of captured WebSocket frames',
    browser.frames.some(frame => frame.includes('"type":"e2e_store_keyring"')) &&
    !browser.frames.some(frame => frame.includes(code)));
  return code;
}

// One contact is established over linked IRC by the surrounding fixture. The
// other five use independent signed test bundles and the normal ratchet store.
async function checkSixContactIdentityReset(browser, network, peer, confirmReset, check) {
  async function seedContacts(network, peer) {
    const original = _e2eDmKey(peer, network);
    const firstEpoch = E2E.dmSessions[original].epoch;
    const contacts = [original];
    const [ownDH, ownSign] = await _e2ePublicIdentity(E2E.identityKeys);
    const dhPair = () => crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits','deriveKey']);
    const sign = async (key, bytes) => bytesToBase64(new Uint8Array(
      await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,bytes)));
    for (let i=1; i<=5; i++) {
      const slot = _e2eDmKey('resetfixture'+i, network);
      const [dh, signer, prekey] = await Promise.all([dhPair(),
        crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']), dhPair()]);
      const [peerDH, peerSign, spk] = await Promise.all([exportPub(dh.publicKey,'ECDH'),
        exportPub(signer.publicKey,'ECDSA'),exportPub(prekey.publicKey,'ECDH')]);
      const bundle = {identity_dh_key:peerDH,identity_sign_key:peerSign,
        signed_prekey:{key_id:1,public_key:spk,signature:await sign(signer.privateKey,base64ToBytes(spk))}};
      const x = await x3dhInitiate(bundle);
      try {
        const header = {sender_ik:ownDH,sender_sign_ik:ownSign,ephemeral_pub:x.ephemeralPub,spk_id:1,
          used_otpk_id:x.usedOTPKId,sender_sign_sig:await sign(E2E.identityKeys.signKeyPair.privateKey,
            _x3dhHeaderSigMsg(ownDH,x.ephemeralPub,1,x.usedOTPKId))};
        await _withRatchetLock(slot,()=>ratchetInitSend(slot,x.sharedSecret,spk,peerDH,x.identityAD,
          {connId:network,theirSignPub:peerSign,x3dhHeader:header}));
      } finally { x.sharedSecret.fill(0); }
      while (E2E.dmSessions[slot].epoch < firstEpoch+i) await ratchetEncrypt(slot,'disposable ratchet step');
      contacts.push(slot);
    }
    const epochs = [];
    for (const slot of contacts) {
      const response = await _e2eRequestSession(slot);
      if (!response?.blob || await _e2eSha256Hex(response.blob)!==E2E.dmSessions[slot]._storeRevision)
        throw new Error('The server did not confirm the seeded revision');
      const bytes = await aesDecryptBlob(response.blob,_e2eCtxSession(slot));
      try {
        const record = JSON.parse(new TextDecoder().decode(bytes));
        if (!record.RK || !await _e2eUsesCurrentIdentity(record)) throw new Error('Incorrect stored identity');
        epochs.push(record.epoch);
      } finally { bytes.fill(0); }
    }
    return {contacts,epochs};
  }
  const {contacts,epochs} = await browser.evaluate(`(${seedContacts})(${JSON.stringify(network)},${JSON.stringify(peer)})`);
  check('six independent scoped ratchets have increasing authenticated generations',
    epochs.length===6 && epochs.every((v,i)=>Number.isSafeInteger(v) && v===epochs[0]+i));
  const originalIdentity = await browser.evaluate('_e2eOwnFingerprint()');
  await confirmReset();
  const result = await browser.evaluate(`(async slots=>{
    const replies=await Promise.all(slots.map(slot=>_e2eRequestSession(slot,true)));
    const floor=await _e2eReadSessionFloor(replies[0]?.floor_blob,_e2eUser());
    return {identity:await _e2eOwnFingerprint(),absent:replies.filter(reply=>reply?.blob==='' && typeof reply.floor_blob==='string').length,floor:floor?.epoch};
  })(${JSON.stringify(contacts)})`);
  console.log('SIX-CONTACT-RESET '+JSON.stringify({epochs,absent:result.absent,floor:result.floor,rotated:result.identity!==originalIdentity}));
  check('one confirmed identity reset retires all six contacts and retains the highest generation',
    result.identity!==originalIdentity && result.absent===6 && result.floor>epochs.at(-1));
}

async function waitForSetupTapPoint(device,waitFor) {
  return waitFor(()=>device.evaluate(`(async()=>{
    await document.fonts.ready;
    const button=document.querySelector(${q(setupButton)});
    if(!button||button.disabled)return false;
    const before=button.getBoundingClientRect();
    await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
    if(!button.isConnected)return false;
    const after=button.getBoundingClientRect();
    const x=after.left+after.width/2, y=after.top+after.height/2;
    return Math.abs(x-before.left-before.width/2)<1&&Math.abs(y-before.top-before.height/2)<1&&
      button.contains(document.elementFromPoint(x,y))?{x,y}:false;
  })()`),'private encryption setup button has a stable, unobstructed touch position');
}

async function tapSetupWithHistory(device, conn, nick, text, waitFor, check) {
  const probe='window.e2eSetupTouchFixture';
  const start=point=>device.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[point]});
  const end=()=>device.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
  await device.evaluate(`_sidebarActivate(${q(conn)},${q(nick)});
    wsend({type:'get_logs',conn_id:${q(conn)},target:${q(nick)},limit:50})`);
  await waitFor(()=>device.evaluate(`!!${probe}.history&&!!document.querySelector(${q(setupButton)})`),
    'actual history reply and setup button are ready for the mobile tap');
  const controlPoint=async()=>{
    await device.evaluate(`document.querySelector(${q(setupButton)}).scrollIntoView({block:'nearest',behavior:'instant'});`+
      `${probe}.button=document.querySelector(${q(setupButton)})`);
    return waitForSetupTapPoint(device,waitFor);
  };
  if(text){
    const drag=await controlPoint();
    await start(drag);
    await device.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:drag.x,y:drag.y+20}]});
    await end();
    check('dragging from the setup button does not open recovery',await device.evaluate(`${probe}.unlockCount===0`));
    await start(await controlPoint());
    await new Promise(resolve=>setTimeout(resolve,2300));
    await end();
    check('releasing the setup button after a long press does not open recovery',
      await device.evaluate(`${probe}.unlockCount===0`));
    await start(await controlPoint());
    await device.evaluate(`_sidebarActivate(${q(conn)},'status')`);
    await end();
    check('releasing an old setup press after switching conversations does not open recovery',
      await device.evaluate(`${probe}.unlockCount===0`));
    await device.evaluate(`_sidebarActivate(${q(conn)},${q(nick)})`);
  }
  const point=await controlPoint();
  await start(point);
  try{
    await device.evaluate(`${probe}.deliver(${probe}.history)`);
    await waitFor(()=>device.evaluate(`!_processingLogs.has(${q(conn+'/'+nick)})&&
      (!${q(text)}||getBuf(${q(conn)},${q(nick)}).some(message=>message.text===${q(text)}))`),
    'the actual history merges during the pressed mobile control',1400);
    check(text?'a nonempty history reply defers repainting the pressed setup control':'an empty history reply does not replace the pressed setup control',
      await device.evaluate(`${probe}.button.isConnected&&(!${q(text)}||
        !document.getElementById('chat-area').textContent.includes(${q(text)}))`));
    if(text)check('the original setup control moves away from the stationary finger before release',await device.evaluate(`(()=>{
      const button=${probe}.button;
      button.style.transform='translateX(170px)';
      return button.isConnected&&!button.contains(document.elementFromPoint(${point.x},${point.y}));
    })()`));
  }finally{
    await end();
  }
  if(text) check('the merged history remains visible after completing the setup tap',await waitFor(()=>device.evaluate(`
    document.getElementById('chat-area').textContent.includes(${q(text)})`),'history is rendered after the native tap'));
  await waitPrompt(device,waitFor,setupText);
  check('the original stationary touch opens recovery once',await device.evaluate(`${probe}.unlockCount===1`));
}

async function keyringOnDisk(tmp, user) {
  const file = path.join(tmp, 'e2e', user, 'keyring.json');
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

export async function seedLegacyE2e({browser, waitFor, check, tmp, user, password, vault, channel}) {
  await login(browser, user, password, waitFor);
  await unlockVault(browser, vault);
  await waitFor(() => browser.evaluate("E2E._bootPhase==='ready'&&E2E.identityReady"), 'old client E2E setup', 35000);
  await browser.evaluate('handleEncryptCommand(["keygen"],null,' + q(channel) + ')');
  await waitFor(async () => {
    const names = await fs.readdir(path.join(tmp, 'e2e', user, 'channels')).catch(() => []);
    return names.some(name => name.endsWith('.enc'));
  }, 'old client saved the channel key');
  const oldKeyring = await keyringOnDisk(tmp, user);
  check('previous release wrote a real v2 keyring', oldKeyring.blob.startsWith('e2k2.') && oldKeyring.migrated);
  const identity = await browser.evaluate('Promise.all([exportPub(E2E.identityKeys.dhKeyPair.publicKey,"ECDH"),exportPub(E2E.identityKeys.signKeyPair.publicKey,"ECDSA")])');
  const channelKey = await browser.evaluate('crypto.subtle.exportKey("raw",E2E.channelKeys[' + q(channel) + ']).then(k=>bytesToBase64(new Uint8Array(k)))');
  return {identity, channelKey};
}

export async function checkLegacyMigration({browser, waitFor, check, tmp, user, password, vault, channel, legacy}) {
  await login(browser, user, password, waitFor);
  await unlockVault(browser, vault);
  await waitFor(() => browser.evaluate('!document.getElementById("e2e-setup-offer").hidden'), 'legacy recovery offer');
  check('legacy recovery setup is offered without a passphrase popup', !await browser.evaluate(promptOpen));
  await browser.evaluate("document.querySelector('[data-cryptirc-click=ignoreEncryptionSetup]').click()");
  check('ignoring the offer hides it', await browser.evaluate('document.getElementById("e2e-setup-offer").hidden'));
  await browser.evaluate(openEncryptionSettings);
  await waitPrompt(browser, waitFor, 'Enter your vault passphrase');
  await fillPrompt(browser, vault+'-incorrect');
  await waitFor(() => browser.evaluate('!E2E._devicePromptPending && !('+promptOpen+')'), 'a wrong vault passphrase frees the unlock request');
  await browser.evaluate(openEncryptionSettings);
  await waitPrompt(browser, waitFor, 'Enter your vault passphrase');
  await fillPrompt(browser, vault);
  const code = await setUpRecovery(browser, waitFor, check);
  check('legacy account migrated to a finalized v3 keyring', await waitFor(async () => {
    const stored = await keyringOnDisk(tmp, user);
    if (!stored.blob.startsWith('e2k3.')) return false;
    const v3 = JSON.parse(Buffer.from(stored.blob.slice(5), 'base64').toString());
    return stored.migrated && Buffer.from(v3.w, 'base64').length === 60 && !JSON.stringify(stored).includes(code);
  }, 'v3 keyring dropped the previous key'));
  const identity = await browser.evaluate('Promise.all([exportPub(E2E.identityKeys.dhKeyPair.publicKey,"ECDH"),exportPub(E2E.identityKeys.signKeyPair.publicKey,"ECDSA")])');
  check('migration preserves both identity fingerprints', identity.every((key, i) => key === legacy.identity[i]));
  await waitFor(() => browser.evaluate('!!E2E.channelKeys[' + q(channel) + ']'), 'migrated channel key loaded');
  check('migration preserves the shared channel key', await browser.evaluate(
    'crypto.subtle.exportKey("raw",E2E.channelKeys[' + q(channel) + ']).then(k=>bytesToBase64(new Uint8Array(k)))'
  ) === legacy.channelKey);
  const dir = path.join(tmp, 'e2e', user);
  const files = [path.join(dir, 'identity.enc')];
  for (const sub of ['sessions', 'channels']) {
    files.push(...(await fs.readdir(path.join(dir, sub))).filter(name => name.endsWith('.enc')).map(name => path.join(dir, sub, name)));
  }
  check('migration wraps identity, prekeys and channel secrets under v3', (await Promise.all(
    files.map(file => fs.readFile(file, 'utf8'))
  )).every(blob => blob.startsWith('e2e3.')));
  const archivedDm = await browser.evaluate(`(async () => {
    const fixtureNick = 'legacydmfixture';
    const [peerDh, peerSign, localDh] = await Promise.all([
      crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),
      crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),
      crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits'])
    ]);
    const peerPub = await exportPub(peerDh.publicKey,'ECDH');
    const peerSignPub = await exportPub(peerSign.publicKey,'ECDSA');
    const myIdentity = E2E.identityKeys;
    const ad = e2eIdentityAD(await exportPub(myIdentity.dhKeyPair.publicKey,'ECDH'),
      await exportPub(myIdentity.signKeyPair.publicKey,'ECDSA'),peerPub,peerSignPub);
    const localRatchet = {pub:await exportPub(localDh.publicKey,'ECDH'),
      priv:await crypto.subtle.exportKey('jwk',localDh.privateKey)};
    const fixtureText = 'A message authenticated under an archived ratchet';
    const fixture = async cid => {
      const key = _e2eDmKey(fixtureNick,cid), slot = '__legacy__'+key;
      const secret = crypto.getRandomValues(new Uint8Array(64));
      const session = await ratchetInitRecv(key,secret,peerPub,bytesToBase64(ad),peerPub,localRatchet,
        {connId:cid,theirSignPub:peerSignPub});
      session.epoch = 2;
      session.DHr = peerPub;
      const [mk] = await chainKeyStep(secret.subarray(32));
      const header = {dh:peerPub,pn:0,n:0};
      const c = await messageEncrypt(mk,new TextEncoder().encode(fixtureText),header,ad);
      const wire = E2E_DM_PREFIX+btoa(JSON.stringify({h:{d:header.dh,p:header.pn,n:header.n},c:bytesToBase64(c)}));
      const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(session)),_e2eCtxSession(slot));
      await _e2eWs({type:'e2e_store_session',partner:slot,blob});
      return {cid,key,slot,session,wire,stored:(await _e2eFetchSession(slot))===blob};
    };
    const stopped = await fixture(crypto.randomUUID());
    const other = await fixture(crypto.randomUUID());
    const archiveOnly = stopped.stored&&other.stored&&!(await _e2eFetchSession(stopped.key));
    await handleEncryptCommand(['off'],stopped.cid,fixtureNick);
    const removed = !(await _e2eFetchSession(stopped.slot))&&!!(await _e2eFetchSession(other.slot));
    E2E.dmSessions[stopped.key] = stopped.session;
    let blocked;
    try {
      const result = await e2eDecryptIncoming(fixtureNick,fixtureNick,stopped.wire,{conn_id:stopped.cid,live:true});
      blocked = result.encrypted&&result.plaintext.includes('/encrypt on '+fixtureNick)&&
        E2E.state.dm[stopped.key]?.on===0&&!(await _e2eFetchSession(stopped.key));
    } finally { delete E2E.dmSessions[stopped.key]; }
    const invalid = JSON.parse(atob(other.wire.slice(E2E_DM_PREFIX.length)));
    const corrupt = base64ToBytes(invalid.c);
    corrupt[corrupt.length-1] ^= 1;
    invalid.c = bytesToBase64(corrupt);
    const rejected = await e2eDecryptIncoming(fixtureNick,fixtureNick,E2E_DM_PREFIX+btoa(JSON.stringify(invalid)),
      {conn_id:other.cid,live:true});
    const kept = rejected.plaintext!==fixtureText&&!E2E.dmSessions[other.key]&&!E2E.state.dm[other.key]?.on&&
      !!(await _e2eFetchSession(other.slot))&&!(await _e2eFetchSession(other.key));
    const resumed = await e2eDecryptIncoming(fixtureNick,fixtureNick,other.wire,{conn_id:other.cid,live:true});
    return {archiveOnly,removed,blocked,kept,restored:resumed.plaintext===fixtureText&&E2E.state.dm[other.key]?.on===1};
  })()`);
  check('disabling an archived Signal DM removes only its network slot and blocks stale headerless messages',
    archivedDm.archiveOnly&&archivedDm.removed&&archivedDm.blocked);
  check('an archived Signal session survives an invalid message and restores after authenticating a genuine one',
    archivedDm.kept&&archivedDm.restored);
  check('migration browser had no unhandled exceptions', browser.errors.length === 0);
}

export async function compose(browser, network, target, text) {
  await browser.evaluate('setActive(' + q(network) + ',' + q(target) + ');' +
    "document.getElementById('msg-input').focus();document.getElementById('msg-input').value=" + q(text));
  await browser.send('Input.dispatchKeyEvent', {type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await browser.send('Input.dispatchKeyEvent', {type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
}

async function checkManualEnableDraft({browser,peer,check,waitFor,owner,other,otherWs,networkA,networkB,stamp}) {
  const slot=`_e2eDmKey(${q(other)},${q(networkA)})`;
  const composer="document.getElementById('msg-input')";
  await peer.evaluate('void e2ePromptDeviceUnlock()');
  await waitPrompt(peer,waitFor,setupText);
  await peer.evaluate(cancelPrompt);
  await waitFor(()=>peer.evaluate("!E2E.identityReady&&!E2E._interactiveUnlock&&_e2eLsGet(_e2eSetupPreference())===true"),'recipient chooses Ignore and stays connected to IRC');
  await compose(browser,networkA,other,'/encrypt off '+other);
  const disabled=()=>browser.evaluate(`(async()=>{if(_sendLock||E2E._stateSaving||E2E.state?.dm[${slot}]?.on!==0)return false;
    const record=await _e2eRequestSession(${slot},true);const state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
    return record?.blob===''&&typeof record.floor_blob==='string'&&state.dm[${slot}]?.on===0;})()`);
  check('the sender explicitly turned encryption off and the authenticated contact slot is empty',await waitFor(disabled,'confirmed off setting and empty slot'));
  await browser.evaluate(`(()=>{
    const req=_e2eReq,handle=e2eHandleEvent,original=fetch;
    const probe=window.manualEnableDraft={release:null,phase:null,reasons:[],translated:[]};
    _e2eReq=async(message,...args)=>{
      if(probe.phase==='preflight'&&E2E._pendingOn?.[${slot}]?.checking&&message.type==='e2e_load_session'&&message.partner===${slot}){
        probe.phase=null;await new Promise(resolve=>{probe.release=resolve;});
      }
      return req(message,...args);
    };
    e2eHandleEvent=async event=>{
      if(event.type==='e2e_bundle_missing'&&event.req===E2E._pendingOn?.[${slot}]?.req){
        probe.reasons.push(event.reason);
        if(probe.phase==='bundle'){probe.phase=null;await new Promise(resolve=>{probe.release=resolve;});}
      }
      return handle(event);
    };
    const settings=translationSettings();settings.enabled=true;settings.chats[translationChatKey(${q(networkA)},${q(other)})]={outgoing:'es'};
    if(!storeTranslationSettings(settings))throw Error('could not enable local translation fixture');
    window.fetch=(url,options,...args)=>{
      if(String(url).endsWith('/api/translation')){
        const data=JSON.parse(options.body);probe.translated.push(data.text);
        return Promise.resolve(Response.json({text:data.text,source:'en'}));
      }
      return original.call(window,url,options,...args);
    };
  })()`);
  const press=async()=>{
    await waitFor(()=>browser.evaluate('!_sendLock'),'the Send button is ready');
    await clickVisible(browser,'#send-btn');
    await waitFor(()=>browser.evaluate('!_sendLock'),'the Send click finished');
  };
  const trials=[];
  for(const phase of ['preflight','bundle']){
    if(phase==='bundle')await waitFor(()=>browser.evaluate(`Date.now()-(_e2eRestartRequested.get(JSON.stringify([currentUser,${slot}]))||0)>=15100`),'manual retry cooldown completes',25000);
    const draft='synthetic private draft '+phase+' '+stamp,mark=otherWs.events.length,sent=browser.frames.length;
    await browser.evaluate(`manualEnableDraft.phase=${q(phase)};manualEnableDraft.release=null;manualEnableDraft.reasons.length=0;`);
    await clickVisible(browser,'#e2e-lock');await clickVisible(browser,'#encrypt-panel-body [data-encrypt-cmd=on]');
    await waitFor(()=>browser.evaluate("!!manualEnableDraft.release"),'the real enable request is waiting at '+phase);
    await clickVisible(browser,'#encrypt-overlay [data-cryptirc-click=closeEncryptPanel]');
    await browser.evaluate(composer+'.focus()');
    await browser.send('Input.insertText',{text:draft});
    await press();
    const first=await browser.evaluate(`({draft:${composer}.value===${q(draft)},held:!!_signalHeldDraftFor(${q(networkA)},${q(other)}),status:E2E.lastBlockReason})`);
    check('first Send leaves the draft visible during '+phase,first.draft&&/still being set up|checking/i.test(first.status));
    await browser.evaluate('manualEnableDraft.release();manualEnableDraft.release=null');
    await waitFor(()=>browser.evaluate(`manualEnableDraft.reasons.includes('peer-setup')&&!E2E._pendingOn?.[${slot}]`),'recipient declined recovery setup and lookup failed normally');
    await press();
    const plain=()=>otherWs.events.slice(mark).filter(e=>e.type==='irc_message'&&e.from===owner&&e.conn_id===networkB&&e.text===draft).length;
    const state=await browser.evaluate(`({retained:${composer}.value===${q(draft)},recorded:_histSignalHeld.get(${q(draft)})?.has(currentUser)||false,
      local:_histLocal.has(${q(draft)}),sync:_histSyncOk.has(${q(draft)}),translated:manualEnableDraft.translated.filter(s=>s===${q(draft)}).length})`);
    const attempt=browser.frames.slice(sent).some(frame=>{const m=JSON.parse(frame);return m.type==='send'&&m.raw==='PRIVMSG '+other+' :'+draft;});
    if(attempt)await waitFor(()=>plain(),'ordinary IRC recipient receives the synthetic baseline send');
    const atPeer=await row(peer,networkB,owner,draft);
    trials.push({phase,firstHeld:first.held,...state,attempt,peer:atPeer,irc:plain()});
    // The user deliberately confirms /encrypt off again before composing fresh plaintext.
    await compose(browser,networkA,other,'/encrypt off '+other);
    await waitFor(()=>browser.evaluate(`!_signalHeldDraftFor(${q(networkA)},${q(other)})&&!_histSignalHeld.get(${q(draft)})?.has(currentUser)`),'local opt-out releases the held composer and history');
    await waitFor(disabled,'fresh opt-out is acknowledged');
    await browser.evaluate(`${composer}.focus();${composer}.select()`);
    const plainControl='intentional public test draft '+phase+' '+stamp;
    await browser.send('Input.insertText',{text:plainControl});
    await press();
    await waitFor(()=>otherWs.events.slice(mark).find(e=>e.type==='irc_message'&&e.from===owner&&e.text===plainControl),'ordinary peer sees an explicitly fresh, unencrypted control after the hold');
    await waitFor(()=>row(peer,networkB,owner,plainControl),'the ordinary peer sees the fresh draft in its conversation');
    // Confirm ordering after actual IRC traffic has reached the receiving connection.
    const trial=trials.at(-1);
    trial.irc=plain();
    trial.synced=browser.frames.slice(sent).some(frame=>{const m=JSON.parse(frame);return m.type==='save_preferences'&&frame.includes(draft);});
    console.log('MANUAL-ENABLE-TRIAL '+JSON.stringify(trial));
    check('fresh plaintext after a deliberate opt-out can use the chosen translator',await browser.evaluate(`manualEnableDraft.translated.includes(${q(plainControl)})`));
  }
  console.log('MANUAL-ENABLE-DRAFT '+JSON.stringify(trials));
  for(const trial of trials)check('second Send after failed manual '+trial.phase+' keeps the same protected draft local',
    trial.firstHeld&&trial.retained&&trial.recorded&&trial.local&&!trial.sync&&!trial.synced&&!trial.translated&&!trial.attempt&&!trial.peer&&!trial.irc);
}

async function clickVisible(browser, selector, touch = false) {
  const point = await browser.evaluate(`(() => {
    const el = document.querySelector(${q(selector)});
    if (!el) throw new Error('Missing control: ' + ${q(selector)});
    el.scrollIntoView({block:'nearest',inline:'nearest'});
    const r = el.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    const top = document.elementFromPoint(x, y);
    if (!el.contains(top)) throw new Error('Control is covered: ' + ${q(selector)} + ' by ' + (top?.id || top?.className || top?.tagName || 'viewport'));
    return {x, y};
  })()`);
  if (touch) {
    await browser.send('Input.dispatchTouchEvent', {type:'touchStart',touchPoints:[point]});
    await browser.send('Input.dispatchTouchEvent', {type:'touchEnd',touchPoints:[]});
    return;
  }
  await browser.send('Input.dispatchMouseEvent', {type:'mousePressed', button:'left', clickCount:1, ...point});
  await browser.send('Input.dispatchMouseEvent', {type:'mouseReleased', button:'left', clickCount:1, ...point});
}

const row = (browser, net, target, text, kind) => browser.evaluate(
  `getBuf(${q(net)},${q(target)}).some(m=>m.text===${q(text)}${kind ? `&&m.kind===${q(kind)}` : ''})`);
const hasKey = (browser,channel,cid) => browser.evaluate(`!!E2E.channelKeys[_e2ePskSlot(${q(channel)},${q(cid)})]`);

async function openSetupInvite(device, cid, nick, waitFor, touch = false) {
  await device.evaluate(`_sidebarActivate(${q(cid)},${q(nick)})`);
  await waitFor(()=>device.evaluate(`['Set up encryption','Unlock encryption'].includes(document.querySelector(${q(setupButton)})?.textContent)`),
    'private encryption setup button is visible');
  await device.evaluate(`document.querySelector(${q(setupButton)}).scrollIntoView({block:'nearest'})`);
  if (touch) {
    const point=await waitForSetupTapPoint(device,waitFor);
    await device.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[point]});
    await device.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
  } else await clickVisible(device,setupButton);
}

export async function acceptIdentity(browser, waitFor) {
  await waitFor(() => browser.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"), 'identity confirmation');
  await browser.evaluate("document.getElementById('e2e-id-accept').click()");
}

async function checkCrossedRestartDevices(a,b,{chromium,password,stamp,order,waitFor,check}) {
  const original=a.page, endpoint=new URL('/cryptirc',await original.evaluate('location.href')).href;
  const opened=[], passive=[];
  const keepOpen=process.env.CRYPTIRC_TEST_RESTART_SIBLINGS!=='closed';
  const session=side=>'E2E.dmSessions[_e2eDmKey('+q(side.peer)+','+q(side.cid)+')]';
  const activeA={...a,peer:b.nick},activeB={...b,peer:a.nick},sides=[activeA,activeB];
  const text=['crossed A '+stamp,'crossed B '+stamp],next=['after A '+stamp,'after B '+stamp];
  const rowCount=(page,side,message)=>page.evaluate('getBuf('+q(side.cid)+','+q(side.peer)+').filter(m=>m.encrypted&&m.text==='+q(message)+').length');
  const open=async name=>{
    const page=await chromium(name,endpoint);
    opened.push(page);
    await login(page,a.nick,password,waitFor);
    await waitFor(()=>page.evaluate('E2E._vaultUp&&E2E._krReceived'),'sibling receives the existing account keyring');
    await page.evaluate('void e2ePromptDeviceUnlock()');
    await waitPrompt(page,waitFor,unlockText);
    await fillPrompt(page,a.code);
    await waitFor(()=>page.evaluate('E2E.identityReady&&!E2E._resyncPending&&!!'+session(activeA)+'?.RK'),'sibling loads the confirmed session');
    return page;
  };
  const relay=async(index,message)=>{
    const from=sides[index], to=sides[1-index], at=from.page.frames.length, mark=to.observer.events.length;
    await compose(from.page,from.cid,to.nick,message);
    const submitted=()=>from.page.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===from.cid&&e.raw?.startsWith('PRIVMSG '+to.nick+' :[e2edm2]'));
    const wire=await waitFor(()=>submitted()[0]?.raw.split(' :')[1],'browser submits its ordinary Signal message').catch(()=>null);
    if(!wire)return {submitted:submitted().length,delivered:0};
    const received=()=>to.observer.events.slice(mark).filter(e=>e.type==='irc_message'&&e.conn_id===to.cid&&e.from===from.nick&&e.text===wire).length;
    await waitFor(received,'the independent linked IRC observer receives the exact ciphertext',45000).catch(()=>false);
    return {submitted:submitted().length,delivered:received()};
  };
  const hold=(side)=>side.page.evaluate('('+function(nick){
    const original=e2eDecryptIncoming;
    let release;
    const waiting=new Promise(resolve=>{release=resolve;});
    e2eDecryptIncoming=async (...args)=>{
      if(args[0]===nick&&(args[2].startsWith('[e2ex3dh]')||args[2].startsWith('[e2edm2]')))await waiting;
      return original(...args);
    };
    window.releaseCrossedRestart=()=>{e2eDecryptIncoming=original;release();delete window.releaseCrossedRestart;};
  }+')('+q(side.peer)+')');
  try {
    const ack='confirmed before crossed restart '+stamp;
    await compose(b.page,b.cid,a.nick,ack);
    await waitFor(()=>row(original,a.cid,b.nick,ack),'original session confirmed in both directions');
    passive.push(await open('crossed-passive-one'),await open('crossed-passive-two'));
    activeA.page=await open('crossed-foreground');
    await original.send('Page.navigate',{url:'about:blank'});
    if(!keepOpen)for(const page of passive)await page.close();
    const starts=await Promise.all(sides.map(side=>side.page.evaluate(session(side)+'.startEph')));
    await Promise.all(sides.map(side=>compose(side.page,side.cid,side.peer,'/encrypt restart '+side.peer)));
    await Promise.all(sides.map((side,i)=>waitFor(()=>side.page.evaluate(session(side)+'?.x3dhPending&&'+session(side)+'.startEph!=='+q(starts[i])),
      'both profiles have prepared their own independent restart',42000)));
    await Promise.all(sides.map(hold));
    let first;
    try {
      first=await Promise.all(text.map((message,i)=>relay(i,message)));
      // Model the two foreground browsers briefly lagging the independent IRC observers.
      await new Promise(resolve=>setTimeout(resolve,500));
    } finally {await Promise.all(sides.map(side=>side.page.evaluate('window.releaseCrossedRestart?.()')));}
    const incoming=messages=>Promise.all(sides.map((side,i)=>rowCount(side.page,side,messages[1-i])));
    const waitRows=messages=>waitFor(async()=>(await incoming(messages)).every(n=>n===1),'each active reader opens the incoming IRC message',18000).catch(()=>false);
    await waitRows(text);
    const firstReaders=await incoming(text);
    const firstRendered=await Promise.all(sides.map((side,i)=>side.page.evaluate('Array.from(document.querySelectorAll("#chat-area .msg-row")).filter(r=>r._msgRef?.encrypted&&r._msgRef.text==='+q(text[1-i])+').length')));
    const passiveReaders=keepOpen?await Promise.all(passive.map(page=>rowCount(page,activeA,text[1]))):[];
    const state=await Promise.all(sides.map(side=>side.page.evaluate('(()=>{const s='+session(side)+';return {initiator:s?.isInitiator,pending:!!s?.x3dhPending,received:s?.Nr,alternate:!!E2E._glareAlt?.[_e2eDmKey('+q(side.peer)+','+q(side.cid)+')]};})()')));
    const following=[];
    for(const [i,message] of next.entries())following.push(await relay(i,message));
    await waitRows(next);
    const followupReaders=await incoming(next);
    const firstReadersAfterReplies=await incoming(text);
    const finalStarts=await Promise.all(sides.map(side=>side.page.evaluate(session(side)+'.startEph')));
    const converged=!!finalStarts[0]&&finalStarts[0]===finalStarts[1];
    console.log('CROSSED-RESTART-DEVICES '+JSON.stringify({order,passiveOpen:keepOpen,first,firstReaders,firstRendered,passiveReaders,state,following,followupReaders,firstReadersAfterReplies,converged}));
    check('the linked IRC observers receive each crossed message and each subsequent reply once',
      [...first,...following].every(r=>r.submitted===1&&r.delivered===1));
    check('both active profiles and the open siblings read their incoming messages once and the peers converge on one session',
      [...firstReaders,...firstRendered,...passiveReaders,...followupReaders].every(n=>n===1)&&converged);
  } finally {
    for(const page of opened)if(page.chrome.exitCode===null&&page.chrome.signalCode===null)await page.close();
    await original.send('Page.navigate',{url:endpoint+'/'});
    await waitFor(()=>original.evaluate('window._appShown&&_wsReady()&&E2E.identityReady').catch(()=>false),'original profile returns');
  }
}

async function checkCrossedFirstContacts({browser,peer,owner,other,networkA,networkB,ownerWs,otherWs,stamp,waitFor,check}) {
  const sides=[{page:browser,cid:networkA,nick:other,from:owner,observer:otherWs,text:'first A '+stamp},
    {page:peer,cid:networkB,nick:owner,from:other,observer:ownerWs,text:'first B '+stamp}];
  const session=side=>`E2E.dmSessions[_e2eDmKey(${q(side.nick)},${q(side.cid)})]`;
  for(const side of sides){
    check('simultaneous first contact starts without a prior ratchet',await side.page.evaluate('!'+session(side)));
    await side.page.evaluate(`(()=>{
      const original=handleEvent,events=[];
      handleEvent=e=>{
        if((e.type==='e2e_x3dh_header'&&e.from_nick===${q(side.nick)})||
           (e.type==='irc_message'&&e.from===${q(side.nick)}&&/^(?:\\[e2ex3dh\\]|\\[e2edm2\\])/.test(e.text))){
          events.push(e);return;
        }
        return original(e);
      };
      window.releaseFirstContact=()=>{handleEvent=original;events.forEach(original);delete window.releaseFirstContact;};
    })()`);
  }
  const received=(side,mark,wire)=>side.observer.events.slice(mark).filter(e=>e.type==='irc_message'&&e.from===side.from&&e.text===wire).length;
  const send=async(side,text)=>{
    const at=side.page.frames.length,mark=side.observer.events.length;
    await compose(side.page,side.cid,side.nick,text);
    const wire=await waitFor(()=>{
      const frames=side.page.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===side.cid&&
        e.raw?.startsWith('PRIVMSG '+side.nick+' :[e2edm2]'));
      return frames.length===1&&frames[0].raw.split(' :')[1];
    },'ordinary initial-contact message submitted once');
    await waitFor(()=>received(side,mark,wire)===1,'ordinary initial-contact message relayed once');
    return ()=>received(side,mark,wire)===1&&!side.observer.events.slice(mark).some(e=>e.type==='irc_message'&&e.text===text);
  };
  const readable=(side,text)=>side.page.evaluate(`getBuf(${q(side.cid)},${q(side.nick)}).some(m=>m.encrypted&&m.text===${q(text)})`);
  let starts,receipts;
  try{
    await Promise.all(sides.map(side=>compose(side.page,side.cid,side.nick,'/encrypt on '+side.nick)));
    await Promise.all(sides.map(side=>acceptIdentity(side.page,waitFor)));
    starts=await Promise.all(sides.map(side=>waitFor(()=>side.page.evaluate(session(side)+'?.x3dhPending?.ephemeral_pub'),
      'each user created an independent initial Signal offer')));
    receipts=await Promise.all(sides.map(side=>send(side,side.text)));
  }finally{await Promise.all(sides.map(side=>side.page.evaluate('window.releaseFirstContact()')));}
  const replies=['after A '+stamp,'after B '+stamp];
  await Promise.all(sides.map((side,i)=>waitFor(()=>readable(side,sides[1-i].text),'both crossed first messages open')));
  for(const [i,side] of sides.entries()){
    receipts.push(await send(side,replies[i]));
    await waitFor(()=>readable(sides[1-i],replies[i]),'an ordinary reply after simultaneous first contact opens');
  }
  const pubs=await Promise.all(sides.map(side=>side.page.evaluate("exportPub(E2E.identityKeys.dhKeyPair.publicKey,'ECDH')")));
  const winner=Buffer.compare(Buffer.from(pubs[0],'base64'),Buffer.from(pubs[1],'base64'))<0?0:1;
  check('two independent first contacts still converge on the lower public identity’s offer and read both ways',starts[0]!==starts[1]&&
    await waitFor(async()=>(await Promise.all(sides.map(side=>side.page.evaluate(session(side)+'.startEph')))).every(v=>v===starts[winner]),
      'both peers use the same winning initial session')&&receipts.every(confirm=>confirm()));
}

async function checkRestartFromHistory(author,contact,stamp,waitFor,check) {
  const session=(side,other)=>`E2E.dmSessions[_e2eDmKey(${q(other.nick)},${q(side.cid)})]`;
  const pin=(side,other)=>side.page.evaluate(`E2E.trustStore[_e2eDmKey(${q(other.nick)},${q(side.cid)})]?.fingerprint`);
  const send=async(from,to,text)=>{
    const sent=from.page.frames.length, observed=to.observer.events.length;
    await compose(from.page,from.cid,to.nick,text);
    const frames=()=>from.page.frames.slice(sent).map(JSON.parse)
      .filter(e=>e.type==='send'&&e.conn_id===from.cid);
    const encrypted=()=>frames().filter(e=>e.raw?.startsWith('PRIVMSG '+to.nick+' :[e2edm2]'));
    const arrivals=()=>to.observer.events.slice(observed)
      .filter(e=>e.type==='irc_message'&&e.conn_id===to.cid&&e.from===from.nick);
    const wire=await waitFor(()=>encrypted()[0]?.raw.split(' :')[1],'outgoing protected text submitted');
    await waitFor(()=>arrivals().some(e=>e.text===wire),'independent IRC recipient observes the protected text');
    const submitted=encrypted().length;
    return {wire, delivered:()=>submitted===1&&encrypted().filter(e=>e.raw.endsWith(' :'+wire)).length===1&&
      arrivals().filter(e=>e.text===wire).length===1&&
      !frames().some(e=>e.raw?.endsWith(' :'+text))&&!arrivals().some(e=>e.text===text)};
  };
  const stable=process.env.CRYPTIRC_TEST_OFFLINE_STABLE==='1';
  const confirmedRestart=process.env.CRYPTIRC_TEST_OFFLINE_CONFIRMED_RESTART==='1';
  if(stable||confirmedRestart){
    const reply='confirm the existing chat before going offline '+stamp;
    const seen=await send(contact,author,reply);
    await waitFor(()=>row(author.page,author.cid,contact.nick,reply),'the remembered author reads the first ordinary reply');
    check('the healthy chat has the same confirmed Signal session on both sides',seen.delivered()&&
      !await author.page.evaluate('!!'+session(author,contact)+'.x3dhPending')&&
      await author.page.evaluate(session(author,contact)+'.startEph')===await contact.page.evaluate(session(contact,author)+'.startEph'));
  }
  if(confirmedRestart){
    for(const [from,to,text] of [[author,contact,'author authenticated reply '+stamp],[contact,author,'contact authenticated reply '+stamp]]){
      const receipt=await send(from,to,text);
      await waitFor(()=>to.page.evaluate(`getBuf(${q(to.cid)},${q(from.nick)}).filter(m=>m.encrypted&&m.text===${q(text)}).length===1`),
        'the recipient reads the authenticated reply before going offline');
      check('the authenticated reply crosses linked IRC once',receipt.delivered());
    }
    check('both peers have confirmed the existing session before the browser exits',
      !await author.page.evaluate('!!'+session(author,contact)+'.x3dhPending')&&
      !await contact.page.evaluate('!!'+session(contact,author)+'.x3dhPending'));
  }
  const known=await pin(author,contact), previous=await contact.page.evaluate(session(contact,author)+'.startEph');
  const senderStart=await author.page.evaluate(session(author,contact)+'.startEph');
  const blocked=process.env.CRYPTIRC_TEST_OFFLINE_POLICY;
  if(blocked){
    check('the tested receive preference is supported',['ignore','off'].includes(blocked));
    const before=author.observer.events.length;
    await compose(author.page,author.cid,contact.nick,(blocked==='ignore'?'/ignore ':'/encrypt off ')+contact.nick);
    await waitFor(()=>author.page.evaluate(blocked==='ignore'?`isIgnored(${q(contact.nick)})`:
      `!E2E._stateSaving && E2E.state.dm[_e2eDmKey(${q(contact.nick)},${q(author.cid)})]?.on===0`),
    'the original sender saves their receive preference before closing');
    if(blocked==='ignore' && process.env.CRYPTIRC_TEST_OFFLINE_ACK_PREF==='1'){
      await waitFor(()=>author.observer.events.slice(before).some(e=>e.type==='preferences'&&e.prefs&&
        JSON.parse(e.prefs).ignoreList?.includes(contact.nick.toLowerCase())),'a second socket receives the saved Ignore');
    }
  }
  const oldPage=author.page;
  await oldPage.close();
  check('the original author browser exits before the contact sends its offline message',oldPage.chrome.exitCode!==null||oldPage.chrome.signalCode!==null);
  if(!stable||confirmedRestart){
    await compose(contact.page,contact.cid,author.nick,'/encrypt restart '+author.nick);
    await waitFor(()=>contact.page.evaluate(`!!${session(contact,author)}?.x3dhPending&&${session(contact,author)}.startEph!==${q(previous)}`),
      'the contact establishes a replacement while its peer is offline');
  }
  const firstText='sent while whole browser was closed '+stamp;
  const first=await send(contact,author,firstText);
  const pace=process.env.CRYPTIRC_TEST_REACTION_LATE_REPLY;
  const overnight=pace==='overnight';
  const elapsed=overnight?12*60*60*1000:pace==='wall-11'?11*60*1000:await contact.page.evaluate('E2E_RESTART_RECEIVE_MS+2500');
  if(pace==='wall'||pace==='wall-11')await new Promise(resolve=>setTimeout(resolve,elapsed));
  else await contact.page.evaluate(`(()=>{const now=Date.now; Date.now=()=>now()+${elapsed};})()`);
  author.page=await oldPage.reopen(overnight?elapsed:0);
  await waitFor(()=>author.page.evaluate('_wsReady()&&E2E.keyReady&&E2E.identityReady').catch(()=>false),'remembered original browser unlocks',35000);
  await author.page.evaluate('_sidebarActivate('+q(author.cid)+','+q(contact.nick)+')');
  const readHistory=()=>author.page.evaluate(`(()=>{
    const matches=getBuf(${q(author.cid)},${q(contact.nick)}).filter(m=>m._dmHistoryWire===${q(first.wire)});
    if(matches.length!==1)return false;
    const m=matches[0];
    return {readable:m.encrypted&&m.text===${q(firstText)},state:m._dmHistoryState,
      unavailable:m.encrypted&&m._dmHistoryState==='unavailable',
      warning:!!E2E.trustStore[_e2eDmKey(${q(contact.nick)},${q(author.cid)})]?.keyChanged};
  })()`);
  await waitFor(async()=>(await readHistory())?.readable,'give history time to authenticate the stored replacement',12000).catch(()=>false);
  const atReopen=await readHistory();
  if(blocked){
    const state=await author.page.evaluate(`(()=>{const k=_e2eDmKey(${q(contact.nick)},${q(author.cid)});return {
      start:E2E.dmSessions[k]?.startEph,on:E2E.state?.dm?.[k]?.on,ignored:isIgnored(${q(contact.nick)})};})()`);
    const preserved=blocked==='ignore'?state.ignored && state.start===senderStart:state.on===0 && !state.start;
    console.log('OFFLINE-POLICY '+JSON.stringify({blocked,ignored:state.ignored,on:state.on,sameStart:state.start===senderStart,
      hasSession:!!state.start,readable:!!atReopen?.readable,arrived:first.delivered(),samePin:known===await pin(author,contact)}));
    check('reopening stored ciphertext honors the saved receive preference and keeps the original contact pin',
      preserved && !atReopen?.readable && first.delivered() && known===await pin(author,contact));
    return;
  }
  const round=[];
  for(const [from,to,text] of [[author,contact,'first after reopening '+stamp],[contact,author,'reply after reopening '+stamp]]){
    const receipt=await send(from,to,text);
    const visible=await waitFor(()=>to.page.evaluate(`getBuf(${q(to.cid)},${q(from.nick)}).filter(m=>m.encrypted&&m.text===${q(text)}).length===1`),
      'the contact displays the fresh protected message after offline restart',18000).catch(()=>false);
    round.push({delivered:receipt.delivered(),readable:!!visible});
  }
  const history=await readHistory();
  const samePin=!!known&&known===await pin(author,contact);
  console.log('OFFLINE-RESTART-HISTORY '+JSON.stringify({stable,confirmedRestart,firstDelivered:first.delivered(),atReopen,history,round,samePin}));
  check('the offline replacement text has a visible history row and the original contact pin survives',
    first.delivered()&&history&&(history.readable||history.unavailable)&&!history.warning&&samePin);
  check('both fresh protected messages after the offline restart arrive once and can be read',round.every(r=>r.delivered&&r.readable));
  check('the returning recipient opens the exact missed text with its available keys before sending anything',!!atReopen?.readable);
}

async function checkLateRestartReplies({browser,peer,chromium,owner,other,ownerWs,otherWs,networkA,networkB,
  password,ownerCode,stamp,waitFor,check,mode}) {
  const state=(page,cid,nick)=>page.evaluate(`(()=>{
    const k=_e2eDmKey(${q(nick)},${q(cid)}),s=E2E.dmSessions[k],pin=E2E.trustStore[k];
    return {start:s?.startEph,pending:!!s?.x3dhPending,pin:pin?.fingerprint,changed:!!pin?.keyChanged};
  })()`);
  const send=async(sender,recipient,cid,rcid,from,to,text,observer)=>{
    const at=sender.frames.length,mark=observer.events.length;
    await compose(sender,cid,to,text);
    const sent=()=>sender.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===cid&&
      e.raw?.startsWith('PRIVMSG '+to+' :[e2edm2]'));
    const wires=()=>sent().map(e=>e.raw.split(' :')[1]);
    const arrivals=()=>observer.events.slice(mark).filter(e=>e.type==='irc_message'&&e.conn_id===rcid&&e.from===from);
    const delivered=await waitFor(()=>arrivals().some(e=>wires().includes(e.text)),'independent IRC receipt for the late encrypted PM').catch(()=>false);
    const readable=delivered&&await waitFor(()=>recipient.evaluate(`getBuf(${q(rcid)},${q(from)}).some(m=>m.encrypted&&m.text===${q(text)})`),
      'the recipient opens this exact late PM',16000).catch(()=>false);
    return {readable:!!readable,submitted:sent().length,relayed:arrivals().filter(e=>wires().includes(e.text)).length,
      clear:arrivals().some(e=>e.text===text)};
  };
  const exchange=async(author,label)=>[
    await send(author,peer,networkA,networkB,owner,other,label+' A '+stamp,otherWs),
    await send(peer,author,networkB,networkA,other,owner,label+' B '+stamp,ownerWs),
  ];
  const good=results=>results.every(r=>r.readable&&r.submitted===1&&r.relayed===1&&!r.clear);
  const initial=await exchange(browser,'early');
  const [a,b]=await Promise.all([state(browser,networkA,other),state(peer,networkB,owner)]);
  const converged=!!a.start&&a.start===b.start&&!a.pending&&!b.pending&&!a.changed&&!b.changed;
  const elapsed=await browser.evaluate('E2E_RESTART_RECEIVE_MS+2500');
  if(mode==='wall')await new Promise(resolve=>setTimeout(resolve,elapsed));
  else await Promise.all([browser,peer].map(page=>page.evaluate(`(()=>{
    const original=Date.now;Date.now=()=>original()+${elapsed};window.restoreLateClock=()=>{Date.now=original;};
  })()`)));
  // Discard the original author's live ratchet. Only the independently unlocked
  // profile can receive and reply during this part of the exchange.
  const url=await browser.evaluate('location.href');
  let late,fresh,recovered,matchingPins;
  try{
    late=await exchange(browser,'late');
    console.log('RESTART-BEFORE-REOPEN '+JSON.stringify({mode,converged,initial,late}));
    await browser.send('Page.navigate',{url:'about:blank'});
    fresh=await chromium('restart-late-new-profile',new URL('/cryptirc',url).href);
    await login(fresh,owner,password,waitFor);
    await waitFor(()=>fresh.evaluate('E2E._vaultUp&&E2E._krReceived'),'new profile receives the existing keyring');
    await fresh.evaluate('void e2ePromptDeviceUnlock()');
    await waitPrompt(fresh,waitFor,unlockText);
    await fillPrompt(fresh,ownerCode);
    await waitFor(()=>fresh.evaluate('E2E.keyReady&&E2E.identityReady'),'new profile unlocks the saved identity');
    await fresh.evaluate('_sidebarActivate('+q(networkA)+','+q(other)+')');
    await waitFor(()=>fresh.evaluate(`!!E2E.dmSessions[_e2eDmKey(${q(other)},${q(networkA)})]?.RK`),'new profile loads the confirmed conversation');
    const freshState=await state(fresh,networkA,other);
    matchingPins=!!a.pin&&freshState.pin===a.pin&&!freshState.changed;
    recovered=[
      await send(peer,fresh,networkB,networkA,other,owner,'new profile B '+stamp,ownerWs),
      await send(fresh,peer,networkA,networkB,owner,other,'new profile A '+stamp,otherWs),
    ];
    if(process.env.CRYPTIRC_TEST_RESTART_SECOND_DEVICE==='1'){
      await browser.send('Page.navigate',{url});
      await waitFor(()=>browser.evaluate('_wsReady()&&E2E._vaultUp&&E2E._krReceived').catch(()=>false),
        'original browser reconnects alongside the independent profile');
      if(!await browser.evaluate('E2E.keyReady')){
        await browser.evaluate('void e2ePromptDeviceUnlock()');
        await waitPrompt(browser,waitFor,unlockText);
        await fillPrompt(browser,ownerCode);
      }
      await browser.evaluate('_sidebarActivate('+q(networkA)+','+q(other)+')');
      await waitFor(()=>browser.evaluate(`E2E.identityReady&&!!E2E.dmSessions[_e2eDmKey(${q(other)},${q(networkA)})]?.RK`),
        'returning original browser loads the confirmed session');
      const messages=['desktop after restart ','phone after restart ','peer after restart '].map(label=>label+stamp);
      const receipts=await Promise.all([
        send(browser,peer,networkA,networkB,owner,other,messages[0],otherWs),
        send(fresh,peer,networkA,networkB,owner,other,messages[1],otherWs),
        send(peer,browser,networkB,networkA,other,owner,messages[2],ownerWs),
      ]);
      const readable=(device,cid,nick)=>device.evaluate(`(() => {
        const rows=getBuf(${q(cid)},${q(nick)});
        return ${q(messages)}.every(text=>rows.filter(m=>m.encrypted&&m.text===text).length===1);
      })()`);
      const allRead=await waitFor(async()=>(await Promise.all([
        readable(browser,networkA,other),readable(fresh,networkA,other),readable(peer,networkB,owner)
      ])).every(Boolean),'nine readable private message rows after idle, restart and simultaneous sends',30000).catch(()=>false);
      console.log('RESTART-THREE-DISPLAYS '+JSON.stringify({receipts,allRead}));
      check('two active account devices and their independent contact each read all three simultaneous messages once after a restart',
        good(receipts)&&allRead);
    }
  }finally{
    if(fresh)await fresh.send('Page.navigate',{url:'about:blank'});
    if(mode==='clock')await Promise.all([browser,peer].map(page=>page.evaluate('window.restoreLateClock?.();delete window.restoreLateClock')));
    await browser.send('Page.navigate',{url});
    await waitFor(()=>browser.evaluate('_appShown&&_wsReady()&&E2E.identityReady').catch(()=>false),'original remembered profile reopens');
  }
  console.log('RESTART-LATE-REPLIES '+JSON.stringify({mode,converged,initial,late,matchingPins,recovered}));
  check('the explicit successor converges and both users read one encrypted IRC delivery in each direction',converged&&good(initial));
  check('both users still read each protected reply after the previous receive window expires',good(late));
  check('a fresh profile keeps the pinned peer and reads and sends once after the explicit restart',matchingPins&&good(recovered));
}

async function shareKey(browser, waitFor, cmd, network, channel) {
  await browser.evaluate('void handleEncryptCommand([' + q(cmd) + '],' + q(network) + ',' + q(channel) + ')');
  await waitPrompt(browser, waitFor, 'Copy this key and share it');
  const words = await browser.evaluate(input + '.value');
  await browser.evaluate(acceptPrompt);
  return words;
}

async function checkConcurrentEncryptionSettings({browser, chromium, owner, password, stamp, waitFor, check}) {
  await waitFor(()=>browser.evaluate('E2E._vaultUp&&E2E._krReceived'),'first profile discovers its account keyring');
  await browser.evaluate(openEncryptionSettings);
  const code=await setUpRecovery(browser,waitFor,check);
  await browser.evaluate('closeEncryptPanel()');
  const openDevice=async profile=>{
    const page=await chromium(profile);
    await login(page,owner,password,waitFor);
    await waitFor(()=>page.evaluate('E2E._vaultUp&&E2E._krReceived'),'new profile discovers the same keyring');
    await page.evaluate('void e2ePromptDeviceUnlock()');
    await waitPrompt(page,waitFor,unlockText);
    await fillPrompt(page,code);
    await waitFor(()=>page.evaluate("E2E._bootPhase==='ready'&&E2E.identityReady&&!E2E._stateSaving"),'new profile restores the account settings');
    return page;
  };
  const sibling=await openDevice('channel-settings-second');
  const channels=['#preference-a-'+stamp,'#preference-b-'+stamp];
  const choose=(page,index,on)=>page.evaluate(`_e2eStateSetChan(${q(channels[index])},${on},1);void 0`);
  const settled=page=>page.evaluate('Promise.resolve(E2E._stateSaving).then(()=>true)');
  const channelValues=(page,fromServer)=>page.evaluate(`(async()=>{
    const settings=${fromServer?"await _e2eDecodeState(await _e2eFetchSession('__state__'))":'E2E.state'};
    return ${q(channels)}.map(channel=>settings?.ch?.[channel]?.on??null);
  })()`);
  await choose(browser,0,true);
  await settled(browser);
  check('the first sequential channel setting is saved',q(await channelValues(sibling,true))===q([1,null]));
  await choose(sibling,1,true);
  await settled(sibling);
  check('a second sequential channel setting keeps the first',q(await channelValues(browser,true))===q([1,1]));

  // Hold one already-sealed preference write before its real request. Both
  // profiles read the same revision and use their ordinary save code throughout.
  function observe(hold) {
    const request=_e2eReq;
    const probe=window.channelSettingsFixture={writes:[],read:null,release:null,restore(){
      this.release?.();_e2eReq=request;delete window.channelSettingsFixture;
    }};
    _e2eReq=async (message,...args)=>{
      if(message.partner!=='__state__')return request(message,...args);
      if(message.type==='e2e_load_session'){
        const reply=await request(message,...args);
        if(typeof reply?.blob==='string')probe.read=reply.blob?await _e2eSha256Hex(reply.blob):'';
        return reply;
      }
      if(message.type!=='e2e_store_session')return request(message,...args);
      const write={read:probe.read,expect:message.expect??null,written:await _e2eSha256Hex(message.blob)};
      probe.writes.push(write);
      if(hold&&probe.writes.length===1)await new Promise(resolve=>{probe.release=resolve;});
      const reply=await request(message,...args);
      write.ok=reply?.ok===true;
      write.conflict=typeof reply?.conflict==='string'?(reply.conflict?await _e2eSha256Hex(reply.conflict):''):null;
      return reply;
    };
  }
  await browser.evaluate(`(${observe})(false)`);
  await sibling.evaluate(`(${observe})(true)`);
  try {
    await choose(sibling,1,false);
    await waitFor(()=>sibling.evaluate('!!channelSettingsFixture.release'),'second profile holds its first settings write');
    await choose(browser,0,false);
    await settled(browser);
    await sibling.evaluate('channelSettingsFixture.release()');
    await settled(sibling);
    const [[first],writes]=await Promise.all([browser,sibling].map(page=>page.evaluate('channelSettingsFixture.writes')));
    const [second,retry]=writes;
    const sameRead=!!first?.read&&first.read===second?.read;
    const matchedConflict=!!retry&&first.ok&&!second.ok&&first.expect===first.read&&second.expect===second.read&&
      second.conflict===first.written&&retry.expect===second.conflict&&retry.ok;
    const server=await channelValues(browser,true);
    const fresh=await openDevice('channel-settings-fresh');
    const reopened=await channelValues(fresh,false);
    console.log('ENCRYPTED-CHANNEL-SETTINGS '+JSON.stringify({sameRead,matchedConflict,writes:writes.length,server,reopened}));
    check('both profiles prepared different settings from one server revision',sameRead);
    check('both concurrent channel choices survive on the server and in a newly enrolled profile',
      q(server)===q([0,0])&&q(reopened)===q([0,0]));
    check('the second profile retries against the exact winning sealed revision',matchedConflict);
  } finally {
    await Promise.all([browser,sibling].map(page=>page.evaluate('window.channelSettingsFixture?.restore()')));
  }
  return code;
}

export async function checkE2eChat({
  browser, chromium, check, waitFor, pause, owner, other, password, vault, tmp, ownerWs, otherWs,
  networkA, networkB, channel, stamp, request, ownerSession, echoGate,
}) {
  await browser.send('Emulation.clearDeviceMetricsOverride');
  await browser.send('Emulation.setTouchEmulationEnabled', {enabled:false});
  if(process.env.CRYPTIRC_TEST_ENCRYPTED_SETTINGS_CONCURRENCY==='1'){
    return checkConcurrentEncryptionSettings({browser,chromium,owner,password,stamp,waitFor,check});
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_FOCUSED==='1' && process.env.CRYPTIRC_TEST_SIGNAL_AUDIT && process.env.CRYPTIRC_TEST_E2E_BRIDGE==='1'){
    await waitFor(()=>browser.evaluate('E2E._vaultUp&&E2E._krReceived'),'focused sender discovers the account keyring');
    await browser.evaluate(openEncryptionSettings);
    const recovery=await setUpRecovery(browser,waitFor,check);
    await browser.evaluate('closeEncryptPanel()');
    return recovery;
  }
  let peer = await chromium('encrypted-peer');
  await login(peer, other, password, waitFor);
  await unlockVault(peer, vault);
  await waitFor(() => peer.evaluate('E2E._vaultUp === true && E2E._krReceived'), 'peer vault ready');
  check('public chat sharing is available before setting up E2E',
    await browser.evaluate('_chatAllowsPublicContent({conn_id:' + q(networkA) + ',target:"#public-check"})'));
  await browser.evaluate('void handleEncryptCommand(["on",'+q(other)+'],'+q(networkA)+','+q(channel)+');void e2ePromptDeviceUnlock()');
  await waitPrompt(browser, waitFor, setupText);
  await browser.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await browser.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await waitFor(() => browser.evaluate('!E2E._interactiveUnlock && !('+promptOpen+')'), 'setup dismissed with Escape');
  check('Escape dismisses setup without saving Ignore', !await browser.evaluate('_e2eLsGet(_e2eSetupPreference())'));
  await browser.evaluate('void handleEncryptCommand(["on",'+q(other)+'],'+q(networkA)+','+q(channel)+')');
  await waitPrompt(browser, waitFor, setupText);
  await browser.evaluate('void customPrompt("Other setup-time dialog")');
  check('replacing the setup prompt does not save Ignore', await waitFor(
    () => browser.evaluate('!E2E._interactiveUnlock && !_e2eLsGet(_e2eSetupPreference())'), 'replaced setup prompt settled', 3000));
  await browser.evaluate(cancelPrompt);
  await browser.evaluate('void handleEncryptCommand(["on",'+q(other)+'],'+q(networkA)+','+q(channel)+')');
  await waitPrompt(browser, waitFor, setupText);
  check('recovery setup can be ignored when starting encryption', await browser.evaluate(
    "document.getElementById('custom-prompt-cancel').textContent==='Ignore'"));
  const declinedAt = browser.frames.length;
  await browser.evaluate(cancelPrompt);
  await waitFor(() => browser.evaluate('!E2E._interactiveUnlock && !E2E._booting'), 'ignored recovery setup');
  check('ignoring setup leaves encryption unchanged and clears the displayed code',
    await browser.evaluate('!E2E.keyReady && '+input+".value==='' && _e2eLsGet(_e2eSetupPreference())===true") &&
    !browser.frames.slice(declinedAt).some(frame=>frame.includes('"type":"e2e_store_keyring"')));
  await reopen(browser, waitFor, 'window._appShown && E2E._krReceived && !E2E._booting', 'reopened after ignoring setup');
  await pause(1450);
  check('reopening after Ignore leaves setup deferred', await browser.evaluate('!('+promptOpen+') && _e2eLsGet(_e2eSetupPreference())===true'));
  await browser.evaluate('setActive(' + q(networkA) + ',' + q(channel) + ')');
  await browser.evaluate(`new Promise(resolve => {
    void navigator.locks.request('cryptirc-e2e:' + _e2eUser() + ':keyring-setup', () => new Promise(release => {
      window.releaseSetupLock = release;
      resolve();
    }));
  })`);
  try {
    await clickVisible(browser, '#e2e-lock');
    await clickVisible(browser, panelUnlock);
    check('an older tab holding the setup lock cannot block the recovery prompt', await waitFor(
      () => browser.evaluate(promptOpen + '&&' + promptText + '.includes(' + q(setupText) + ')'),
      'setup prompt while the old browser lock is held', 6000));
    await browser.evaluate(cancelPrompt + ';closeEncryptPanel()');
    await waitFor(() => browser.evaluate('!E2E._interactiveUnlock'), 'contended setup prompt dismissed');
  } finally {
    await browser.evaluate('window.releaseSetupLock(); delete window.releaseSetupLock');
  }
  const competitor = await chromium('encrypted-setup-race');
  await login(competitor, owner, password, waitFor);
  await waitFor(() => competitor.evaluate('E2E._vaultUp === true && E2E._krReceived'), 'second setup device ready');
  await competitor.evaluate('setActive(' + q(networkA) + ',' + q(channel) + ');void e2ePromptDeviceUnlock()');
  await waitPrompt(competitor, waitFor, setupText);
  const losingCode = await competitor.evaluate(input + '.value');
  await browser.evaluate(openEncryptionSettings);
  const ownerCode = await setUpRecovery(browser, waitFor, check);
  await browser.evaluate('closeEncryptPanel()');
  await competitor.evaluate(acceptPrompt);
  await waitPrompt(competitor, waitFor, 'Paste your saved E2E recovery code');
  await fillPrompt(competitor, losingCode);
  await waitFor(() => competitor.evaluate('getBuf(' + q(networkA) + ',' + q(channel) +
    ').some(m=>m.text.includes("Discard it"))'), 'losing setup shows a discard message');
  check('the losing setup shows a visible message to discard its recovery code', await competitor.evaluate(`
    document.getElementById('generic-toast')?.textContent.includes('Discard the code shown here')
  `));
  check('only the winning concurrent setup creates a valid recovery code',
    !await competitor.evaluate('E2E.keyReady') &&
    await competitor.evaluate('(()=>{return !E2E.identityReady})()'));
  await waitFor(() => browser.evaluate('E2E._txq.length===0'), 'initiator prekeys sent');
  await waitFor(()=>fs.stat(path.join(tmp,'e2e',owner,'bundle.json')).catch(()=>null),'initiator key bundle is available on the server');
  if(process.env.CRYPTIRC_TEST_MANUAL_ENABLE_DRAFT==='1'){
    await checkManualEnableDraft({browser,peer,check,waitFor,owner,other,otherWs,networkA,networkB,stamp});
    return ownerCode;
  }
  const peerBundle=path.join(tmp,'e2e',other,'bundle.json');
  await fs.mkdir(path.dirname(peerBundle),{recursive:true});
  await fs.writeFile(peerBundle,'{',{flag:'wx'});
  const unavailableDraft='held for an unavailable key bundle '+stamp;
  try {
    await compose(browser,networkA,other,unavailableDraft);
    check('an unreadable existing peer bundle does not invite a plaintext send or new identity setup',
      await waitFor(()=>browser.evaluate(`E2E.lastBlockReason?.includes('is unavailable right now')&&
        document.getElementById('msg-input').value===${q(unavailableDraft)}&&! (${plainPrompt})`),'unreadable bundle fails closed')&&
      !otherWs.events.some(e=>e.type==='e2e_setup_needed'||e.text?.includes(unavailableDraft)));
  } finally {await fs.unlink(peerBundle);}
  const setupDraft='ordinary DM to a local contact before encryption setup '+stamp;
  await compose(browser,networkA,other,setupDraft);
  await otherWs.wait(e=>e.type==='e2e_setup_needed'&&e.conn_id===networkB&&e.from===owner,'targeted local setup notice');
  await otherWs.wait(e=>e.type==='irc_message'&&e.text===setupDraft,'same-server recipient without a key receives the plain DM');
  check('an unconfigured local contact receives one plaintext message with no sender dialog',
    otherWs.events.filter(e=>e.type==='irc_message'&&e.text===setupDraft).length===1&&
    !await browser.evaluate(`(${plainPrompt})||(${promptOpen})`));
  check('the local setup invitation goes only to the recipient',
    !ownerWs.events.some(e=>e.type==='e2e_setup_needed'&&e.from===owner));
  check('a setup invitation never opens a prompt on its own',!await peer.evaluate(promptOpen));
  check('setup notices respect ignores, PM protection, and IRC network scope',await peer.evaluate(`(async () => {
    const cid=${q(networkB)}, ignored='ignorefixture', protectedNick='protectedfixture', wrong='wrong-network';
    const oldSettings=getPmSettings, mask='*!*@ignored.example';
    ignoreList.add(ignored);
    ignoreList.add(mask);
    try {
      await e2eHandleEvent({type:'e2e_setup_needed',conn_id:cid,from:ignored});
      await e2eHandleEvent({type:'e2e_setup_needed',conn_id:cid,from:'maskfixture',prefix:'maskfixture!user@ignored.example'});
      await e2eHandleEvent({type:'e2e_setup_needed',conn_id:wrong,from:protectedNick});
      getPmSettings=()=>({enabled:true});
      await e2eHandleEvent({type:'e2e_setup_needed',conn_id:cid,from:protectedNick});
      return !getBuf(cid,ignored).length&&!getBuf(cid,'maskfixture').length&&!getBuf(cid,protectedNick).length&&!getBuf(wrong,protectedNick).length;
    } finally {getPmSettings=oldSettings;ignoreList.delete(ignored);ignoreList.delete(mask);}
  })()`));
  const nextDraft='another ordinary DM '+stamp;
  await compose(browser,networkA,other,nextDraft);
  await otherWs.wait(e=>e.type==='irc_message'&&e.text===nextDraft,'second plain DM arrives before the contact sets up encryption');
  check('repeated ordinary sends run without prompting or flooding the recipient',
    otherWs.events.filter(e=>e.type==='e2e_setup_needed'&&e.conn_id===networkB&&e.from===owner).length===1&&
    !await browser.evaluate(`!!(${plainPrompt})`));
  const quote='test quote '+stamp;
  const plainReply='ordinary quoted reply '+stamp;
  await browser.evaluate(`setReply(${q(other)},${q(quote)},{conn_id:${q(networkA)},target:${q(other)}})`);
  await compose(browser,networkA,other,plainReply);
  await otherWs.wait(e=>e.type==='irc_message'&&e.text===plainReply,'ordinary quoted reply is delivered');
  const quoteIndex=otherWs.events.findIndex(e=>e.type==='irc_message'&&e.text===`> <${other}> ${quote}`);
  check('ordinary quoted replies send the quote and reply in order with no dialog',quoteIndex>=0&&
    quoteIndex<otherWs.events.findIndex(e=>e.type==='irc_message'&&e.text===plainReply)&&
    !await browser.evaluate(`!!(${plainPrompt})`));
  const pinnedKey=`_e2eDmKey(${q(other)},${q(networkA)})`;
  await browser.evaluate(`E2E.trustStore[${pinnedKey}]={fingerprint:'test pin',verified:true}`);
  const pinBlocked='known peer must remain protected '+stamp;
  try {
    await compose(browser,networkA,other,pinBlocked);
    check('a trusted peer gets no plaintext override when their bundle becomes unavailable',
      await waitFor(()=>browser.evaluate(`!E2E._pendingOn?.[${pinnedKey}]&&
        document.getElementById('msg-input').value===${q(pinBlocked)}&&! (${plainPrompt})`),'known peer remains blocked')&&
      !otherWs.events.some(e=>e.text?.includes(pinBlocked)));
  } finally {await browser.evaluate(`delete E2E.trustStore[${pinnedKey}]`);}
  await openSetupInvite(peer,networkB,owner,waitFor);
  const peerCode=await setUpRecovery(peer, waitFor, check);
  const keyring = await keyringOnDisk(tmp, owner);
  check('new account stores only a wrapped v3 keyring',
    keyring.blob.startsWith('e2k3.') && !JSON.stringify(keyring).includes(ownerCode));
  check('new account vault unlock response contains no E2E pepper or key',
    ownerWs.events.some(ev => ev.type === 'vault_unlocked' && ev.vault_verified &&
      !ev.e2e_pepper && !ev.e2e_legacy_key && !ev.e2e_enc_key));

  await waitFor(() => peer.evaluate('E2E._txq.length===0'), 'responder prekeys sent');
  const lateReply=process.env.CRYPTIRC_TEST_REACTION_LATE_REPLY;
  const order=process.env.CRYPTIRC_TEST_REACTION_IDENTITY_ORDER;
  const simultaneous=process.env.CRYPTIRC_TEST_SIGNAL_SIMULTANEOUS_CONTACT==='1';
  let reactionOwnerCode=ownerCode;
  if((simultaneous||(process.env.CRYPTIRC_TEST_REACTION_OPPOSITE_GLARE==='1'&&['clock','wall'].includes(lateReply)))&&['author','restart'].includes(order)){
    // Both identities were freshly generated by ordinary account setup. Pick
    // their test roles before either one starts this encrypted conversation.
    const publicKey=page=>page.evaluate("exportPub(E2E.identityKeys.dhKeyPair.publicKey,'ECDH')");
    const [first,second]=await Promise.all([publicKey(browser),publicKey(peer)]);
    const authorWins=Buffer.compare(Buffer.from(first,'base64'),Buffer.from(second,'base64'))<0;
    if(authorWins!==(order==='author')){
      [browser,peer]=[peer,browser];[owner,other]=[other,owner];
      [networkA,networkB]=[networkB,networkA];[ownerWs,otherWs]=[otherWs,ownerWs];
      reactionOwnerCode=peerCode;
    }
  }
  if(simultaneous){
    await checkCrossedFirstContacts({browser,peer,owner,other,networkA,networkB,ownerWs,otherWs,stamp,waitFor,check});
    return ownerCode;
  }
  const receiverKey=`_e2eDmKey(${q(owner)},${q(networkB)})`;
  await peer.evaluate(`(async()=>{
    const name=_e2eCanon(${q(owner)},${q(networkB)});
    const saved=await generateChannelKey();
    await storeChannelKey(name,saved.key,saved.keyB64);
    setActive(${q(networkB)},${q(owner)});
    window.savedTestMethodSend=wsend;
    wsend=message=>{
      if(message.type==='e2e_fetch_bundle'&&message.username===${q(owner)}){
        queueMicrotask(()=>e2eHandleEvent({type:'e2e_bundle_missing',conn_id:message.conn_id,req:message.req,reason:'unavailable'}));
        return true;
      }
      return window.savedTestMethodSend(message);
    };
    void handleEncryptCommand(['use-signal'],${q(networkB)},${q(owner)});
  })()`);
  const chooseSignal=`[...document.querySelectorAll('[role=alertdialog] button')].find(button=>button.textContent==='Use Signal')`;
  try {
    await waitFor(()=>peer.evaluate(`!!(${chooseSignal})`),'select Signal before a session exists');
    await peer.evaluate(`(${chooseSignal}).click()`);
    await waitFor(()=>peer.evaluate(`_e2ePrefersSignal(${receiverKey})&&!E2E._pendingOn?.[${receiverKey}]`),'failed discovery keeps Signal selected');
  } finally {await peer.evaluate('wsend=window.savedTestMethodSend;delete window.savedTestMethodSend');}
  const heldSwitchDraft='hold while Signal has no session '+stamp;
  const beforeMethodSend=ownerWs.events.length;
  await compose(peer,networkB,owner,heldSwitchDraft);
  check('a failed first Signal lookup keeps the draft and its saved shared key',await waitFor(()=>peer.evaluate(`
    e2eTargetState(${q(owner)},{conn_id:${q(networkB)}}).mode==='blocked'&&
    !!E2E.channelKeys[_e2ePskSlot(_e2eCanon(${q(owner)},${q(networkB)}),${q(networkB)})]&&document.getElementById('msg-input').value===${q(heldSwitchDraft)}`),
    'selected Signal is blocked until ready')&&!ownerWs.events.slice(beforeMethodSend).some(e=>e.type==='irc_message'&&e.from===other));
  const dm = 'encrypted DM '+stamp;
  const peerKey = `_e2eDmKey(${q(other)},${q(networkA)})`;
  await compose(browser, networkA, other, dm);
  await waitFor(() => browser.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"), 'same-instance automatic identity prompt');
  check('first same-instance PM starts encryption and holds the message for identity confirmation',
    !otherWs.events.some(ev=>ev.text?.includes(dm)));
  await acceptIdentity(browser, waitFor);
  await waitFor(() => browser.evaluate(`!!E2E.dmSessions[${peerKey}]`), 'initiator session');
  await waitFor(() => otherWs.events.some(ev => ev.text?.startsWith('[e2ex3dh]')), 'X3DH header reached the peer');
  const oppositeGlare = process.env.CRYPTIRC_TEST_REACTION_OPPOSITE_GLARE === '1';
  const reactionHandoff = oppositeGlare || process.env.CRYPTIRC_TEST_REACTION_HANDOFF === '1';
  if (reactionHandoff) {
    await checkFirstSignalReaction({browser,peer,networkA,networkB,owner,other,dm,ownerWs,otherWs,waitFor,check,oppositeGlare,
      accept:()=>acceptIdentity(peer,waitFor)});
  } else await acceptIdentity(peer, waitFor);
  await waitFor(() => row(peer, networkB, owner, dm), 'recipient decrypted first DM');
  check('testnet receives authenticated DM ciphertext',
    await otherWs.wait(ev => ev.type === 'irc_message' && ev.conn_id===networkB && ev.from===owner &&
      ev.text?.startsWith('[e2edm2]'),'the separate IRC observer receives the encrypted DM') &&
    !otherWs.events.some(ev => ev.text?.includes(dm)));
  const reply = 'ratchet reply '+stamp;
  await compose(peer, networkB, owner, reply);
  await waitFor(() => row(browser, networkA, other, reply), 'initiator decrypted ratchet reply');
  check('Double Ratchet works in both directions on the linked IRC testnet', true);
  if(process.env.CRYPTIRC_TEST_SIGNAL_DISCONNECT==='1'){
    const disconnectedAt=otherWs.events.length;
    otherWs.send({type:'disconnect',id:networkB,reason:'test peer goes offline'});
    await waitFor(()=>otherWs.events.slice(disconnectedAt).some(e=>e.type==='disconnected'&&e.conn_id===networkB),
      'recipient actually disconnects from IRC');
    await pause(500);
    const offlineDraft='encrypted reply after IRC peer leaves '+stamp,sendAt=browser.frames.length,eventAt=ownerWs.events.length;
    await compose(browser,networkA,other,offlineDraft);
    const warning=await waitFor(()=>ownerWs.events.slice(eventAt).find(e=>e.type==='irc_delivery_warning'&&e.conn_id===networkA&&e.target===other),
      'IRC refuses the established encrypted chat send after its peer goes offline');
    const wire=browser.frames.slice(sendAt).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===networkA&&e.raw?.startsWith('PRIVMSG '+other+' :'));
    check('the established session uses only ciphertext for the offline attempt',
      wire.length===1&&wire[0].raw.startsWith('PRIVMSG '+other+' :[e2edm2]')&&!wire[0].raw.includes(offlineDraft));
    const display=await waitFor(()=>browser.evaluate(`(()=>{
      const rows=getBuf(${q(networkA)},${q(other)});
      const warning=rows.findLast(row=>row.kind==='error'&&/recipient is not online|is offline/.test(row.text));
      const row=rows.findLast(row=>row.text===${q(offlineDraft)});
      return warning&&{warn:warning.text,markedFailed:row?.sendState==='failed',draftKept:document.getElementById('msg-input').value===${q(offlineDraft)}};})()`),
      'sender sees the offline failure in the encrypted chat');
    console.log('SIGNAL OFFLINE '+JSON.stringify({serverIdentifiedUnsentWire:!!warning.unsent_wire,...display}));
    check('the exact offline Signal bubble is rejected and its plaintext stays off the wire',
      warning.unsent_wire===wire[0].raw.split(' :')[1]&&display.markedFailed&&
      !ownerWs.events.slice(eventAt).some(e=>e.type==='irc_echo'&&e.text===warning.unsent_wire));
    await clickVisible(browser,'[data-restore-unsent]');
    check('Restore draft puts back the original draft with Signal required',await browser.evaluate(
      `document.getElementById('msg-input').value===${q(offlineDraft)}&&!!_signalHeldDraftFor(${q(networkA)},${q(other)})`));
    const reconnectAt=otherWs.events.length;
    otherWs.send({type:'connect',id:networkB});
    await waitFor(()=>otherWs.events.slice(reconnectAt).some(e=>e.type==='connected'&&e.conn_id===networkB),'same recipient reconnects');
    await waitFor(()=>peer.evaluate(`networks.some(n=>n.config.id===${q(networkB)}&&n.connected)`),'the receiving browser sees IRC reconnect');
    const after='encrypted DM after IRC reconnect '+stamp;
    await compose(browser,networkA,other,after);
    await waitFor(()=>row(peer,networkB,owner,after),'recipient reads an encrypted message after reconnect');
    const again='encrypted reply after IRC reconnect '+stamp;
    await compose(peer,networkB,owner,again);
    await waitFor(()=>row(browser,networkA,other,again),'sender reads an encrypted reply after reconnect');
    check('Signal resumes in both directions after the IRC recipient reconnects',true);
    return ownerCode;
  }

  if(oppositeGlare&&(lateReply==='clock'||lateReply==='wall')){
    await checkLateRestartReplies({browser,peer,chromium,owner,other,ownerWs,otherWs,networkA,networkB,
      password,ownerCode:reactionOwnerCode,stamp,waitFor,check,mode:lateReply});
    return ownerCode;
  }
  if (reactionHandoff) await checkRestartedSignalReaction({browser,peer,networkA,networkB,owner,other,dm,ownerWs,compose,waitFor,check,stamp,echoGate});
  if(echoGate)return ownerCode;
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:dm,target:'PM',emoji:'👍'});
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:dm,target:'PM thumbs-down',emoji:'👎'});
  }
  if(process.env.CRYPTIRC_TEST_REACTION_HISTORY==='1'){
    // Earlier toggles leave a durable record of the last confirmed removal.
    // Exercise restoration on a different message that nobody has reacted to.
    const historyParent = 'unreacted encrypted DM '+stamp;
    await compose(browser,networkA,other,historyParent);
    await waitFor(()=>row(peer,networkB,owner,historyParent),'recipient reads the untouched reaction history parent');
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:historyParent,target:'PM',emoji:'❤️',
      reopen:{connId:networkB,target:owner}});
    check('a reopened device still uses Signal and retains the older shared key',await waitFor(()=>peer.evaluate(`
      _e2ePrefersSignal(${receiverKey})&&e2eTargetState(${q(owner)},{conn_id:${q(networkB)}}).mode==='dm'&&
      !!E2E.channelKeys[_e2ePskSlot(_e2eCanon(${q(owner)},${q(networkB)}),${q(networkB)})]`),'reopened method and saved key'));
  }
  const dmAction='ratchet action '+stamp;
  await compose(peer,networkB,owner,'/me '+dmAction);
  await waitFor(()=>row(browser,networkA,other,dmAction,'action'),'initiator decrypted a ratchet action');
  await reopen(browser,waitFor,'window._appShown && E2E.keyReady && E2E.identityReady','same encrypted device reopened for history');
  await browser.evaluate('setActive('+q(networkA)+','+q(other)+')');
  check('remembered device reopens sent and received Signal DMs from history',await waitFor(()=>browser.evaluate(`(()=>{
    const visible=document.getElementById('chat-area').textContent;
    return visible.includes(${q(dm)})&&visible.includes(${q(reply)});
  })()`),'visible decrypted DM history after reopen'));
  check('reopened Signal history preserves an encrypted action',await waitFor(
    ()=>row(browser,networkA,other,dmAction,'action'),'decrypted action after reopen'));
  check('reopened Signal history uses no unlock popup or visible protocol frames',await browser.evaluate(`
    !(${promptOpen}) && !/\\[e2e(?:dm|x3dh)/.test(document.getElementById('chat-area').textContent)
  `));
  check('Signal history is encrypted on disk, scoped to one conversation, and clearable',await browser.evaluate(`(async()=>{
    const cid=${q(networkA)}, target='local-history-fixture', peer='fixture';
    const wire='[e2edm2]archive-fixture', privateText='fixture local DM only';
    const lines=[{from:peer,text:wire}];
    await e2eRememberDmHistory(cid,target,peer,wire,privateText);
    const key=await _e2eHistoryKey(_e2eUser(),E2E.e2eEncKey);
    const id=await _e2eHistoryId(key,['message',_e2eHistoryScope(cid,target),peer,wire]);
    const record=await _e2eIdbGet(['dm-history',_e2eUser(),id]);
    const index=JSON.stringify(await _e2eIdbGet(['dm-history-index',_e2eUser()]));
    const right=(await e2eReadDmHistory(cid,target,lines)).get(lines[0])===privateText;
    const wrongNetwork=(await e2eReadDmHistory('other-network',target,lines)).size===0;
    const wrongSender=(await e2eReadDmHistory(cid,target,[{from:'other',text:wire}])).size===0;
    const oldWrite=e2eRememberDmHistory(cid,target,peer,wire,privateText);
    const otherWrite=e2eRememberDmHistory(cid,'other-fixture',peer,wire,privateText);
    await Promise.all([oldWrite,otherWrite,e2eClearDmHistory(cid,target)]);
    const cleared=(await e2eReadDmHistory(cid,target,lines)).size===0;
    const retained=(await e2eReadDmHistory(cid,'other-fixture',lines)).get(lines[0])===privateText;
    await e2eClearDmHistory(cid,'other-fixture');
    return record instanceof Uint8Array&&!new TextDecoder().decode(record).includes(privateText)&&
      !index.includes(cid)&&!index.includes(target)&&right&&wrongNetwork&&wrongSender&&cleared&&retained;
  })()`));
  check('older Signal ciphertext without a local copy appears as an unavailable message',await browser.evaluate(`(async()=>{
    const x=await _decryptLogLines(${q(other)},[{from:${q(other)},text:'[e2edm2]prior'}],${q(networkA)});
    return x[0].encrypted&&x[0].text===DM_HISTORY_UNAVAILABLE;
  })()`));
  check('the optimistic Signal row can be masked before its IRC echo arrives',await browser.evaluate(`(()=>{
    const cid=${q(networkA)}, target='history-pending-fixture', original=rateLimitedSend;
    const m={from:getNick(cid),text:'optimistic fixture',kind:'action',encrypted:true};
    rateLimitedSend=()=>{};
    try {
      _queueChatSend({conn_id:cid,raw:'PRIVMSG '+target+' :[e2edm2]pending'},m);
      return m._dmHistoryWire==='[e2edm2]pending'&&m._dmHistoryState==='ready'&&!m.id;
    } finally { rateLimitedSend=original; }
  })()`));
  check('encryption-like text in channel logs remains ordinary visible text',await browser.evaluate(`(async()=>{
    const lines=['[e2edm2] ordinary channel text','[e2ex3dh] ordinary channel text'].map(text=>({text,from:'fixture',kind:'privmsg'}));
    const processed=await _decryptLogLines(${q(channel)},lines,${q(networkA)});
    return processed.length===2&&processed.every((row,i)=>row.text===lines[i].text&&!row.encrypted&&!row._e2eSetupLine);
  })()`));
  check('distinct encrypted rows in the same second survive sync while exact wire copies are deduplicated',await browser.evaluate(`(async()=>{
    const cid=${q(networkA)}, target='history-replay-fixture', ts=Math.floor(Date.now()/1000);
    const log=(id,text)=>({id,ts,from:'fixture',text,kind:'privmsg'});
    try {
      await appendSyncLines(cid,target,[log(101,'[e2edm2]one'),log(102,'[e2edm2]two'),log(103,'[e2edm2]one')]);
      const buf=getBuf(cid,target);
      return buf.map(m=>m.id).join(',')==='101,102'&&
        applyHeldDmHistory(cid,target,'fixture','[e2edm2]one','authenticated fixture')&&
        buf.length===2&&buf[0].id===101&&buf[0].text==='authenticated fixture';
    } finally { delete buffers[bk(cid,target)]; delete _lastMsgId[bk(cid,target)]; }
  })()`));
  check('an obsolete wrapped history index key is replaced on first use',await browser.evaluate(`(async()=>{
    const cid=${q(networkA)}, target='history-index-reset-fixture', user=_e2eUser();
    const lines=[{from:'fixture',text:'[e2edm2]replacement-index'}];
    const stale=crypto.getRandomValues(new Uint8Array(60));
    if(!await _e2eIdbPut(['dm-history-id-key',user],stale)) return false;
    _e2eHistoryKeys.delete(E2E.e2eEncKey);
    try {
      await e2eRememberDmHistory(cid,target,lines[0].from,lines[0].text,'new cache entry');
      const active=await _e2eIdbGet(['dm-history-id-key',user]);
      return _e2eCmpBytes(active,stale)!==0&&(await e2eReadDmHistory(cid,target,lines)).get(lines[0])==='new cache entry';
    } finally { await e2eClearDmHistory(cid,target); }
  })()`));
  const pinnedFingerprint=await browser.evaluate(`E2E.trustStore[${peerKey}].fingerprint`);
  check('confirmed peer can be marked verified on this device',
    await browser.evaluate(`e2eMarkVerified(${q(other)},${q(networkA)})`));
  await browser.evaluate('e2eSaveState()');
  await waitFor(()=>browser.evaluate('E2E._txq.length===0'),'encrypted trust state sent');
  check('peer trust is never sent or stored as a plaintext mirror',
    [browser,peer].every(b=>!b.frames.some(frame=>frame.includes('"type":"e2e_update_trust"'))) &&
    (await Promise.all([owner,other].map(async user=>
      !(await fs.readdir(path.join(tmp,'e2e',user))).some(name=>name.startsWith('trust.json')))))
      .every(Boolean));

  check('encrypted media and preview overrides always require an explicit click',await browser.evaluate(`(async()=>{
    const appearance=loadAppearance, policy=loadXPolicy;
    const cid=${q(networkA)}, target=${q(other)}, key=bk(cid,target);
    try {
      loadAppearance=()=>({extMedia:'all',ytPreview:'auto',linkPreviews:true});
      loadXPolicy=()=>({load:'auto_public',conversations:{[key]:{load:'auto'}}});
      const urls=[location.origin+'/cryptirc/files/a.png','https://media.invalid/a.jpg','https://media.invalid/a.mp3',
        'https://media.invalid/a.mp4','https://www.youtube.com/watch?v=jNQXAC9IVRw'];
      const nodes=urls.map(url=>buildMediaEl(url,true));
      await new Promise(resolve=>setTimeout(resolve,10));
      return nodes.every(node=>node&&!node.querySelector('img[src],audio[src],video[src],iframe'))&&
        tweetDisclosure({connId:cid,target,isPrivate:true,encrypted:true})==='manual'&&
        tweetDisclosure({connId:cid,target,isPrivate:true,encrypted:false})==='auto';
    } finally {loadAppearance=appearance;loadXPolicy=policy;}
  })()`));

  check('a session load that crosses a lock cannot reinstall plaintext key state',await browser.evaluate(`(async()=>{
    const slot='lock-generation-fixture', context=_e2eCtxSession(slot);
    const blob=await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({RK:'fixture',epoch:1})),context);
    const decrypt=_e2eGcmDec;
    let reached,release;
    const waiting=new Promise(resolve=>{reached=resolve;});
    const held=new Promise(resolve=>{release=resolve;});
    E2E._v2Slots.delete(context);
    _e2eGcmDec=async (...args)=>{
      const bytes=await decrypt(...args);
      if(args[2]&&new TextDecoder().decode(args[2]).endsWith(context)){reached();await held;}
      return bytes;
    };
    try {
      const opening=_e2eInstallStoredInner(slot,blob);
      await waiting;
      E2E._lockGen++;
      release();
      return await opening===null&&!E2E.dmSessions[slot]&&!E2E._v2Slots.has(context);
    } finally {release();_e2eGcmDec=decrypt;}
  })()`));
  check('a delayed device restore preserves a session advanced during decryption',await browser.evaluate(`(async()=>{
    const slot='device-restore-fixture', context=_e2eDevSlot(slot);
    const original={RK:'fixture',epoch:1}, advanced={RK:'fixture',epoch:3};
    const blob=await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({RK:'fixture',epoch:2})),context);
    const read=_e2eIdbGet, decrypt=aesDecryptBlob;
    let reached,release;
    const waiting=new Promise(resolve=>{reached=resolve;});
    const held=new Promise(resolve=>{release=resolve;});
    E2E.dmSessions[slot]=original;
    _e2eIdbGet=async key=>key.endsWith(':'+slot)?{ep:2,blob}:read(key);
    aesDecryptBlob=async (...args)=>{
      const bytes=await decrypt(...args);
      if(args[1]===context){reached();await held;}
      return bytes;
    };
    try {
      const opening=_e2eSyncFromDevice(slot);
      await waiting;
      E2E.dmSessions[slot]=advanced;
      release();
      await opening;
      return E2E.dmSessions[slot]===advanced;
    } finally {
      release();
      _e2eIdbGet=read;
      aesDecryptBlob=decrypt;
      delete E2E.dmSessions[slot];
      E2E._v2Slots.delete(context);
    }
  })()`));
  check('a browser-only lock keeps an already wrapped Signal save queued',await browser.evaluate(`(async()=>{
    const slot='queued-lock-fixture', send=_e2eWs, write=_e2eWriteDeviceSession;
    const ready=E2E.keyReady, serverGeneration=E2E._serverLockGen;
    let mayPersist;
    _e2eWs=(msg,guard)=>{
      if(msg.type!=='e2e_commit_session'||msg.partner!==slot)return send(msg,guard);
      mayPersist=guard;
      queueMicrotask(()=>_e2eResolveWaiter({type:'e2e_session_committed',req:msg.req,partner:slot,ok:true}));
      return Promise.resolve(true);
    };
    _e2eWriteDeviceSession=(key,session)=>key===slot?Promise.resolve():write(key,session);
    try {
      await saveSession(slot,{RK:'fixture',epoch:0},{snd:true});
      if(!mayPersist?.())return false;
      E2E._sessionTombstones.set(slot,0);
      const afterDeletion=mayPersist();
      E2E._sessionTombstones.delete(slot);
      E2E._lockGen++;
      E2E.keyReady=false;
      const afterDeviceLock=mayPersist();
      E2E._serverLockGen++;
      return !afterDeletion&&afterDeviceLock&&!mayPersist();
    } finally {
      _e2eWs=send;
      _e2eWriteDeviceSession=write;
      E2E.keyReady=ready;
      E2E._serverLockGen=serverGeneration;
      delete E2E.dmSessions[slot];
      delete E2E._sessionEpoch[slot];
      delete _e2eDev().ep[slot];
    }
  })()`));
  check('a removed Signal session cannot return from older IndexedDB state',await browser.evaluate(`(async()=>{
    const slot='device-tombstone-fixture', read=_e2eIdbGet;
    const blob=await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({RK:'fixture',epoch:2})),_e2eDevSlot(slot));
    E2E._sessionEpoch[slot]=3;
    _e2eIdbGet=async key=>key.endsWith(':'+slot)?{ep:2,blob}:read(key);
    try {
      await _e2eSyncFromDevice(slot);
      return !E2E.dmSessions[slot]&&E2E._sessionEpoch[slot]===3;
    } finally {
      _e2eIdbGet=read;
      delete E2E.dmSessions[slot];
      delete E2E._sessionEpoch[slot];
    }
  })()`));
  check('a confirmed Signal close retires older device state and preserves a later replacement',await browser.evaluate(`(async()=>{
    const key='device-delete-race-fixture', user=_e2eUser(), slot='s:'+user+':'+key;
    try {
      const wrapped=ep=>aesEncryptBlob(new TextEncoder().encode(JSON.stringify({RK:'fixture',epoch:ep})),_e2eDevSlot(key));
      await _e2eIdbPut(slot,{ep:9,blob:await wrapped(9)});
      // Every production caller first closes the canonical slot and records
      // its acknowledged generation while holding this contact's ratchet lock.
      E2E._sessionTombstones.set(key,10);
      await _e2eDropSession(key);
      const deleted=await _e2eIdbGet(slot);
      const replacement=await wrapped(11);
      await _e2eIdbPut(slot,{ep:11,blob:replacement});
      await _e2eDropSession(key);
      const kept=await _e2eIdbGet(slot);
      return deleted?.del===1&&deleted.ep===10&&_e2eDev().ep[key]===10&&kept?.ep===11&&kept.blob===replacement;
    } finally {
      await _e2eIdbDel(slot);
      delete E2E._sessionEpoch[key];
      E2E._sessionTombstones.delete(key);
      delete _e2eDev().ep[key]; _e2eDevSave();
    }
  })()`));
  check('a deletion wins an equal-epoch restore from either store',await browser.evaluate(`(async()=>{
    const slot='equal-epoch-delete-fixture', read=_e2eIdbGet, data=new TextEncoder().encode(JSON.stringify({RK:'fixture',epoch:7}));
    const account=await aesEncryptBlob(data,_e2eCtxSession(slot)), device=await aesEncryptBlob(data,_e2eDevSlot(slot));
    let record={ep:7,del:1};
    _e2eIdbGet=async key=>key.endsWith(':'+slot)?record:read(key);
    try {
      await _e2eSyncFromDevice(slot);
      record={ep:7,blob:device};
      await _e2eSyncFromDevice(slot);
      return E2E._sessionTombstones.get(slot)===7&&!E2E.dmSessions[slot]&&
        await _e2eInstallStoredInner(slot,account)===null&&!E2E.dmSessions[slot];
    } finally {
      _e2eIdbGet=read; E2E._sessionTombstones.delete(slot); delete E2E._sessionEpoch[slot]; delete E2E.dmSessions[slot];
    }
  })()`));

  check('re-establishment can replace a restored older ratchet without loading its old chain',await browser.evaluate(`(async()=>{
    const slot='rollback-regression-fixture', ctx=_e2eCtxSession(slot);
    const initial=await _e2eRequestSession(slot,true);
    const floor=await _e2eReadSessionFloor(initial?.floor_blob,_e2eUser());
    if(!floor||initial.blob)return false;
    const oldEpoch=floor.epoch+3, highest=oldEpoch+2;
    const stale=await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({RK:'older-fixture',epoch:oldEpoch})),ctx);
    const req=crypto.randomUUID(), dev=_e2eDev();
    try {
      const put=await _e2eReq({type:'e2e_commit_session',partner:slot,blob:stale,expect:'',floor_expect:floor.digest,
        req,dv:_e2eDeviceId(),snd:false,create:true},
        'e2e_session_committed',4000,e=>e.req===req);
      if(!put?.ok)return false;
      E2E._sessionEpoch[slot]=highest;
      if(await _e2eInstallStoredInner(slot,stale)!==null || !E2E.dmSessions[slot]?._unusable || E2E.dmSessions[slot]?.RK)return false;
      await saveSession(slot,{RK:'fresh-fixture',startEph:'new-fixture'});
      const stored=await _e2eRequestSession(slot);
      return stored?.blob!==stale && E2E.dmSessions[slot].epoch>highest &&
        JSON.parse(new TextDecoder().decode(await aesDecryptBlob(stored.blob,ctx))).RK==='fresh-fixture';
    } finally {
      await _e2eCloseSessionSlot(slot,slot,E2E._lockGen);
      await _e2eIdbDel('s:'+_e2eUser()+':'+slot);
      delete E2E.dmSessions[slot];delete E2E._sessionEpoch[slot];delete dev.ep[slot];_e2eDevSave();
    }
  })()`));
  check('a pre-upgrade device record cannot recreate a deleted ratchet by sending or receiving',await browser.evaluate(`(async()=>{
    const slot='unversioned-device-fixture';
    const initial=await _e2eRequestSession(slot,true);
    const floor=await _e2eReadSessionFloor(initial?.floor_blob,_e2eUser());
    if(!floor||initial.blob)return false;
    const previous={RK:'local-only-fixture',epoch:floor.epoch+3,startEph:'original'};
    E2E.dmSessions[slot]=previous;
    try {
      const bytes=new TextEncoder().encode(JSON.stringify(previous));
      const blob=await aesEncryptBlob(bytes,_e2eCtxSession(slot));
      const commit=async snd=>{
        const req=crypto.randomUUID();
        return _e2eReq({type:'e2e_commit_session',partner:slot,blob,expect:'',floor_expect:floor.digest,
          req,dv:_e2eDeviceId(),snd,create:true},
          'e2e_session_committed',4000,e=>e.req===req);
      };
      if(!(await commit(false))?.ok || await _e2eDeleteSlot({type:'e2e_delete_session',partner:slot}) ||
          !await _e2eCloseSessionSlot(slot,slot,E2E._lockGen))return false;
      const outgoing=await commit(true);
      if(!outgoing || outgoing.ok || outgoing.conflict!=='')return false;
      for(const snd of [true,false]){
        let stopped=false;
        try{await saveSession(slot,{...previous},{snd});}catch{stopped=true;}
        if(!stopped || (await _e2eRequestSession(slot))?.blob || E2E.dmSessions[slot]!==previous)return false;
      }
      await saveSession(slot,{RK:'fresh-fixture',startEph:'new'},{create:true,replaceRevision:E2E._sessionSyncRepair.get(slot)});
      return !!(await _e2eRequestSession(slot))?.blob && E2E.dmSessions[slot].startEph==='new' && !E2E._sessionSyncRepair.has(slot);
    } finally {
      await _e2eCloseSessionSlot(slot,slot,E2E._lockGen);
      await _e2eIdbDel('s:'+_e2eUser()+':'+slot);
      delete E2E.dmSessions[slot];delete E2E._sessionEpoch[slot];delete _e2eDev().ep[slot];
      E2E._sessionSyncRepair.delete(slot);_e2eDevSave();
    }
  })()`));

  const restoredSlot='session-restore-before-close-fixture';
  const restoredFile=path.join(tmp,'e2e',owner,'sessions',restoredSlot+'.enc');
  const savedEpoch=await browser.evaluate(`(async()=>{
    const slot=${q(restoredSlot)};
    await saveSession(slot,{RK:'disposable restore fixture',startEph:'first'},{create:true});
    return E2E.dmSessions[slot].epoch;
  })()`);
  const olderRecord=await fs.readFile(restoredFile);
  try {
    const confirmed=await browser.evaluate(`(async()=>{
      const slot=${q(restoredSlot)};
      for(let i=0;i<4;i++)await saveSession(slot,{...E2E.dmSessions[slot],Ns:i+1},{snd:true});
      const stored=await _e2eRequestSession(slot);
      return JSON.parse(new TextDecoder().decode(await aesDecryptBlob(stored.blob,_e2eCtxSession(slot)))).epoch;
    })()`);
    await fs.writeFile(restoredFile+'.restore',olderRecord,{mode:0o600});
    await fs.rename(restoredFile+'.restore',restoredFile);
    const closed=await browser.evaluate(`(async()=>{
      const slot=${q(restoredSlot)}, user=_e2eUser();
      const old=await _e2eRequestSession(slot,true);
      const observed=JSON.parse(new TextDecoder().decode(await aesDecryptBlob(old.blob,_e2eCtxSession(slot)))).epoch;
      const live=E2E.dmSessions[slot].epoch;
      const acknowledged=await _e2eCloseSessionSlot(slot,slot,E2E._lockGen);
      const current=await _e2eRequestSession(slot,true);
      const floor=await _e2eReadSessionFloor(current?.floor_blob,user);
      return {observed,live,acknowledged,absent:!!current&&!current.blob,floor:floor?.epoch||0};
    })()`);
    console.log('RESTORED-CLOSE-FLOOR '+JSON.stringify({savedEpoch,confirmed,...closed}));
    check('closing a restored older ratchet preserves this device’s higher acknowledged epoch',
      confirmed>=savedEpoch+4&&closed.observed===savedEpoch&&closed.live===confirmed&&
      closed.acknowledged&&closed.absent&&closed.floor>confirmed);
  } finally {
    olderRecord.fill(0);
    await browser.evaluate(`(async()=>{
      const slot=${q(restoredSlot)}, user=_e2eUser();
      await _e2eCloseSessionSlot(slot,slot,E2E._lockGen);
      await _e2eIdbDel('s:'+user+':'+slot);
      delete E2E.dmSessions[slot];delete E2E._sessionEpoch[slot];delete _e2eDev().ep[slot];_e2eDevSave();
    })()`);
  }

  const offFixture='#shared-off-'+stamp;
  const label='Shared-key scope fixture';
  ownerWs.send({type:'add_network',network:{id:crypto.randomUUID(),label,server:'127.0.0.1',
    port:Number(process.env.IRC_PORT),tls:false,tls_accept_invalid_certs:false,nick:owner,username:owner,
    realname:label,auto_join:[],sasl_external:false,auto_reconnect:false}});
  const scopedState=await ownerWs.wait(event=>event.type==='state'&&event.networks?.some(net=>net.config.label===label),
    'second network for the shared-key off fixture');
  const elsewhere=scopedState.networks.find(net=>net.config.label===label).config.id;
  try {
    const start=ownerWs.events.length;
    await browser.evaluate(`(async()=>{
      const name=${q(offFixture)}, cid=${q(networkA)};
      const legacy=await generateChannelKey(), scoped=await generateChannelKey();
      await storeChannelKey(name,legacy.key,legacy.keyB64);
      await storeChannelKey(_e2eScopedPskSlot(name,cid),scoped.key,scoped.keyB64);
    })()`);
    await waitFor(()=>ownerWs.events.slice(start).some(e=>e.type==='e2e_channel_key'&&e.channel==='@'+networkA+':'+offFixture),
      'server stores the scoped shared key');
    if(process.env.CRYPTIRC_TEST_CHANNEL_OFF_RECONNECT==='1'){
      await browser.evaluate(`(()=>{
        const connect=connectWs;
        connectWs=()=>{};
        window.resumeChannelOff=()=>{connectWs=connect;_onResume();};
        ws.close();
      })()`);
      await waitFor(()=>browser.evaluate('!_wsReady()&&E2E.keyReady'),'the channel key remains available during the reconnect');
      const frames=browser.frames.length;
      await browser.evaluate(`void (window.channelOffAttempt=handleEncryptCommand(['off'],${q(networkA)},${q(offFixture)}))`);
      await pause(250);
      await browser.evaluate('window.resumeChannelOff();');
      await browser.evaluate('window.channelOffAttempt');
      const requests=browser.frames.slice(frames).map(JSON.parse);
      check('one channel-off action survives an actual WebSocket reconnect and reads only channel inventory',
        requests.some(e=>e.type==='e2e_list_channel_keys'&&typeof e.req==='string')&&
        requests.filter(e=>e.type==='e2e_delete_channel_key').length===1);
      await waitFor(()=>browser.evaluate('!E2E._resyncPending'),'normal encryption resync finishes after channel-off acknowledgment');
    }else await browser.evaluate(`handleEncryptCommand(['off'],${q(networkA)},${q(offFixture)})`);
    check('switching off a scoped chat preserves shared-key protection on another network',
      await browser.evaluate(`e2eTargetState(${q(offFixture)},{conn_id:${q(networkA)}}).mode==='none'&&
        e2eTargetState(${q(offFixture)},{conn_id:${q(elsewhere)}}).mode==='psk'`));
    const snapshotAt=ownerWs.events.length;
    ownerWs.send({type:'e2e_load_keyring'});
    check('the server stores the per-network opt-out while retaining the legacy shared key',
      await waitFor(()=>ownerWs.events.slice(snapshotAt).find(e=>e.type==='e2e_keyring'&&
        e.channels?.includes(offFixture)&&!e.channels.includes('@'+networkA+':'+offFixture)&&
        e.disabled_channels?.includes('@'+networkA+':'+offFixture)),'scoped opt-out readback'));
    await browser.evaluate(`removeChannelKey(${q(offFixture)},[${q(offFixture)}])`);
  } finally {
    ownerWs.send({type:'remove_network',id:elsewhere});
    await ownerWs.wait(event=>event.type==='state'&&!event.networks?.some(net=>net.config.id===elsewhere),
      'scoped shared-key fixture network removed');
  }

  const inventoryTest=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='psk-inventory-refresh';
  const pskSlot='@'+networkA+':'+channel;
  if(inventoryTest){
    await browser.evaluate(`(()=>{
      const socket=ws, handle=socket.onmessage, slot=${q(pskSlot)};
      const gate={olderList:null,oldKey:null,reply:null,accept:false,deliver:message=>handle.call(socket,message),restore:()=>{
        if(ws===socket)socket.onmessage=handle;
        delete window.pskInventoryFixture;
      }};
      window.pskInventoryFixture=gate;
      socket.onmessage=message=>{
        const event=JSON.parse(message.data);
        if(event.type==='e2e_channel_list'&&!gate.olderList&&!event.channels.includes(slot)){
          gate.olderList=message;
          return;
        }
        if(event.type==='e2e_channel_key'&&event.channel===slot){
          if(!event.req){gate.oldKey||=message;return;}
          if(!gate.accept){gate.reply=message;return;}
        }
        handle.call(socket,message);
      };
      wsend({type:'e2e_list_channel_keys'});
    })()`);
    await waitFor(()=>browser.evaluate('!!window.pskInventoryFixture.olderList'),'the real prior inventory omits the unwritten slot');
  }
  const words = await shareKey(browser, waitFor, 'keygen', networkA, channel);
  await peer.evaluate('handleEncryptCommand(' + q(['add', ...words.split(' ')]) + ',' + q(networkB) + ',' + q(channel) + ')');
  await waitFor(() => hasKey(peer,channel,networkB), 'peer imported channel PSK');
  check('channel key stays out of the chat buffer and WebSocket frames',
    !await browser.evaluate('getBuf(' + q(networkA) + ',' + q(channel) + ').some(m=>m.text?.includes(' + q(words) + '))') &&
    ![...browser.frames,...peer.frames].some(frame => frame.includes(words)));
  const channelText = 'encrypted channel '+stamp;
  const waitForChannelMessage=async(text,fromIndex,name)=>{
    try { await waitFor(()=>row(peer,networkB,channel,text),name); }
    catch(error){
      const metadata=(device,cid)=>device.evaluate(`(()=>{
        const slot=_e2ePskSlot(${q(channel)},${q(cid)}), key=E2E.channelKeys[slot];
        return {key:key&&_e2ePskIds.get(key),binding:key&&_e2ePskSendBinding(slot,${q(cid)},key),
          nick:getNick(${q(cid)}),mode:e2eTargetState(${q(channel)},{conn_id:${q(cid)}}).mode,
          hasDraft:document.getElementById('msg-input').value===${q(text)},queue:_rateQueue.length,
          rendered:getBuf(${q(cid)},${q(channel)}).slice(-3).map(m=>[m.kind,m._pskHistoryState||'',m.sendState||''])};
      })()`);
      const [sender,receiver]=await Promise.all([metadata(browser,networkA),metadata(peer,networkB)]);
      const incoming=otherWs.events.slice(fromIndex).filter(e=>e.type==='irc_message'&&e.conn_id===networkB&&e.target===channel&&e.text?.startsWith('sd8~'));
      const last=incoming.at(-1);
      const decodes=last && await peer.evaluate(`channelDecryptEx(_e2ePskSlot(${q(channel)},${q(networkB)}),
        ${q(last.text)},${q(last.from)},{conn_id:${q(networkB)}}).then(result=>result?.pt===${q(text)})`);
      const detail={sameKey:!!sender.key&&sender.key===receiver.key,sameBinding:JSON.stringify(sender.binding)===JSON.stringify(receiver.binding),
        fromMatches:last?.from===sender.nick,received:incoming.length,decodes:!!decodes,senderMode:sender.mode,receiverMode:receiver.mode,
        hasDraft:sender.hasDraft,queue:sender.queue,senderRows:sender.rendered,receiverRows:receiver.rendered,
        senderBlock:await browser.evaluate('E2E.lastBlockReason'),
        senderSendState:await browser.evaluate(`(()=>{
          const slot=_e2ePskSlot(${q(channel)},${q(networkA)});
          return {socket:_wsReady(),resync:!!E2E._resyncPending,generation:E2E._chanKeyGen[slot],
            accountGeneration:E2E.state?.ch?.[slot]?.g,removed:!!E2E.chanRemoved[slot]};
        })()`)};
      throw new Error(error.message+' '+JSON.stringify(detail));
    }
  };
  const didSubmitChannel=at=>browser.frames.slice(at).some(frame=>{
    const event=JSON.parse(frame);
    return event.type==='send'&&event.conn_id===networkA&&event.raw?.startsWith('PRIVMSG '+channel+' :');
  });
  const beforeChannel=otherWs.events.length;
  const beforeChannelFrames=browser.frames.length;
  if(inventoryTest){
    await waitFor(()=>browser.evaluate('!!window.pskInventoryFixture.oldKey'),'the store genuinely echoed the newly wrapped scoped key');
    await browser.evaluate('window.pskInventoryFixture.deliver(window.pskInventoryFixture.olderList)');
  }
  await compose(browser, networkA, channel, channelText);
  if(inventoryTest){
    await waitFor(()=>browser.evaluate('!!window.pskInventoryFixture.reply'),'the fresh scoped read answers the delayed inventory');
    check('the first shared-key draft waits for the authenticated scoped read without sending plaintext',
      await browser.evaluate(`document.getElementById('msg-input').value===${q(channelText)}`)&&
      !didSubmitChannel(beforeChannelFrames));
    await browser.evaluate(`(()=>{
      const gate=window.pskInventoryFixture;
      gate.accept=true;
      gate.deliver(gate.reply);
    })()`);
  }
  await waitForChannelMessage(channelText,beforeChannel,'recipient decrypted shared-key message');
  check('testnet receives shared-key ciphertext',
    await otherWs.wait(ev=>ev.type==='irc_message'&&ev.conn_id===networkB&&ev.from===owner&&ev.target===channel&&
      ev.text?.startsWith('sd8~'),'the separate IRC observer receives the encrypted channel message') &&
    !otherWs.events.some(ev => ev.text?.includes(channelText)));
  if(inventoryTest){
    const req=crypto.randomUUID();
    try{
      ownerWs.send({type:'e2e_delete_channel_key',channel:pskSlot,v:3,req});
      await waitFor(()=>ownerWs.events.find(event=>event.type==='e2e_key_deleted'&&event.req===req&&event.ok),
        'the same-account observer really deletes the scoped key');
      await waitFor(()=>browser.evaluate(`(()=>{
        const state=e2eTargetState(${q(channel)},{conn_id:${q(networkA)}});
        return state.mode==='blocked'&&!state.pskInventory&&state.reason.includes('was removed');
      })()`),'the scoped read confirms that the other device actually removed the key');
      await browser.evaluate(`new Promise(resolve=>{
        const waiters=E2E._waiters.e2e_channel_key_done||=([]);
        waiters.push({match:event=>event.channel===${q(pskSlot)},done:resolve});
        window.pskInventoryFixture.deliver(window.pskInventoryFixture.oldKey);
      })`);
      const removed='held after a real PSK deletion '+stamp, at=browser.frames.length;
      await compose(browser,networkA,channel,removed);
      await waitFor(()=>browser.evaluate(`E2E.lastBlockReason?.includes('was removed')&&
        document.getElementById('msg-input').value===${q(removed)}`),'the delayed old key cannot bypass the confirmed removal');
      check('genuine other-device deletion keeps the draft and sends nothing after the stale key update',
        !didSubmitChannel(at));
      return ownerCode;
    }finally{await browser.evaluate('window.pskInventoryFixture?.restore()');}
  }
  const sharedWire=otherWs.events.find(ev=>ev.type==='irc_message'&&ev.from===owner&&ev.target===channel&&ev.text?.startsWith('sd8~'))?.text;
  check('a shared key is scoped to its IRC connection and rejects unbound live ciphertext',!!sharedWire&&await peer.evaluate(`(async()=>{
    const name=${q(channel)}, cid=${q(networkB)}, from=${q(owner)}, wire=${q(sharedWire)};
    const slot=_e2ePskSlot(name,cid), env=JSON.parse(atob(wire.slice(4)));
    const other='12345678-1234-1234-1234-123456789abc';
    const previous=_isupport[cid], snapshot=networks.find(n=>n.config.id===cid);
    const key=E2E.channelKeys[slot], wrongRoom='#different-'+name.slice(1);
    _isupport[other]={..._isupport[cid],network:'separate-network-fixture'};
    E2E.channelKeys[wrongRoom]=key;
    try {
      const valid=await channelDecryptEx(slot,wire,from,{conn_id:cid});
      const repeat=await channelDecryptEx(slot,wire,from,{conn_id:cid,live:true});
      const foreign=await channelDecryptEx(slot,wire,from,{conn_id:other});
      const wrongSender=await channelDecryptEx(slot,wire,from+'z',{conn_id:cid});
      const wrongTarget=await channelDecryptEx(wrongRoom,wire,from,{conn_id:cid});
      const unbound=await channelDecryptEx(slot,'sd8~'+btoa(JSON.stringify({v:1,n:env.n,c:env.c})),from,{conn_id:cid,live:true});
      delete _isupport[cid];
      const bootstrapped=await channelDecryptEx(slot,wire,from,{conn_id:cid});
      return slot===_e2eScopedPskSlot(name,cid)&&e2eTargetState(name,{conn_id:other}).mode==='none'&&
        env.v===2&&valid?.verified&&repeat?.replay&&!foreign?.pt&&!wrongSender?.pt&&!wrongTarget?.pt&&
        unbound?.bad&&!unbound.pt&&snapshot?.network_name&&bootstrapped?.verified;
    } finally {_isupport[cid]=previous;delete _isupport[other];delete E2E.channelKeys[wrongRoom];}
  })()`));
  check('older authenticated shared-key history keeps its media private and shows a legacy warning',await peer.evaluate(`(async()=>{
    const target=${q(channel)}, cid=${q(networkB)}, from=${q(owner)}, text='legacy saved message https://fixture.example.invalid/image.png';
    const slot=_e2ePskSlot(target,cid), key=E2E.channelKeys[slot];
    const nonce=crypto.getRandomValues(new Uint8Array(12));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},key,new TextEncoder().encode(text));
    const env={v:1,n:bytesToBase64(nonce),c:bytesToBase64(new Uint8Array(ct)),t:1,i:'fixture'};
    env.m=bytesToBase64(await _e2ePskMac(key,_e2ePskBinding(target,from),env));
    const wire='sd8~'+btoa(JSON.stringify(env));
    const [saved]=await _decryptLogLines(target,[{id:0,ts:1,from,kind:'privmsg',text:wire}],cid);
    const presented=buildRow(saved,{conn_id:cid,target});
    const live=await e2eDecryptIncoming(from,target,wire,{conn_id:cid,live:true});
    return saved.encrypted&&saved._pskHistoryState==='legacy'&&saved.text.includes('legacy encrypted history')&&
      saved.text.endsWith(text)&&!presented.querySelector('[title="E2E encrypted"]')&&
      !!presented.querySelector('.msg-media-load')&&!presented.querySelector('.msg-media img')&&
      live.pskStatus==='refused'&&!live.plaintext.includes(text);
  })()`));
  check('a complete shared-key code works across different unnamed IRC endpoints',await browser.evaluate(`(async()=>{
    const a='a1a00000-0000-4000-8000-000000000001', b='a1a00000-0000-4000-8000-000000000002';
    const target='#unnamed-fixture', from='FixtureNick';
    const aSlot=_e2eScopedPskSlot(target,a), bSlot=_e2eScopedPskSlot(target,b);
    const key=(await generateChannelKey()).key, scope=crypto.randomUUID().replace(/-/g,'');
    _e2ePskScopes.set(key,scope);
    networks.push({config:{id:a,server:'one.example.invalid',port:6667}},
      {config:{id:b,server:'two.example.invalid',port:6697}});
    try {
      E2E.channelKeys[aSlot]=key;
      const wire=await channelEncrypt(aSlot,'scoped fixture',from,false,a);
      E2E.channelKeys[bSlot]=key;
      const reused=_e2ePskSendBinding(bSlot,b,key);
      delete E2E.channelKeys[aSlot];
      const opened=await channelDecryptEx(bSlot,wire,from,{conn_id:b,live:true});
      return !reused&&opened?.verified&&opened.pt==='scoped fixture';
    } finally {networks.splice(-2);delete E2E.channelKeys[aSlot];delete E2E.channelKeys[bSlot];}
  })()`));
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'||process.env.CRYPTIRC_TEST_REACTION_HISTORY==='1'){
    await peer.evaluate('setActive('+q(networkB)+','+q(channel)+')');
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:channelText,target:'channel',emoji:'❤️'});
    if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
      await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:channelText,target:'channel thumbs-down',emoji:'👎'});
    }
  }
  const action = 'encrypted action '+stamp;
  const beforeAction=otherWs.events.length;
  await compose(browser, networkA, channel, '/me '+action);
  await waitForChannelMessage(action,beforeAction,'recipient decrypted action');
  const notice = 'encrypted notice '+stamp;
  const beforeNotice=otherWs.events.length;
  await compose(browser, networkA, channel, '/notice '+channel+' '+notice);
  await waitForChannelMessage(notice,beforeNotice,'recipient decrypted notice');
  check('channel actions and notices stay encrypted on IRC',
    !otherWs.events.some(ev => ev.text?.includes(action) || ev.text?.includes(notice)));
  check('encrypted composer keeps files and paste contents off the host', await browser.evaluate(`
    (async()=>{
      const originalFetch=window.fetch, composer=document.getElementById('msg-input');
      let publicPosts=0;
      window.fetch=(url,opts)=>{
        const route=String(url);
        if((route.endsWith('/paste')||route.endsWith('/upload/init'))&&opts?.method==='POST'){
          publicPosts++;
          return Promise.resolve(new Response('{"error":"test"}',{status:403}));
        }
        return originalFetch(url,opts);
      };
      try {
        await uploadFile(new File(['test content'],'encrypted-test.txt',{type:'text/plain'}));
        showPasteModal();
        _smartPasteText='private draft';
        composer.value='';
        smartPasteYes();
        return publicPosts===0&&!document.getElementById('paste-content')&&composer.value==='private draft';
      } finally { window.fetch=originalFetch; composer.value=''; }
    })()
  `));
  const file = await request('/upload/init',{method:'POST',token:ownerSession,body:{
    id:crypto.randomUUID(),original_name:'encrypted-test.txt',size:12,source_conn_id:networkA,source_target:channel,
  }});
  check('the server rejects upload initialization for a protected target',
    file.status===403 && /encrypted chats/.test(file.data?.error));

  const nextKey = await shareKey(browser, waitFor, 'rotate', networkA, channel);
  check('rotation generates a different channel key', nextKey !== words);
  const rotatedText = 'new channel key '+stamp;
  const beforeRotation = otherWs.events.length;
  await compose(browser, networkA, channel, rotatedText);
  await waitFor(() => otherWs.events.slice(beforeRotation).some(ev =>
    ev.type === 'irc_message' && ev.text?.startsWith('sd8~')), 'rotated ciphertext reached IRC');
  await pause(300);
  check('original channel key does not decrypt traffic after rotation', !await row(peer, networkB, channel, rotatedText));
  await peer.evaluate('handleEncryptCommand(' + q(['add', ...nextKey.split(' ')]) + ',' + q(networkB) + ',' + q(channel) + ')');
  const lastChannelText = 'received after rekey '+stamp;
  const beforeCurrentKey=otherWs.events.length;
  await compose(browser, networkA, channel, lastChannelText);
  await waitForChannelMessage(lastChannelText,beforeCurrentKey,'peer decrypted with the rotated key');
  check('channel resumes encrypted chat after both members update the PSK', true);
  if(process.env.CRYPTIRC_TEST_PSK_STRESS==='1'){
    for(let index=0;index<8;index++){
      const replacement=await shareKey(browser,waitFor,'rotate',networkA,channel);
      await peer.evaluate(`handleEncryptCommand(${q(['add',...replacement.split(' ')])},${q(networkB)},${q(channel)})`);
      const outbound='rotation-'+index+'-'+stamp, reply='back-'+index+'-'+stamp, at=otherWs.events.length;
      await compose(browser,networkA,channel,outbound);
      await waitForChannelMessage(outbound,at,'shared-key rotation '+index);
      await compose(peer,networkB,channel,reply);
      await waitFor(()=>row(browser,networkA,channel,reply),'return trip after rotation '+index,30000);
      check('shared-key rotation '+index+' delivers both directions as ciphertext',
        ![...ownerWs.events,...otherWs.events].some(e=>e.text===outbound||e.text===reply));
    }
  }

  const freshDevice = await chromium('encrypted-recovery');
  await login(freshDevice, owner, password, waitFor);
  await waitFor(() => freshDevice.evaluate(`E2E._bootPhase==="locked" && E2E._krReceived && _wsReady() &&
    networks.some(n=>n.config.id===${q(networkA)}&&n.connected)`), 'new device stays locked on its connected network');
  const lockedIncoming='encrypted DM arrives while locked '+stamp;
  const lockedSenderAt=peer.frames.length, lockedRecipientAt=ownerWs.events.length;
  await compose(peer,networkB,owner,lockedIncoming);
  const lockedWire=await waitFor(()=>peer.frames.slice(lockedSenderAt).map(f=>JSON.parse(f)).find(
    m=>m.type==='send'&&m.conn_id===networkB&&m.raw?.includes(' :[e2edm2]'))?.raw.split(' :')[1],
    'sender transmits a ciphertext for the locked device');
  await waitFor(()=>ownerWs.events.slice(lockedRecipientAt).some(e=>e.type==='irc_message'&&e.conn_id===networkA&&e.from===other&&e.text===lockedWire),
    'the locked account receives the matching IRC ciphertext');
  await waitFor(()=>freshDevice.evaluate(`getBuf(${q(networkA)},${q(other)}).some(m=>m.e2eSetupAction==='unlock')`),
    'an incoming encrypted DM offers an unlock button on the locked device');
  check('an incoming encrypted DM leaves the device locked until the unlock action is chosen',!await freshDevice.evaluate(promptOpen));
  await openSetupInvite(freshDevice,networkA,other,waitFor);
  await waitPrompt(freshDevice,waitFor,unlockText);
  await freshDevice.evaluate(cancelPrompt);
  await waitFor(()=>freshDevice.evaluate('!E2E._interactiveUnlock'),'cancelled inline unlock settles');
  await pause(1450);
  check('a new device does not automatically ask for the recovery code', !await freshDevice.evaluate(promptOpen));
  await freshDevice.evaluate('setActive(' + q(networkA) + ',' + q(channel) + ')');
  await clickVisible(freshDevice, '#e2e-lock');
  await freshDevice.evaluate(`
    document.getElementById('generic-toast')?.remove();
    window.testOriginalWsReady = _wsReady;
    _wsReady = () => false;
  `);
  await clickVisible(freshDevice, panelUnlock);
  const connectionNotice = await freshDevice.evaluate(`
    document.getElementById('generic-toast')?.textContent.includes('Connect to CryptIRC') === true &&
    !document.querySelector(${q(panelUnlock)}).disabled && !(${promptOpen}) &&
    !document.getElementById('vault-overlay').classList.contains('show')
  `);
  await freshDevice.evaluate('_wsReady = window.testOriginalWsReady; delete window.testOriginalWsReady');
  check('the channel lock explains when encrypted chats cannot be unlocked offline', connectionNotice);
  await freshDevice.evaluate(`
    window.testOriginalWsend = wsend;
    wsend = msg => msg.type === 'e2e_load_keyring' ? false : window.testOriginalWsend(msg);
  `);
  await clickVisible(freshDevice, panelUnlock);
  await waitFor(() => freshDevice.evaluate(`
    document.getElementById('generic-toast')?.textContent.includes('Could not load your encryption keyring') &&
    !document.querySelector(${q(panelUnlock)}).disabled
  `), 'a failed keyring load reports an error and allows retry');
  await freshDevice.evaluate('wsend = window.testOriginalWsend; delete window.testOriginalWsend');
  check('a failed encryption keyring request gives retry feedback', true);
  await freshDevice.evaluate(`
    window.testOriginalIdbOpen = indexedDB.open;
    indexedDB.open = () => (window.testStalledIdbOpen = {});
  `);
  try {
    await clickVisible(freshDevice, panelUnlock);
    check('a stalled browser key cache falls back to the recovery prompt', await waitFor(
      () => freshDevice.evaluate(promptOpen + '&&' + promptText + '.includes(' + q(unlockText) + ')'),
      'recovery prompt after browser key cache timeout', 8000));
    check('a late cache open closes its database handle', await freshDevice.evaluate(`(() => {
      const request = window.testStalledIdbOpen;
      let closed = false;
      request.result = { close() { closed = true; } };
      request.onsuccess();
      return closed;
    })()`));
  } finally {
    await freshDevice.evaluate('indexedDB.open = window.testOriginalIdbOpen; delete window.testOriginalIdbOpen; delete window.testStalledIdbOpen');
  }
  check('a stalled remember-device write aborts its transaction and closes the database', await freshDevice.evaluate(`(async () => {
    const open = indexedDB.open;
    let aborted = false, closed = false;
    indexedDB.open = () => {
      const request = {};
      queueMicrotask(() => {
        request.result = {
          objectStoreNames: { contains: () => true },
          transaction: () => ({
            objectStore: () => ({ put: () => ({}) }),
            abort() { aborted = true; },
          }),
          close() { closed = true; },
        };
        request.onsuccess();
      });
      return request;
    };
    try { return !await _e2eIdbPutKey(_e2eUser(), {}) && aborted && closed; }
    finally { indexedDB.open = open; }
  })()`));
  await freshDevice.evaluate('void customPrompt("Other local dialog")');
  check('replacing the recovery prompt releases the original unlock attempt', await waitFor(
    () => freshDevice.evaluate('!E2E._interactiveUnlock && !document.querySelector(' + q(panelUnlock) + ').disabled'),
    'replaced recovery prompt released the unlock action', 3000));
  await freshDevice.evaluate(cancelPrompt);

  const beforeReload = await freshDevice.evaluate('performance.timeOrigin');
  await freshDevice.evaluate(`
    window.testOriginalSetTimeout = window.setTimeout;
    window.testOriginalUnlock = e2ePromptDeviceUnlock;
    window.stallChecks = 0;
    window.setTimeout = (fn, delay, ...args) => window.testOriginalSetTimeout(
      delay === 30000 ? () => { window.stallChecks++; fn(...args); } : fn,
      delay === 30000 ? 300 : delay, ...args);
    e2ePromptDeviceUnlock = () => new Promise(resolve => { window.finishStalledUnlock = resolve; });
  `);
  try {
    await clickVisible(freshDevice, panelUnlock);
    await freshDevice.evaluate('void customPrompt("Keep this dialog open")');
    check('the reload fallback waits while a prompt is visible', await waitFor(
      () => freshDevice.evaluate('window.stallChecks > 0 && !!document.querySelector(' + q(panelUnlock + ':disabled') + ')'),
      'the open prompt paused the reload fallback', 3000));
    await freshDevice.evaluate(cancelPrompt);
    check('a prolonged unlock offers an explicit reload instead of a disabled button', await waitFor(
      () => freshDevice.evaluate(`!!document.querySelector('#encrypt-panel-body [data-encrypt-cmd=reload]:not(:disabled)')`),
      'reload action for a prolonged unlock', 3000));
    await clickVisible(freshDevice, '#encrypt-panel-body [data-encrypt-cmd=reload]');
    check('the stalled-unlock reload action reloads the page', await waitFor(
      () => freshDevice.evaluate(`performance.timeOrigin !== ${beforeReload} && window._appShown &&
        E2E._bootPhase === 'locked' && E2E._krReceived`).catch(() => false), 'reloaded after stalled unlock'));
  } finally {
    await freshDevice.evaluate(`
      if (window.testOriginalUnlock) {
        window.finishStalledUnlock?.();
        window.setTimeout = window.testOriginalSetTimeout;
        e2ePromptDeviceUnlock = window.testOriginalUnlock;
        delete window.finishStalledUnlock;
        delete window.testOriginalSetTimeout;
        delete window.testOriginalUnlock;
        delete window.stallChecks;
      }
    `).catch(() => {});
  }
  await freshDevice.evaluate('setActive(' + q(networkA) + ',' + q(channel) + ')');
  await clickVisible(freshDevice, '#e2e-lock');
  await clickVisible(freshDevice, panelUnlock);
  await waitPrompt(freshDevice, waitFor, unlockText);
  check('unlock from the channel lock opens a focused recovery prompt in front of Encryption',
    await freshDevice.evaluate(`(() => {
      const field = ${input}, r = field.getBoundingClientRect();
      return document.activeElement === field && field === document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
    })()`));
  await freshDevice.evaluate(cancelPrompt + ';closeEncryptPanel()');
  await waitFor(() => freshDevice.evaluate('!E2E._interactiveUnlock'), 'channel lock recovery prompt dismissed');
  const lockedDraft = 'draft held until explicitly unlocked '+stamp;
  const lockedAt = freshDevice.frames.length;
  await compose(freshDevice, networkA, channel, lockedDraft);
  await waitFor(()=>freshDevice.evaluate("document.getElementById('composer-encryption-action').textContent==='Unlock'"),'a held encrypted draft offers the inline unlock action');
  await clickVisible(freshDevice,'#composer-encryption-action');
  await waitPrompt(freshDevice, waitFor, unlockText);
  await fillPrompt(freshDevice, losingCode);
  await waitFor(() => freshDevice.evaluate("E2E._bootPhase==='locked'&& !("+promptOpen+")"), 'incorrect code rejected');
  check('a recovery code from the losing setup cannot unlock the keyring', !await freshDevice.evaluate('E2E.keyReady'));
  check('an incorrect recovery code gives visible retry feedback', await freshDevice.evaluate(`
    document.getElementById('generic-toast')?.textContent.includes('That recovery code did not unlock your encrypted chats')
  `));
  check('send on a locked encrypted chat keeps the draft and sends no plaintext',
    await freshDevice.evaluate('document.getElementById("msg-input").value==='+q(lockedDraft)) &&
    !freshDevice.frames.slice(lockedAt).some(frame=>frame.includes(lockedDraft)));
  const actionDraft='/me held behind encryption '+stamp;
  await compose(freshDevice, networkA, channel, actionDraft);
  await waitPrompt(freshDevice, waitFor, unlockText);
  await freshDevice.evaluate(cancelPrompt);
  await waitFor(() => freshDevice.evaluate('!E2E._interactiveUnlock && !('+promptOpen+')'), 'locked action prompt dismissed');
  check('encrypted slash commands also keep their draft while locked',
    await freshDevice.evaluate('document.getElementById("msg-input").value==='+q(actionDraft)) &&
    !freshDevice.frames.slice(lockedAt).some(frame=>frame.includes(actionDraft.slice(4))));
  await freshDevice.evaluate("document.querySelector('#e2e-unlock-banner button').click()");
  await waitPrompt(freshDevice, waitFor, unlockText);
  const freshCount = freshDevice.frames.length;
  await fillPrompt(freshDevice, ownerCode);
  await waitFor(() => freshDevice.evaluate("E2E._bootPhase==='ready'&&E2E.identityReady"), 'new device recovered E2E keys');
  await waitFor(() => hasKey(freshDevice,channel,networkA), 'new device loaded channel PSK');
  check('unlocking does not send an earlier encrypted slash-command draft',
    !freshDevice.frames.slice(lockedAt).some(frame=>frame.includes(actionDraft.slice(4))) &&
    await freshDevice.evaluate('document.getElementById("msg-input").value==='+q(actionDraft)));
  check('recovered device restores the verified peer pin from encrypted state',
    await freshDevice.evaluate(`E2E.trustStore[${peerKey}]?.verified===true && E2E.trustStore[${peerKey}].fingerprint===${q(pinnedFingerprint)}`));
  check('new device recovers identity, DM ratchet and channel key without sending the code or a vault unlock',
    await freshDevice.evaluate(`!!E2E.dmSessions[${peerKey}]`) &&
    !freshDevice.frames.slice(freshCount).some(frame => frame.includes(ownerCode) || frame.includes('"type":"unlock_vault"')));
  const afterRestore = 'DM after recovery '+stamp;
  await compose(freshDevice, networkA, other, afterRestore);
  await waitFor(() => row(peer, networkB, owner, afterRestore), 'ratchet resumed on recovered device');
  check('recovered device sends through the restored DM ratchet', true);
  await reopen(freshDevice, waitFor, 'window._appShown && E2E._bootPhase==="ready" && E2E.identityReady', 'cached device reopened');
  check('reopening a remembered device restores keys without a popup', !await freshDevice.evaluate(promptOpen));

  await freshDevice.evaluate('_deviceLockNow(false)');
  await waitFor(() => freshDevice.evaluate('!E2E.keyReady'), 'device lock erased E2E keys from memory');
  check('intentional device lock requires a passphrase and has no Later action', await freshDevice.evaluate(`
    document.getElementById('vault-overlay').classList.contains('show') && document.getElementById('vault-unlock-later').hidden`));
  const blocked = 'must not reach IRC '+stamp;
  const sentBefore = freshDevice.frames.length;
  await compose(freshDevice, networkA, channel, blocked);
  await freshDevice.evaluate('void e2ePromptDeviceUnlock()');
  await pause(300);
  check('locked browser does not put protected chat on the wire',
    !freshDevice.frames.slice(sentBefore).some(frame => frame.includes(blocked)) &&
    await freshDevice.evaluate('!E2E.keyReady && !('+promptOpen+')'));
  await freshDevice.evaluate('handleEncryptCommand(["off"],' + q(networkA) + ',' + q(channel) + ')');
  check('a locked device preserves the encryption hint and sends no delete',
    await freshDevice.evaluate('e2eTargetState(' + q(channel) + ').mode==="blocked"') &&
    !freshDevice.frames.slice(sentBefore).some(frame => frame.includes('"type":"e2e_delete_channel_key"')));
  ownerWs.send({type:'send',conn_id:networkA,raw:'NOTICE '+channel+' :'+blocked});
  await ownerWs.wait(ev => ev.type === 'irc_message' && ev.text?.includes(channel) && ev.text?.includes('blocked'), 'server plaintext backstop');
  check('server blocks a plaintext send to a stored encrypted target',
    !otherWs.events.some(ev => ev.text?.includes(blocked)));
  check('encryption browsers had no unhandled exceptions', [browser,peer,freshDevice].every(b=>b.errors.length===0));

  const beforeChange = ownerWs.events.length;
  ownerWs.send({type:'change_passphrase',old:vault,new:vault+'-changed'});
  const changed = await waitFor(() => ownerWs.events.slice(beforeChange).find(ev =>
    ev.type === 'vault_unlocked' && ev.vault_verified), 'vault passphrase changed');
  check('vault passphrase changes leave the independent E2E keyring unchanged',
    (await keyringOnDisk(tmp, owner)).blob === keyring.blob && !changed.e2e_pepper);
  await browser.evaluate('handleEncryptCommand(["off"],' + q(networkA) + ',' + q(channel) + ')');
  check('an unlocked device clears the channel policy after a server acknowledgement',
    await browser.evaluate(`e2eTargetState(${q(channel)},{conn_id:${q(networkA)}}).mode==="none"`));
  const afterOff = 'explicitly unencrypted after off '+stamp;
  await compose(browser, networkA, channel, afterOff);
  await otherWs.wait(ev => ev.type === 'irc_message' && ev.text === afterOff,'channel send after acknowledged disable');
  check('server permits ordinary chat after explicit, acknowledged disable', true);
  await browser.evaluate(`setActive(${q(networkA)},${q(other)})`);
  const retryGuidance='🔐 Still waiting for an encrypted reply from '+other+'. Your next message will retry the key exchange.';
  const restartStatus=()=>browser.evaluate(`(()=>{
    const s=E2E.dmSessions[${peerKey}],messages=getBuf(${q(networkA)},${q(other)});
    return {start:s?.startEph||null,lookup:!!E2E._pendingOn?.[${peerKey}],
      pending:!!s?.RK&&!!s.startEph&&s.x3dhPending?.ephemeral_pub===s.startEph,
      outstanding:!!s?.restartPrev?.RK&&s.restartPrev.until>Date.now()&&!E2E._sessionSyncRepair.has(${peerKey}),
      guidanceCount:messages.filter(m=>m.text===${q(retryGuidance)}).length,
      guidanceVisible:document.getElementById('chat-area').textContent.includes(${q(retryGuidance)})};
  })()`);
  for(const repeat of [false,true]){
    const before=await restartStatus(),start=browser.frames.length;
    await compose(browser,networkA,other,'/encrypt restart '+other);
    const outcome=await waitFor(async()=>{
      const s=await restartStatus();
      if(s.lookup||!s.pending)return false;
      const requested=browser.frames.slice(start).map(JSON.parse).some(m=>
        m.type==='e2e_fetch_bundle'&&m.conn_id===networkA&&m.username===other);
      if(s.start!==before.start&&requested)return 'prepared';
      if(!requested&&before.pending&&before.outstanding&&s.outstanding&&s.start===before.start&&
        s.guidanceCount>before.guidanceCount&&s.guidanceVisible)return 'awaiting reply';
      return false;
    },'this restart prepares a new offer or visibly retries the outstanding exchange');
    if(repeat)check('a repeated restart preserves the outstanding exchange and explains how to confirm it',outcome==='awaiting reply');
  }
  const deliverAfterRestart=async(sender,network,to,receiver,receiveNetwork,from,observer,text)=>{
    const sent=sender.frames.length,received=observer.events.length,prefix='PRIVMSG '+to+' :';
    await compose(sender,network,to,text);
    await waitFor(()=>row(receiver,receiveNetwork,from,text),'the independent peer reads the restarted session');
    const lines=sender.frames.slice(sent).map(JSON.parse).filter(f=>f.type==='send'&&f.conn_id===network).map(f=>f.raw);
    const wires=lines.filter(raw=>raw.startsWith(prefix+'[e2edm2]')).map(raw=>raw.slice(prefix.length));
    const arrivals=observer.events.slice(received).filter(e=>e.type==='irc_message'&&e.conn_id===receiveNetwork&&e.from===from);
    check('the restarted PM reaches the independent account as exactly one matching ciphertext',
      wires.length===1&&arrivals.filter(e=>e.text===wires[0]).length===1&&!lines.includes(prefix+text)&&!arrivals.some(e=>e.text===text));
  };
  await deliverAfterRestart(browser,networkA,other,peer,networkB,owner,otherWs,'same-instance send after restart '+stamp);
  await deliverAfterRestart(peer,networkB,owner,browser,networkA,other,ownerWs,'same-instance reply after restart '+stamp);
  return ownerCode;
}

export async function checkCrossInstanceE2e({browser,peer,createRemote,chromium,ownerCode,check,waitFor,owner,ownerWs,remote,password,vault,networkA,remoteNetwork,remoteWs,stamp,otherWs,ownerData,remoteData,peerWeb,ordinary,ordinaryLines,ordinarySend}) {
  const updatedPeer=await peer.evaluate("typeof _e2eSetupRow==='function'");
  const mode=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT;
  const duplicateCloseTest=mode==='duplicate-close'||mode==='cold-duplicate-close';
  const interruptedCloseTest=mode==='interrupted-close'||duplicateCloseTest;
  // Start the recipient in its phone layout before login. Changing the viewport
  // just before aiming a tap races the app's delayed mobile appearance update.
  if(updatedPeer&&!interruptedCloseTest&&mode!=='bridge-window'){
    await peer.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:3,mobile:true});
    await peer.send('Emulation.setTouchEmulationEnabled',{enabled:true});
  }
  await login(peer,remote,password,waitFor);
  await waitFor(() => peer.evaluate('E2E._vaultUp && E2E._krReceived'), 'bridge peer discovery');
  if(mode==='crossed-first-contact'||mode==='crossed-restart-siblings'||mode==='late-restart-reply'||mode==='offline-restart-history'){
    await peer.evaluate(openEncryptionSettings);
    const remoteCode=await setUpRecovery(peer,waitFor,check);
    await peer.evaluate('closeEncryptPanel()');
    const sides=[{page:browser,nick:owner,cid:networkA,observer:ownerWs,code:ownerCode},
      {page:peer,nick:remote,cid:remoteNetwork,observer:remoteWs,code:remoteCode}];
    const origins=await Promise.all(sides.map(s=>s.page.evaluate('location.origin')));
    check('the two PM users are on separate CryptIRC web installations and linked IRC connections',
      origins[0]!==origins[1]&&networkA!==remoteNetwork&&process.env.IRC_PORT!==process.env.IRC_LEAF_PORT);
    const keys=await Promise.all(sides.map(s=>s.page.evaluate("exportPub(E2E.identityKeys.dhKeyPair.publicKey,'ECDH')")));
    const order=process.env.CRYPTIRC_TEST_REACTION_IDENTITY_ORDER;
    if(['author','restart'].includes(order)&&(Buffer.compare(Buffer.from(keys[0],'base64'),Buffer.from(keys[1],'base64'))<0)!==(order==='author'))sides.reverse();
    const [a,b]=sides;
    const pair={browser:a.page,peer:b.page,owner:a.nick,other:b.nick,networkA:a.cid,networkB:b.cid,
      ownerWs:a.observer,otherWs:b.observer,stamp,waitFor,check};
    if(mode==='crossed-first-contact'){await checkCrossedFirstContacts(pair);return;}
    await Promise.all([a.page.evaluate('_sidebarActivate('+q(a.cid)+','+q(b.nick)+')'),
      b.page.evaluate('_sidebarActivate('+q(b.cid)+','+q(a.nick)+')')]);
    const dm='bridged first '+stamp;
    const mark=b.observer.events.length,at=a.page.frames.length;
    await compose(a.page,a.cid,b.nick,dm);
    await acceptIdentity(a.page,waitFor);
    await acceptIdentity(b.page,waitFor);
    await waitFor(()=>row(b.page,b.cid,a.nick,dm),'independent bridge recipient opens the original Signal PM');
    const frames=a.page.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===a.cid&&e.raw?.startsWith('PRIVMSG '+b.nick+' :[e2edm2]'));
    check('the initial PM crosses linked IRC once and remains private',frames.length===1&&
      b.observer.events.slice(mark).filter(e=>e.type==='irc_message'&&e.from===a.nick&&e.conn_id===b.cid&&e.text===frames[0].raw.split(' :')[1]).length===1&&
      !b.observer.events.slice(mark).some(e=>e.text===dm));
    if(mode==='crossed-restart-siblings'){
      await checkCrossedRestartDevices(a,b,{chromium,password,stamp,order,waitFor,check});
      return;
    }
    if(mode==='offline-restart-history'){
      await checkRestartFromHistory(a,b,stamp,waitFor,check);
      return;
    }
    await checkReactionDuringSignalSetup({...pair,dm,manual:'bundle',oppositeGlare:true});
    await checkLateRestartReplies({...pair,chromium,password,ownerCode:a.code,mode:process.env.CRYPTIRC_TEST_REACTION_LATE_REPLY||'clock'});
    return;
  }
  if(mode==='off-translation-handoff'){
    const cid=q(networkA),nick=q(remote),key=q(await browser.evaluate(`_e2eDmKey(${nick},${cid})`));
    const variant=process.env.CRYPTIRC_TEST_CONSENT_LANGUAGE||'stable';
    const retryStore=variant==='store-retry',beforeCommit=retryStore||variant==='precommit',changed=beforeCommit||variant==='change';
    await compose(browser,networkA,remote,'/encrypt off '+remote);
    await waitFor(()=>browser.evaluate(`(async()=>{const saved=await _e2eRequestSession('__state__');
      return saved?.blob && (await _e2eDecodeState(saved.blob)).dm?.[${key}]?.on===0;})()`),'the account confirms explicit plaintext for this DM');
    const previous='ordinary peer text for language detection '+stamp,draft='draft awaiting peer language '+stamp;
    const queued='already paced from the explicitly off chat '+stamp;
    if(beforeCommit){
      await browser.evaluate('(()=>{const drain=drainRateQueue;drainRateQueue=()=>{};window.releaseOptOutQueue=()=>{drainRateQueue=drain;_kickRateQueue();};})()');
      await compose(browser,networkA,remote,queued);
      await waitFor(()=>browser.evaluate(`_rateQueue.some(m=>m.raw==='PRIVMSG '+${nick}+' :'+${q(queued)})`),'an ordinary explicitly off message is waiting for its paced IRC handoff');
    }
    remoteWs.send({type:'send',conn_id:remoteNetwork,raw:'PRIVMSG '+owner+' :'+previous});
    await waitFor(()=>row(browser,networkA,remote,previous),'the signed-in sender has a real earlier language sample');
    await browser.evaluate(`(()=>{
      const prefs=translationSettings();prefs.enabled=true;prefs.chats[translationChatKey(${cid},${nick})]={outgoing:'peer',incoming:'off'};
      if(!storeTranslationSettings(prefs))throw Error('could not enable the fixture translation');
      const fetchService=fetch.bind(window);window.providerPosts=[];
      window.fetch=async(resource,opts)=>{
        if(new URL(resource instanceof Request?resource.url:resource,location.href).pathname!=='/cryptirc/api/translation')return fetchService(resource,opts);
        const {text}=JSON.parse(opts.body);providerPosts.push(text);
        if(text===${q(previous)})await new Promise(done=>{window.releaseLanguage=done;});
        return Response.json({text,source:'es'});
      };
      const run=handleInput;handleInput=(line,...args)=>{const result=run(line,...args);window.lastTestInput={line,result};if(line===${q(draft)})window.enterFinished=result;return result;};
      const handle=handleEvent;handleEvent=ev=>{
        if(ev.type!=='e2e_session_moved')return handle(ev);
      };
    })()`);
    const sent=browser.frames.length,mark=remoteWs.events.length;
    await compose(browser,networkA,remote,draft);
    await waitFor(()=>browser.evaluate('!!window.releaseLanguage'),'the language lookup is in flight before the provider receives the draft');
    let sibling;
    if(changed){
      sibling=await chromium('off-translation-sibling');await login(sibling,owner,password,waitFor);
      await waitFor(()=>sibling.evaluate('E2E._vaultUp&&E2E._krReceived'),'a sibling opens the same account');
      await sibling.evaluate('void e2ePromptDeviceUnlock()');await waitPrompt(sibling,waitFor,unlockText);await fillPrompt(sibling,ownerCode);
      await waitFor(()=>sibling.evaluate('E2E.identityReady'),'the sibling has the existing identity');
      await peer.evaluate(openEncryptionSettings);await setUpRecovery(peer,waitFor,check);await peer.evaluate('closeEncryptPanel()');
      if(beforeCommit)await sibling.evaluate(`(()=>{const request=_e2eReq;_e2eReq=(m,...args)=>{
        if(m.type!=='e2e_commit_session'||m.partner!==${key})return request(m,...args);
        _e2eReq=request;return new Promise(done=>{window.commitAcceptedContact=()=>done(request(m,...args));});
      };})()`);
      await compose(sibling,networkA,remote,'/encrypt on '+remote);
      if(retryStore){
        await waitFor(()=>sibling.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"),'the genuine first fingerprint is waiting before the storage refusal');
        const file=path.join(ownerData,'e2e',owner,'sessions','__state__.enc'),backup=file+'.test-saved';
        const baseline=await fs.readFile(file,'utf8');
        check('the isolated fault targets the actual sealed account state',baseline===await sibling.evaluate("_e2eFetchSession('__state__')"));
        await fs.rename(file,backup);
        try{
          await fs.mkdir(file);
          await acceptIdentity(sibling,waitFor);
          await waitFor(()=>sibling.evaluate(`!E2E._pendingOn?.[${key}]&&getBuf(${cid},${nick}).some(m=>m.text?.includes('Could not confirm that this chat switched to Signal'))`),'a real refused account-state write leaves actionable guidance');
          check('the refused account-state write never reaches ratchet creation',await sibling.evaluate('!window.commitAcceptedContact'));
        }finally{
          await fs.rmdir(file).catch(e=>{if(e.code!=='ENOENT')throw e;});await fs.rename(backup,file);
        }
        check('the intact canonical opt-out is restored before retry',await browser.evaluate(`(async()=>{const s=await _e2eDecodeState(await _e2eFetchSession('__state__'));return s.dm[${key}]?.on===0&&!s.trust[${key}]?.fp;})()`));
        await compose(sibling,networkA,remote,'/encrypt on '+remote);
      }else await acceptIdentity(sibling,waitFor);
      if(beforeCommit){
        await waitFor(()=>sibling.evaluate('!!window.commitAcceptedContact'),'the sibling accepted the contact and reached the first ratchet write');
        const state=await waitFor(()=>browser.evaluate(`(async()=>{const r=await _e2eRequestSession(${key},true),stored=await _e2eRequestSession('__state__');
          const s=stored?.blob&&await _e2eDecodeState(stored.blob);return r?.blob===''&&s&&(${retryStore}||s.trust?.[${key}]?.fp)?{on:s.dm?.[${key}]?.on,trusted:!!s.trust?.[${key}]?.fp}:null;})()`),
          'the sending browser reads the canonical preference while the actual ratchet is still empty');
        console.log('OFF-REOPEN-PRECOMMIT '+JSON.stringify(state));
      }else await waitFor(()=>sibling.evaluate(`(async()=>{const r=await _e2eRequestSession(${key},true);return !!r?.blob;})()`),'an independent device has committed the real contact session');
    }
    await browser.evaluate('releaseLanguage();window.enterFinished');
    const arrived=()=>remoteWs.events.slice(mark).filter(e=>e.type==='irc_message'&&e.conn_id===remoteNetwork&&e.from===owner&&e.text===draft).length;
    if(!changed)await waitFor(()=>arrived()===1,'the explicitly approved unchanged translation reaches the IRC peer');
    const posted=await browser.evaluate(`providerPosts.filter(t=>t===${q(draft)}).length`);
    const sentCount=text=>browser.frames.slice(sent).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===networkA&&e.raw==='PRIVMSG '+remote+' :'+text).length;
    const submitted=sentCount(draft);
    const retained=await browser.evaluate(`document.getElementById('msg-input').value===${q(draft)}`);
    console.log('OFF-TRANSLATION-HANDOFF '+JSON.stringify({variant,changed,posted,submitted,arrived:arrived(),retained}));
    if(beforeCommit){
      await browser.evaluate(`(()=>{const p=translationSettings();p.chats[translationChatKey(${cid},${nick})].outgoing='off';storeTranslationSettings(p);})()`);
      const direct='untranslated while the sibling establishes Signal '+stamp;
      await compose(browser,networkA,remote,direct);
      await waitFor(()=>browser.evaluate(`window.lastTestInput?.line===${q(direct)}`),'the composer has handled the direct draft');
      await browser.evaluate('window.lastTestInput.result');
      await browser.evaluate('releaseOptOutQueue()');
      await waitFor(()=>browser.evaluate('!_rateQueue.length&&!_rateDmRetry'),'the actual paced IRC handoff finishes');
      const received=remoteWs.events.slice(mark).filter(e=>e.type==='irc_message'&&e.from===owner&&e.text===direct).length;
      const kept=await browser.evaluate(`document.getElementById('msg-input').value===${q(direct)}`);
      const restorable=await browser.evaluate(`getBuf(${cid},${nick}).some(m=>m.text===${q(queued)}&&m.sendState==='failed'&&_unsentPlainDrafts.has(m))`);
      console.log('OFF-REOPEN-DIRECT '+JSON.stringify({submitted:sentCount(direct),received,kept,queued:sentCount(queued),restorable}));
      check('a sibling’s accepted Signal contact holds an explicitly off untranslated draft before the first ratchet commit',sentCount(direct)===0&&received===0&&kept);
      check('a previously paced explicit-off draft stays recoverable and never reaches IRC after a sibling approves Signal',restorable&&sentCount(queued)===0&&!remoteWs.events.slice(mark).some(e=>e.type==='irc_message'&&e.from===owner&&e.text===queued));
    }
    check('after language detection an explicitly off DM sends the draft only if the saved peer session remains empty',
      posted===(changed?0:1)&&submitted===(changed?0:1)&&arrived()===(changed?0:1)&&(!changed||retained));
    if(beforeCommit){
      await sibling.evaluate('commitAcceptedContact()');
      await waitFor(()=>sibling.evaluate(`e2eTargetState(${nick},{conn_id:${cid}}).mode==='dm'`),'the confirmed encryption setup completes');
      const secure='first encrypted after reenabling '+stamp;
      await compose(sibling,networkA,remote,secure);await acceptIdentity(peer,waitFor);
      await waitFor(()=>row(peer,remoteNetwork,owner,secure),'the independent peer reads fresh encrypted text after the protected gap');
    }
    return;
  }
  if(mode==='queued-first-contact'){
    const decision=process.env.CRYPTIRC_TEST_PEER_IDENTITY||'accept';
    check('the fixture uses a real first-contact decision',['accept','decline','pending'].includes(decision));
    const cid=q(networkA),nick=q(remote),key=q(await browser.evaluate(`_e2eDmKey(${nick},${cid})`));
    const phone=await chromium('queued-first-contact');
    await login(phone,owner,password,waitFor);await waitFor(()=>phone.evaluate('E2E._vaultUp&&E2E._krReceived'),'phone discovers its existing account');
    await phone.evaluate('void e2ePromptDeviceUnlock()');await waitPrompt(phone,waitFor,unlockText);await fillPrompt(phone,ownerCode);
    await waitFor(()=>phone.evaluate('E2E.identityReady'),'phone unlocks its existing identity');
    const draft=Array.from({length:100},(_,i)=>stamp+i.toString(36).padStart(2,'0')).join(' '),start=browser.frames.length,arrivals=remoteWs.events.length;
    await browser.evaluate(`(()=>{
      const prefs=translationSettings();prefs.enabled=true;prefs.chats[translationChatKey(${cid},${nick})]={outgoing:'es',incoming:'off'};
      if(!storeTranslationSettings(prefs))throw Error('could not enable the test translation');
      const request=fetch.bind(window);window.firstContactTranslations=[];
      window.fetch=(resource,opts)=>{
        if(new URL(resource instanceof Request?resource.url:resource,location.href).pathname!=='/cryptirc/api/translation')return request(resource,opts);
        const {text}=JSON.parse(opts.body);firstContactTranslations.push(text);return Promise.resolve(Response.json({text,source:'en'}));
      };
      const drain=drainRateQueue;drainRateQueue=()=>{};window.releaseFirstContactQueue=()=>{drainRateQueue=drain;_kickRateQueue();};
    })()`);
    await compose(browser,networkA,remote,draft);
    const pieces=await waitFor(()=>browser.evaluate(`(()=>{const p=_rateQueue.filter(f=>f.raw?.startsWith('PRIVMSG '+${nick}+' :')).map(f=>f.raw.split(' :')[1]);return p.length>1?p:null})()`),'the plain message is queued in distinct IRC pieces after discovery');
    check('a draft to an unconfigured contact needs no confirmation',!await browser.evaluate(`!!(${plainPrompt})`));
    await peer.evaluate(openEncryptionSettings);await setUpRecovery(peer,waitFor,check);await peer.evaluate('closeEncryptPanel()');
    await phone.evaluate(`(()=>{
      const read=_e2eReq;
      _e2eReq=(m,...rest)=>{
        if(m.type!=='e2e_commit_session'||m.partner!==${key})return read(m,...rest);
        _e2eReq=read;return new Promise(done=>{window.releaseFirstRatchet=()=>done(read(m,...rest));});
      };
    })()`);
    await compose(phone,networkA,remote,'/encrypt on '+remote);
    await waitFor(()=>phone.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"),'the real linked-network bundle reaches its fingerprint confirmation');
    const account=()=>browser.evaluate(`(async()=>{
      const slot=await _e2eRequestSession(${key},true),record=await _e2eRequestSession('__state__');
      const state=record?.blob?await _e2eDecodeState(record.blob):null;
      return {empty:slot?.blob===''&&typeof slot.floor_blob==='string',trusted:!!state?.trust?.[${key}]?.fp,on:state?.dm?.[${key}]?.on??null};
    })()`);
    if(decision==='accept'){
      await acceptIdentity(phone,waitFor);
      await waitFor(()=>phone.evaluate('!!window.releaseFirstRatchet'),'accepted contact reaches its first real conditional ratchet write');
      await waitFor(async()=>(await account()).trusted,'the sending browser can read the persisted contact fingerprint before the ratchet is committed');
    }else if(decision==='decline'){
      await phone.evaluate("document.querySelector('#e2e-id-cancel').click()");
      await waitFor(()=>phone.evaluate(`!E2E._pendingOn?.[${key}]`),'the declined contact is no longer being set up');
    }
    const prior=await account();
    check('the canonical ratchet is still empty and the stored fingerprint matches the user’s actual decision',prior.empty&&prior.trusted===(decision==='accept'));
    const host=()=>browser.frames.slice(start).map(JSON.parse).filter(f=>f.type==='send'&&f.conn_id===networkA).map(f=>f.raw.split(' :')[1]);
    const wires=()=>remoteWs.events.slice(arrivals).filter(e=>e.type==='irc_message'&&e.conn_id===remoteNetwork&&e.from===owner).map(e=>e.text);
    await browser.evaluate('releaseFirstContactQueue()');
    await waitFor(()=>browser.evaluate('!_rateQueue.length&&!_rateDmRetry'),'the complete earlier IRC queue is decided');
    if(decision!=='accept')await waitFor(()=>pieces.every(text=>wires().includes(text)),'the independent IRC user receives every approved piece',16000);
    const sent=pieces.map(s=>host().filter(t=>t===s).length),received=pieces.map(s=>wires().filter(t=>t===s).length);
    const rows=await browser.evaluate(`getBuf(${cid},${nick}).filter(m=>${q(pieces)}.includes(m.text)).map(m=>m.sendState||'sent')`);
    const translated=await browser.evaluate(`firstContactTranslations.filter(t=>t===${q(draft)}).length`);
    console.log('Queued first-contact decision',JSON.stringify({decision,prior,sent,received,rows,translated}));
    const accepted=decision==='accept',expected=accepted?0:1;
    check('each previously approved part follows the confirmed first-contact state on the sender and independent IRC',translated===1&&rows.length===pieces.length&&rows.every(s=>s===(accepted?'failed':'sent'))&&sent.every(n=>n===expected)&&received.every(n=>n===expected));
    if(accepted){
      const buttons='#chat-area [data-restore-unsent]';
      await waitFor(()=>browser.evaluate(`document.querySelectorAll(${q(buttons)}).length===${pieces.length}`),'each undelivered part is recoverable from its failed row');
      await browser.evaluate(`document.querySelector('#msg-input').value='draft in progress';document.querySelector(${q(buttons)}).click()`);
      check('restoring a held part preserves a newer draft',await browser.evaluate("document.querySelector('#msg-input').value==='draft in progress'"));
      await browser.evaluate(`document.querySelector('#msg-input').value='';document.querySelector(${q(buttons)}).click()`);
      check('restoring puts only the selected failed part in the composer without sending it',await browser.evaluate(`document.querySelector('#msg-input').value===${q(pieces[0])}`)&&pieces.every(t=>!host().includes(t)&&!wires().includes(t)));
    }else{
      if(decision==='decline'){
        const cursor=ownerWs.events.length;
        await compose(phone,networkA,remote,'/encrypt on '+remote);
        const outcome=await waitFor(async()=>{
          if(await phone.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"))return 'prompt';
          if(ownerWs.events.slice(cursor).some(e=>e.type==='e2e_bundle_missing'&&e.conn_id===networkA&&e.reason==='peer-busy'))return 'busy';
        },'an explicit retry gets a fingerprint confirmation or a busy reply from the linked network');
        if(outcome==='busy'){
          await waitFor(()=>phone.evaluate(`getBuf(${cid},${nick}).some(m=>m.text?.includes('encryption is temporarily busy'))`),'the retry explains the temporary network limit in the DM');
          const declined=await account();
          check('the busy interval keeps the declined fingerprint untrusted',declined.empty&&!declined.trusted);
          const remaining=await phone.evaluate(`(_e2eAutoBusy.get(${cid}.toLowerCase()+'\\n'+${key})||0)-Date.now()`);
          check('the linked bridge sets a bounded retry window',remaining>0&&remaining<=60000);
          await new Promise(resolve=>setTimeout(resolve,remaining+250));
          await compose(phone,networkA,remote,'/encrypt on '+remote);
        }
      }
      await acceptIdentity(phone,waitFor);
      await waitFor(()=>phone.evaluate('!!window.releaseFirstRatchet'),'the newly accepted contact reaches its actual ratchet creation');
    }
    await phone.evaluate('releaseFirstRatchet()');
    await waitFor(()=>phone.evaluate(`e2eTargetState(${nick},{conn_id:${cid}}).mode==='dm'`),'the contact now has its confirmed Signal session');
    const text='fresh encrypted PM after '+decision+' '+stamp,at=phone.frames.length;
    await compose(phone,networkA,remote,text);await acceptIdentity(peer,waitFor);
    await waitFor(()=>row(peer,remoteNetwork,owner,text),'the peer reads the new encrypted message');
    const ciphertext=phone.frames.slice(at).map(JSON.parse).filter(f=>f.type==='send'&&f.raw?.startsWith('PRIVMSG '+remote+' :[e2edm2]')).map(f=>f.raw.split(' :')[1]);
    check('the post-setup PM is independently received once as matching ciphertext',ciphertext.length===1&&wires().filter(s=>s===ciphertext[0]).length===1&&!wires().includes(text));
    const reply='encrypted reply after '+decision+' '+stamp;
    await compose(peer,remoteNetwork,owner,reply);
    await waitFor(()=>row(phone,networkA,remote,reply),'the phone reads the independent peer’s encrypted reply after setup');
    await compose(phone,networkA,remote,'/encrypt off '+remote);
    await waitFor(async()=>{const s=await account();return s.empty&&s.on===0;},'the deliberate off decision retires the ratchet');
    const plain='deliberately clear after off '+stamp;
    await compose(phone,networkA,remote,plain);
    await waitFor(()=>wires().includes(plain),'an explicitly disabled contact again receives deliberate plaintext');
    check('the deliberate clear PM after turning Signal off is delivered once',wires().filter(t=>t===plain).length===1);
    return;
  }
  if(mode==='first-account-shared-consent'){
    const queued=process.env.CRYPTIRC_TEST_ENROLL_AFTER_QUEUE==='1';
    const source=peer,conn=remoteNetwork,target=ordinary,draft='draft before account enrollment '+stamp;
    const language=process.env.CRYPTIRC_TEST_CONSENT_LANGUAGE,previous='a previous message in the peer language '+stamp;
    if(language){
      check('the peer language fixture checks translation before queueing',['change','stable'].includes(language)&&!queued);
      ordinarySend('PRIVMSG '+remote+' :'+previous);
      await waitFor(()=>row(source,conn,target,previous),'the ordinary IRC peer supplies a real message for language detection');
    }
    const endpoint=await source.evaluate("new URL('/cryptirc',location.href).href");
    const sibling=await chromium('sibling-first-enrollment',endpoint);
    await login(sibling,remote,password,waitFor);
    await waitFor(()=>sibling.evaluate('E2E._vaultUp&&E2E._krReceived&&!E2E.keyReady'),'the account is new on both browsers');
    if(await source.evaluate(promptOpen))await source.evaluate(cancelPrompt);
    if(queued)await source.evaluate(`(()=>{
      const drain=drainRateQueue;drainRateQueue=()=>{};
      window.releaseFirstClear=()=>{drainRateQueue=drain;_kickRateQueue();};
    })()`);
    else await source.evaluate(`(()=>{
      const prefs=translationSettings();prefs.enabled=true;
      prefs.chats[translationChatKey(${q(conn)},${q(target)})]={outgoing:${q(language?'peer':'es')},incoming:'off'};
      if(!storeTranslationSettings(prefs))throw Error('Could not enable outgoing translation');
      window.enrollmentTranslationCalls=[];
      const fetchService=window.fetch.bind(window);
      window.fetch=async(resource,options)=>{
        const url=resource instanceof Request?resource.url:resource;
        if(new URL(url,location.href).pathname!=='/cryptirc/api/translation')return fetchService(resource,options);
        const {text}=JSON.parse(options.body);
        enrollmentTranslationCalls.push(text);
        if(text===${q(previous)})await new Promise(done=>{window.finishPeerLanguage=done;});
        return Response.json({text,source:'es'});
      };
    })()`);
    const start=source.frames.length,local=remoteWs.events.length;
    const sent=()=>source.frames.slice(start).map(JSON.parse).filter(f=>f.type==='send'&&f.conn_id===conn&&f.raw==='PRIVMSG '+target+' :'+draft).length;
    const arrived=()=>ordinaryLines.filter(line=>line.includes(' PRIVMSG '+target+' :')&&line.endsWith(' :'+draft)).length;
    // The Enter handler awaits handleInput directly. _sendLock belongs to the
    // touch Send button and can be false before this draft's decision returns.
    await source.evaluate(`(()=>{
      const send=handleInput;
      handleInput=(...args)=>{
        const result=send(...args);
        if(args[0]===${q(draft)})window.enrollmentInputResult=result;
        return result;
      };
    })()`);
    if(!queued&&!language) await source.evaluate(`(()=>{
      const request=_e2eRequestSession;
      _e2eRequestSession=async (key,floor,...rest)=>{
        if(floor&&key===_e2eDmKey(${q(target)},${q(conn)})){
          _e2eRequestSession=request;
          await new Promise(resolve=>{window.releaseFirstClear=resolve;});
        }
        return request(key,floor,...rest);
      };
    })()`);
    await compose(source,conn,target,draft);
    if(queued)await waitFor(()=>source.evaluate(`_rateQueue.some(frame=>frame.raw==='PRIVMSG '+${q(target)}+' :'+${q(draft)})`),'the first draft is in the actual send queue');
    else if(language)await waitFor(()=>source.evaluate('!!window.finishPeerLanguage'),'the provider is identifying the previous message’s language');
    else await waitFor(()=>source.evaluate('!!window.releaseFirstClear'),'the first send is checking its current account slot');
    check('account setup races do not open a plaintext confirmation',!await source.evaluate(`!!(${plainPrompt})`));
    if(language==='stable'){
      await source.evaluate('finishPeerLanguage()');
      await source.evaluate('window.enrollmentInputResult');
      await waitFor(()=>arrived()===1,'the independently observed IRC user receives the unchanged translated draft');
      const calls=await source.evaluate(`enrollmentTranslationCalls.map(s=>s===${q(previous)}?'language':s===${q(draft)}?'draft':'other')`);
      check('authorized peer-language translation and IRC each receive the intended draft once',sent()===1&&arrived()===1&&JSON.stringify(calls)===JSON.stringify(['language','draft']));
      return;
    }
    await sibling.evaluate(openEncryptionSettings);
    const code=await setUpRecovery(sibling,waitFor,check);await sibling.evaluate('closeEncryptPanel()');
    await compose(sibling,conn,target,'/encrypt keygen');
    await waitPrompt(sibling,waitFor,'Copy this key and share it');await sibling.evaluate(acceptPrompt);
    const slot=await sibling.evaluate(`_e2eScopedPskSlot(${q(target)},${q(conn)})`);
    await waitFor(()=>remoteWs.events.slice(local).some(e=>e.type==='e2e_channel_key'&&e.channel===slot&&e.blob?.startsWith('e2e3.')),'the server stores the sibling’s shared key for this exact contact');
    check('no clear draft reached its host or IRC before the sibling finished setup',sent()===0&&arrived()===0);
    if(language)await source.evaluate('finishPeerLanguage()');
    else await source.evaluate('releaseFirstClear()');
    await source.evaluate('window.enrollmentInputResult');
    await waitFor(()=>source.evaluate('!_rateQueue.length&&!_rateDmRetry'),'the fresh browser acts on the changed encryption setup');
    const refusal=await source.evaluate(`({kept:document.getElementById('msg-input').value===${q(draft)},
      failed:getBuf(${q(conn)},${q(target)}).some(m=>m.text===${q(draft)}&&m.sendState==='failed'),
      help:getBuf(${q(conn)},${q(target)}).some(m=>m.kind==='error'&&m.text.includes('/encrypt unlock')),
      provider:window.enrollmentTranslationCalls?.filter(t=>t===${q(draft)}).length||0})`);
    console.log('Enrollment during the plaintext send check',JSON.stringify({queued,language:language||null,host:sent(),peer:arrived(),...refusal}));
    check('new account enrollment keeps stale plaintext off translation, the sending host and IRC, with visible unlock guidance',
      sent()===0&&arrived()===0&&refusal.provider===0&&refusal.help&&(queued?refusal.failed:refusal.kept));
    await compose(source,conn,target,'/encrypt unlock');await waitPrompt(source,waitFor,unlockText);await fillPrompt(source,code);
    await waitFor(()=>source.evaluate(`E2E.identityReady&&e2eTargetState(${q(target)},{conn_id:${q(conn)}}).mode==='psk'`),'unlocking loads the sibling’s real shared key');
    const offset=ordinaryLines.length;
    await compose(source,conn,target,'send after enrolling the account '+stamp);
    await waitFor(()=>ordinaryLines.slice(offset).some(line=>line.includes(' PRIVMSG '+target+' :sd8~')),'normal send reaches the ordinary peer encrypted');
    return;
  }
  if(mode==='first-account-plain'||mode==='queued-plain-consent'){
    const fresh=mode==='first-account-plain',source=fresh?peer:browser,conn=fresh?remoteNetwork:networkA,target=fresh?ordinary:remote;
    const records=(at)=>source.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.raw?.startsWith('PRIVMSG '+target+' :')).map(e=>e.raw.split(' :')[1]);
    const clearAtPeer=text=>fresh?ordinaryLines.filter(line=>line.includes(' PRIVMSG '+ordinary+' :')&&line.endsWith(' :'+text)).length:
      remoteWs.events.filter(e=>e.type==='irc_message'&&e.from===owner&&e.text===text).length;
    if(fresh){
      if(await source.evaluate(promptOpen))await source.evaluate(cancelPrompt);
      const draft='from account before setup '+stamp,at=source.frames.length;
      const state=await source.evaluate(`(async()=>{const k=_e2eDmKey(${q(target)},${q(conn)});const kr=await _e2eReq({type:'e2e_load_keyring'},'e2e_keyring');
        const slot=await _e2eRequestSession(k,true);return {unconfigured:!E2E.keyReady&&!kr?.blob&&kr?.has_identity===false,blob:slot?.blob,floor:typeof slot?.floor_blob};})()`);
      check('the sender truly has no account keyring or identity',state.unconfigured);
      await compose(source,conn,target,draft);
      await waitFor(()=>clearAtPeer(draft)===1,'independent ordinary IRC client receives the fresh account’s first draft',20000);
      const commandDraft='ordinary /msg from the same account '+stamp;
      await compose(source,conn,'status','/msg '+target+' '+commandDraft);
      await waitFor(()=>clearAtPeer(commandDraft)===1,'the ordinary IRC client also receives a /msg from the status tab');
      check('ordinary plaintext and /msg each send once with no confirmation',
        records(at).filter(t=>t===draft).length===1&&records(at).filter(t=>t===commandDraft).length===1&&
        clearAtPeer(draft)===1&&clearAtPeer(commandDraft)===1&&!await source.evaluate(`(${plainPrompt})||(${promptOpen})`));
      check('both drafts use separate discovery requests for the current nick holder',new Set(source.frames.slice(at).map(JSON.parse)
        .filter(frame=>frame.type==='e2e_fetch_bundle'&&frame.username===target).map(frame=>frame.req)).size===2);
      const queryDraft='query from the status tab '+stamp;
      await compose(source,conn,'status','/query '+target+' '+queryDraft);
      await waitFor(()=>clearAtPeer(queryDraft)===1,'a /query sends while opening the recipient tab');
      check('a named query sends once and opens the right tab',records(at).filter(t=>t===queryDraft).length===1&&
        await source.evaluate(`active.target===${q(target)}`));
      const artAt=source.frames.length;
      const art=await source.evaluate("makeAsciiArt('OK').split('\\n').filter(l=>l.trim()).map(l=>ircSafe(l).slice(0,400))");
      await compose(source,conn,target,'/ascii OK');
      await waitFor(()=>art.every(line=>clearAtPeer(line)===art.filter(piece=>piece===line).length),'one IRC delivery for each line of a multi-line command');
      check('a multi-line command sends the complete batch using one discovery without a prompt',
        art.length>1&&JSON.stringify(records(artAt))===JSON.stringify(art)&&
        source.frames.slice(artAt).map(JSON.parse).filter(f=>f.type==='e2e_fetch_bundle'&&f.username===target).length===1&&
        !await source.evaluate(`(${plainPrompt})||(${promptOpen})`));
      return;
    }
    const initial=Array.from({length:100},(_,i)=>stamp+i.toString(36).padStart(2,'0')).join(' ');
    const next='new draft during discovery '+stamp,at=source.frames.length;
    const decision=process.env.CRYPTIRC_TEST_CONSENT_OUTCOME||'edit';
    const command=decision==='slash-edit'?'/msg '+target+' '+next:next;
    await source.evaluate(`(()=>{
      const drain=drainRateQueue;
      clearTimeout(_rateTimer);_rateTimer=null;drainRateQueue=()=>{};
      window.releasePlainQueue=()=>{drainRateQueue=drain;_kickRateQueue();};
    })()`);
    await compose(source,conn,target,initial);
    const pieces=await waitFor(()=>source.evaluate(`(()=>{
      const a=_rateQueue.filter(m=>m.raw?.startsWith('PRIVMSG '+${q(target)}+' :')).map(m=>m.raw.split(' :')[1]);
      return a.length>=2&&a.some(t=>t.includes(${q(stamp)}))?a:false;})()`),'the first clear draft was split by the normal composer');
    await waitFor(()=>source.evaluate("!document.getElementById('msg-input').value"),'the first queued draft returns control to the composer');
    if(decision==='reconnect'||decision==='queue-expire'){
      if(decision==='reconnect'){
        await source.evaluate('window.previousPlainSocket=ws;ws.close()');
        await waitFor(()=>source.evaluate('ws!==window.previousPlainSocket&&_wsReady()&&!E2E._resyncPending'),'new authenticated WebSocket finishes encryption resync');
      }else await source.evaluate('window.realQueueClock=Date.now;Date.now=()=>realQueueClock()+61000');
      await source.evaluate('releasePlainQueue()');
      await waitFor(()=>source.evaluate('!_rateQueue.length&&!_rateDmRetry'),'queued plaintext is reconsidered after discovery expires');
      if(decision==='queue-expire') await source.evaluate('Date.now=realQueueClock');
      const failed=await source.evaluate(`getBuf(${q(conn)},${q(target)}).filter(m=>m.sendState==='failed'&&m.text.includes(${q(stamp)})).length`);
      check('a reconnect or expired lookup holds every stale piece with a recoverable failed row',
        failed===pieces.length&&records(at).length===0&&pieces.every(p=>clearAtPeer(p)===0));
      await compose(source,conn,target,next);
      await waitFor(()=>clearAtPeer(next)===1,'a new draft sends after a fresh lookup');
      return;
    }
    await source.evaluate(`(()=>{
      const deliver=e2eHandleEvent, key=_e2eDmKey(${q(target)},${q(conn)});
      e2eHandleEvent=async event=>{
        if(event.type==='e2e_bundle_missing'&&event.req===E2E._pendingOn?.[key]?.req){
          e2eHandleEvent=deliver;
          await new Promise(resolve=>{window.releasePlainLookup=resolve;});
        }
        return deliver(event);
      };
    })()`);
    await compose(source,conn,target,command);
    await waitFor(()=>source.evaluate('!!window.releasePlainLookup'),'the second draft has its own real lookup answer');
    await source.evaluate('releasePlainQueue()');
    if(decision==='expire'){
      await waitFor(()=>source.evaluate('!_pendingComposerSends.size'),'the missing lookup response times out');
      check('a lookup that times out holds the second draft',await source.evaluate(`document.getElementById('msg-input').value===${q(next)}`));
    } else if(decision!=='approve'){
      await source.send('Input.insertText',{text:' edited'});
      check('the edited draft remains in the composer during discovery',
        await source.evaluate(`document.getElementById('msg-input').value===${q(command+' edited')}`));
    }
    await source.evaluate('releasePlainLookup()');
    await waitFor(()=>source.evaluate('!_pendingComposerSends.size&&!_rateQueue.length&&!_rateDmRetry'),'remaining plaintext chunks settle after the lookup',16000);
    await waitFor(()=>pieces.every(piece=>clearAtPeer(piece)>0)&&(decision!=='approve'||clearAtPeer(next)>0),
      'the independently observed IRC deliveries settle',16000);
    const counts=pieces.map(piece=>clearAtPeer(piece)),sent=records(at);
    check('every earlier piece reaches the peer once and in order',
      counts.every(n=>n===1)&&pieces.every((piece,i)=>sent[i]===piece)&&sent.length===pieces.length+(decision==='approve'?1:0));
    check('only an unchanged draft with a completed lookup sends automatically',
      (decision==='approve'?sent.at(-1)===next&&clearAtPeer(next)===1:!sent.includes(next)&&!clearAtPeer(next))&&
      !await source.evaluate(`!!(${plainPrompt})`));
    return;
  }
  if(mode==='publication-retry'){
    const button=setupButton+'[data-e2e-unlock]';
    const bundle=path.join(remoteData,'e2e',remote,'bundle.json');
    await compose(browser,networkA,remote,'/encrypt on '+remote);
    await remoteWs.wait(e=>e.type==='e2e_setup_needed'&&e.from===owner,'new account receives the first-contact setup invitation');
    // Only this disposable account's public bundle is unavailable. Its keyring,
    // sealed identity and browser connection still use the normal storage paths.
    await fs.mkdir(path.dirname(bundle),{recursive:true});
    await fs.mkdir(bundle);
    let identity;
    try{
      await openSetupInvite(peer,remoteNetwork,owner,waitFor);
      await waitPrompt(peer,waitFor,setupText);
      const code=await peer.evaluate(input+'.value');
      await peer.evaluate(acceptPrompt);
      await waitPrompt(peer,waitFor,'Paste your saved E2E recovery code');
      await fillPrompt(peer,code);
      await waitFor(()=>peer.evaluate('E2E.keyReady&&!E2E._booting&&!!E2E.identityKeys'),'account keeps its unlocked identity after the public-bundle write fails',45000);
      const retryable=()=>peer.evaluate(`(()=>{const b=document.querySelector(${q(button)});return b&&!b.disabled&&b.textContent==='Retry Signal setup'&&!E2E.identityReady;})()`);
      check('the chat offers an enabled retry after setup finishes without its public keys',await retryable());
      await clickVisible(peer,'#e2e-lock');
      check('the Encryption panel also offers an in-place retry',await peer.evaluate(`document.querySelector(${q(panelUnlock+':not(:disabled)')})?.textContent==='Retry Signal setup'`));
      await peer.evaluate('closeEncryptPanel()');
      identity=await peer.evaluate('_e2ePublicIdentity(E2E.identityKeys)');
      const start=peer.frames.length;
      await compose(peer,remoteNetwork,owner,'/encrypt unlock');
      await waitFor(()=>peer.frames.slice(start).some(f=>JSON.parse(f).type==='e2e_load_identity'),'the unlock command retries with the existing device key');
      await waitFor(()=>peer.evaluate('!E2E._interactiveUnlock&&!E2E._booting'),'the failed retry returns to the conversation',35000);
      check('a second temporary failure leaves a working retry and does not ask for the recovery code',await retryable()&&!await peer.evaluate(promptOpen));
    }finally{await fs.rmdir(bundle);}
    await clickVisible(peer,button,true);
    await waitFor(()=>peer.evaluate(`E2E.identityReady&&document.querySelector(${q(button)})?.disabled&&document.querySelector(${q(button)}).textContent==='Encryption ready'`),'the in-place retry confirms publication and updates its original invitation',35000);
    const published=JSON.parse(await fs.readFile(bundle,'utf8'));
    check('retry publishes the same previously saved signing and DH identity',identity[0]===published.identity_dh_key&&identity[1]===published.identity_sign_key&&!await peer.evaluate(promptOpen));
    const text='first encrypted PM after in-place retry '+stamp,at=browser.frames.length,seen=remoteWs.events.length;
    await compose(browser,networkA,remote,text);
    await acceptIdentity(browser,waitFor);await acceptIdentity(peer,waitFor);
    await waitFor(()=>row(peer,remoteNetwork,owner,text),'independent recipient reads the first encrypted PM after retry');
    const sent=browser.frames.slice(at).map(JSON.parse).filter(f=>f.type==='send'&&f.raw?.startsWith('PRIVMSG '+remote+' :'));
    const wires=sent.map(f=>f.raw.split(' :')[1]).filter(w=>w.startsWith('[e2edm2]'));
    const receipt=remoteWs.events.slice(seen).filter(e=>e.type==='irc_message'&&e.from===owner);
    check('the fresh PM crosses the linked IRC servers once as the encrypted wire',wires.length===1&&receipt.filter(e=>e.text===wires[0]).length===1&&!receipt.some(e=>e.text===text));
    return;
  }
  if(mode==='publication-ready'){
    await compose(browser,networkA,remote,'/encrypt on '+remote);
    await remoteWs.wait(e=>e.type==='e2e_setup_needed'&&e.conn_id===remoteNetwork&&e.from===owner,'new contact receives its own setup link');
    await peer.evaluate(`(()=>{
      const send=_e2eWs,gate=window.publicationGate={release:null};
      _e2eWs=(message,...rest)=>{
        if(message.type!=='e2e_publish_bundle'||gate.release)return send(message,...rest);
        return new Promise(resolve=>{gate.release=()=>{_e2eWs=send;resolve(send(message,...rest));};});
      };
    })()`);
    await openSetupInvite(peer,remoteNetwork,owner,waitFor);
    const finishing=setUpRecovery(peer,waitFor,check);
    finishing.catch(()=>{});
    const pathToBundle=path.join(remoteData,'e2e',remote,'bundle.json');
    const published=()=>fs.readFile(pathToBundle,'utf8').then(JSON.parse).then(b=>!!b.identity_sign_key).catch(()=>false);
    const action=setupButton+'[data-e2e-unlock]';
    await waitFor(()=>peer.evaluate('!!publicationGate.release'),'the real public bundle is waiting for transport');
    let waiting;
    try{
      await waitFor(()=>peer.evaluate(`['Encryption ready','Setting up encryption…'].includes(document.querySelector(${q(action)})?.textContent)`),
        'the setup action shows its current state',4500).catch(()=>false);
      waiting=await peer.evaluate(`({label:document.querySelector(${q(action)})?.textContent,ready:E2E.identityReady})`);
      waiting.published=await published();
      console.log('Public bundle held',JSON.stringify(waiting));
    }finally{await peer.evaluate('publicationGate.release()');}
    await finishing;
    await waitFor(()=>peer.evaluate(`document.querySelector(${q(action)})?.textContent==='Encryption ready'`),'the user sees encryption ready');
    check('the setup button and identity wait for the persisted public bundle',!waiting.published&&!waiting.ready&&waiting.label==='Setting up encryption…'&&await published());
    const first='first after visible readiness '+stamp,at=browser.frames.length,peerAt=remoteWs.events.length;
    await compose(browser,networkA,remote,first);
    await acceptIdentity(browser,waitFor);await acceptIdentity(peer,waitFor);
    await waitFor(()=>row(peer,remoteNetwork,owner,first),'the newly set-up contact reads the first encrypted PM');
    const sent=browser.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.raw?.startsWith('PRIVMSG '+remote+' :'));
    const ciphertext=sent.filter(e=>e.raw.includes(' :[e2edm2]'));
    check('the first send after displayed readiness produces exactly one independently readable encrypted message',
      ciphertext.length===1&&!sent.some(e=>e.raw.endsWith(' :'+first))&&remoteWs.events.slice(peerAt).some(e=>e.from===owner&&e.text===ciphertext[0].raw.split(' :')[1]));
    return;
  }
  if(mode==='new-peer-queued-plain'){
    const target=remote,qualified=await browser.evaluate(`_e2eDmKey(${q(remote)},${q(networkA)})`),key=q(qualified);
    const account=await browser.evaluate(`(async()=>{const s=await _e2eRequestSession(${key},true);
      return {slot:s.blob==='',setting:E2E.state.dm[${key}]?.on??null,pin:!!E2E.trustStore[${key}]};})()`);
    check('new peer has no canonical ratchet, pin or saved off preference',account.slot&&account.setting===null&&!account.pin);
    const sibling=await chromium('neon-never-first-sibling');
    await login(sibling,owner,password,waitFor);
    await waitFor(()=>sibling.evaluate('E2E._vaultUp&&E2E._krReceived'),'sibling discovers owner keyring');
    await sibling.evaluate('void e2ePromptDeviceUnlock()');await waitPrompt(sibling,waitFor,unlockText);await fillPrompt(sibling,ownerCode);
    await waitFor(()=>sibling.evaluate('E2E.keyReady&&E2E.identityReady&&!E2E._resyncPending'),'sibling unlocks the same account');
    const records=(device,index,word)=>device.frames.slice(index).map(JSON.parse).filter(f=>f.type==='send'&&f.conn_id===networkA&&f.raw==='PRIVMSG '+remote+' :'+word).length;
    const peerCount=(index,word)=>remoteWs.events.slice(index).filter(e=>e.type==='irc_message'&&e.conn_id===remoteNetwork&&e.from===owner&&e.text===word).length;
    const control='ordinary before first signal '+stamp,controlAt=browser.frames.length,controlPeer=remoteWs.events.length;
    await compose(browser,networkA,remote,control);
    await waitFor(()=>peerCount(controlPeer,control)===1&&records(browser,controlAt,control)===1,'plain DM reaches the unconfigured contact once');
    check('first-use plaintext sends without a dialog',!await browser.evaluate(`!!(${plainPrompt})`));
    await waitFor(()=>browser.evaluate('!_sendLock&&!_rateQueue.length'),'control fully drained');
    const draft='queued before first signal '+stamp;
    await browser.evaluate(`(()=>{
      const drain=drainRateQueue,handler=e2eHandleEvent;
      clearTimeout(_rateTimer);_rateTimer=null;
      drainRateQueue=()=>{};window.auditFirstMove={events:0};
      auditFirstMove.releaseQueue=()=>{drainRateQueue=drain;_kickRateQueue();};
      e2eHandleEvent=async function(ev){
        if(ev.type==='e2e_session_moved'&&ev.partner===${key}){
          auditFirstMove.events++;
          if(!auditFirstMove.canApply){await new Promise(resolve=>{(auditFirstMove.releases||=[]).push(resolve);});}
        }
        return handler(ev);
      };
      auditFirstMove.acceptUpdate=()=>{auditFirstMove.canApply=true;for(const wake of auditFirstMove.releases||[])wake();};
    })()`);
    const frameAt=browser.frames.length,peerAt=remoteWs.events.length;
    await compose(browser,networkA,remote,draft);
    await waitFor(()=>browser.evaluate(`_rateQueue.some(m=>m.raw==='PRIVMSG '+${q(target)}+' :'+${q(draft)})`),'the discovered plain DM occupies the paced queue');
    await peer.evaluate(openEncryptionSettings);await setUpRecovery(peer,waitFor,check);await peer.evaluate('closeEncryptPanel()');
    await waitFor(()=>fs.readFile(path.join(remoteData,'e2e',remote,'bundle.json'),'utf8').then(JSON.parse).catch(()=>null),'genuine remote bundle publication');
    // The automatic and explicit bridge lookups share the same per-nick allowance.
    await new Promise(done=>setTimeout(done,61000));
    await compose(sibling,networkA,remote,'/encrypt on '+remote);
    await acceptIdentity(sibling,waitFor);
    const stored=await waitFor(()=>sibling.evaluate(`(async()=>{const record=await _e2eRequestSession(${key},true);
      return !!record?.blob&&E2E.state.dm[${key}]?.on===1&&!!E2E.dmSessions[${key}]?.RK;})()`),'sibling establishes a first canonical Signal session',30000);
    const moved=await waitFor(()=>browser.evaluate('auditFirstMove.events>0'),'old browser receives genuine first-session notification',12000).catch(()=>false);
    const before=await browser.evaluate(`({state:E2E.state.dm[${key}]?.on??null,moved:_e2eMovedPending(${key}),queued:_rateQueue.length,mode:e2eTargetState(${q(remote)},{conn_id:${q(networkA)}}).mode})`);
    check('the exact plaintext draft remains queued before the first authenticated session',
      before.queued===1&&records(browser,frameAt,draft)===0&&peerCount(peerAt,draft)===0);
    await browser.evaluate('auditFirstMove.releaseQueue()');
    await waitFor(()=>browser.evaluate('!_rateQueue.length'),'old queue is resolved',16000).catch(()=>false);
    await new Promise(done=>setTimeout(done,600));
    const details=await browser.evaluate(`({pending:_rateQueue.length,failed:getBuf(${q(networkA)},${q(remote)}).some(m=>m.text===${q(draft)}&&m.sendState==='failed')})`);
    check('queued plaintext fails visibly before reaching IRC after first Signal setup',
      stored&&moved&&details.pending===0&&details.failed&&records(browser,frameAt,draft)===0&&peerCount(peerAt,draft)===0);
    await browser.evaluate('auditFirstMove.acceptUpdate()');
    return;
  }
  if(['named-status','named-status-auto','named-status-explicit','named-status-reaction','named-status-plain-reaction','named-status-commands'].includes(mode)){
    await peer.evaluate(openEncryptionSettings);await setUpRecovery(peer,waitFor,check);await peer.evaluate('closeEncryptPanel()');
    await waitFor(()=>fs.readFile(path.join(remoteData,'e2e',remote,'bundle.json'),'utf8').then(JSON.parse).catch(()=>null),
      'the disposable named peer has published its own key bundle');
    await peer.evaluate(`setActive(${q(remoteNetwork)},'status');void handleInput('/nick status')`);
    const owns=await waitFor(()=>peer.evaluate(`getNick(${q(remoteNetwork)}).toLowerCase()==='status'`),'the disposable peer owns nick status',10000).catch(()=>false);
    check('the fixture owns the IRC nick status before any private user message',owns);
    const named='status',alias=await browser.evaluate("_dmTarget('status')");
    const ownsNick=()=>peer.evaluate(`getNick(${q(remoteNetwork)}).toLowerCase()==='status'`);
    const key=await browser.evaluate(`_e2eDmKey('status',${q(networkA)})`);
    if(mode==='named-status-plain-reaction'){
      for(const [device,conn,target,wireNick] of [[browser,networkA,alias,named],[peer,remoteNetwork,owner,owner]]){
        await compose(device,conn,target,'/encrypt off '+wireNick);
        await waitFor(()=>device.evaluate(`(async()=>{
          const k=_e2eDmKey(${q(wireNick)},${q(conn)}),slot=await _e2eRequestSession(k,true);
          return !_sendLock&&!E2E._pendingOn?.[k]&&E2E.state?.dm[k]?.on===0&&slot?.blob==='';})()`),'confirmed clear PM');
      }
      const text='clear message from the named peer '+stamp;
      check('the peer owns nick status for the clear PM',await ownsNick());
      await compose(peer,remoteNetwork,owner,text);
      await waitFor(()=>row(browser,networkA,alias,text),'the named user’s clear PM');
      await browser.evaluate(`setActive(${q(networkA)},${q(alias)})`);
      await waitFor(()=>browser.evaluate(`(()=>{const r=${reactionRow(text)};return !!r&&!!messageReactionFor(r);})()`),'real IRC anchor on the clear named-user PM');
      const at=remoteWs.events.length,from=browser.frames.length,emoji='👍';
      check('the account still owns the private clear reaction target',await ownsNick());
      check('the normal clear-message Like button is usable',await browser.evaluate(reactionButton(text,emoji)));
      await waitFor(()=>remoteWs.events.slice(at).some(e=>e.type==='irc_reaction'&&e.from===owner&&e.emoji===emoji&&!e.own),'the named user receives the clear Like');
      const reacted=await waitFor(()=>peer.evaluate(`(${reactionRow(text)})?.querySelector('.reaction-count')?.textContent===${q(emoji+' 1')}`),'the named user sees the clear Like on the correct message');
      check('one public-format Like goes to the real status nick and both users see its confirmation',
        reacted&&browser.frames.slice(from).map(JSON.parse).filter(e=>e.type==='react'&&e.target===named&&e.reaction?.kind==='plain').length===1&&
        await waitFor(()=>browser.evaluate(`(${reactionRow(text)})?.querySelector('.reaction-count')?.getAttribute('aria-pressed')==='true'`),'own clear Like is confirmed'));
      return;
    }
    if(mode==='named-status-auto'||mode==='named-status-explicit'){
      const at=browser.frames.length,serverLine='server window test '+stamp;
      await compose(browser,networkA,'status',serverLine);
      await compose(browser,networkA,'status','/encrypt on');
      check('the actual server window refuses ordinary text and an untargeted encryption command',
        await waitFor(()=>browser.evaluate(`getBuf(${q(networkA)},'status').some(m=>m.text.includes('Usage: /encrypt on'))`),'server-window guidance')&&
        !browser.frames.slice(at).map(JSON.parse).some(e=>e.type==='e2e_fetch_bundle'||e.raw?.includes(serverLine)));
      await browser.evaluate(`void handleInput('/query status')`);
      check('a fresh named-user query is separate from the server log',await browser.evaluate('active.target===_dmTarget("status")'));
      const initial=browser.frames.length,wireStart=remoteWs.events.length,first='first message to named peer '+stamp;
      check('the peer still owns its test nick before private initiation',await ownsNick());
      if(mode==='named-status-auto') await compose(browser,networkA,alias,first);
      else await compose(browser,networkA,alias,'/encrypt on');
      const requests=()=>browser.frames.slice(initial).map(JSON.parse).filter(e=>e.type==='e2e_fetch_bundle'&&e.username===named);
      const discovered=await waitFor(()=>requests().length,'discovery started for the real status nick',10000).catch(()=>0);
      if(!discovered){
        const frames=browser.frames.slice(initial).map(JSON.parse),arrivals=remoteWs.events.slice(wireStart);
        console.log('Named-user initiation before discovery',JSON.stringify({mode,requests:0,
          clearAtHost:frames.filter(e=>e.type==='send'&&e.raw?.endsWith(' :'+first)).length,
          clearAtPeer:arrivals.filter(e=>e.from===owner&&e.text===first).length}));
      }
      check('the client starts discovery for the real status nick',discovered);
      try{await acceptIdentity(browser,waitFor);}catch(error){
        const replies=ownerWs.events.filter(e=>requests().some(request=>e.req===request.req)).map(e=>({type:e.type,reason:e.reason,bridge:e.bridge}));
        const local=await browser.evaluate(`({waiting:!!E2E._pendingOn?.[${q(key)}],accepted:!!E2E.trustStore[${q(key)}]?.fingerprint,
          genericPrompt:document.getElementById('custom-prompt-msg')?.textContent,blocked:E2E.lastBlockReason})`);
        console.log('Named-user identity confirmation',JSON.stringify({replies,local}));throw error;
      }
      if(mode==='named-status-explicit'){
        await waitFor(()=>browser.evaluate(`!!E2E.dmSessions[${q(key)}]?.startEph&&!E2E._pendingOn?.[${q(key)}]&&
          e2eTargetState(${q(alias)},{conn_id:${q(networkA)}}).mode==='dm'`),'the explicit session is established');
        check('the peer owns its nick before the explicitly encrypted message',await ownsNick());
        await compose(browser,networkA,alias,first);
      }
      try{await acceptIdentity(peer,waitFor);}catch(error){
        const sent=browser.frames.slice(initial).map(JSON.parse).filter(e=>e.type==='send'&&e.raw?.startsWith('PRIVMSG status :'));
        console.log('Named-user first message handoff',JSON.stringify({
          headers:sent.filter(e=>e.raw.includes(' :[e2ex3dh]')).length,encrypted:sent.filter(e=>e.raw.includes(' :[e2edm2]')).length,
          clear:sent.filter(e=>e.raw.endsWith(' :'+first)).length,
          atPeer:remoteWs.events.slice(wireStart).filter(e=>e.from===owner&&e.text?.startsWith('[e2edm2]')).length}));
        throw error;
      }
      await waitFor(()=>row(peer,remoteNetwork,owner,first),'the independent named user decrypts the first PM');
      const sent=browser.frames.slice(initial).map(JSON.parse);
      const wires=sent.filter(e=>e.type==='send'&&e.raw?.startsWith('PRIVMSG status :[e2edm2]'));
      check('initiating to the named contact performs discovery and delivers precisely one encrypted first PM',
        requests().length===1&&wires.length===1&&remoteWs.events.slice(wireStart).filter(e=>e.from===owner&&e.text===wires[0].raw.split(' :')[1]).length===1&&
        !sent.some(e=>e.raw?.includes(first)||(e.type==='save_preferences'&&e.prefs?.includes(first)))&&
        !await row(browser,networkA,'status',first));
      return;
    }
    const receiveAt=ownerWs.events.length,body='signal from named contact '+stamp;
    await compose(peer,remoteNetwork,owner,body);await acceptIdentity(peer,waitFor);
    await acceptIdentity(browser,waitFor);
    await waitFor(()=>row(browser,networkA,alias,body),'the private query opens the message from the named Signal sender');
    const seen=ownerWs.events.slice(receiveAt).filter(e=>e.conn_id===networkA&&e.from===named&&e.text?.startsWith('[e2edm2]')).length;
    const data=await browser.evaluate(`(async()=>{
      const saved=await _e2eRequestSession(${q(key)},true);
      return {stored:!!saved?.blob,mode:e2eTargetState(_dmTarget('status'),{conn_id:${q(networkA)}}).mode,
        inAlias:getBuf(${q(networkA)},_dmTarget('status')).some(m=>m.text===${q(body)}),
        inServer:getBuf(${q(networkA)},'status').some(m=>m.text===${q(body)})};
    })()`);
    check('the encrypted message from status is delivered to the named user’s query and excluded from the server log',
      seen===1&&data.stored&&data.mode==='dm'&&data.inAlias&&!data.inServer);
    await browser.evaluate(`setActive(${q(networkA)},'status');void handleInput('/query status')`);
    check('ordinary query opens the literal status user',await browser.evaluate('active.target===_dmTarget("status")'));
    const answer='response for named contact '+stamp,from=browser.frames.length,dest=remoteWs.events.length;
    check('the independent account owns the recipient nick before the reply',await ownsNick());
    await compose(browser,networkA,alias,answer);
    await waitFor(()=>row(peer,remoteNetwork,owner,answer),'the named status recipient decrypts the reply');
    const direct=browser.frames.slice(from).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===networkA&&e.raw?.startsWith('PRIVMSG status :'));
    const wire=direct.filter(e=>e.raw.includes(' :[e2edm2]'));
    check('the reply to the literal IRC user status produces one matching encrypted message and zero clear chat frames',
      wire.length===1&&!direct.some(e=>e.raw.endsWith(' :'+answer))&&
      await waitFor(()=>remoteWs.events.slice(dest).some(e=>e.from===owner&&e.text===wire[0].raw.split(' :')[1]),'the actual IRC wire reaches the named peer'));
    if(mode==='named-status-commands'){
      const account=()=>browser.evaluate(`(async()=>{
        const slot=await _e2eRequestSession(${q(key)},true),psk=_e2eScopedPskSlot('status',${q(networkA)});
        return {active:!!slot?.blob,off:E2E.state.dm[${q(key)}]?.on===0,shared:!!E2E.channelKeys[psk]};})()`);
      const before=await account();
      const command=async(view,text,expected)=>{
        const offset=await browser.evaluate(`getBuf(${q(networkA)},${q(view)}).length`);
        await compose(browser,networkA,view,'/encrypt '+text);
        return waitFor(()=>browser.evaluate(`getBuf(${q(networkA)},${q(view)}).slice(${offset}).some(m=>m.text.includes(${q(expected)}))`),
          'encryption command '+text.split(' ')[0]+' responds in its originating view',4000);
      };
      check('the named contact starts with a readable Signal session and no shared key',before.active&&!before.off&&!before.shared);
      const at=browser.frames.length;
      for(const name of ['off','stop','on','start','restart','verify','trust','accept','reject','status']){
        await command('status',name,'Usage: /encrypt '+name);
      }
      for(const name of ['keygen','add','share','rotate','suggest-signal','use-signal','use-shared-key']){
        await command('status',name,'Open the channel or private chat');
      }
      const after=await account();
      check('all 17 target-dependent commands keep the actual user’s keys intact in the console',
        after.active&&!after.off&&!after.shared&&!browser.frames.slice(at).map(JSON.parse).some(e=>['e2e_close_session','e2e_fetch_bundle','e2e_suggest_signal'].includes(e.type)));
      await command('status','fingerprint','Your fingerprint:');
      await command('status','status status','DM status');
      await command(alias,'status','DM status');
      const suggestions=ownerWs.events.length,remoteSuggestions=remoteWs.events.length;
      check('the peer owns its nick before exchanging private method suggestions',await ownsNick());
      await compose(peer,remoteNetwork,owner,'/encrypt suggest-signal');
      await waitFor(()=>ownerWs.events.slice(suggestions).some(e=>e.type==='e2e_signal_suggestion'&&e.nick===named&&!e.sent),'method suggestion received from status');
      const review='#chat-area [data-e2e-method=review]';
      await waitFor(()=>browser.evaluate(`!!document.querySelector(${q(review)})`),'named peer’s review action in its private query');
      await browser.evaluate(`document.querySelector(${q(review)}).click()`);
      check('the private review action opens this user’s panel, with a real suggestion button',await browser.evaluate(
        `active.target===${q(alias)}&&!!document.querySelector('#encrypt-panel-body [data-encrypt-cmd=suggest-signal]')&&
          !getBuf(${q(networkA)},'status').some(m=>m.e2eSetupAction==='method-request')`));
      check('the receiver still holds the real IRC nick before the reverse suggestion',await ownsNick());
      await browser.evaluate("document.querySelector('#encrypt-panel-body [data-encrypt-cmd=suggest-signal]').click()");
      await waitFor(()=>remoteWs.events.slice(remoteSuggestions).some(e=>e.type==='e2e_signal_suggestion'&&e.nick===owner&&!e.sent),'private method suggestion delivered to the named peer');
      await browser.evaluate('closeEncryptPanel()');
      const last='protected after console commands '+stamp;
      check('the test account still owns the nick before the protected send',await ownsNick());
      await compose(browser,networkA,alias,last);
      check('the named contact still reads an encrypted PM after console commands',await waitFor(()=>row(peer,remoteNetwork,owner,last),'the real user still decrypts'));
      await compose(browser,networkA,alias,'/encrypt stop');
      check('implicit stop in the real private query closes the authenticated peer slot',await waitFor(async()=>{
        const state=await account();return state.off&&!state.active;},'the named user’s session closes'));
      await waitFor(()=>browser.evaluate('!_sendLock'),'private stop finishes');
      await compose(browser,networkA,alias,'/encrypt keygen');
      await waitPrompt(browser,waitFor,'Copy this key');
      await browser.evaluate(cancelPrompt);
      check('the real private query can create its own shared key',await waitFor(async()=>(await account()).shared,'private named key'));
      await command('status','share','Open the channel or private chat');
      check('the server console does not expose the real user’s saved shared key',!await browser.evaluate(promptOpen));
      await compose(browser,networkA,alias,'/encrypt share');
      await waitPrompt(browser,waitFor,'Copy this key');await browser.evaluate(cancelPrompt);
      await waitFor(()=>browser.evaluate('!_sendLock'),'private share finishes');
      await compose(browser,networkA,'status','/encrypt off status');
      check('an explicitly addressed console command removes the named user’s shared key',await waitFor(async()=>{
        const state=await account();return !state.shared&&state.off&&!state.active;},'explicitly named off completes'));
      return;
    }
    if(mode==='named-status-reaction'){
      await browser.evaluate(`setActive(${q(networkA)},${q(alias)})`);
      await peer.evaluate(`setActive(${q(remoteNetwork)},${q(owner)})`);
      check('the linked IRC endpoints both support reactions',await browser.evaluate(`reactionEnabled(${q(networkA)})`)&&
        await peer.evaluate(`reactionEnabled(${q(remoteNetwork)})`));
      check('the named user still owns the private reaction target',await ownsNick());
      await checkSealedReaction({browser:peer,peer:browser,check,waitFor,sourceWs:remoteWs,text:body,target:'real user named status',emoji:'👍'});
      check('the named account still owns its nick before the reverse Like',await ownsNick());
      await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:answer,target:'reply from the named user',emoji:'👍'});
    }
    return;
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='bridge-window'){
    await peer.evaluate(openEncryptionSettings);
    await setUpRecovery(peer,waitFor,check);
    const bundlePath=path.join(remoteData,'e2e',remote,'bundle.json');
    const published=await waitFor(()=>fs.readFile(bundlePath,'utf8').then(JSON.parse).catch(()=>null),'remote public bundle');
    const first=crypto.randomUUID().replaceAll('-',''), explicit=crypto.randomUUID().replaceAll('-','');
    const replies=id=>ownerWs.events.filter(event=>event.req===id&&event.conn_id===networkA);
    // Pause only this test's disposable peer web process. Both IRC connections
    // stay registered, and both requests receive genuine delayed peer responses.
    if(!peerWeb.kill('SIGSTOP')) throw new Error('Could not pause the fixture peer web process');
    const start=performance.now();
    try{
      for(const [req,wait_for_peer] of [[first,false],[explicit,true]]){
        ownerWs.send({type:'e2e_fetch_bundle',username:remote,conn_id:networkA,req,wait_for_peer});
      }
      await waitFor(()=>replies(first).some(e=>e.type==='e2e_bundle_missing'&&e.reason==='unconfirmed'),
        'first-contact discovery reports a delayed peer',12000);
      check('automatic first-contact discovery expires while explicit lookup remains pending',replies(explicit).length===0);
      await new Promise(resolve=>setTimeout(resolve,Math.max(0,7500-(performance.now()-start))));
    }finally{
      peerWeb.kill('SIGCONT');
    }
    const received=await waitFor(()=>replies(explicit).find(e=>e.type==='e2e_bundle'&&e.bridge),
      'explicit lookup accepts the delayed peer bundle',25000);
    const elapsedMs=Math.round(performance.now()-start);
    check('a delayed explicit lookup receives the actual peer identity over linked IRC',
      received.username===remote&&received.bundle.identity_sign_key===published.identity_sign_key&&
      elapsedMs>5000&&replies(first).length===1&&replies(explicit).length===1);
    const absent=crypto.randomUUID().replaceAll('-',''), silent=crypto.randomUUID().replaceAll('-','');
    const secondStart=performance.now();
    for(const [req,username] of [[absent,'abs'+stamp],[silent,ordinary]]){
      ownerWs.send({type:'e2e_fetch_bundle',username,conn_id:networkA,req,wait_for_peer:true});
    }
    await waitFor(()=>replies(absent).some(e=>e.type==='e2e_bundle_missing'&&e.reason==='peer-offline'),
      'IRC reports the absent peer before the long lookup would expire',15000);
    const offlineMs=Math.round(performance.now()-secondStart);
    check('an absent nick ends only its own lookup and an online silent client stays pending',replies(silent).length===0);
    await waitFor(()=>replies(silent).some(e=>e.type==='e2e_bundle_missing'&&e.reason==='unconfirmed'),
      'the online nonparticipating client gets the full explicit discovery window',30000);
    const silentMs=Math.round(performance.now()-secondStart);
    check('an online silent client times out once after the extended window',silentMs>=24500&&replies(silent).length===1&&replies(absent).length===1);
    console.log('BRIDGE WINDOW '+JSON.stringify({elapsedMs,offlineMs,silentMs}));
    return;
  }
  if(mode==='bridge-ordinary'||mode==='bridge-ordinary-cold'){
    const cold=mode==='bridge-ordinary-cold';
    const hello='ordinary client says hello '+stamp;
    ordinarySend('PRIVMSG '+owner+' :'+hello);
    await waitFor(()=>row(browser,networkA,ordinary,hello),'the ordinary IRC client starts the conversation');
    await browser.evaluate(`setActive(${q(networkA)},${q(ordinary)})`);
    await waitFor(()=>browser.evaluate(`(()=>{
      const key=_e2eDmKey(${q(ordinary)},${q(networkA)});
      return _e2eChatProbes.get(_e2eChatProbeKey(${q(networkA)},key))?.noBridge;
    })()`),'the IRCd identifies the ordinary client when the user opens the DM');
    await browser.evaluate(`window.replyGate={socket:ws,handle:e2eHandleEvent,held:[],statuses:[]};
      e2eHandleEvent=event=>{
        if(event.type==='e2e_keyring') { replyGate.held.push(event); return Promise.resolve(); }
        return replyGate.handle(event);
      };
      const status=document.getElementById('composer-encryption-status');
      replyGate.observer=new MutationObserver(()=>{
        if(status.classList.contains('show')) replyGate.statuses.push(status.textContent);
      });
      replyGate.observer.observe(status,{childList:true,subtree:true,attributes:true});
      if(${cold}){_e2eWipeMemory();E2E.state=null;E2E._krReceived=false;E2E._bootPhase=undefined;}
      ws.close();`);
    const refreshPending=cold?'!E2E.keyReady':'E2E._resyncPending';
    await waitFor(()=>browser.evaluate(`ws!==replyGate.socket&&_wsReady()&&${refreshPending}&&replyGate.held.length>0`),
      'the new browser connection is ready with account-wide encryption refresh stalled');
    const reply='one reply while the keyring is delayed '+stamp;
    const first=browser.frames.length, began=performance.now();
    try{
      await compose(browser,networkA,ordinary,reply);
      await waitFor(()=>ordinaryLines.filter(line=>line.endsWith(' :'+reply)).length===1,
        'the ordinary peer receives plaintext before the keyring response is released',4500).catch(async error=>{
        console.log('PLAIN REPLY DIAGNOSTIC '+JSON.stringify({
          state:await browser.evaluate(`({
            probe:!!e2eCanCheckPlainReply(${q(ordinary)},${q(networkA)}),resync:E2E._resyncPending,
            boot:E2E._bootPhase,draft:document.getElementById('msg-input').value===${q(reply)},
            focused:document.activeElement?.id,statuses:replyGate.statuses,block:E2E.lastBlockReason,
            queued:_rateQueue.some(msg=>msg.raw?.endsWith(' :'+${q(reply)}))})`),
          sent:browser.frames.slice(first).map(JSON.parse).filter(f=>
            ['send','e2e_check_plain_reply','e2e_fetch_bundle'].includes(f.type)).map(f=>f.type),
          refused:ownerWs.events.some(e=>e.type==='irc_delivery_warning'&&e.unsent_wire===reply),
        }));
        throw error;
      });
      check('plain reply takes one scoped settings check and shows no encryption status',
        performance.now()-began<1300&&await browser.evaluate(`${refreshPending}&&replyGate.statuses.length===0`)&&
        browser.frames.slice(first).map(JSON.parse).filter(f=>f.type==='e2e_check_plain_reply').length===1);
      if(cold){
        const held='reply with no cached device key '+stamp;
        await browser.evaluate(`_e2ePlainReplyProbe(${q(ordinary)},${q(networkA)}).probe.deviceKey=Promise.resolve(null)`);
        const transport=browser.frames.length;
        await compose(browser,networkA,ordinary,held);
        await waitFor(()=>browser.evaluate('document.getElementById("composer-encryption-status").classList.contains("show")'),
          'the browser holds the draft when it cannot authenticate the settings');
        check('a cold device without its saved key cannot release the draft in plaintext',
          !browser.frames.slice(transport).map(JSON.parse).some(f=>f.raw?.endsWith(' :'+held))&&
          await browser.evaluate(`document.getElementById('msg-input').value===${q(held)}`));
        await browser.evaluate(`document.getElementById('msg-input').value='';_clearComposerSendAttempt();
          _e2ePlainReplyProbe(${q(ordinary)},${q(networkA)}).probe.deviceKey=null;`);
      }
    }finally{
      await browser.evaluate(`(async()=>{const gate=replyGate;gate.observer.disconnect();e2eHandleEvent=gate.handle;
        for(const event of gate.held) await e2eHandleEvent(event);
        delete window.replyGate;})()`);
    }
    await waitFor(()=>browser.evaluate('E2E.keyReady&&E2E._bootPhase==="ready"&&!E2E._resyncPending'),'account-wide encryption refresh finishes');
    const draft='IRC without message tags '+stamp,at=browser.frames.length;
    const received=()=>ordinaryLines.filter(line=>line.includes(' PRIVMSG '+ordinary+' :')&&line.endsWith(' :'+draft));
    await compose(browser,networkA,ordinary,draft);
    await waitFor(()=>received().length===1,'ordinary recipient on the linked server receives the plaintext PM',12000);
    check('the module confirms the recipient cannot receive encryption probes',ownerWs.events.some(e=>
      e.type==='e2e_bundle_missing'&&e.conn_id===networkA&&e.reason==='peer-no-bridge'));
    check('two linked IRCds deliver one plaintext PM without any confirmation',received().length===1&&
      browser.frames.slice(at).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===networkA&&e.raw==='PRIVMSG '+ordinary+' :'+draft).length===1&&
      !await browser.evaluate(`(${promptOpen})||(${plainPrompt})||!document.getElementById('composer-encryption-action').hidden`));
    const revision=browser.frames.slice(first).map(JSON.parse)
      .find(f=>f.raw===`PRIVMSG ${ordinary} :${reply}`)?.e2e_plain_revision;
    check('the ordinary reply carries its checked settings revision through the actual IRC handoff',typeof revision==='string');
    if(cold) check('the cold reply also binds the authenticated keyring to the actual IRC handoff',/^([a-f0-9]{64})?\.[a-f0-9]{64}$/.test(revision));
    const peerSlot=`@${networkA}:${ordinary.toLowerCase()}`;
    await browser.evaluate(`(async()=>{const key=await generateChannelKey();await storeChannelKey(${q(peerSlot)},key.key,key.keyB64);})()`);
    await waitFor(()=>browser.evaluate(`_e2eReq({type:'e2e_load_keyring'},'e2e_keyring').then(ev=>ev?.channels?.includes(${q(peerSlot)}))`),
      'a shared key now protects the same contact');
    const stale='ordinary reply with stale authorization '+stamp;
    ownerWs.send({type:'send',conn_id:networkA,raw:`PRIVMSG ${ordinary} :${stale}`,e2e_plain_revision:revision});
    await ownerWs.wait(e=>e.type==='irc_delivery_warning'&&e.target===ordinary&&e.unsent_wire===stale,
      'the web server rejects the stale plaintext authorization');
    check('a stale ordinary-reply authorization sends zero plaintext to the protected IRC peer',
      !ordinaryLines.some(line=>line.endsWith(' :'+stale)));
    return;
  }
  if(mode==='bridge-first-contact-review'||mode==='bridge-first-contact-review-protected'){
    const protectedInbox=mode.endsWith('-protected');
    await peer.evaluate(openEncryptionSettings);
    const recoveryCode=await setUpRecovery(peer,waitFor,check);
    await peer.evaluate('closeEncryptPanel()');
    await waitFor(()=>fs.stat(path.join(remoteData,'e2e',remote,'bundle.json')).catch(()=>null),'peer published its first Signal bundle');
    await peer.close();
    const draft='first contact while the recipient browser was closed '+stamp;
    await compose(browser,networkA,remote,draft);
    await acceptIdentity(browser,waitFor);
    await remoteWs.wait(e=>e.type==='irc_message'&&e.from===owner&&e.text.startsWith('[e2edm2]'),
      'the disconnected recipient’s IRC connection receives the encrypted first message');
    const opened=await peer.reopen();
    if(!await waitFor(()=>opened.evaluate('_wsReady()'),'the recipient’s profile reconnects',5000).catch(()=>false))
      await login(opened,remote,password,waitFor);
    await waitFor(()=>opened.evaluate('window._appShown'),'the recipient opens the chat app');
    if(!await opened.evaluate('E2E._vaultUp')) await unlockVault(opened,vault);
    await waitFor(()=>opened.evaluate('E2E._vaultUp&&E2E._krReceived'),'the returning device receives the keyring');
    if(!await waitFor(()=>opened.evaluate('E2E.identityReady'),'the recipient’s identity is restored',5000).catch(()=>false)){
      await opened.evaluate(openEncryptionSettings);
      await waitPrompt(opened,waitFor,unlockText);
      await fillPrompt(opened,recoveryCode);
      await waitFor(()=>opened.evaluate('E2E.identityReady'),'the recipient unlocks its saved identity');
      await opened.evaluate('closeEncryptPanel()');
    }
    if(protectedInbox) await opened.evaluate(`localStorage.setItem('cryptirc_block_pms','true');
      localStorage.setItem('cryptirc_pm_deliver_first','true');`);
    await opened.evaluate(`setActive(${q(remoteNetwork)},${q(owner)})`);
    const review='#chat-area [data-e2e-verify-identity]';
    await waitFor(()=>opened.evaluate(`!!document.querySelector(${q(review)})`),'the new encrypted conversation offers Verify Signal identity');
    check('history waits for the recipient to choose verification',!await opened.evaluate("!!document.getElementById('e2e-id-dialog')")&&
      !await row(opened,remoteNetwork,owner,draft));
    await opened.evaluate(`document.querySelector(${q(review)}).click()`);
    await acceptIdentity(opened,waitFor);
    if(protectedInbox){
      await waitFor(()=>opened.evaluate(`e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='dm'`),
        'explicit review establishes Signal in the protected inbox');
      check('explicit verification leaves the PM protection settings and allow list intact',
        await opened.evaluate(`getPmSettings(${q(remoteNetwork)}).enabled&&!isPmAllowedFor(${q(remoteNetwork)},${q(owner)})`));
      const reply='encrypted reply after review in a protected inbox '+stamp;
      await compose(opened,remoteNetwork,owner,reply);
      await waitFor(()=>row(browser,networkA,remote,reply),'the other client reads the encrypted reply after protected-inbox review');
      return;
    }
    await waitFor(()=>row(opened,remoteNetwork,owner,draft),'the verified recipient reads the original encrypted PM from history');
    check('one explicit verification opens the original message',true);
    return;
  }
  if(mode==='bridge-superseded-plain'){
    const first='superseded ordinary draft '+stamp;
    const latest='replacement ordinary draft '+stamp;
    const incoming='ordinary reply during lookup '+stamp;
    await browser.evaluate(`(()=>{
      setActive(${q(networkA)},${q(ordinary)});
      const handle=e2eHandleEvent;
      window.ordinaryLookup={event:null,release:async()=>{
        e2eHandleEvent=handle;
        if(ordinaryLookup.event) await handle(ordinaryLookup.event);
      }};
      e2eHandleEvent=event=>{
        if(event.type==='e2e_bundle_missing'&&event.reason==='unconfirmed'&&event.conn_id===${q(networkA)}){
          ordinaryLookup.event=event;
          return Promise.resolve();
        }
        return handle(event);
      };
    })()`);
    const from=browser.frames.length;
    await compose(browser,networkA,ordinary,first);
    await waitFor(()=>browser.evaluate('!!ordinaryLookup.event'),'ordinary client’s capability check is in flight');
    ordinarySend('PRIVMSG '+owner+' :'+incoming);
    const incomingText=await waitFor(()=>browser.evaluate(`getBuf(${q(networkA)},${q(ordinary)})
      .find(message=>message.text.includes(${q(incoming)}))?.text`),'ordinary client sends during the check');
    await compose(browser,networkA,ordinary,latest);
    await browser.evaluate('ordinaryLookup.release()');
    const delivered=await waitFor(()=>ordinaryLines.some(line=>line.endsWith(' :'+latest)),
      'the replacement draft reaches the ordinary peer',5500).catch(()=>false);
    const errors=await browser.evaluate(`getBuf(${q(networkA)},${q(ordinary)})
      .filter(message=>message.kind==='error'&&message.text.includes('Message not sent')).length`);
    check('ordinary chat stays plaintext while discovery is pending',incomingText===incoming);
    check('one Send of the replacement draft delivers it without a stale-check error',delivered&&errors===0&&
      !ordinaryLines.some(line=>line.endsWith(' :'+first))&&
      ordinaryLines.filter(line=>line.endsWith(' :'+latest)).length===1);
    check('replacement draft reuses the original capability check',browser.frames.slice(from).map(JSON.parse)
      .filter(frame=>frame.type==='e2e_fetch_bundle'&&frame.username===ordinary).length===1);
    const manualFrom=browser.frames.length;
    await compose(browser,networkA,ordinary,'/encrypt on '+ordinary);
    await waitFor(()=>browser.frames.slice(manualFrom).map(JSON.parse)
      .some(frame=>frame.type==='e2e_fetch_bundle'&&frame.username===ordinary&&frame.wait_for_peer),
      'explicit Signal setup requests a key');
    const manualIncoming='ordinary text during explicit Signal setup '+stamp;
    ordinarySend('PRIVMSG '+owner+' :'+manualIncoming);
    await waitFor(()=>row(browser,networkA,ordinary,'⚠️ [NOT ENCRYPTED] '+manualIncoming),
      'plaintext is labeled while explicit Signal setup is pending');
    const protectedDraft='draft during explicit Signal setup '+stamp;
    await compose(browser,networkA,ordinary,protectedDraft);
    await waitFor(()=>browser.evaluate(`!_sendLock&&document.getElementById('msg-input').value===${q(protectedDraft)}`),
      'explicit Signal setup keeps the protected draft');
    check('waiting for an explicitly requested key never sends the protected draft in plaintext',
      !browser.frames.slice(manualFrom).map(JSON.parse).some(frame=>frame.raw?.endsWith(' :'+protectedDraft))&&
      !ordinaryLines.some(line=>line.endsWith(' :'+protectedDraft)));
    return;
  }
  if(mode==='bridge-plain-uncertain'){
    await peer.evaluate(openEncryptionSettings);
    await setUpRecovery(peer,waitFor,check);
    await peer.evaluate('closeEncryptPanel()');
    await waitFor(()=>fs.stat(path.join(remoteData,'e2e',remote,'bundle.json')).catch(()=>null),'peer published its first Signal bundle');
    const typeDraft=async (target,text)=>{
      await browser.evaluate(`setActive(${q(networkA)},${q(target)});document.getElementById('msg-input').value='';
        document.getElementById('msg-input').focus()`);
      await browser.send('Input.insertText',{text});
      await waitFor(()=>browser.evaluate(`(()=>{
        const k=_e2eDmKey(${q(target)},${q(networkA)});
        const probe=_e2eChatProbes.get(_e2eChatProbeKey(${q(networkA)},k));
        return _e2eChatProbeCurrent(probe)&&!probe.finish;
      })()`),'typing finishes a quiet encryption lookup');
    };
    const draft='first Signal PM '+stamp,from=browser.frames.length;
    const sent=()=>browser.frames.slice(from).map(JSON.parse).filter(f=>f.type==='send'&&f.raw?.startsWith('PRIVMSG '+remote+' :'));
    await typeDraft(remote,draft);
    check('typing does not start a Signal prompt or send the typed message',
      sent().length===0&&!await browser.evaluate(promptOpen));
    await compose(browser,networkA,remote,draft);
    await acceptIdentity(browser,waitFor);
    await acceptIdentity(peer,waitFor);
    await waitFor(()=>row(peer,remoteNetwork,owner,draft),'recipient decrypts the first PM when the bridge answers');
    check('a first PM picks Signal when the bridge replies',sent().some(f=>f.raw.includes(' :[e2edm2]'))&&
      sent().every(f=>!f.raw.includes(draft))&&!remoteWs.events.some(e=>e.type==='irc_message'&&e.text===draft));
    check('sending reuses the prekey bundle already fetched while typing',browser.frames.slice(from).map(JSON.parse)
      .filter(f=>f.type==='e2e_fetch_bundle'&&f.username===remote).length===1);
    const protectedDraft='protected PM '+stamp,protectedAt=browser.frames.length;
    if(!peerWeb.kill('SIGSTOP')) throw new Error('Could not pause the disposable peer web process');
    try{
      await compose(browser,networkA,remote,protectedDraft);
      const frame=await waitFor(()=>browser.frames.slice(protectedAt).map(JSON.parse)
        .find(f=>f.raw?.startsWith('PRIVMSG '+remote+' :[e2edm2]')),'an established chat sends Signal while the peer web is paused');
      check('an established chat keeps its protection while the peer is slow',!frame.raw.includes(protectedDraft)&&
        !browser.frames.slice(protectedAt).map(JSON.parse).some(f=>f.raw?.endsWith(' :'+protectedDraft)));
    }finally{
      peerWeb.kill('SIGCONT');
    }
    await waitFor(()=>row(peer,remoteNetwork,owner,protectedDraft),'recipient decrypts the second PM after web resumes');
    const text='plain '+stamp,named='named '+stamp,action='waves '+stamp;
    const firstLookup=browser.frames.length;
    await typeDraft(ordinary,text);
    for(const [tab,command,payload] of [[ordinary,text,text],['status','/msg '+ordinary+' '+named,named],[ordinary,'/me '+action,'\x01ACTION '+action+'\x01']]){
      const received=()=>ordinaryLines.filter(line=>line.endsWith(' :'+payload)).length;
      const mark=ownerWs.events.length;
      const began=performance.now();
      await compose(browser,networkA,tab,command);
      const echoedBody=payload.startsWith('\x01ACTION ') ? action : payload;
      await waitFor(()=>ownerWs.events.slice(mark).some(e=>e.type==='irc_echo'&&e.target===ordinary&&e.text===echoedBody),
        'CryptIRC hands off the plaintext PM automatically',8000);
      const handoffMs=Math.round(performance.now()-began);
      check('a prepared plaintext PM is handed off without another bridge wait',handoffMs<1100);
      await waitFor(()=>received()===1,'ordinary tagged IRC client receives the PM automatically',15000);
      console.log('TAGGED PLAINTEXT '+JSON.stringify({handoffMs,deliveryMs:Math.round(performance.now()-began)}));
      check('a silent ordinary client receives one plaintext PM and the composer clears without a prompt',
        await browser.evaluate(`!document.getElementById('msg-input').value&&!(${promptOpen})&&
          document.getElementById('composer-encryption-action').hidden&&
          !document.getElementById('composer-encryption-status').classList.contains('show')`));
    }
    check('ordinary PMs reuse one discovery result across sends',browser.frames.slice(firstLookup).map(JSON.parse)
      .filter(f=>f.type==='e2e_fetch_bundle'&&f.username===ordinary).length===1);
    return;
  }
  const refreshTest=['setup-refresh-empty','setup-refresh-history'].includes(mode);
  let onboardingWindowEnds=0;
  if(updatedPeer){
    const setupDraft='ordinary DM before bridged encryption setup '+stamp;
    const otherEventsBeforeSetup=otherWs.events.length;
    await compose(browser,networkA,remote,refreshTest?'/encrypt on '+remote:setupDraft);
    await remoteWs.wait(e=>e.type==='e2e_setup_needed'&&e.conn_id===remoteNetwork&&e.from===owner,'targeted bridged setup notice');
    onboardingWindowEnds=Date.now()+61000;
    if(!refreshTest){
      await remoteWs.wait(e=>e.type==='irc_message'&&e.text===setupDraft,'unconfigured bridged peer receives the ordinary message');
      check('an unconfigured bridged contact receives plaintext once without a sender prompt',
        remoteWs.events.filter(e=>e.type==='irc_message'&&e.text===setupDraft).length===1&&
        !await browser.evaluate(`!!(${plainPrompt})`));
    }
    check('the bridged recipient gets no popup and no other account gets the notice',
      !await peer.evaluate(promptOpen)&&!otherWs.events.slice(otherEventsBeforeSetup).some(e=>e.type==='e2e_setup_needed'&&e.from===owner));
    if(interruptedCloseTest) await peer.evaluate(openEncryptionSettings);
    if(refreshTest){
      const history=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='setup-refresh-history'?'actual history during setup '+stamp:'';
      await peer.evaluate(`(()=>{
        const socket=ws, handle=socket.onmessage, text=${q(history)};
        const unlock=e2ePromptDeviceUnlock;
        const fixture={history:null,unlockCount:0,deliver:message=>handle.call(socket,message),restore:()=>{
          if(ws===socket)socket.onmessage=handle;
          e2ePromptDeviceUnlock=unlock;
          delete window.e2eSetupTouchFixture;
        }};
        e2ePromptDeviceUnlock=(...args)=>{fixture.unlockCount++;return unlock(...args);};
        window.e2eSetupTouchFixture=fixture;
        socket.onmessage=message=>{
          const event=JSON.parse(message.data);
          if(event.conn_id===${q(remoteNetwork)}&&event.target===${q(owner)}){
            if(text&&event.type==='irc_message'&&event.text===text)return;
            if(event.type==='log_lines'){
              if(text?event.lines.some(row=>row.text===text):!event.lines.length)fixture.history=message;
              return;
            }
          }
          handle.call(socket,message);
        };
      })()`);
      if(history){
        ownerWs.send({type:'send',conn_id:networkA,raw:`PRIVMSG ${remote} :${history}`});
        await remoteWs.wait(event=>event.type==='irc_message'&&event.from===owner&&event.text===history,
          'the witness receives the normal IRC line to be loaded from history');
      }
      try { await tapSetupWithHistory(peer,remoteNetwork,owner,history,waitFor,check); }
      finally { await peer.evaluate('window.e2eSetupTouchFixture?.restore()'); }
    }else if(!interruptedCloseTest) await openSetupInvite(peer,remoteNetwork,owner,waitFor,true);
  } else {
    const setupDraft='ordinary DM to a legacy bridged peer '+stamp;
    await compose(browser,networkA,remote,setupDraft);
    await remoteWs.wait(e=>e.type==='irc_message'&&e.text===setupDraft,
      'the legacy bridge peer receives plaintext after the unanswered lookup');
    check('a legacy peer that did not answer gets one plaintext PM with no sender dialog',
      !await browser.evaluate(`!!(${plainPrompt})`)&&remoteWs.events.filter(e=>e.type==='irc_message'&&e.text===setupDraft).length===1);
    onboardingWindowEnds=Date.now()+61000;
    await peer.evaluate(openEncryptionSettings);
  }
  await setUpRecovery(peer,waitFor,check);
  if(refreshTest)return;
  if(updatedPeer){
    await peer.send('Emulation.clearDeviceMetricsOverride');
    await peer.send('Emulation.setTouchEmulationEnabled',{enabled:false});
  }
  await peer.evaluate('closeEncryptPanel()');
  await waitFor(()=>fs.stat(path.join(remoteData,'e2e',remote,'bundle.json')).catch(()=>null),'remote prekey bundle stored');

  const mixedFirst = process.env.CRYPTIRC_TEST_SIGNAL_HANDOFF!=='0' &&
    await peer.evaluate("typeof e2eStageSignalHistory==='function'&&typeof _e2eScopedPskSlot==='function'");
  const mixedKey = `_e2eDmKey(${q(owner)},${q(remoteNetwork)})`;
  const mixedName = `_e2eScopedPskSlot(_e2eCanon(${q(owner)},${q(remoteNetwork)}),${q(remoteNetwork)})`;
  if(mixedFirst){
    await peer.evaluate(`(async()=>{
      const saved=await generateChannelKey();
      await storeChannelKey(${mixedName},saved.key,saved.keyB64);
      setActive(${q(remoteNetwork)},${q(owner)});
    })()`);
    await waitFor(()=>peer.evaluate(`!E2E._stateSaving&&e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='psk'`),
      'first bridge recipient has a saved shared key');
  }

  const first = 'first encrypted cross-instance DM '+stamp;
  const framesAtStart = browser.frames.length;
  await compose(browser,networkA,remote,first);
  await waitFor(()=>browser.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"),'cross-instance automatic identity prompt');
  check('the bridge holds the first DM for identity confirmation',!remoteWs.events.some(e=>e.text?.includes(first)));
  check('a DM awaiting automatic encryption stays available in local input history without syncing',
    await browser.evaluate(`inputHistory.includes(${q(first)})&&!gatherPreferences().inputHistory.includes(${q(first)})`));
  const prefsAtStart=browser.frames.length;
  await browser.evaluate("_prefsAckSig='';flushPrefsToServer()");
  await waitFor(()=>browser.frames.slice(prefsAtStart).some(frame=>JSON.parse(frame).type==='save_preferences'),
    'preferences sent during automatic encryption setup');
  await acceptIdentity(browser,waitFor);
  let priorOffer;
  if(mixedFirst){
    check('the initial bridged Signal offer waits behind the existing shared key without pinning or creating a session',
      await waitFor(()=>peer.evaluate(`!!_e2ePendingHeader(${mixedKey})&&E2E._orphans?.[${mixedKey}]?.length===1&&
        !E2E.dmSessions[${mixedKey}]&&!E2E.trustStore[${mixedKey}]&&
        getBuf(${q(remoteNetwork)},${q(owner)}).some(m=>m._dmHistoryState==='pending')`),'mixed-method first message was held'));
    priorOffer=await peer.evaluate(`_e2ePendingHeader(${mixedKey})`);
    check('an offer with a broken signature cannot displace the held Signal offer',await peer.evaluate(`(async()=>{
      const offer=_e2ePendingHeader(${mixedKey});
      await _e2eHandleHeader(${q(owner)},{...offer,ephemeral_pub:offer.sender_ik},'irc',${q(remoteNetwork)});
      return _e2ePendingHeader(${mixedKey})===offer&&!E2E.trustStore[${mixedKey}];
    })()`));
    if(process.env.CRYPTIRC_TEST_SIGNAL_HISTORY_RECOVERY==='1'){
      await reopen(peer,waitFor,"E2E._bootPhase==='ready'&&E2E.identityReady",'recipient opens a new browser page before agreeing');
      await peer.evaluate(`setActive(${q(remoteNetwork)},${q(owner)})`);
      try {
        await waitFor(()=>peer.evaluate(`!!_e2eRecentOffers.get(${mixedKey})?.some(r=>r.text.startsWith('[e2edm2]'))&&
          !_e2ePendingHeader(${mixedKey})&&!E2E.dmSessions[${mixedKey}]&&!!E2E.channelKeys[${mixedName}]`),
          'reopened device stages the recent offer from encrypted scrollback');
      } catch (error) {
        const state=await peer.evaluate(`({phase:E2E._bootPhase,active:active?.target===${q(owner)},
          ready:E2E.keyReady,session:!!E2E.dmSessions[${mixedKey}],offer:!!_e2ePendingHeader(${mixedKey}),
          shared:!!E2E.channelKeys[${mixedName}],staged:_e2eRecentOffers.get(${mixedKey})?.length||0,
          buffered:getBuf(${q(remoteNetwork)},${q(owner)}).filter(m=>m._dmHistoryWire).length,
          requested:_pendingLogs.has(${q(remoteNetwork+'/'+owner)})})`);
        throw new Error(error.message+' '+JSON.stringify(state));
      }
    }
    await peer.evaluate(`setActive(${q(remoteNetwork)},${q(owner)});showEncryptPanel()`);
    const switchConfirm='[role=alertdialog][aria-label="Confirm encryption method"]';
    await clickVisible(peer,'[data-encrypt-cmd="use-signal"]');
    await waitFor(()=>peer.evaluate(`!!document.querySelector(${q(switchConfirm)})`),'mixed-method confirmation');
    await clickVisible(peer,switchConfirm+' button:first-child');
    check('declining a switch leaves the first message unopened and sends no Signal offer',await peer.evaluate(`
      !E2E.dmSessions[${mixedKey}]&&e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='psk'`));
    const framesBeforeApproval=peer.frames.length;
    await clickVisible(peer,'[data-encrypt-cmd="use-signal"]');
    await waitFor(()=>peer.evaluate(`!!document.querySelector(${q(switchConfirm)})`),'mixed-method reapproval');
    await clickVisible(peer,switchConfirm+' button:last-child');
    await acceptIdentity(peer,waitFor);
    check('switching to Signal authenticates the original held bridged message and avoids a competing handshake',
      await waitFor(()=>row(peer,remoteNetwork,owner,first),'original message recovered after opting in')&&
      !peer.frames.slice(framesBeforeApproval).some(frame=>JSON.parse(frame).type==='e2e_fetch_bundle')&&
      await peer.evaluate(`!E2E.dmSessions[${mixedKey}]?.isInitiator&&!!E2E.channelKeys[${mixedName}]`));
    await peer.evaluate('closeEncryptPanel()');
  } else {
    await acceptIdentity(peer,waitFor);
  }
  await waitFor(()=>row(peer,remoteNetwork,owner,first),'cross-instance peer decrypted first message');
  // The browser and the test observer each have their own WebSocket.
  await remoteWs.wait(e=>e.type==='irc_message'&&e.from===owner&&e.text?.startsWith('[e2edm2]'),
    'cross-instance observer received IRC ciphertext');
  check('linked UnrealIRCd servers carry ciphertext between independent CryptIRC instances',
    !remoteWs.events.some(e=>e.text?.includes(first)));
  const plaintextTypes=browser.frames.slice(framesAtStart).filter(frame=>frame.includes(first)).map(frame=>JSON.parse(frame).type);
  check('the first cross-instance DM stays out of browser sends in plaintext'+
    (plaintextTypes.length ? ' (seen in '+plaintextTypes.join(', ')+')' : ''),plaintextTypes.length===0);
  const reply = 'encrypted cross-instance reply '+stamp;
  const replyFrames=peer.frames.length,replyEvents=ownerWs.events.length;
  await compose(peer,remoteNetwork,owner,reply);
  try {
    await waitFor(()=>row(browser,networkA,remote,reply),'cross-instance reply',30000);
  } catch(error) {
    const inspect=(device,cid,nick)=>device.evaluate(`(()=>{
      const k=_e2eDmKey(${q(nick)},${q(cid)}),s=E2E.dmSessions[k],b=getBuf(${q(cid)},${q(nick)});
      return {state:e2eTargetState(${q(nick)},{conn_id:${q(cid)}}).mode,ns:s?.Ns,nr:s?.Nr,waiting:!!s?.x3dhPending,
        draft:document.getElementById('msg-input').value===${q(reply)},queue:_rateQueue.length,
        visible:b.slice(-4).map(m=>[m.kind,m._dmHistoryState||'',m.kind==='error'||m.kind==='system'?m.text.slice(0,160):''])};
    })()`);
    const submitted=peer.frames.slice(replyFrames).flatMap(f=>{const m=JSON.parse(f);return m.type==='send'&&m.raw?.includes(' :[e2edm2]')?[m.raw.split(' :')[1]]:[];});
    throw new Error(error.message+' '+JSON.stringify({submitted:submitted.length,arrived:ownerWs.events.slice(replyEvents).filter(e=>e.from===remote&&submitted.includes(e.text)).length,
      sender:await inspect(peer,remoteNetwork,owner),recipient:await inspect(browser,networkA,remote)}));
  }
  check('the cross-instance Double Ratchet decrypts the reply',true);
  if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='topology'){
    const port=Number(process.env.IRC_UNSUPPORTED_PORT);
    const add=async(ws,device,nick,label)=>{
      const at=ws.events.length;
      ws.send({type:'add_network',network:{id:crypto.randomUUID(),label,server:'127.0.0.1',port,tls:false,tls_accept_invalid_certs:false,
        nick,username:nick,realname:'Disposable testnet client',auto_join:[],sasl_external:false,auto_reconnect:false}});
      const cfg=await waitFor(()=>ws.events.slice(at).flatMap(e=>e.networks||[]).find(n=>n.config.label===label)?.config.id,'new independent network config');
      ws.send({type:'connect',id:cfg});
      await waitFor(()=>ws.events.slice(at).some(e=>e.type==='connected'&&e.conn_id===cfg&&e.nick===nick),'identical nickname registered on independent IRC network');
      await waitFor(()=>device.evaluate('networks.some(n=>n.config.id==='+q(cfg)+'&&n.connected)'),'browser connected to independent network');
      return cfg;
    };
    const [otherA,otherB]=await Promise.all([add(ownerWs,browser,owner,'Independent A'),add(remoteWs,peer,remote,'Independent B')]);
    const records=(ws,at,cid,from)=>ws.events.slice(at).filter(e=>e.type==='irc_message'&&e.from===from&&e.conn_id===cid);
    const visible=(dev,cid,nick,text)=>dev.evaluate('getBuf('+q(cid)+','+q(nick)+').filter(m=>m.text==='+q(text)+'&&m.encrypted).length');
    const selected=(dev,cid,nick)=>dev.evaluate('e2eTargetState('+q(nick)+',{conn_id:'+q(cid)+'}).mode');
    let count=remoteWs.events.length;
    check('identical nicks on separate real IRC networks have independent Signal state',
      await selected(browser,networkA,remote)==='dm'&&await selected(browser,otherA,remote)==='none'&&
      await selected(peer,remoteNetwork,owner)==='dm'&&await selected(peer,otherB,owner)==='none');
    const plainDm='ordinary-independent-'+stamp;
    await compose(browser,otherA,remote,plainDm);
    await waitFor(()=>records(remoteWs,count,otherB,owner).some(e=>e.text===plainDm),'an ordinary DM arrives on an IRCd without the bridge');
    check('plaintext without a bridge sends once on its own network with no dialog',
      records(remoteWs,count,otherB,owner).filter(e=>e.text===plainDm).length===1&&
      !records(remoteWs,count,remoteNetwork,owner).some(e=>e.text===plainDm)&&
      !await browser.evaluate(`!!(${plainPrompt})`));
    const code=await shareKey(browser,waitFor,'keygen',otherA,remote);
    await peer.evaluate('handleEncryptCommand('+q(['add',...code.split(' ')])+','+q(otherB)+','+q(owner)+')');
    await waitFor(async()=>await selected(peer,otherB,owner)==='psk'&&await selected(browser,otherA,remote)==='psk','both browsers share a private DM key on independent network');
    const dmA='sig-'+stamp,dmB='psk-'+stamp;
    count=remoteWs.events.length;
    await compose(browser,networkA,remote,dmA);
    await compose(browser,otherA,remote,dmB);
    await waitFor(async()=>await visible(peer,remoteNetwork,owner,dmA)===1&&await visible(peer,otherB,owner,dmB)===1,'identical nick opens the correct messages on each IRC network');
    check('cross-instance identical nick uses Signal on the bridged network and shared-key DMs on the unbridged network',
      records(remoteWs,count,remoteNetwork,owner).some(e=>e.text.startsWith('[e2edm2]'))&&records(remoteWs,count,otherB,owner).some(e=>e.text.startsWith('sd8~'))&&
      !(await visible(peer,remoteNetwork,owner,dmB))&&!(await visible(peer,otherB,owner,dmA))&&
      !remoteWs.events.slice(count).some(e=>[dmA,dmB].includes(e.text)));
    const chan='#separate-'+stamp;
    for(const [ws,cid] of [[ownerWs,networkA],[ownerWs,otherA],[remoteWs,remoteNetwork],[remoteWs,otherB]]){
      const start=ws.events.length; ws.send({type:'join_channel',conn_id:cid,channel:chan,key:null});
      await waitFor(()=>ws.events.slice(start).some(e=>['irc_join','irc_join_ex'].includes(e.type)&&e.conn_id===cid&&e.channel===chan),'joined same channel spelling on each IRC network');
    }
    for(const [sender,recipient] of [[networkA,remoteNetwork],[otherA,otherB]]){
      const code=await shareKey(browser,waitFor,'keygen',sender,chan);
      await peer.evaluate('handleEncryptCommand('+q(['add',...code.split(' ')])+','+q(recipient)+','+q(chan)+')');
      await waitFor(()=>hasKey(peer,chan,recipient),'per-network shared channel key ready');
    }
    const a='blue-'+stamp,b='green-'+stamp;
    count=remoteWs.events.length;
    await compose(browser,networkA,chan,a); await compose(browser,otherA,chan,b);
    await waitFor(async()=>await visible(peer,remoteNetwork,chan,a)===1&&await visible(peer,otherB,chan,b)===1,'two actual same-name channels each decrypt their own message');
    check('separate IRC networks isolate identical channel names and encrypt both channel messages',
      !(await visible(peer,remoteNetwork,chan,b))&&!(await visible(peer,otherB,chan,a))&&
      [remoteNetwork,otherB].every(cid=>records(remoteWs,count,cid,owner).filter(e=>e.target===chan&&e.text.startsWith('sd8~')).length===1)&&
      !remoteWs.events.slice(count).some(e=>[a,b].includes(e.text)));
    const off=remoteWs.events.length;
    remoteWs.send({type:'disconnect',id:otherB});
    await waitFor(()=>remoteWs.events.slice(off).some(e=>e.type==='disconnected'&&e.conn_id===otherB),'actual unbridged IRC disconnect');
    const during='online-'+stamp; await compose(browser,networkA,remote,during);
    await waitFor(()=>row(peer,remoteNetwork,owner,during),'supported-network Signal survives the other IRC disconnect');
    const re=remoteWs.events.length; remoteWs.send({type:'connect',id:otherB});
    await waitFor(()=>remoteWs.events.slice(re).some(e=>e.type==='connected'&&e.conn_id===otherB),'independent IRC connection re-registers');
    const after='reconnect-'+stamp; await compose(peer,otherB,owner,after);
    check('shared-key DM resumes after an actual IRC disconnect and the other network keeps its Signal session',
      await waitFor(()=>row(browser,otherA,remote,after),'shared-key DM after IRC reconnect')&&await selected(browser,networkA,remote)==='dm');
    for(const [observer,id] of [[ownerWs,otherA],[remoteWs,otherB]]){
      const at=observer.events.length;observer.send({type:'remove_network',id});
      await waitFor(()=>observer.events.slice(at).some(e=>e.type==='state'&&!e.networks.some(n=>n.config.id===id)),'remove independent test connection');
    }
    return;
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='live-split'){
    const ctl=action=>promisify(execFile)(process.env.CRYPTIRC_TEST_IRC_LINK_CTL,[action],{timeout:25000});
    const prefix='linkoff-'+stamp, back='linkback-'+stamp, answer='reply-'+stamp;
    const toPeer=remoteWs.events.length, toSender=ownerWs.events.length;
    try {
      await ctl('split'); await ctl('down');
      await compose(browser,networkA,remote,prefix);
      await waitFor(()=>ownerWs.events.slice(toSender).some(e=>/no such nick|not online|not on/i.test(e.text||''))
        || browser.evaluate("document.getElementById('msg-input').value==="+q(prefix)),'observe split error or retained draft',3500).catch(()=>{});
      await new Promise(resolve=>setTimeout(resolve,700));
      const evidence=await browser.evaluate('(()=>{const b=getBuf('+q(networkA)+','+q(remote)+');return {shown:b.some(m=>m.text==='+q(prefix)+'), failed:b.some(m=>m.text==='+q(prefix)+'&&m.sendState==="failed"), errorHere:b.some(m=>/no such nick|not delivered|could not send|not online|not on IRC/i.test(m.text||"")), draft:document.getElementById("msg-input").value==='+q(prefix)+'};})()');
      const bounced=ownerWs.events.slice(toSender).filter(e=>/no such nick|not online|not on/i.test(e.text||'')).map(e=>({type:e.type,inChat:e.target===remote,status:e.target==='status'}));
      console.log('SPLIT-DELIVERY '+JSON.stringify({evidence,bounced,peerReceived:remoteWs.events.slice(toPeer).filter(e=>e.from===owner&&e.text?.startsWith('[e2edm2]')).length}));
      await ctl('heal');await ctl('verify');
      await compose(browser,networkA,remote,back);
      await waitFor(()=>row(peer,remoteNetwork,owner,back),'new Signal send decrypts after an ordinary netsplit');
      await compose(peer,remoteNetwork,owner,answer);
      check('normal sends resume in both directions after a real IRC link split',
        await waitFor(()=>row(browser,networkA,remote,answer),'reply after ordinary netsplit')&&!ownerWs.events.some(e=>e.text===answer));
      check('sender sees a failure in the DM or keeps a draft for the message attempted during the split',
        evidence.failed||evidence.errorHere||evidence.draft);
    } finally { await ctl('heal'); }
    return;
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_QUEUE_RECOVERY==='queue-only'){
    const remoteTarget=q(remote),localConn=q(networkA);
    const localSessionKey=`_e2eDmKey(${remoteTarget},${localConn})`;
    await new Promise(resolve=>setTimeout(resolve,61000));
    await waitFor(()=>browser.evaluate(`!E2E.dmSessions[${localSessionKey}].x3dhPending`),
      'phone has a confirmed starting session before the queue regression');
    check('timed-out and empty session replies keep the Signal send queued until the matching lookup completes',await browser.evaluate(`(async()=>{
      const key=${localSessionKey}, request=_e2eReq;
      let allowed,expired;
      const matchKey=msg=>msg.type==='e2e_load_session'&&msg.partner===key;
      const dispatch=()=>e2eWithQueuedSignal(${remoteTarget},${localConn},ok=>{allowed=ok;});
      _e2eMarkMaybeMoved(key);
      try {
        _e2eReq=async (msg,...args)=>{
          if(!matchKey(msg))return request(msg,...args);
          expired=msg.req;
          return null;
        };
        await dispatch();
        if(!expired||allowed!==false||!_e2eMovedPending(key))return false;
        const moved=(E2E._moved ||= Object.create(null));
        const latest=moved[key]={at:Date.now()};
        let matchedLate;
        _e2eReq=async (msg,type,timeout,match,...args)=>{
          if(!matchKey(msg))return request(msg,type,timeout,match,...args);
          matchedLate=match({partner:key,req:expired,blob:''});
          return {partner:key,req:msg.req,blob:''};
        };
        await dispatch();
        if(matchedLate!==false||allowed!==false||moved[key]!==latest)return false;
      } finally {_e2eReq=request;}
      await dispatch();
      if(allowed!==true||_e2eMovedPending(key))return false;
      _e2eMarkMaybeMoved(key);
      try {
        _e2eReq=async (msg,...args)=>matchKey(msg)?{partner:key,req:msg.req,blob:'unreadable'}:request(msg,...args);
        await dispatch();
        return allowed===true&&!_e2eMovedPending(key)&&e2eTargetState(${remoteTarget},{conn_id:${localConn}}).reason.includes('Restart Signal');
      } finally {_e2eReq=request;E2E._sessionSyncRepair.delete(key);}
    })()`));
    await browser.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:3,mobile:true});
    await browser.send('Emulation.setTouchEmulationEnabled',{enabled:true});
    const queued=Array.from({length:18},(_,i)=>`queued Signal part ${i} ${stamp}`).join(' ');
    const restartedPeer='peer restarts while phone send is queued '+stamp;
    const peerKey=`_e2eDmKey(${q(owner)},${q(remoteNetwork)})`;
    const before=await peer.evaluate(`E2E.dmSessions[${peerKey}].startEph`);
    const pieces=await browser.evaluate(`_e2eSplit(${q(queued)},_e2eMaxPlain('dm',_e2eWireBudget(${remoteTarget},${localConn})))`);
    check('the iPhone queue regression exercises a multipart Signal send',pieces.length>1&&new Set(pieces).size===pieces.length);
    // Stretch only the browser rate-queue delay. Session changes and all chat
    // traffic use the real application, WebSocket and linked IRC servers.
    await browser.evaluate(`(() => {
      if(_rateQueue.length) throw new Error('Expected an empty send queue');
      clearTimeout(_rateTimer);
      _rateTimer=setTimeout(()=>{},60000);
      const verdict=e2eQueuedWireVerdict, retry=e2eRetryQueuedDm;
      const trace=[];
      const note=entry=>{if(trace.length<160)trace.push(entry);};
      window.auditQueueRecovery={trace,restore:()=>{e2eQueuedWireVerdict=verdict;e2eRetryQueuedDm=retry;}};
      e2eQueuedWireVerdict=(target,conn,text,...args)=>{
        const result=verdict(target,conn,text,...args);
        if(conn===${localConn}&&target===${remoteTarget}){
          note({at:Date.now(),verdict:typeof result==='string'?result:result?.retry?'retry':result?.reason});
        }
        return result;
      };
      e2eRetryQueuedDm=async(target,conn,...args)=>{
        try{
          const result=await retry(target,conn,...args);
          if(conn===${localConn}&&target===${remoteTarget}) note({at:Date.now(),retry:result?.wire?'replacement':result?.wait?'wait':'refused'});
          return result;
        }catch(error){
          if(conn===${localConn}&&target===${remoteTarget}) note({at:Date.now(),retry:'error',error:error?.message});
          throw error;
        }
      };
    })()`);
    try {
      const atPeer=remoteWs.events.length, atDevice=browser.frames.length, atSender=ownerWs.events.length;
      await compose(browser,networkA,remote,queued);
      const oldWires=await waitFor(async()=>{
        const wires=await browser.evaluate(`_rateQueue.filter(p=>p.raw.includes(' :[e2edm2]')).map(p=>p.raw)`);
        return wires.length===pieces.length&&wires;
      },'phone has all unsent Signal pieces queued');
      await peer.evaluate(`handleEncryptCommand(['restart',${q(owner)}],${q(remoteNetwork)},${q(owner)})`);
      await waitFor(()=>peer.evaluate(`E2E.dmSessions[${peerKey}].startEph!==${q(before)}&&!E2E._pendingOn[${peerKey}]`),
        'peer prepares the replacement Signal session');
      const replacement=await peer.evaluate(`E2E.dmSessions[${peerKey}].startEph`);
      await compose(peer,remoteNetwork,owner,restartedPeer);
      await waitFor(async()=>await row(browser,networkA,remote,restartedPeer)&&
        browser.evaluate(`E2E.dmSessions[${localSessionKey}].startEph===${q(replacement)}`),
        'phone installs the new session before draining the queue');
      {
        check('a queued Signal message cannot be retried while the peer identity is disputed',await browser.evaluate(`(() => {
          const wire=${q(oldWires[0].split(' :')[1])}, key=${localSessionKey};
          const meta=E2E._wireMeta.get(wire), trust=E2E.trustStore[key];
          if(!meta?.sealed||!trust)return false;
          E2E.trustStore[key]={...trust,keyChanged:true};
          try { return e2eQueuedWireVerdict(${remoteTarget},${localConn},wire,0,true).refuse===true; }
          finally { E2E.trustStore[key]=trust; E2E._wireMeta.set(wire,meta); }
        })()`));
      }
      const releasedAt=Date.now();
      await browser.evaluate('_kickRateQueue()');
      const readPieces=()=>peer.evaluate(`getBuf(${q(remoteNetwork)},${q(owner)}).filter(
        m=>${q(pieces)}.includes(m.text)&&m.encrypted).map(m=>${q(pieces)}.indexOf(m.text))`);
      const relayEvents=()=>remoteWs.events.slice(atPeer).filter(event=>event.conn_id===remoteNetwork&&
        event.from===owner&&event.text?.startsWith('[e2edm2]'));
      const sentFrames=()=>browser.frames.slice(atDevice).map(JSON.parse).filter(frame=>frame.conn_id===networkA&&
        frame.raw?.startsWith('PRIVMSG '+remote+' :[e2edm2]'));
      const transportState=()=>({sent:sentFrames().length,received:relayEvents().length,
        senderEchoes:ownerWs.events.slice(atSender).filter(event=>event.type==='irc_echo'&&event.conn_id===networkA&&
          event.target===remote&&event.text?.startsWith('[e2edm2]')).length,
        warnings:ownerWs.events.slice(atSender).flatMap(event=>{
          const reason=/flood|throttl|rate limit|line too long|delivery|not sent/i.exec(event.text||event.message||'');
          return reason?[{type:event.type,reason:reason[0].toLowerCase()}]:[];
        })});
      let relayMs;
      try {
        // IRC may pace delivery after the browser has drained its queue. Keep
        // the old 20-second observation, then time rendering after the peer
        // observer has actually received all ciphertext.
        const arrivedInTwenty=await waitFor(()=>relayEvents().length>=pieces.length,
          'testnet relayed the recovered ciphertext within twenty seconds',20000).catch(()=>false);
        if(!arrivedInTwenty){
          console.log('QUEUE AT 20S '+JSON.stringify({expected:pieces.length,rendered:await readPieces(),...transportState()}));
          await waitFor(()=>relayEvents().length>=pieces.length,'testnet relays every recovered piece',130000);
        }
        relayMs=Date.now()-releasedAt;
        check('the peer opens every piece of the re-encrypted iPhone DM after session replacement',
          await waitFor(async()=>new Set(await readPieces()).size===pieces.length,
            'peer reads every piece of the recovered queued message'));
      } catch (error) {
        const sender=await browser.evaluate(`(()=>{
          const key=${localSessionKey}, live=E2E.dmSessions[key];
          return {rate:getRateLimit(),queued:_rateQueue.length,rateTimer:!!_rateTimer,
            retrying:!!_rateDmRetry,connected:_wsReady(),syncPending:_e2eMovedPending(key),
            repair:E2E._sessionSyncRepair.has(key),expectedSession:live?.startEph===${q(replacement)},
            state:e2eTargetState(${remoteTarget},{conn_id:${localConn}}).mode,trace:window.auditQueueRecovery?.trace};
        })()`);
        console.log('QUEUE DIAGNOSTIC '+JSON.stringify({expected:pieces.length,
          rendered:await readPieces(),oldSent:sentFrames().filter(frame=>oldWires.includes(frame.raw)).length,
          ...transportState(),sender}));
        throw error;
      }
      const renderedOrder=await peer.evaluate(`getBuf(${q(remoteNetwork)},${q(owner)}).filter(
        m=>${q(pieces)}.includes(m.text)&&m.encrypted).map(m=>${q(pieces)}.indexOf(m.text))`);
      check('every recovered piece is rendered once and in order ('+renderedOrder.join(',')+')',
        renderedOrder.length===pieces.length&&renderedOrder.every((position,index)=>position===index));
      const frames=browser.frames.slice(atDevice).map(frame=>JSON.parse(frame));
      const dispatched=await browser.evaluate("window.auditQueueRecovery.trace.filter(entry=>entry.verdict==='send').map(entry=>entry.at)");
      const arrived=relayEvents().map(event=>event.ts).filter(Number.isFinite);
      console.log('QUEUE TIMING '+JSON.stringify({pieces:pieces.length,relayMs,renderedMs:Date.now()-releasedAt,
        dispatchSpanMs:dispatched.length>1?dispatched.at(-1)-dispatched[0]:null,
        receivedSpanMs:arrived.length>1?1000*(arrived.at(-1)-arrived[0]):null}));
      check('the queue discards all unsent ciphertext from the superseded session',!frames.some(frame=>oldWires.includes(frame.raw)));
      const potentialLeak=frames.find(frame=>{
        const serialized=JSON.stringify(frame);
        return serialized.includes(queued)||pieces.some(text=>text.length>=20&&serialized.includes(text));
      });
      check('the queued draft stays encrypted on WebSocket and IRC'+(potentialLeak?' (unexpected '+potentialLeak.type+' frame)':''),
        !potentialLeak&&!remoteWs.events.slice(atPeer).some(e=>pieces.includes(e.text)));
    } finally { await browser.evaluate('window.auditQueueRecovery?.restore(); delete window.auditQueueRecovery; _kickRateQueue()'); }

    return;
  }
  if(interruptedCloseTest||['same-account-gap','simultaneous-devices','simultaneous-first','passive-first','passive-delayed','passive-reenable','passive-order','passive-order-reply','long-draft','stale-composer','offline-reenable','close-refusal','close-lost-ack','identity-adoption','identity-reset','identity-reset-refused'].includes(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT)){
    const phone=await chromium('signal-audit-phone');
    await phone.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:3,mobile:true});
    await login(phone,owner,password,waitFor);
    await waitFor(()=>phone.evaluate('E2E._vaultUp&&E2E._krReceived'),'audit phone discovers the existing keyring');
    await phone.evaluate('void e2ePromptDeviceUnlock()');
    await waitPrompt(phone,waitFor,unlockText);
    await fillPrompt(phone,ownerCode);
    const cid=q(networkA), nick=q(remote), key=`_e2eDmKey(${nick},${cid})`;
    const session=`E2E.dmSessions[${key}]`;
    const ready=`window._appShown&&_wsReady()&&E2E.identityReady&&!E2E._resyncPending&&${session}`;
    await waitFor(()=>phone.evaluate(`!!(${ready})`),'audit phone restores the same Signal session');
    await phone.evaluate(`setActive(${cid},${nick})`);
    if(['identity-adoption','identity-reset','identity-reset-refused'].includes(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT)){
      const peerCid=q(remoteNetwork), own=q(owner), peerKey=`_e2eDmKey(${own},${peerCid})`;
      const pin=(device,slot)=>device.evaluate(`E2E.trustStore[${slot}]?.fingerprint`);
      const pending=(device,slot)=>device.evaluate(`E2E.trustStore[${slot}]?.pendingFingerprint`);
      const revision=device=>device.evaluate(`(async()=>{const blob=await _e2eFetchSession(${key});return blob&&_e2eSha256Hex(blob);})()`);
      const submit=async(device,conn,name,text)=>{
        await waitFor(()=>device.evaluate(`!Object.keys(E2E._kcOpen||{}).length&&!_confirmDialogs.length&&
          !document.getElementById('e2e-id-dialog')&&!(${promptOpen})`),'no encryption dialog covers the composer');
        await device.evaluate(`setActive(${q(conn)},${q(name)});(()=>{
          const input=document.getElementById('msg-input');input.focus();input.select();
        })()`);
        await device.send('Input.insertText',{text});
        await clickVisible(device,'#send-btn');
      };
      const relayed=(sender,from,observer,start,conn,displayText)=>{
        const frames=sender.frames.slice(from).map(frame=>JSON.parse(frame));
        const expected=frames.filter(frame=>frame.type==='send'&&frame.raw?.includes(' :[e2edm2]'))
          .map(frame=>frame.raw.split(' :')[1]);
        const events=observer.events.slice(start).filter(event=>event.conn_id===conn&&event.type==='irc_message');
        const actual=events.filter(event=>expected.includes(event.text));
        return {wire:actual[0]&&createHash('sha256').update(actual[0].text).digest('hex').slice(0,12),
          clear:events.some(event=>event.text===displayText),outgoing:expected.length,received:actual.length,
          typingDone:frames.some(frame=>frame.raw?.includes('@+typing=done'))};
      };
      const dismissKeyWarning=async(device,conn,nickname)=>{
        const slot=`_e2eDmKey(${q(nickname)},${q(conn)})`;
        await waitFor(()=>device.evaluate(`(()=>{
          const expected=E2E.trustStore[${slot}];
          if(!E2E._kcOpen?.[${slot}]||!expected?.pendingFingerprint)return false;
          const warning=[...document.body.children].find(element=>{
            const message=element.firstElementChild?.firstElementChild?.textContent||'';
            return message.startsWith('⚠️ KEY CHANGE WARNING')&&message.includes(${q('Someone using the nick '+nickname+' ')})&&
              message.includes(expected.fingerprint)&&message.includes(expected.pendingFingerprint);
          });
          const button=warning?.querySelector('button');
          if(button?.textContent!=='OK')return false;
          button.dataset.auditKeyWarning='';return true;
        })()`),'both expected fingerprints appear in the changed-key warning');
        await clickVisible(device,'[data-audit-key-warning]');
        await waitFor(()=>device.evaluate(`!E2E._kcOpen?.[${slot}]`),'key-change warning dismissed through its visible control');
      };
      const confirmed=async(device,conn,nickname,action)=>{
        if(action!=='reset-identity')await dismissKeyWarning(device,conn,nickname);
        await device.evaluate(`(()=>{
          const handle=handleEncryptCommand, native=window.confirm;
          const pin=E2E.trustStore[_e2eDmKey(${q(nickname)},${q(conn)})];
          const result={done:false,error:null};window.auditIdentityCommand=result;
          handleEncryptCommand=async(args,...rest)=>{
            if(args[0]!==${q(action)}||args[1]!==${q(nickname)}||rest[0]!==${q(conn)})return handle(args,...rest);
            handleEncryptCommand=handle;
            window.confirm=message=>{
              const expected=${q(action)}==='reset-identity'?message.startsWith('Create a NEW E2E identity?'):
                message.includes(${q('Accept a NEW identity key for '+nickname+'?')})&&
                  message.includes(pin?.fingerprint)&&message.includes(pin?.pendingFingerprint);
              if(!expected)throw new Error('The identity action asked an unexpected confirmation');
              return native.call(window,message);
            };
            try{return await handle(args,...rest);}
            catch(error){result.error=error.message;throw error;}
            finally{window.confirm=native;result.done=true;}
          };
        })()`);
        const command=compose(device,conn,nickname,`/encrypt ${action} ${nickname}`);
        void command.catch(()=>{});
        if(action!=='reject')await waitFor(async()=>{
          try{await device.send('Page.handleJavaScriptDialog',{accept:true});return true;}
          catch(error){if(/no dialog is showing/i.test(error.message))return false;throw error;}
        },'native explicit identity confirmation is answered');
        await command;
        const result=await waitFor(()=>device.evaluate('window.auditIdentityCommand?.done&&window.auditIdentityCommand'),
          'the requested identity command finishes');
        if(result.error)throw new Error(result.error);
      };
      if (process.env.CRYPTIRC_TEST_IDENTITY_SIX==='1') {
        await checkSixContactIdentityReset(browser,networkA,remote,()=>confirmed(browser,networkA,remote,'reset-identity'),check);
        return;
      }
      const ownReset=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='identity-reset';
      const atPeer=remoteWs.events.length, atOwner=ownerWs.events.length;
      if(onboardingWindowEnds>Date.now()) await new Promise(resolve=>setTimeout(resolve,onboardingWindowEnds-Date.now()));
      if (['1','on'].includes(process.env.CRYPTIRC_TEST_IDENTITY_CLOSED_SIBLING)) {
        const activation = process.env.CRYPTIRC_TEST_IDENTITY_CLOSED_SIBLING==='on' ? 'on' : 'restart';
        const tryHistorySync = process.env.CRYPTIRC_TEST_DEVICE_HISTORY_SYNC==='1';
        const previous = await revision(phone);
        await browser.evaluate(`(() => {
          const request = _e2eReq;
          _e2eReq = async (message, ...args) => {
            if (message.type === 'e2e_close_session' && message.partner === ${key}) {
              _e2eReq = request;
              await new Promise(resolve => { window.resumeFixtureRetirement = resolve; });
            }
            return request(message, ...args);
          };
        })()`);
        const reset = confirmed(browser,networkA,remote,'reset-identity');
        void reset.catch(() => {});
        await waitFor(() => browser.evaluate('!!window.resumeFixtureRetirement'),
          'the owner prepares a real close after publishing its new identity');
        const replacement = await browser.evaluate('_e2eOwnFingerprint()');
        try {
          await waitFor(() => phone.evaluate(`E2E.identityReady && ${session}?._unusable &&
            ${session}._storeRevision === ${q(previous)} && _e2eOwnFingerprint().then(fp => fp === ${q(replacement)})`),
            'the phone adopts its new identity while retaining the real previous-session revision');
        } finally {
          await browser.evaluate('window.resumeFixtureRetirement()');
          await reset;
        }
        const staleSibling = await phone.evaluate(`!!${session}?._unusable && ${session}?._storeRevision === ${q(previous)}`);
        check('the account really retired the session while the open phone still remembers its old revision',
          !!previous && !await revision(browser) && staleSibling);
        if(tryHistorySync) await browser.close();
        const start = phone.frames.length;
        await compose(phone,networkA,remote,'/encrypt '+activation+' '+remote);
        await waitFor(() => phone.evaluate(`!!${session}?.x3dhPending && !_sendLock`),
          'the affected phone prepares the first replacement without repeating the command',45000);
        const creates = phone.frames.slice(start).map(JSON.parse).filter(frame =>
          frame.type === 'e2e_commit_session' && frame.create);
        check('the first explicit command created the genuinely absent session using its authenticated retirement floor',
          creates.length === 1 && creates[0].expect === '' && !!creates[0].floor_expect);

        const first = 'restarted by sibling '+stamp;
        const outboundStart = phone.frames.length, inboundStart = remoteWs.events.length;
        await submit(phone,networkA,remote,first);
        await waitFor(async () => await pending(peer,peerKey) === replacement,
          'the independent contact sees the newly established owner identity');
        await confirmed(peer,remoteNetwork,owner,'accept');
        await waitFor(() => row(peer,remoteNetwork,owner,first),'the contact reads the phone message after explicit fingerprint approval',45000);
        const forward = relayed(phone,outboundStart,remoteWs,inboundStart,remoteNetwork,first);
        const answer = 'approved sibling reply '+stamp;
        const replyStart = peer.frames.length, receiverStart = ownerWs.events.length;
        await waitFor(() => peer.evaluate('!_sendLock'),'the peer composer is ready after confirming');
        await submit(peer,remoteNetwork,owner,answer);
        await waitFor(() => row(phone,networkA,remote,answer),'the initiating phone reads the new encrypted response',45000);
        const reply = relayed(peer,replyStart,ownerWs,receiverStart,networkA,answer);
        check('both first messages crossed independent servers once and encrypted after that one phone command',
          [forward,reply].every(result => result.outgoing === 1 && result.received === 1 && !result.clear));
        if(tryHistorySync){
          const wire=peer.frames.slice(replyStart).map(JSON.parse).find(f=>
            f.type==='send'&&f.conn_id===remoteNetwork&&f.raw?.startsWith('PRIVMSG '+owner+' :[e2edm2]'))?.raw.split(' :')[1];
          check('the reply reached only the open owner device while the resetting browser was closed',!!wire);
          const saved=`(async()=>{const line={from:${nick},text:${q(wire)}};
            return (await e2eReadDmHistory(${cid},${nick},[line],{cachedOnly:true})).get(line)===${q(answer)};})()`;
          await waitFor(()=>phone.evaluate(saved),'the phone stores a locally sealed copy of the exact reply');
          await phone.evaluate(`(()=>{
            const reconnect=connectWs;
            window.reconnectHistoryFixture=()=>{connectWs=reconnect;connectWs();};
            connectWs=()=>{};
            _deviceLockNow(false);
            ws.close();
          })()`);
          await waitFor(()=>phone.evaluate('!_wsReady()&&encryptionDeviceLocked()&&!E2E.keyReady'),
            'the source device is offline with its encryption locked');

          const desktop=await browser.reopen();
          const unlocked=`_wsReady()&&E2E.keyReady&&E2E._bootPhase==='ready'&&!E2E._resyncPending`;
          const found=`getBuf(${cid},${nick}).filter(m=>m._dmHistoryWire===${q(wire)})`;
          await waitFor(()=>desktop.evaluate(unlocked),'resetting computer reopens with its remembered key');
          await desktop.evaluate(`setActive(${cid},${nick})`);
          await waitFor(()=>desktop.evaluate(`${found}.some(m=>m._dmHistoryState==='unavailable')`),
            'the exact missed reply has no readable copy on the reopened computer');
          const requests=()=>desktop.frames.map(JSON.parse).filter(f=>f.type==='e2e_history_sync'&&f.kind==='request');
          await waitFor(()=>requests().length,'the visible missed history requests a sibling copy');
          const unrelated=await chromium('device-history-isolation');
          await login(unrelated,otherWs.events.find(e=>e.type==='auth_ok').username,password,waitFor);
          await unrelated.evaluate(`(()=>{
            const handle=e2eHandleEvent;window.historySyncObserved=[];
            e2eHandleEvent=async ev=>{
              if(ev.type==='e2e_history_sync')historySyncObserved.push(ev.id);
              return handle(ev);
            };
          })()`);
          const source=phone;
          await source.evaluate('window.reconnectHistoryFixture()');
          await waitFor(()=>source.evaluate('_wsReady()&&encryptionDeviceLocked()&&!E2E.keyReady'),
            'the phone is online with its encryption still locked');
          await source.evaluate(`(()=>{
            const handle=handleEvent;window.lockedHistoryRequests=[];
            handleEvent=ev=>{
              if(ev.type==='e2e_history_sync'&&ev.kind==='request')lockedHistoryRequests.push(ev.id);
              return handle(ev);
            };
          })()`);
          const fromRequest=requests().length;
          await desktop.evaluate('requestVisibleDmHistorySync(true)');
          await waitFor(()=>requests().length>fromRequest,'the unlocked computer retries while the source is online and locked');
          const requestWhileLocked=requests().at(-1).id;
          await waitFor(()=>source.evaluate(`lockedHistoryRequests.includes(${q(requestWhileLocked)})`),
            'the locked source receives the sealed request');
          check('an offline or locked source leaves the history unreadable and sends no reply',
            !await row(desktop,networkA,remote,answer)&&
            !source.frames.some(frame=>{const f=JSON.parse(frame);return f.type==='e2e_history_sync'&&f.kind==='reply';}));

          // Exercise selection when an earlier copy with the same wire is already readable.
          await desktop.evaluate(`(()=>{
            const buffer=getBuf(${cid},${nick}),index=buffer.findIndex(m=>m._dmHistoryWire===${q(wire)});
            window.knownHistoryFixture={...buffer[index],text:'Already opened on this device',_dmHistoryState:'ready'};
            buffer.splice(index,0,knownHistoryFixture);
          })()`);

          await unlockVault(source,vault);
          await waitFor(()=>source.evaluate('!encryptionDeviceLocked()&&E2E._vaultUp&&E2E._krReceived&&!E2E._booting'),
            'the phone unlocks its vault and reads its encryption keyring');
          if(!await source.evaluate('E2E.keyReady')){
            await source.evaluate('void e2ePromptDeviceUnlock()');
            await waitPrompt(source,waitFor,unlockText);
            await fillPrompt(source,ownerCode);
          }
          await waitFor(()=>source.evaluate(unlocked),'the source unlocks and announces its availability');
          await waitFor(()=>desktop.evaluate(`${found}.some(m=>m._dmHistoryState==='ready'&&m._dmHistoryDeviceCopy&&
            m.encrypted&&m.text===${q(answer)})`),'the original history row opens after the phone unlocks',25000);
          check('a device reply fills the missing row without replacing an already readable copy',
            await desktop.evaluate(`knownHistoryFixture.text==='Already opened on this device'&&!knownHistoryFixture._dmHistoryDeviceCopy&&
              ${found}.filter(m=>m.text===${q(answer)}).length===1&&document.getElementById('chat-area').textContent.includes('Synced copy')`));
          await desktop.evaluate(`(()=>{const buffer=getBuf(${cid},${nick});buffer.splice(buffer.indexOf(knownHistoryFixture),1);
            delete window.knownHistoryFixture;renderChat();})()`);
          const transfers=()=>[...desktop.frames,...source.frames].filter(frame=>frame.includes('"type":"e2e_history_sync"'));
          const requestIds=()=>new Set(requests().map(request=>request.id));
          await waitFor(()=>transfers().map(JSON.parse).some(f=>f.kind==='reply'&&requestIds().has(f.id)),
            'DevTools captures the sealed response to this computer’s request');
          const foreign=(observer)=>observer.events.some(e=>e.type==='e2e_history_sync'&&requestIds().has(e.id));
          check('the sealed handoff is visible only to supported browsers on the owner account',
            transfers().every(frame=>!frame.includes(answer)&&!frame.includes(wire)&&JSON.parse(frame).blob.startsWith('e2e3.'))&&
            !foreign(ownerWs)&&!foreign(otherWs)&&!foreign(remoteWs)&&
            await unrelated.evaluate(`!historySyncObserved.some(id=>${q([...requestIds()])}.includes(id))`));
          await unrelated.close();
          await waitFor(()=>desktop.evaluate(saved),'the restored reply is sealed in the computer’s local history');
          await source.close();
          await desktop.close();
          const again=await desktop.reopen();
          await waitFor(()=>again.evaluate(unlocked),'the computer reopens again with the source offline');
          await again.evaluate(`setActive(${cid},${nick})`);
          check('the restored reply reopens as a synced copy from the computer’s sealed cache',
            await waitFor(()=>again.evaluate(`${found}.length===1&&${found}[0]._dmHistoryDeviceCopy&&${found}[0].text===${q(answer)}`),
              'the locally saved reply reopens with its sync label'));
        }
        return;
      }
      if (process.env.CRYPTIRC_TEST_DELAYED_OFFER === '1') {
        const previous = await phone.evaluate('_e2eOwnFingerprint()');
        const previousSession = await phone.evaluate(session+'.startEph');
        await compose(phone, networkA, remote, '/encrypt restart '+remote);
        await waitFor(() => phone.evaluate(`!!${session}?.x3dhPending && ${session}.startEph!==${q(previousSession)}`),'phone prepared an ordinary new first contact');
        await phone.evaluate(`(() => {
          if (_rateQueue.length) throw new Error('test expected empty outgoing queue');
          const send = drainRateQueue; drainRateQueue = () => {};
          window.resumeOfferQueue = () => { drainRateQueue = send; _kickRateQueue(); };
        })()`);
        const delayed = 'phone draft before deliberate reset '+stamp;
        await compose(phone,networkA,remote,delayed);
        const lines = await waitFor(()=>phone.evaluate(`(() => {
          const values = _rateQueue.map(m=>m.raw?.split(' :')[1]).filter(Boolean);
          const offers = values.filter(t=>t.startsWith('[e2ex3dh]'));
          return offers.length && values.some(t=>t.startsWith('[e2edm2]')) && offers;
        })()`),'ordinary sender has queued its own genuine public offer and first message');
        await confirmed(browser,networkA,remote,'reset-identity');
        const replacement=await browser.evaluate('_e2eOwnFingerprint()');
        check('the user completed an identity reset with the older phone send still queued',replacement!==previous);
        await compose(browser,networkA,remote,'/encrypt restart '+remote);
        await waitFor(()=>browser.evaluate(`!!${session}?.x3dhPending && !_sendLock`),'origin readies the new identity');
        const hello='origin starts a replacement conversation '+stamp;
        await submit(browser,networkA,remote,hello);
        await waitFor(async()=>await pending(peer,peerKey)===replacement,'contact can confirm the new fingerprint');
        await confirmed(peer,remoteNetwork,owner,'accept');
        await waitFor(()=>row(peer,remoteNetwork,owner,hello),'contact reads a message from the new identity',45000);
        const answer='acknowledge current conversation '+stamp;
        await submit(peer,remoteNetwork,owner,answer);
        await waitFor(()=>row(browser,networkA,remote,answer),'origin receives the reply',45000);
        const start=remoteWs.events.length;
        await phone.evaluate('window.resumeOfferQueue()');
        await waitFor(()=>phone.evaluate('!_rateQueue.length&&!_rateDmRetry'),'the ordinary paced queue drained',45000);
        await new Promise(resolve=>setTimeout(resolve,2200));
        const events=remoteWs.events.slice(start).filter(e=>e.conn_id===remoteNetwork&&e.from===owner);
        const oldOffers=events.filter(e=>lines.includes(e.text)).length;
        const peerState=await peer.evaluate(`({matches:E2E.trustStore[${peerKey}]?.fingerprint===${q(replacement)},changed:!!E2E.trustStore[${peerKey}]?.keyChanged,
          oldOffered:E2E.trustStore[${peerKey}]?.pendingFingerprint===${q(previous)}})`);
        console.log('PACED-PUBLIC-OFFER '+JSON.stringify({fragments:lines.length,oldOffers,
          draftOpened:await row(peer,remoteNetwork,owner,delayed),clear:events.some(e=>e.text===delayed),...peerState}));
        check('old queued public setup cannot put a previously accepted contact back into changed-key state',oldOffers===0 && !await row(peer,remoteNetwork,owner,delayed) && !events.some(e=>e.text===delayed) &&
          peerState.matches && !peerState.changed && !peerState.oldOffered);
        return;
      }
      if (process.env.CRYPTIRC_TEST_TWO_CLOSE_REPLIES === '1') {
        const initialStart=await phone.evaluate(session+'.startEph');
        await phone.evaluate(`(() => {
          const dispatch=e2eHandleEvent;
          const a=window.offReplyObservation={answers:[],restore:()=>{e2eHandleEvent=dispatch;}};
          e2eHandleEvent=event=>{
            if(event.type==='e2e_session_closed'&&event.partner===${key}&&a.answers.length<2){
              a.answers.push({accepted:event.ok,conflict:event.conflict!==undefined});return;
            }
            return dispatch(event);
          };
        })()`);
        await compose(phone,networkA,remote,'/encrypt off');
        try{
          await waitFor(()=>phone.evaluate(`offReplyObservation.answers.length===2 && !_sendLock &&
            getBuf(${cid},${nick}).some(m=>m.text.includes('Could not confirm session removal'))`),'both genuine close replies are unavailable and the phone reports the failure',45000);
        }finally{await phone.evaluate('offReplyObservation.restore()');}
        const before=await phone.evaluate(`({lost:offReplyObservation.answers.length,local:!!${session},repair:E2E._sessionSyncRepair.has(${key})})`);
        check('the independent account really has no live slot after both replies were lost',!await revision(browser));
        const mark=phone.frames.length;
        await compose(phone,networkA,remote,'/encrypt restart '+remote);
        const usable=await waitFor(()=>phone.evaluate(`!!${session}?.x3dhPending&&${session}.startEph!==${q(initialStart)}&&!_sendLock`),'single restart after two lost replies',18000).catch(()=>false);
        const creates=phone.frames.slice(mark).map(JSON.parse).filter(f=>f.type==='e2e_commit_session'&&f.create);
        let received=false,reply=false;
        if(usable){
          const a='resumed phone after lost acknowledgements '+stamp,b='received your recovered message '+stamp;
          await submit(phone,networkA,remote,a);
          received=!!await waitFor(()=>row(peer,remoteNetwork,owner,a),'independent contact reads the recovered message');
          await submit(peer,remoteNetwork,owner,b);
          reply=!!await waitFor(()=>row(phone,networkA,remote,b),'phone reads the reply after the restart');
        }
        console.log('LOST-CLOSE-RESTART '+JSON.stringify({...before,usable,creates:creates.length,expectedEmpty:creates[0]?.expect==='',checkedFloor:!!creates[0]?.floor_expect,received,reply}));
        check('the very first restart after losing both close replies restores a readable exchange',usable && received && reply && creates.length===1 && creates[0].expect==='' && !!creates[0].floor_expect);
        return;
      }
      if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='identity-reset-refused'){
        const prior=await browser.evaluate('_e2eOwnFingerprint()');
        const oldStart=await browser.evaluate(`${session}.startEph`);
        const oldRevision=await revision(browser);
        check('the remote contact pins the original account identity before reset',!!oldStart&&!!oldRevision&&await pin(peer,peerKey)===prior);
        await browser.evaluate(`(()=>{
          const request=_e2eReq;
          const audit={refused:false};window.auditResetClose=audit;
          _e2eReq=async(message,...args)=>{
            if(message.type!=='e2e_close_session'||message.partner!==${key})return request(message,...args);
            _e2eReq=request;
            await new Promise(resolve=>{audit.release=resolve;});
            const reply=await request(message,...args);
            audit.refused=reply?.type==='e2e_session_closed'&&reply.req===message.req&&reply.partner===message.partner&&
              reply.ok===false&&reply.conflict===undefined;
            return reply;
          };
        })()`);
        const reset=confirmed(browser,networkA,remote,'reset-identity');
        void reset.catch(()=>{});
        await waitFor(()=>browser.evaluate('!!window.auditResetClose.release'),'new own identity published and its conditional close prepared');
        const replacement=await browser.evaluate('_e2eOwnFingerprint()');
        check('the confirmed reset published a new account identity before retirement',replacement!==prior);
        const floor=path.join(path.dirname(remoteData),'e2e',owner,'session-close-floor.enc');
        const saved=floor+'-fixture-'+crypto.randomUUID();
        const found=await fs.lstat(floor).catch(error=>{if(error.code!=='ENOENT')throw error;return null;});
        if(found&&!found.isFile())throw new Error('unexpected fixture floor file type');
        if(found)await fs.rename(floor,saved);
        let placed=false;
        try{
          await fs.mkdir(floor);placed=true;
          await browser.evaluate('window.auditResetClose.release()');
          await reset;
          check('the server denied retirement of the old ratchet after the account identity changed',
            await browser.evaluate('window.auditResetClose.refused'));
        }finally{
          if(placed)await fs.rmdir(floor);
          if(found)await fs.rename(saved,floor);
        }
        check('the account still holds the exact old sealed revision after the failed close',await revision(browser)===oldRevision);
        const attempt=async (label,device=browser)=>{
          const text='held '+label+' '+stamp;
          const senderAt=device.frames.length, peerAt=remoteWs.events.length;
          await device.evaluate(`(()=>{
            const handle=handleInput,note=_e2eNoteWires;
            const audit={done:false,oldWires:[]};window.auditResetSend=audit;
            _e2eNoteWires=(wires,meta)=>{
              if(meta.mode==='dm'&&meta.k===${key}&&meta.startEph===${q(oldStart)})audit.oldWires.push(...wires);
              return note(wires,meta);
            };
            handleInput=async(value,...args)=>{
              if(value!==${q(text)})return handle(value,...args);
              handleInput=handle;
              try{return await handle(value,...args);}
              finally{audit.done=true;_e2eNoteWires=note;}
            };
          })()`);
          await submit(device,networkA,remote,text);
          await waitFor(()=>device.evaluate('window.auditResetSend.done'),'the real composer processes the ordinary draft',45000);
          const oldWires=await device.evaluate('auditResetSend.oldWires');
          const submits=()=>device.frames.slice(senderAt).map(JSON.parse).filter(frame=>frame.type==='send'&&
            frame.conn_id===networkA&&oldWires.includes(frame.raw?.split(' :')[1]));
          await waitFor(()=>device.evaluate('!_rateQueue.length'),'sender drains its ordinary send queue');
          const oldSent=submits().length;
          if(oldSent){
            await waitFor(()=>remoteWs.events.slice(peerAt).some(event=>event.type==='irc_message'&&event.conn_id===remoteNetwork&&
              event.from===owner&&oldWires.includes(event.text)),'linked IRC independently receives the old-session ciphertext');
            await waitFor(()=>row(peer,remoteNetwork,owner,text),'the prior pinned contact opens the received message',10000).catch(()=>false);
          }
          const seen=relayed(device,senderAt,remoteWs,peerAt,remoteNetwork,text);
          return {oldSent,emitted:seen.outgoing,received:seen.received,clear:seen.clear,
            draftRetained:await device.evaluate(`document.getElementById('msg-input').value===${q(text)}`),
            readBeforeApproval:await row(peer,remoteNetwork,owner,text)&&await pin(peer,peerKey)===prior,
            wire:seen.wire||null};
        };
        if (process.env.CRYPTIRC_TEST_IDENTITY_IMMEDIATE!=='1') {
          const current=await attempt('current');
          const sibling=await attempt('sibling',phone);
          await reopen(browser,waitFor,"window._appShown&&_wsReady()&&E2E._bootPhase==='ready'&&E2E.identityReady",
            'owner reopens with the replacement identity and its remembered unlock');
          check('the reopened browser still uses the newly published identity',await browser.evaluate('_e2eOwnFingerprint()')===replacement);
          const reopened=await attempt('reopened');
          console.log('IDENTITY-RESET-REFUSAL '+JSON.stringify({current,reopened,sibling}));
          check('ordinary sends after a refused identity retirement never reuse the old identity before or after reload',
            [current,reopened].every(result=>!result.oldSent&&!result.readBeforeApproval&&!result.clear&&result.draftRetained));
          check('a second open device also holds its message after its account identity was retired',
            !sibling.oldSent&&!sibling.received&&!sibling.readBeforeApproval&&!sibling.clear&&sibling.draftRetained);
        }
        await compose(browser,networkA,remote,'/encrypt restart '+remote);
        await waitFor(()=>browser.evaluate(`!!${session}?.x3dhPending&&${session}.startEph!==${q(oldStart)}`),
          'owner starts a genuine session with the replacement identity',45000);
        const first='renewed '+stamp;
        const from=browser.frames.length, at=remoteWs.events.length;
        await submit(browser,networkA,remote,first);
        await waitFor(async()=>await pending(peer,peerKey)===replacement,'contact sees the authenticated new account identity');
        await confirmed(peer,remoteNetwork,owner,'accept');
        await waitFor(()=>row(peer,remoteNetwork,owner,first),'contact opens the fresh message after explicitly approving the replacement',45000);
        const resumed=relayed(browser,from,remoteWs,at,remoteNetwork,first);
        check('a deliberate restart and contact approval restore encrypted delivery after the failed retirement',
          await pin(peer,peerKey)===replacement&&resumed.outgoing===1&&resumed.received===1&&!resumed.clear);
        const answer='confirmed '+stamp;
        const replyFrom=peer.frames.length, replyAt=ownerWs.events.length;
        await submit(peer,remoteNetwork,owner,answer);
        await waitFor(()=>row(browser,networkA,remote,answer),'resetting account opens the reply in the new session',45000);
        const replied=relayed(peer,replyFrom,ownerWs,replyAt,networkA,answer);
        check('the recovered account reads the independently relayed reply under its new identity',
          replied.outgoing===1&&replied.received===1&&!replied.clear);
        await waitFor(async()=>await row(phone,networkA,remote,first)&&await row(phone,networkA,remote,answer),
          'the still-open sibling reads both directions after the deliberate identity recovery',45000);
        const third='sibling recovered '+stamp;
        const siblingFrom=phone.frames.length, siblingAt=remoteWs.events.length;
        await submit(phone,networkA,remote,third);
        await waitFor(()=>row(peer,remoteNetwork,owner,third),'the independent contact reads the recovered sibling message',45000);
        const siblingSend=relayed(phone,siblingFrom,remoteWs,siblingAt,remoteNetwork,third);
        check('the recovered sibling sends its own fresh message without another login or user approval',
          siblingSend.outgoing===1&&siblingSend.received===1&&!siblingSend.clear);
        return;
      }
      let before,after,oldDelete,acceptError=null;
      if(ownReset){
        const prior=await browser.evaluate('_e2eOwnFingerprint()');
        const previousEpoch=await browser.evaluate(`${session}.epoch`);
        await browser.evaluate(`(()=>{
          const generate=e2eGenerateAndPublishIdentity;
          e2eGenerateAndPublishIdentity=async (...args)=>{
            try { await generate(...args);await new Promise(resolve=>{window.auditIdentityRelease=resolve;}); }
            finally { e2eGenerateAndPublishIdentity=generate; }
          };
        })()`);
        const at=browser.frames.length;
        const reset=confirmed(browser,networkA,remote,'reset-identity');
        void reset.catch(()=>{});
        try {
          await waitFor(()=>browser.evaluate('!!window.auditIdentityRelease'),'original device publishes replacement identity before cleanup');
          const replacement=await browser.evaluate('_e2eOwnFingerprint()');
          check('the account generated a genuinely different identity',replacement!==prior);
          const fresh=await chromium('signal-audit-rotated-device');
          await login(fresh,owner,password,waitFor);
          await waitFor(()=>fresh.evaluate('E2E._vaultUp&&E2E._krReceived'),'the next device discovers the existing account keyring');
          await fresh.evaluate('void e2ePromptDeviceUnlock()');
          await waitPrompt(fresh,waitFor,unlockText);
          await fillPrompt(fresh,ownerCode);
          await waitFor(()=>fresh.evaluate(`E2E.identityReady&&_wsReady()&&_e2eOwnFingerprint().then(fp=>fp===${q(replacement)})`),
            'fresh device authenticates the new account identity');
          await compose(fresh,networkA,remote,'/encrypt restart '+remote);
          await waitFor(()=>fresh.evaluate(`!!${session}?.x3dhPending`),'fresh device prepares its replacement session',45000);
          check('a fresh device numbers the replacement above the retired session',
            await fresh.evaluate(`${session}.epoch`)>previousEpoch);
          const first='new account identity before first device cleanup '+stamp;
          await compose(fresh,networkA,remote,first);
          await waitFor(async()=>await pending(peer,peerKey)===replacement,'linked peer sees genuine new account identity');
          await confirmed(peer,remoteNetwork,owner,'accept');
          await waitFor(()=>row(peer,remoteNetwork,owner,first),'peer opens the held new-identity message');
          before=await revision(fresh);
          await browser.evaluate('window.auditIdentityRelease()');
          await reset;
          after=await revision(fresh);
        } finally { await browser.evaluate('window.auditIdentityRelease?.();delete window.auditIdentityRelease'); }
        oldDelete=browser.frames.slice(at).some(frame=>JSON.parse(frame).type==='e2e_delete_session');
      } else {
        const previous=await pin(phone,key);
        const rejecter=await chromium('signal-audit-reject-device');
        await login(rejecter,owner,password,waitFor);
        await waitFor(()=>rejecter.evaluate('E2E._vaultUp&&E2E._krReceived'),'the rejecting device discovers the existing keyring');
        await rejecter.evaluate('void e2ePromptDeviceUnlock()');
        await waitPrompt(rejecter,waitFor,unlockText);
        await fillPrompt(rejecter,ownerCode);
        await waitFor(()=>rejecter.evaluate(`!!(${ready})`),'the rejecting device restores the prior session');
        await confirmed(peer,remoteNetwork,owner,'reset-identity');
        const replacement=await peer.evaluate('_e2eOwnFingerprint()');
        await compose(peer,remoteNetwork,owner,'/encrypt on '+owner);
        await waitFor(()=>peer.evaluate(`!!E2E.dmSessions[${peerKey}]?.x3dhPending`),'peer establishes from the new public identity',45000);
        const first='message under the replacement peer identity '+stamp;
        await compose(peer,remoteNetwork,owner,first);
        await waitFor(async()=>await pending(browser,key)===replacement&&await pending(phone,key)===replacement&&
          await pending(rejecter,key)===replacement,'all devices show the same genuine changed peer identity');
        await confirmed(rejecter,networkA,remote,'reject');
        check('reject keeps the previous identity pin and does not open a held replacement message',
          !await pending(rejecter,key)&&await pin(rejecter,key)===previous&&!await row(rejecter,networkA,remote,first));
        await confirmed(browser,networkA,remote,'accept');
        await waitFor(()=>row(browser,networkA,remote,first),'first device approves the replacement and opens the held message');
        check('second device continues to show its unapproved replacement until the user accepts',
          await pin(phone,key)===previous&&await pending(phone,key)===replacement);
        before=await revision(browser);
        const at=phone.frames.length;
        try { await confirmed(phone,networkA,remote,'accept'); }
        catch(error) {
          if(!error.message.includes('E2E_OTPK_MISSING')) throw error;
          acceptError='already consumed one-time prekey';
        }
        after=await revision(browser);
        oldDelete=phone.frames.slice(at).some(frame=>JSON.parse(frame).type==='e2e_delete_session');
        check('the second device uses exactly the expressly approved replacement pin',await pin(phone,key)===replacement);
      }
      console.log('IDENTITY-CAS '+JSON.stringify({ownReset,acceptedBeforeCleanup:!!before,revisionPreserved:before===after,oldDelete,acceptError}));
      check('late identity cleanup preserves the exact already-confirmed replacement revision',!!before&&before===after&&!oldDelete&&!acceptError);
      const finalText='encrypted after identity cleanup '+stamp;
      const forwardAt=browser.frames.length, remoteAt=remoteWs.events.length;
      await submit(browser,networkA,remote,finalText);
      let forward=false;
      try { await waitFor(()=>row(peer,remoteNetwork,owner,finalText),'peer opens message after identity cleanup',45000); forward=true; }
      finally { console.log('IDENTITY-FORWARD '+JSON.stringify(relayed(browser,forwardAt,remoteWs,remoteAt,remoteNetwork,finalText))); }
      const sent=relayed(browser,forwardAt,remoteWs,remoteAt,remoteNetwork,finalText);
      check('the original device can continue sending with the confirmed replacement session',
        forward&&sent.outgoing===1&&sent.received===1&&
        ![...remoteWs.events.slice(atPeer),...ownerWs.events.slice(atOwner)].some(event=>event.text===finalText));
      const answer='encrypted reply after identity cleanup '+stamp;
      const replyAt=peer.frames.length, ownAt=ownerWs.events.length;
      await submit(peer,remoteNetwork,owner,answer);
      let replied=false;
      try { await waitFor(()=>row(browser,networkA,remote,answer),'original device opens reply after identity cleanup',45000); replied=true; }
      finally { console.log('IDENTITY-REPLY '+JSON.stringify(relayed(peer,replyAt,ownerWs,ownAt,networkA,answer))); }
      const returned=relayed(peer,replyAt,ownerWs,ownAt,networkA,answer);
      check('the original device opens the peer reply after late identity cleanup',
        replied&&returned.outgoing===1&&returned.received===1&&!ownerWs.events.slice(atOwner).some(event=>event.text===answer));
      return;
    }
    if(interruptedCloseTest){
      const stale=await chromium('signal-audit-closed-stale');
      await login(stale,owner,password,waitFor);
      await waitFor(()=>stale.evaluate('E2E._vaultUp&&E2E._krReceived'),'third device discovers its account keyring');
      await stale.evaluate('void e2ePromptDeviceUnlock()');
      await waitPrompt(stale,waitFor,unlockText);
      await fillPrompt(stale,ownerCode);
      await waitFor(()=>stale.evaluate(`!!(${ready})`),'third device restores the old Signal ratchet');
      const epoch=device=>device.evaluate(`${session}?.epoch`);
      const resumeParent=duplicateCloseTest && process.env.CRYPTIRC_TEST_REACTION_RESUME==='1' &&
        process.env.CRYPTIRC_TEST_INBOUND_RESUME==='1' ? await prepareResumeReaction({stale,peer,networkA,remote,remoteNetwork,owner,stamp,compose,waitFor}) : null;
      const initial=await epoch(stale), desktopPage=await browser.evaluate('performance.timeOrigin');
      const partner=await browser.evaluate(key);
      const submit=async(device,connection,target,text)=>{
        await device.evaluate(`setActive(${q(connection)},${q(target)});(()=>{
          const input=document.getElementById('msg-input');input.focus();input.select();
        })()`);
        await device.send('Input.insertText',{text});
        await clickVisible(device,'#send-btn');
      };
      const normal={offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1};
      for(const device of [phone,stale]){
        await device.send('Network.emulateNetworkConditions',{...normal,offline:true});
        await device.evaluate('if(ws?.readyState===1)ws.close()');
        await waitFor(()=>device.evaluate('!navigator.onLine&&!_wsReady()'),'one signed-in device is offline');
      }
      const independent='pky'+stamp;
      const {device:secondPeer,id:secondPeerNet}=await createRemote(independent);
      await login(secondPeer,independent,password,waitFor);
      await waitFor(()=>secondPeer.evaluate('E2E._vaultUp&&E2E._krReceived'),'independent peer discovers its account keyring');
      await secondPeer.evaluate(openEncryptionSettings);
      await setUpRecovery(secondPeer,waitFor,check);
      await secondPeer.evaluate('closeEncryptPanel()');
      const independentKey=await browser.evaluate(`_e2eDmKey(${q(independent)},${cid})`);
      const independentSession=()=>browser.evaluate(`(()=>{
        const s=E2E.dmSessions[${q(independentKey)}];
        return s?{epoch:s.epoch,revision:s._storeRevision,start:s.startEph}:null;
      })()`);
      const independentFirst='unrelated active Signal chat before close '+stamp;
      await compose(secondPeer,secondPeerNet,owner,independentFirst);
      await acceptIdentity(secondPeer,waitFor);
      await acceptIdentity(browser,waitFor);
      await waitFor(()=>row(browser,networkA,independent,independentFirst),'desktop accepts the independent Signal session');
      const independentConfirm='desktop confirms its other Signal session '+stamp;
      await submit(browser,networkA,independent,independentConfirm);
      await waitFor(()=>row(secondPeer,secondPeerNet,owner,independentConfirm),'other peer opens a normal encrypted reply before the close');
      const independentBefore=await independentSession();
      for(let i=0;i<4;i++){
        const advance='desktop advances while two devices offline '+i+' '+stamp;
        await compose(browser,networkA,remote,advance);
        await waitFor(()=>row(peer,remoteNetwork,owner,advance),'peer authenticates desktop advance '+i);
      }
      const newest=await epoch(browser);
      check('only the open desktop has advanced the account ratchet',newest>=initial+4&&await epoch(stale)===initial);
      await phone.send('Network.emulateNetworkConditions',normal);
      await waitFor(()=>phone.evaluate('navigator.onLine&&_wsReady()&&E2E.identityReady'),'closing phone reconnects');
      await phone.evaluate(`(()=>{
        const handle=e2eHandleEvent;
        e2eHandleEvent=event=>{
          if(event.type==='e2e_session_closed'&&event.partner===${key}&&event.ok){
            window.interruptedCloseAccepted=true;return;
          }
          return handle(event);
        };
      })()`);
      const phoneAt=phone.frames.length;
      await submit(phone,networkA,remote,'/encrypt off');
      await waitFor(()=>phone.evaluate('!!window.interruptedCloseAccepted'),'real web confirms the close before the phone handles its reply');
      phone.chrome.kill('SIGKILL');
      await waitFor(()=>phone.chrome.signalCode==='SIGKILL','the disposable closing browser stops');
      const closingFrames=phone.frames.slice(phoneAt).map(JSON.parse);
      const requested=closingFrames.findIndex(frame=>frame.type==='e2e_close_session'&&frame.partner===partner&&
        /^[0-9a-f]{64}$/.test(frame.expect));
      const laterState=closingFrames.slice(requested+1).filter(frame=>frame.type==='e2e_store_session'&&frame.partner==='__state__')
        .map(frame=>frame.blob);
      const interrupted=await browser.evaluate(`(async()=>{
        const current=await _e2eRequestSession(${key},true);
        const state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
        const floor=typeof _e2eReadSessionFloor==='function' ? await _e2eReadSessionFloor(current?.floor_blob,currentUser) : null;
        const uploads=await Promise.all(${q(laterState)}.map(_e2eDecodeState));
        return {closed:!!current&&!current.blob,on:state?.dm?.[${key}]?.on,floor:floor?.epoch||0,
          uploadedOff:uploads.some(state=>!state||state.dm?.[${key}]?.on===0)};
      })()`);
      check('the conditional close removes the active record before the phone writes opt-out',
        requested>=0&&interrupted.closed&&interrupted.on===1&&!interrupted.uploadedOff);
      // This check counts a single IRC ciphertext. Multipart drafts are
      // exercised separately through the same composer.
      const independentText='side '+stamp;
      const independentAt=browser.frames.length;
      await submit(browser,networkA,independent,independentText);
      const independentSeen=await waitFor(()=>row(secondPeer,secondPeerNet,owner,independentText),
        'the other peer opens an ordinary live encrypted reply').catch(()=>false);
      const independentAfter=await independentSession();
      const independentWrites=browser.frames.slice(independentAt).map(JSON.parse).filter(frame=>
        frame.type==='e2e_commit_session'&&frame.partner===independentKey);
      const independentContinues=independentSeen&&!!independentBefore?.revision&&independentAfter?.start===independentBefore.start&&
        independentAfter.epoch===independentBefore.epoch+1&&independentAfter.epoch<(interrupted.floor||newest+1)&&
        independentWrites.length===1&&independentWrites[0].expect===independentBefore.revision&&
        !Object.hasOwn(independentWrites[0],'floor_expect');
      if(!independentContinues) console.log('INDEPENDENT-ACTIVE '+JSON.stringify({seen:independentSeen,
        before:independentBefore?.epoch,after:independentAfter?.epoch,floor:interrupted.floor,commits:independentWrites.length,
        sender:await browser.evaluate(`({mode:e2eTargetState(${q(independent)},{conn_id:${cid}}).mode,
          retained:document.getElementById('msg-input').value===${q(independentText)},blocked:!!E2E.lastBlockReason,
          queued:_rateQueue.length})`)}));
      await stale.send('Network.emulateNetworkConditions',normal);
      await waitFor(()=>stale.evaluate('navigator.onLine&&_wsReady()&&E2E.identityReady&&!document.getElementById("msg-input").disabled'),
        'third device reconnects with its original session');
      check('the third device has no authenticated knowledge of the desktop advances',await epoch(stale)===initial);
      let fresh, boundary, overlapFrom, overlapPeer;
      const first='new '+stamp, answer='reply '+stamp;
      if(duplicateCloseTest){
        // Let both actual closes finish. Delay only the second browser's
        // opt-out upload, while a new profile still sees the prior on setting.
        await stale.evaluate(`(()=>{
          const request=_e2eReq, handle=e2eHandleEvent, command=handleEncryptCommand, input=handleInput;
          const audit={acks:0,moves:0,enables:0};window.auditDuplicateClose=audit;
          _e2eReq=async(message,...args)=>{
            const holdRead=${q(process.env.CRYPTIRC_TEST_RESUME_EARLY==='1')}
              ? message.partner==='__state__' && message.resume_peer===${key} : message.partner===${key};
            if(audit.enables===1&&!audit.resumeCheck&&message.type==='e2e_load_session'&&holdRead)
              await new Promise(resolve=>{audit.resumeCheck=resolve;});
            if(message.type==='e2e_store_session'&&message.partner==='__state__'&&!audit.release){
              const state=await _e2eDecodeState(message.blob);
              if(state?.dm?.[${key}]?.on===0) await new Promise(resolve=>{audit.release=resolve;});
            }
            const result=await request(message,...args);
            if(message.type==='e2e_close_session'&&message.partner===${key}&&message.expect===''&&result?.ok) audit.acks++;
            return result;
          };
          e2eHandleEvent=async event=>{
            const result=await handle(event);
            if(audit.acks&&event.type==='e2e_session_moved'&&event.partner===${key}) audit.moves++;
            return result;
          };
          handleEncryptCommand=(args,conn,target)=>{
            if(conn===${cid}&&args[0]==='on'&&args[1]===${nick}) audit.enables++;
            return command(args,conn,target);
          };
          handleInput=async(text,...args)=>{
            if(text!==${q(first)}||!audit.resumeCheck||audit.attemptDone) return input(text,...args);
            try{return await input(text,...args);}finally{audit.attemptDone=true;}
          };
        })()`);
      }
      await submit(stale,networkA,remote,'/encrypt off');
      if(duplicateCloseTest){
        await waitFor(()=>stale.evaluate('auditDuplicateClose.acks===1&&!!auditDuplicateClose.release'),
          'second browser confirms a real close of the absent row and prepares its opt-out');
        const local=await stale.evaluate(`(async()=>{
          const record=await _e2eIdbGet('s:'+currentUser+':'+${key});
          return {marker:E2E._sessionTombstones.get(${key}),idb:record?.del&&record.ep,state:E2E.state.dm[${key}]};
        })()`);
        const canonical=await browser.evaluate(`(async()=>{
          const row=await _e2eRequestSession(${key},true),state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
          return {absent:row.blob==='',on:state?.dm?.[${key}]?.on,floor:(await _e2eReadSessionFloor(row.floor_blob,currentUser)).epoch};
        })()`);
        check('only the second browser has the delayed opt-out and its acknowledged IndexedDB marker',
          canonical.absent&&canonical.on===1&&local.state.on===0&&local.state.closedEpoch===local.marker&&local.idb===local.marker);
        fresh=await chromium('signal-duplicate-close-fresh');
        await login(fresh,owner,password,waitFor);
        await waitFor(()=>fresh.evaluate('E2E._vaultUp&&E2E._krReceived'),'new profile discovers the existing keyring');
        await fresh.evaluate('void e2ePromptDeviceUnlock()');
        await waitPrompt(fresh,waitFor,unlockText);await fillPrompt(fresh,ownerCode);
        await waitFor(()=>fresh.evaluate("E2E.identityReady&&E2E._bootPhase==='ready'&&!E2E._resyncPending&&_wsReady()"),
          'new profile finishes a normal unlock');
        check('the new profile starts with only the account floor and no per-contact ratchet or marker',
          await fresh.evaluate(`!E2E.dmSessions[${key}]&&!E2E._sessionEpoch[${key}]&&!_e2eDev().ep[${key}]&&E2E.state.dm[${key}]?.on===1`));
        if(onboardingWindowEnds>Date.now()) await new Promise(resolve=>setTimeout(resolve,onboardingWindowEnds-Date.now()));
        await submit(fresh,networkA,remote,'/encrypt on '+remote);
        const created=await waitFor(()=>fresh.evaluate(`${session}?.x3dhPending&&${session}.epoch`),
          'a new profile explicitly creates the replacement while the opt-out is delayed',45000);
        await waitFor(()=>stale.evaluate('auditDuplicateClose.moves>0'),'the opted-out browser receives the genuine sibling session notice');
        await stale.evaluate(`_withRatchetLock(${key},async()=>{})`);
        check('the sibling notice does not silently re-enable a conversation the user disabled',
          await stale.evaluate(`E2E.state.dm[${key}]?.on===0&&!${session}?.RK&&auditDuplicateClose.enables===0`));
        boundary={priorFloor:interrupted.floor,floor:canonical.floor,marker:local.marker,idb:local.idb,created};
        console.log('DUPLICATE-CLOSE-BOUNDARY '+JSON.stringify(boundary));
        if (process.env.CRYPTIRC_TEST_INBOUND_RESUME==='1') {
          const ground='ready before deliberate resume '+stamp;
          await waitFor(()=>fresh.evaluate(`!_sendLock&&!E2E._pendingOn?.[${key}]&&e2eTargetState(${nick},{conn_id:${cid}}).mode==='dm'`),'replacement sender is ready');
          await submit(fresh,networkA,remote,ground);
          await waitFor(()=>row(peer,remoteNetwork,owner,ground),'contact reads the replacement before the delayed opt-out is saved');
          await submit(peer,remoteNetwork,owner,ground+' reply');
          await waitFor(()=>row(fresh,networkA,remote,ground+' reply'),'the replacement works both ways before the opt-out arrives');
        }
        await stale.evaluate('auditDuplicateClose.release()');
        // A failed implementation may request a redundant prekey on the
        // second /on. Give it the normal IRC allowance for an independent test.
        onboardingWindowEnds=Date.now()+61000;
      }
      const marker=await waitFor(()=>stale.evaluate(`(async()=>{
        const state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
        return state?.dm?.[${key}]?.on===0&&state.dm[${key}].closedEpoch;
      })()`),'third device writes its explicit authenticated opt-out');
      if(mode==='cold-duplicate-close'){
        const activeSlot=await fresh.evaluate(`_e2eRequestSession(${key},true).then(v=>!!v?.blob)`);
        check('a newer sibling Signal slot and the closer’s later off setting both exist',activeSlot&&boundary.created>marker);
        const coldCloser=async previous=>{
          const device=await previous.relaunch();
          await waitFor(()=>device.evaluate(`window._appShown&&_wsReady()&&E2E.keyReady&&E2E.identityReady&&
            E2E._krReceived&&!E2E._resyncPending`),'remembered closer reopens already unlocked');
          await device.evaluate(`setActive(${cid},${nick})`);
          return device;
        };
        // Observe the provider boundary without sending test text to an external service.
        const observeTranslation=device=>device.evaluate(`(()=>{
          const settings=translationSettings();settings.enabled=true;
          settings.chats[translationChatKey(${cid},${nick})]={outgoing:'es'};
          if(!storeTranslationSettings(settings)) throw Error('Could not enable outgoing translation for test DM');
          window.testTranslationCalls=[];
          requestTranslation=async text=>{testTranslationCalls.push(text);return {text,source:'en'};};
        })()`);
        // The open closer may still have no inventory hint for the new sibling
        // ratchet. Delay its real slot read to cover a preferences flush too.
        const openDraft='open closer private '+stamp,openAt=stale.frames.length;
        await observeTranslation(stale);
        await waitFor(()=>stale.evaluate('!_sendLock'),'the previous opt-out command finished');
        await stale.evaluate(`(()=>{
          const read=_e2eRequestSession;
          _e2eRequestSession=async(partner,floor,...rest)=>{
            if(partner===${key}&&floor){
              _e2eRequestSession=read;
              await new Promise(resolve=>{window.releaseDraftCheck=resolve;});
            }
            return read(partner,floor,...rest);
          };
        })()`);
        await submit(stale,networkA,remote,openDraft);
        await waitFor(()=>stale.evaluate(`!!window.releaseDraftCheck||!!_signalHeldDraftFor(${cid},${nick})`),'open closer checks or holds the new draft');
        await stale.evaluate('flushPrefsToServer()');
        check('the open opt-out device keeps a new draft out of translation and synced history during confirmation',
          await stale.evaluate(`!testTranslationCalls.includes(${q(openDraft)})&&!_histSyncOk.has(${q(openDraft)})`)&&
          !stale.frames.slice(openAt).some(f=>f.includes(openDraft)));
        await stale.evaluate('window.releaseDraftCheck?.()');
        await waitFor(()=>stale.evaluate(`!_sendLock&&!!_signalHeldDraftFor(${cid},${nick})`),'open closer retains the conflicting draft after confirmation');
        const cold=await coldCloser(stale),draft='cold closer '+stamp;
        await observeTranslation(cold);
        const sentAt=cold.frames.length,seenAt=remoteWs.events.length;
        const sent=(device,offset)=>device.frames.slice(offset).map(JSON.parse).filter(f=>
          f.type==='send'&&f.conn_id===networkA&&f.raw.startsWith('PRIVMSG '+remote+' :')).map(f=>f.raw.split(' :')[1])
          .filter(text=>!text.startsWith('[e2ex3dh]'));
        const seen=offset=>remoteWs.events.slice(offset).filter(e=>e.type==='irc_message'&&e.conn_id===remoteNetwork&&e.from===owner).map(e=>e.text);
        await submit(cold,networkA,remote,draft);
        await waitFor(()=>cold.evaluate(`document.getElementById('msg-input').value===${q(draft)}&&getBuf(${cid},${nick}).some(m=>
          m.kind==='error'&&m.text.includes(${q('/encrypt on '+remote)})&&m.text.includes(${q('/encrypt off '+remote)}))`),
          'the unlocked closer keeps the draft and explains both explicit choices');
        check('the cold closer sends no draft to its host or the IRC peer and adds no optimistic sent row',
          sent(cold,sentAt).length===0&&seen(seenAt).every(text=>text!==draft&&!text.startsWith('[e2edm2]'))&&!await row(cold,networkA,remote,draft));
        await waitFor(()=>cold.evaluate('!_sendLock'),'composer accepts the next edit');
        const edited=draft+' edited';
        await submit(cold,networkA,remote,edited);
        await waitFor(()=>cold.evaluate(`!_sendLock&&document.getElementById('msg-input').value===${q(edited)}`),'a correction to the held draft stays in the composer');
        await cold.evaluate('flushPrefsToServer()');
        check('the draft and its correction stay out of synced input history and outgoing translation',
          await cold.evaluate(`[${q(draft)},${q(edited)}].every(t=>_histLocal.has(t)&&!_histSyncOk.has(t)&&!testTranslationCalls.includes(t))`)&&
          !cold.frames.slice(sentAt).some(f=>f.includes(draft)));
        await clickVisible(cold,'#e2e-lock');
        check('the encryption panel describes the saved session and offers to resume or end it',await cold.evaluate(`
          document.getElementById('encrypt-panel-body').textContent.includes(${q('/encrypt on '+remote)})&&
          !!document.querySelector('#encrypt-panel-body [data-encrypt-cmd=on]')&&!!document.querySelector('#encrypt-panel-body [data-encrypt-cmd=off]')`));
        await clickVisible(cold,'#encrypt-panel-body [data-encrypt-cmd=on]');
        await waitFor(()=>cold.evaluate(`e2eTargetState(${nick},{conn_id:${cid}}).mode==='dm'&&!E2E._pendingOn?.[${key}]`),'closer resumes the saved Signal session');
        check('explicit enable preserves the corrected draft',await cold.evaluate(`document.getElementById('msg-input').value===${q(edited)}`));
        await clickVisible(cold,'#encrypt-overlay .encrypt-close');
        await clickVisible(cold,'#send-btn');
        await waitFor(()=>row(peer,remoteNetwork,owner,edited),'independent peer reads the resumed draft');
        const wires=sent(cold,sentAt);
        check('the held draft reaches IRC once as the matching Signal ciphertext',
          wires.length===1&&wires[0].startsWith('[e2edm2]')&&
          await waitFor(()=>seen(seenAt).includes(wires[0]),'independent IRC account receives the resumed ciphertext')&&!seen(seenAt).includes(edited));
        await waitFor(()=>cold.evaluate('!_sendLock'),'composer accepts the explicit disable');
        await submit(cold,networkA,remote,'/encrypt off');
        await waitFor(()=>cold.evaluate(`(async()=>{
          if(E2E.state?.dm?.[${key}]?.on!==0||E2E.dmSessions[${key}])return false;
          const slot=await _e2eRequestSession(${key},true);return slot?.blob===''&&typeof slot.floor_blob==='string';
        })()`),'explicit disable removes the canonical session');
        const off=await coldCloser(cold),plain='confirmed plain '+stamp;
        await observeTranslation(off);
        const plainAt=off.frames.length,plainPeer=remoteWs.events.length;
        await submit(off,networkA,remote,plain);
        await waitFor(()=>seen(plainPeer).includes(plain),'genuinely off PM reaches the independent IRC recipient');
        check('a cold confirmed-off account can intentionally send plaintext once',
          sent(off,plainAt).length===1&&sent(off,plainAt)[0]===plain&&seen(plainPeer).filter(text=>text===plain).length===1&&
          await off.evaluate(`testTranslationCalls.filter(t=>t===${q(plain)}).length===1`));
        const queued='plain before a sibling enables Signal '+stamp;
        await waitFor(()=>off.evaluate('!_sendLock&&!_rateQueue.length'),'confirmed-off composer has finished');
        await off.evaluate(`(()=>{
          const drain=drainRateQueue;drainRateQueue=()=>{};
          window.releasePlainQueue=()=>{drainRateQueue=drain;_kickRateQueue();};
        })()`);
        const queueAt=off.frames.length,queuePeer=remoteWs.events.length;
        await submit(off,networkA,remote,queued);
        await waitFor(()=>off.evaluate(`_rateQueue.some(f=>f.raw==='PRIVMSG '+${nick}+' :'+${q(queued)})`),'genuine plain draft enters the paced queue');
        const sibling=await coldCloser(fresh);
        await submit(sibling,networkA,remote,'/encrypt on '+remote);
        await waitFor(()=>sibling.evaluate(`(async()=>{
          const saved=await _e2eRequestSession(${key},true);
          return !!saved?.blob&&E2E.state.dm[${key}]?.on===1&&!!E2E.dmSessions[${key}]?.RK;
        })()`),'sibling has confirmed an active Signal slot before queue release');
        await off.evaluate('releasePlainQueue()');
        await waitFor(()=>off.evaluate(`!_rateQueue.length&&getBuf(${cid},${nick}).some(m=>m.text===${q(queued)}&&m.sendState==='failed')`),
          'the previous plain send visibly fails after the sibling enables Signal');
        check('the queue rechecks the saved session and releases no plaintext to the sender host or IRC',
          !sent(off,queueAt).includes(queued)&&!seen(queuePeer).includes(queued));
        return;
      }
      if(onboardingWindowEnds>Date.now()) await new Promise(resolve=>setTimeout(resolve,onboardingWindowEnds-Date.now()));
      if(duplicateCloseTest){
        // The panel runs the same /on command while leaving the composer
        // available. Exercise an ordinary Send during its canonical-slot read.
        await stale.evaluate(`setActive(${cid},${nick})`);
        await clickVisible(stale,'#e2e-lock');
        await clickVisible(stale,'#encrypt-panel-body [data-encrypt-cmd="on"]');
        await waitFor(()=>stale.evaluate('!!auditDuplicateClose.resumeCheck'),'explicit enable waits for the canonical session check');
        await clickVisible(stale,'#encrypt-overlay .encrypt-close');
        overlapFrom=stale.frames.length;overlapPeer=remoteWs.events.length;
        await submit(stale,networkA,remote,first);
        await waitFor(()=>stale.evaluate('auditDuplicateClose.attemptDone&&!_sendLock'),'the ordinary send attempt finishes with the session lookup still delayed',20000);
        check('the real composer retains a draft submitted while explicit enable checks the current session',
          await stale.evaluate(`document.getElementById('msg-input').value===${q(first)}`));
        if(process.env.CRYPTIRC_TEST_CANCEL_ENABLE==='1'){
          const before=stale.frames.length;
          await stale.evaluate(`(()=>{const run=handleEncryptCommand,record=_e2eStateSetDm;
            const decision=window.cancelledEnable={off:false,enabled:false};
            handleEncryptCommand=(args,...rest)=>{if(args[0]==='off')decision.off=true;return run(args,...rest);};
            _e2eStateSetDm=(peer,on,...rest)=>{if(decision.off&&peer===${key}&&on)decision.enabled=true;return record(peer,on,...rest);};
          })()`);
          await submit(stale,networkA,remote,'/encrypt off '+remote);
          await waitFor(()=>stale.frames.slice(before).some(frame=>JSON.parse(frame).type==='e2e_load_keyring'),
            'the later disable starts checking the stored keys');
          await stale.evaluate('auditDuplicateClose.resumeCheck()');
          await waitFor(()=>stale.evaluate(`(async()=>{const saved=await _e2eRequestSession(${key},true);
            return !E2E._pendingOn?.[${key}]&&saved?.blob===''&&E2E.state.dm[${key}]?.on===0&&!${session}?.RK;})()`),
            'the later disable completes on both the browser and the host');
          const state=await stale.evaluate('cancelledEnable');
          const frames=stale.frames.slice(before).map(JSON.parse);
          check('a later disable supersedes a pending enable without briefly restoring the session or releasing its private draft',
            state.off&&!state.enabled&&!frames.some(f=>f.type==='e2e_fetch_bundle'||f.type==='e2e_commit_session'&&f.create||f.type==='send'&&f.raw?.endsWith(' :'+first))&&
            !remoteWs.events.slice(overlapPeer).some(e=>e.text===first));
          return;
        }
        if (process.env.CRYPTIRC_TEST_INBOUND_RESUME==='1') {
          const incoming='arrives during resume '+stamp;
          const sincePeer=peer.frames.length, sinceRelay=ownerWs.events.length;
          await stale.evaluate(`(()=>{
            const open=e2eDecryptIncoming;
            auditDuplicateClose.receive=[];
            e2eDecryptIncoming=(from,target,text,opts)=>{
              if(from===${nick}&&opts?.conn_id===${cid}&&opts.live) auditDuplicateClose.receive.push(text);
              return open(from,target,text,opts);
            };
          })()`);
          await submit(peer,remoteNetwork,owner,incoming);
          const wire=await waitFor(()=>{
            const wires=peer.frames.slice(sincePeer).map(JSON.parse).filter(e=>e.type==='send'&&e.raw?.includes(' :[e2edm2]')).map(e=>e.raw.split(' :')[1]);
            return ownerWs.events.slice(sinceRelay).find(e=>e.type==='irc_message'&&e.from===remote&&wires.includes(e.text))?.text;
          },'independent IRC connection receives the encrypted reply during Resume');
          await waitFor(()=>stale.evaluate(`auditDuplicateClose.receive.includes(${q(wire)})`),'the opted-out browser receives that exact ciphertext while it is checking');
          const next=incoming+' again';
          await waitFor(()=>peer.evaluate('!_sendLock'),'the peer composer is ready for another reply');
          await submit(peer,remoteNetwork,owner,next);
          const heldWires=await waitFor(()=>{
            const sent=peer.frames.slice(sincePeer).map(JSON.parse).filter(e=>e.type==='send'&&e.raw?.includes(' :[e2edm2]')).map(e=>e.raw.split(' :')[1]);
            const received=ownerWs.events.slice(sinceRelay).filter(e=>e.type==='irc_message'&&e.from===remote&&sent.includes(e.text));
            const wires=received.map(e=>e.text);
            return new Set(wires).size===2 && wires;
          },'two distinct genuine ciphertexts arrive before the session check completes');
          check('the same ratchet message has one Resume identifier across both supported header formats',
            await stale.evaluate(`(()=>{
              const [one,two]=${q(heldWires)}.map(w=>JSON.parse(atob(w.slice(E2E_DM_PREFIX.length))));
              const legacy={header:{dh:one.h.d,n:one.h.n,pn:one.h.p}};
              const id=_e2eResumeMessageId(one,false);
              return id && id===_e2eResumeMessageId(legacy,false) && id!==_e2eResumeMessageId(two,false) &&
                id!==_e2eResumeMessageId(one,true);
            })()`));
          check('the incoming message stays unreadable until the saved session is confirmed',!await row(stale,networkA,remote,incoming));
          if (process.env.CRYPTIRC_TEST_RESUME_EARLY==='1') {
            await waitFor(()=>row(fresh,networkA,remote,next),'the desktop opens both replies before the phone’s first settings request reaches the host');
            const previous=await waitFor(()=>stale.evaluate(`E2E._pendingOn?.[${key}]?.beforeAdvance||null`),
              'the waiting phone receives the previous sealed revision on its live account connection');
            check('only the receiving account gets the sealed revision while its desktop opens both replies',
              !!await row(fresh,networkA,remote,incoming) && previous.startsWith('e2e3.') &&
              ownerWs.events.some(e=>e.type==='e2e_live_receive'&&e.previous===previous) &&
              !remoteWs.events.some(e=>e.type==='e2e_live_receive'&&e.previous===previous) &&
              !await row(stale,networkA,remote,next));
          }
          const finish=()=>stale.evaluate('auditDuplicateClose.resumeCheck()');
          if (resumeParent) await checkResumeReaction({stale,peer,networkA,remote,remoteNetwork,owner,ownerWs,parent:resumeParent,finish,waitFor,check});
          else await finish();
          await waitFor(()=>row(stale,networkA,remote,incoming),'the same incoming message opens after explicit resume');
          await waitFor(()=>row(stale,networkA,remote,next),'the next incoming message also opens in the resumed conversation');
          await clickVisible(stale,'#send-btn');
          await waitFor(()=>row(peer,remoteNetwork,owner,first),'the peer opens the unchanged held draft');
          await submit(peer,remoteNetwork,owner,answer);
          await waitFor(()=>row(stale,networkA,remote,answer),'the resumed device opens the next reply');
          const displayed=await stale.evaluate(`getBuf(${cid},${nick}).filter(m=>m.encrypted&&m.from===${nick}&&[${q(incoming)},${q(next)}].includes(m.text)).map(m=>m.text)`);
          const inOrder=displayed.length===2&&displayed[0]===incoming&&displayed[1]===next;
          const clear=ownerWs.events.slice(sinceRelay).filter(e=>e.text===incoming||e.text===next).length;
          console.log('LIVE-REPLY-DURING-RESUME '+JSON.stringify({sealed:heldWires.length,readable:displayed.length,inOrder,clear}));
          check('the peer sent the held incoming message as ciphertext only',!clear&&heldWires.length===2&&inOrder);
          if (process.env.CRYPTIRC_TEST_RESUME_HISTORY==='1') {
            const reopened=await stale.relaunch();
            await waitFor(()=>reopened.evaluate('window._appShown&&_wsReady()&&E2E.keyReady&&E2E.identityReady&&!E2E._resyncPending'),
              'the remembered mobile profile reopens with its unlocked identity');
            await reopened.evaluate(`setActive(${cid},${nick})`);
            const history=await waitFor(()=>reopened.evaluate(`(()=>{
              const wires=${q(heldWires)}, expected=${q([incoming,next])};
              const messages=getBuf(${cid},${nick}).filter(m=>m.from===${nick}&&wires.includes(m._dmHistoryWire));
              return messages.length===2&&messages.every((m,i)=>m.encrypted&&m.text===expected[i]&&m._dmHistoryWire===wires[i]);
            })()`),'both live Resume replies return from the saved profile after full process exit');
            check('the reopened phone restores both exact encrypted replies in order with no extra recovery prompt',
              history&&!await reopened.evaluate(promptOpen));
          }
          return;
        }
        await stale.evaluate('auditDuplicateClose.resumeCheck()');
      }else await submit(stale,networkA,remote,'/encrypt on '+remote);
      let replacement;
      try {
        replacement=await waitFor(()=>stale.evaluate(`${session}?.x3dhPending&&${session}.epoch`),
          'third device explicitly re-enables Signal',45000);
      } catch (error) {
        const state=await stale.evaluate(`({
          mode:e2eTargetState(${nick},{conn_id:${cid}}).mode,pending:!!E2E._pendingOn?.[${key}],
          identityDialog:!!document.getElementById('e2e-id-dialog'),epoch:${session}?.epoch,
          notice:getBuf(${cid},${nick}).filter(row=>row.kind==='system'||row.kind==='error').slice(-3).map(row=>row.text)
        })`);
        throw new Error(error.message+' '+JSON.stringify(state));
      }
      const atPeer=remoteWs.events.length, atOwner=ownerWs.events.length;
      if(duplicateCloseTest){
        const sent=stale.frames.slice(overlapFrom).map(JSON.parse).filter(f=>f.type==='send'&&f.conn_id===networkA&&
          f.raw?.includes(' '+remote+' :')&&(f.raw.endsWith(' :'+first)||f.raw.includes(' :[e2edm2]')));
        const received=remoteWs.events.slice(overlapPeer).filter(e=>e.type==='irc_message'&&e.conn_id===remoteNetwork&&
          e.from===owner&&(e.text===first||e.text?.startsWith('[e2edm2]')));
        check('the overlapping send remains in the composer and puts neither plaintext nor a message envelope on the independent relay',
          !sent.length&&!received.length&&await stale.evaluate(`document.getElementById('msg-input').value===${q(first)}`));
        await clickVisible(stale,'#send-btn');
      }else await compose(stale,networkA,remote,first);
      await waitFor(()=>row(peer,remoteNetwork,owner,first),'independent peer opens the replacement Signal message');
      await compose(peer,remoteNetwork,owner,answer);
      await waitFor(()=>row(stale,networkA,remote,answer),'third device opens the real encrypted reply');
      const [firstSeen,replySeen]=await Promise.all([first,answer].map(text=>waitFor(
        ()=>row(browser,networkA,remote,text),'the open desktop recovers the replacement transcript',12000).catch(()=>false)));
      const seen={first:firstSeen,reply:replySeen,epoch:await epoch(browser)};
      const linked=remoteWs.events.slice(atPeer).filter(event=>event.type==='irc_message'&&event.conn_id===remoteNetwork&&
        event.from===owner&&event.text?.startsWith('[e2edm2]'));
      const replies=ownerWs.events.slice(atOwner).filter(event=>event.type==='irc_message'&&event.conn_id===networkA&&
        event.from===remote&&event.text?.startsWith('[e2edm2]'));
      const plaintext=[...remoteWs.events.slice(atPeer),...ownerWs.events.slice(atOwner)].some(event=>[first,answer].includes(event.text));
      console.log('INTERRUPTED-CLOSE '+JSON.stringify({initial,newest,interrupted,marker,replacement,seen,
        peerWires:linked.length,replyWires:replies.length,plaintext}));
      check('the newer authenticated closure floor survives the closing browser crash and bounds replacement',
        interrupted.floor>newest&&marker>=interrupted.floor&&replacement>marker);
      check('the unreloaded desktop reads the replacement Signal message and reply from the real IRC relay',
        seen.first&&seen.reply&&seen.epoch>=replacement&&await browser.evaluate(`performance.timeOrigin===${q(desktopPage)}`)&&
        linked.length===1&&replies.length===1&&!plaintext);
      if(duplicateCloseTest){
        check('the new session generation strictly exceeds the second browser’s confirmed close marker',
          boundary.created>boundary.marker&&boundary.marker===marker&&boundary.created>boundary.floor);
        const on=await stale.evaluate(`(async()=>{
          const state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
          return auditDuplicateClose.enables===1&&state.dm?.[${key}]?.on===1&&E2E.state.dm[${key}]?.on===1;
        })()`);
        const siblingRead=await waitFor(async()=>await row(fresh,networkA,remote,first)&&await row(fresh,networkA,remote,answer),
          'the creating sibling opens both the message sent by the re-enabled browser and the independent peer reply',30000);
        check('one explicit enable on the actual closer restores two-way Signal on all three remaining browsers',
          on&&siblingRead&&seen.first&&seen.reply&&linked.length===1&&replies.length===1&&!plaintext);
      }
      check('an existing independent ratchet advances below the global floor with the same authenticated revision chain',
        independentContinues);
      return;
    }
    if(['offline-reenable','close-refusal','close-lost-ack'].includes(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT)){
      const refuse=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='close-refusal';
      const lostAck=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='close-lost-ack';
      const epoch=device=>device.evaluate(`${session}?.epoch`);
      const page=await browser.evaluate('performance.timeOrigin');
      const initial=await epoch(phone);
      const normal={offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1};
      await phone.evaluate(`(()=>{
        const key=${key}, install=_e2eInstallStoredInner, get=_e2eReq, handle=e2eHandleEvent, dispatch=handleEvent;
        window.auditClose={attempts:[],release:null,lost:false,passive:[]};
        // Delay only passive installation on the reconnecting phone. Its exact
        // close command still reads and authenticates the real account record.
        if(!${refuse}) _e2eInstallStoredInner=(slot,...args)=>slot===key?null:install(slot,...args);
        else handleEvent=event=>{
          const passiveMessage=['log_lines','sync_lines','irc_message'].includes(event.type)&&
            event.conn_id===${cid}&&typeof event.target==='string'&&bk(${cid},event.target)===bk(${cid},${nick});
          if(passiveMessage||(event.type==='e2e_session_moved'&&event.partner===key)){
            auditClose.passive.push(event);return;
          }
          return dispatch(event);
        };
        _e2eReq=async (message,...args)=>{
          if(message.type!=='e2e_close_session'||message.partner!==key) return get(message,...args);
          const entry={floor:typeof _e2ePendingCloseFloor==='function'?_e2ePendingCloseFloor(key):_e2eLsGet(_e2eDevKey())?.ep?.[key],
            activeFloor:_e2eLsGet(_e2eDevKey())?.ep?.[key],conflict:false,ok:false};
          auditClose.attempts.push(entry);
          if(${refuse}) return null;
          if(auditClose.attempts.length===1) await new Promise(resolve=>{auditClose.release=resolve;});
          const result=await get(message,...args);
          entry.conflict=typeof result?.conflict==='string';entry.empty=result?.conflict==='';entry.ok=result?.ok===true;
          return result;
        };
        if(${lostAck}) e2eHandleEvent=event=>{
          if(event.type==='e2e_session_closed'&&event.partner===key&&event.ok&&!auditClose.lost){auditClose.lost=true;return;}
          return handle(event);
        };
        window.auditRestoreClose=()=>{
          auditClose.release?.();_e2eInstallStoredInner=install;_e2eReq=get;e2eHandleEvent=handle;handleEvent=dispatch;
          for(const event of auditClose.passive.splice(0)) dispatch(event);
        };
      })()`);
      let newest, marker, attempts;
      try{
        await phone.send('Network.emulateNetworkConditions',{...normal,offline:true});
        await phone.evaluate('if(ws?.readyState===1)ws.close()');
        await waitFor(()=>phone.evaluate('!navigator.onLine&&!_wsReady()'),'phone becomes really disconnected');
        const advance=async i=>{
          const text='desktop while phone is behind '+i+' '+stamp;
          await compose(browser,networkA,remote,text);
          await waitFor(()=>row(peer,remoteNetwork,owner,text),'linked peer opens desktop advance '+i);
        };
        for(let i=1;i<=4;i++) await advance(i);
        newest=await epoch(browser);
        check('offline phone misses four valid desktop ratchet advances',newest>=initial+4&&await epoch(phone)===initial);
        await phone.send('Network.emulateNetworkConditions',normal);
        await waitFor(()=>phone.evaluate('navigator.onLine&&_wsReady()&&E2E.identityReady&&!document.getElementById("msg-input").disabled'),
          'original phone document can submit commands after reconnecting');
        await compose(phone,networkA,remote,'/encrypt off');
        if(refuse){
          await waitFor(()=>phone.evaluate(`auditClose.attempts.length===1&&getBuf(${cid},${nick})
            .some(row=>row.text.includes('Could not confirm session removal. Encryption stays on.'))`),
            'phone receives a failed confirmation while the account keeps its genuine session');
          const [attempt]=await phone.evaluate('auditClose.attempts');
          const beforeSend=await phone.evaluate(`({epoch:${session}?.epoch,passive:auditClose.passive.length,
            repair:E2E._sessionSyncRepair.has(${key}),hasActiveIdentity:E2E.identityReady})`);
          check('the failed close observed the active account epoch without changing the phone ratchet',
            attempt.floor>=newest&&beforeSend.epoch===initial&&!beforeSend.repair&&beforeSend.hasActiveIdentity);
          const text='genuine send after refused close '+stamp;
          const from=remoteWs.events.length;
          await compose(phone,networkA,remote,text);
          let delivered=false;
          try { await waitFor(()=>row(peer,remoteNetwork,owner,text),'peer opens first send after refused close',15000); delivered=true; }
          finally { console.log('CLOSE-REFUSAL '+JSON.stringify({initial,newest,attempt,beforeSend,delivered})); }
          check('failed removal leaves strict adoption available for the same current active revision',
            delivered&&attempt.activeFloor===initial&&await epoch(phone)>newest&&
            remoteWs.events.slice(from).some(event=>event.text?.startsWith('[e2edm2]'))&&
            !remoteWs.events.slice(from).some(event=>event.text===text));
          return;
        }
        const off=`!${session}&&!E2E._stateSaving&&E2E.state.dm[${key}]?.on===0`;
        await waitFor(()=>phone.evaluate(`!!auditClose.release||(${off})`),'phone starts its normal opt-out or completes the older unconditional close');
        if(await phone.evaluate('!!auditClose.release')){
          check('phone persisted the authenticated observed epoch before requesting deletion',
            await phone.evaluate(`auditClose.attempts[0].floor>=${newest}`));
          await advance(5);
          newest=await epoch(browser);
          await phone.evaluate('auditClose.release()');
        }
        await waitFor(()=>phone.evaluate(off),'phone completes the normal off command');
        marker=await waitFor(()=>phone.evaluate(`(async()=>{
          const state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
          return state?.dm?.[${key}]?.on===0&&state.dm[${key}].closedEpoch;
        })()`),'the authenticated opt-out reaches the account store');
        attempts=await phone.evaluate('auditClose.attempts');
        if(lostAck) check('a genuine lost successful close reply retries against an absent record exactly once',
          await phone.evaluate('auditClose.lost')&&attempts.filter(attempt=>attempt.empty).length===1&&
          attempts.filter(attempt=>attempt.ok).length===1);
      }finally{
        await phone.send('Network.emulateNetworkConditions',normal);
        await phone.evaluate('window.auditRestoreClose?.();delete window.auditRestoreClose');
      }
      console.log('OFFLINE-CLOSE '+JSON.stringify({initial,newest,marker,attempts}));
      check('an in-flight desktop send forces a close retry at its newer authenticated epoch',
        attempts.at(0)?.conflict&&attempts.at(-1)?.ok&&attempts.at(-1).floor>=newest&&marker>newest);
      if(onboardingWindowEnds>Date.now()) await new Promise(resolve=>setTimeout(resolve,onboardingWindowEnds-Date.now()));
      await compose(phone,networkA,remote,'/encrypt on '+remote);
      await waitFor(()=>phone.evaluate(`${session}?.x3dhPending&&${session}.epoch>${marker}&&E2E.state.dm[${key}]?.on===1`),
        'phone explicitly starts a new session above the shared closure',45000);
      const outgoing='first encrypted after offline close '+stamp, response='encrypted reply after offline close '+stamp;
      const atPeer=remoteWs.events.length, atOwner=ownerWs.events.length;
      await compose(phone,networkA,remote,outgoing);
      check('phone’s first new Signal message reaches the peer and the open desktop before any reply',await waitFor(async()=>
        await row(peer,remoteNetwork,owner,outgoing)&&await row(browser,networkA,remote,outgoing),'peer and desktop read the first new encrypted draft',30000));
      await compose(peer,remoteNetwork,owner,response);
      check('both still-open account devices decrypt the remote reply',await waitFor(async()=>
        await row(phone,networkA,remote,response)&&await row(browser,networkA,remote,response),'desktop and phone read the peer reply',30000)&&
        await browser.evaluate(`performance.timeOrigin===${page}`));
      const received=[...remoteWs.events.slice(atPeer),...ownerWs.events.slice(atOwner)];
      check('real relay observers see encrypted wire for the new message and reply without cleartext',
        !received.some(event=>[outgoing,response].includes(event.text))&&
        [owner,remote].every(sender=>received.some(event=>event.type==='irc_message'&&event.from===sender&&event.text?.startsWith('[e2edm2]'))));
      return;
    }
    if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='stale-composer'){
      const contact='pks'+stamp;
      const {observer,id,device}=await createRemote(contact);
      await login(device,contact,password,waitFor);
      await waitFor(()=>device.evaluate('E2E._vaultUp&&E2E._krReceived'),'new contact discovers its keyring');
      await device.evaluate(openEncryptionSettings);
      await setUpRecovery(device,waitFor,check);
      await device.evaluate('closeEncryptPanel()');
      const k=`_e2eDmKey(${q(contact)},${cid})`;
      const incoming='phone responds to an incoming Signal chat '+stamp;
      const phoneReply='phone confirms the incoming session '+stamp;
      const desktopPage=await browser.evaluate('performance.timeOrigin');
      // Keep the incoming offer unseen on this desktop with a local ignore. Do
      // not sync that fixture preference to the phone, which accepts normally.
      await browser.evaluate(`ignoreList.add(${q(contact)});true`);
      try {
        await compose(device,id,owner,incoming);
        await acceptIdentity(device,waitFor);
        await acceptIdentity(phone,waitFor);
        check('only the phone establishes as responder to a new incoming Signal conversation',
          await waitFor(()=>row(phone,networkA,contact,incoming),'phone opens the incoming Signal message')&&
          await phone.evaluate(`E2E.dmSessions[${k}]?.isInitiator===false`)&&
          await browser.evaluate(`!E2E.dmSessions[${k}]&&!E2E.state.dm[${k}]&&!E2E.trustStore[${k}]`));
        await compose(phone,networkA,contact,phoneReply);
        await waitFor(()=>row(device,id,owner,phoneReply),'contact reads the phone’s encrypted reply');
        await compose(phone,networkA,contact,'/encrypt off');
        await waitFor(()=>phone.evaluate(`!_sendLock&&!E2E._stateSaving&&!E2E.dmSessions[${k}]&&E2E.state.dm[${k}]?.on===0`),
          'phone disables the responder session');
      } finally { await browser.evaluate(`ignoreList.delete(${q(contact)})`); }
      const closedEpoch=await phone.evaluate(`(async()=>{
        const state=await _e2eDecodeState(await _e2eFetchSession('__state__'));
        return state?.dm?.[${k}]?.on===0 ? state.dm[${k}].closedEpoch : null;
      })()`);
      check('the desktop has not learned the phone’s saved encryption opt-out',closedEpoch>1&&
        await browser.evaluate(`performance.timeOrigin===${q(desktopPage)}&&!E2E.dmSessions[${k}]&&!E2E.state.dm[${k}]`));
      const draft='held desktop draft after responder off '+stamp;
      const beforeFrames=browser.frames.length, beforeIrc=observer.events.length;
      const outbound=()=>browser.frames.slice(beforeFrames).map(frame=>JSON.parse(frame)).filter(frame=>
        frame.type==='send'&&frame.conn_id===networkA&&frame.raw?.includes(' '+contact+' :'));
      await compose(browser,networkA,contact,draft);
      await waitFor(async()=>{
        // Exercise the old path to completion if it incorrectly offers an
        // identity prompt, so a silent no-send alone can't make this pass.
        await browser.evaluate("document.querySelector('#e2e-id-accept:not(:disabled)')?.click()");
        return browser.evaluate(`!_sendLock&&!E2E._pendingOn?.[${k}]`);
      },'submitting the stale desktop draft finishes',30000);
      const held=await browser.evaluate(`({draft:document.getElementById('msg-input').value===${q(draft)},
        reason:E2E.lastBlockReason||'',epoch:E2E.dmSessions[${k}]?.epoch??null,on:E2E.state.dm[${k}]?.on??null})`);
      console.log('STALE-COMPOSER '+JSON.stringify({closedEpoch,...held,ircSends:outbound().length}));
      check('the stale desktop retains its draft and explains how to explicitly enable Signal',
        held.draft&&held.reason.includes('/encrypt on '+contact)&&held.epoch===null&&held.on===0);
      check('the held draft emits neither a Signal envelope, setup header, nor plaintext',!outbound().length&&
        !observer.events.slice(beforeIrc).some(ev=>ev.type==='irc_message'&&ev.from===owner));
      const added=' with additional words', edited=draft+added;
      await browser.evaluate(`(()=>{const input=document.getElementById('msg-input');
        input.focus();input.setSelectionRange(input.value.length,input.value.length);})()`);
      await browser.send('Input.insertText',{text:added});
      await browser.evaluate('_deviceLockNow(false)');
      await waitFor(()=>browser.evaluate(`encryptionDeviceLocked()&&!E2E.keyReady&&!E2E._sessionSyncRepair.has(${k})`),
        'device lock clears the old session repair marker');
      await unlockVault(browser,vault);
      await waitFor(()=>browser.evaluate('!encryptionDeviceLocked()&&E2E._vaultUp&&E2E._krReceived'),
        'the vault passphrase unlocks the desktop');
      await browser.evaluate('if(!E2E.identityReady) void e2ePromptDeviceUnlock()');
      await waitFor(()=>browser.evaluate(`E2E.identityReady||(${promptOpen}&&${promptText}.includes(${q(unlockText)}))`),
        'the desktop can restore its Signal recovery key');
      if(!await browser.evaluate('E2E.identityReady')) await fillPrompt(browser,ownerCode);
      await waitFor(()=>browser.evaluate(`!encryptionDeviceLocked()&&E2E.identityReady&&E2E.state?.dm?.[${k}]?.on===0`),
        'desktop unlock restores the account’s authenticated off setting');
      check('device unlock preserves the edited text in the held composer',
        await browser.evaluate(`document.getElementById('msg-input').value===${q(edited)}`));
      const retryHeld=async label=>{
        await clickVisible(browser,'#send-btn');
        await waitFor(()=>browser.evaluate('!_sendLock'),label+' submission finishes');
        return browser.evaluate(`document.getElementById('msg-input').value===${q(edited)}`);
      };
      const heldAfterLock=await retryHeld('post-lock');
      if(!heldAfterLock||outbound().length){
        const leaked=await waitFor(()=>observer.events.slice(beforeIrc).find(event=>
          event.type==='irc_message'&&event.from===owner&&event.text===edited), 'stale desktop sent synthetic draft as plaintext').catch(()=>null);
        console.log('STALE-HELD-LOCK '+JSON.stringify({heldAfterLock,wireSends:outbound().length,plainAtPeer:!!leaked}));
      }
      check('the same edited Signal draft stays held after a real device lock and unlock',heldAfterLock&&!outbound().length);
      await browser.evaluate('void _reloadForUpdate(true);true');
      await waitFor(()=>browser.evaluate(`performance.timeOrigin!==${q(desktopPage)}&&window._appShown&&E2E.identityReady&&
        document.getElementById('msg-input').value===${q(edited)}`).catch(()=>false),'update reload restores the held draft',30000);
      const reloadedPage=await browser.evaluate('performance.timeOrigin');
      check('updating the client reloads the edits and keeps the same draft off IRC',
        await retryHeld('post-update')&&await browser.evaluate(`E2E.lastBlockReason?.includes(${q('/encrypt off '+contact)})`)&&
        !outbound().length&&
        !observer.events.slice(beforeIrc).some(event=>event.type==='irc_message'&&event.from===owner));
      await browser.evaluate("document.getElementById('msg-input').focus()");
      for(const [key,code] of [['ArrowDown',40],['ArrowUp',38]]){
        await browser.send('Input.dispatchKeyEvent',{type:'keyDown',key,code:key,windowsVirtualKeyCode:code});
        await browser.send('Input.dispatchKeyEvent',{type:'keyUp',key,code:key,windowsVirtualKeyCode:code});
        const expected=key==='ArrowDown'?'':edited;
        await waitFor(()=>browser.evaluate(`document.getElementById('msg-input').value===${q(expected)}`),'trusted composer '+key+' selects the expected history line');
      }
      const heldAfterRecall=await retryHeld('recalled edited draft');
      const plainFromRecall=()=>observer.events.slice(beforeIrc).some(event=>
        event.type==='irc_message'&&event.from===owner&&event.text===edited);
      if(!heldAfterRecall||outbound().length) await waitFor(plainFromRecall,'peer observes the recalled synthetic draft',20000).catch(()=>{});
      const plainSubmitted=outbound().some(frame=>frame.raw===`PRIVMSG ${contact} :${edited}`);
      console.log('EDITED-RECALL '+JSON.stringify({held:heldAfterRecall,wireSends:outbound().length,plainSubmitted,plaintextAtPeer:plainFromRecall()}));
      check('clearing and recalling an edited protected draft keeps it private until an explicit choice',
        heldAfterRecall&&!outbound().length&&!plainFromRecall());
      await browser.evaluate(`handleEncryptCommand(['off'],${cid},${q(contact)})`);
      await waitFor(()=>browser.evaluate(`!E2E._stateSaving&&!E2E._sessionSyncRepair.has(${k})&&E2E.state?.dm?.[${k}]?.on===0`),
        'desktop acknowledges the local encryption opt-out');
      const plainAtPeer=()=>observer.events.slice(beforeIrc).filter(event=>event.type==='irc_message'&&
        event.from===owner&&event.text===edited).length;
      check('explicitly disabling encryption in this desktop lets the user send the held draft once as plaintext',
        !await retryHeld('post-acknowledgement')&&
        await waitFor(()=>plainAtPeer()===1,'peer sees the one consciously unencrypted message')&&
        outbound().filter(event=>event.raw===`PRIVMSG ${contact} :${edited}`).length===1);
      await compose(browser,networkA,contact,'/encrypt on '+contact);
      await waitFor(async()=>{
        await browser.evaluate("document.querySelector('#e2e-id-accept:not(:disabled)')?.click()");
        return browser.evaluate(`!_sendLock&&!E2E._pendingOn?.[${k}]&&E2E.dmSessions[${k}]?.x3dhPending&&
          E2E.dmSessions[${k}].epoch>${closedEpoch}&&E2E.state.dm[${k}]?.on===1`);
      },'explicit desktop encryption starts above the phone’s closed epoch',40000);
      await compose(browser,networkA,contact,draft);
      check('explicitly re-enabled Signal reaches the phone and peer before a reply',await waitFor(async()=>
        await row(phone,networkA,contact,draft)&&await row(device,id,owner,draft),
        'phone and peer open the deliberately re-enabled draft',30000));
      const answer='peer replies after explicit desktop enable '+stamp;
      await compose(device,id,owner,answer);
      check('both still-open devices can read the encrypted reply',await waitFor(async()=>
        await row(browser,networkA,contact,answer)&&await row(phone,networkA,contact,answer),
        'desktop and phone read the encrypted reply',30000)&&await browser.evaluate(`performance.timeOrigin===${q(reloadedPage)}`));
      check('the earlier explicit clear send is still the only copy on the receiving IRC connection',plainAtPeer()===1);
      return;
    }
    if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='long-draft'){
      const size=await browser.evaluate(`_e2eMaxPlain('dm',_e2eWireBudget(${nick},${cid}))`);
      const pieces=Array.from({length:33},(_,i)=>('piece'+i+'-'+stamp).padEnd(size,'a'));
      await browser.evaluate(`(()=>{setRateLimit(2200); const send=wsend;window.auditDraftSent=[];
        wsend=(message,...rest)=>{if(message?.type==='send' && message.raw?.includes(' :[e2edm2]')) window.auditDraftSent.push(Date.now());
          return send(message,...rest);};})()`);
      const wireAt=remoteWs.events.length,frameAt=browser.frames.length,ownerAt=ownerWs.events.length;
      await compose(browser,networkA,remote,pieces.join(''));
      await waitFor(()=>row(peer,remoteNetwork,owner,pieces[0]),'first piece reaches its recipient',45000);
      const first=Date.now();
      const list=(dev,connection,target)=>dev.evaluate(`getBuf(${q(connection)},${q(target)}).filter(
        m=>m.encrypted&&${q(pieces)}.includes(m.text)).map(m=>m.text)`);
      const complete=async(dev,connection,target)=>JSON.stringify(await list(dev,connection,target))===JSON.stringify(pieces);
      try {
        // The IRCd can deliver more slowly than the client's configured queue.
        // Time transport and browser rendering separately.
        await waitFor(()=>remoteWs.events.slice(wireAt).filter(e=>e.type==='irc_message'&&e.from===owner&&
          e.text?.startsWith('[e2edm2]')).length>=pieces.length,'IRC relays the final piece of the slow draft',240000);
        await waitFor(async()=>await complete(peer,remoteNetwork,owner)&&await complete(phone,networkA,remote),
          'all delivered draft pieces decrypt in order for the peer and passive phone',30000);
      } catch(error) {
        const received=await list(peer,remoteNetwork,owner),seen=await list(phone,networkA,remote);
        const number=wire=>JSON.parse(Buffer.from(wire.slice(8),'base64').toString()).h.n;
        const numbers=remoteWs.events.slice(wireAt).filter(e=>e.type==='irc_message'&&e.from===owner&&
          e.text?.startsWith('[e2edm2]')).map(e=>number(e.text));
        const submitted=browser.frames.slice(frameAt).map(frame=>JSON.parse(frame)).filter(m=>m.type==='send'&&
          m.raw?.includes(' :[e2edm2]')).map(m=>number(m.raw.split(' :')[1]));
        throw new Error(error.message+' '+JSON.stringify({submitted,received:numbers,peerMissing:pieces.map((s,i)=>received.includes(s)?null:i).filter(i=>i!==null),
          phoneMissing:pieces.map((s,i)=>seen.includes(s)?null:i).filter(i=>i!==null),status:ownerWs.events.slice(ownerAt)
            .filter(e=>e.type==='irc_delivery_warning'||(e.target==='status'&&/flood|throttl|limit|drop|offline|no such/i.test(e.text||'')))
            .slice(-5).map(e=>({type:e.type,text:String(e.text||'').slice(0,120)})),sender:await browser.evaluate(`({queued:_rateQueue.length,
          elapsed:Math.round((window.auditDraftSent.at(-1)-window.auditDraftSent[0])/1000),rate:getRateLimit(),
          policy:E2E.lastBlockReason,notices:getBuf(${cid},${nick}).filter(m=>m.kind==='error').slice(-2).map(m=>m.text.slice(0,130))})`)}));
      }
      check('a 33-piece Signal draft stays readable on the passive phone and remote peer at a slow IRC line rate',
        Date.now()-first>60000 && remoteWs.events.slice(wireAt).filter(e=>e.type==='irc_message'&&e.from===owner&&
          e.text?.startsWith('[e2edm2]')).length===pieces.length);
      console.log('LONG-DRAFT '+JSON.stringify({pieces:pieces.length,relaySeconds:Math.round((Date.now()-first)/1000),
        submitSeconds:await browser.evaluate('Math.round((window.auditDraftSent.at(-1)-window.auditDraftSent[0])/1000)')}));
      return;
    }
    if(['simultaneous-first','passive-first','passive-delayed','passive-reenable','passive-order','passive-order-reply'].includes(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT)){
      const fresh='pkz'+stamp;
      const {observer,id,device}=await createRemote(fresh);
      await login(device,fresh,password,waitFor);
      await waitFor(()=>device.evaluate('E2E._vaultUp&&E2E._krReceived'),'new contact discovers their keyring');
      await device.evaluate(openEncryptionSettings);
      await setUpRecovery(device,waitFor,check);
      await device.evaluate('closeEncryptPanel()');
      await waitFor(()=>fs.stat(path.join(remoteData,'e2e',fresh,'bundle.json')).catch(()=>false),'new contact publishes their first bundle');
      const delayed=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='passive-delayed';
      const reenable=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='passive-reenable';
      const earlyReply=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='passive-order-reply';
      const reordered=earlyReply||process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='passive-order';
      const restart=process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='passive-first';
      const passive=reordered||reenable||delayed||restart;
      const texts=passive?['first-desk-'+stamp]:['first-desk-'+stamp,'first-phone-'+stamp];
      const acceptWhenAsked=b=>b.evaluate("document.querySelector('#e2e-id-accept:not(:disabled)')?.click()");
      if(!passive){
        await phone.evaluate(`(()=>{const start=_e2eAutoStart;
          _e2eAutoStart=async (...args)=>{
            const result=await start(...args);
            if(args[0]===${q(fresh)}&&result==='ready'){_e2eMarkMaybeMoved(args[1]);_e2eAutoStart=start;}
            return result;
          };
        })()`);
      }
      if(reordered){
        await phone.evaluate(`(()=>{const note=_e2eNoteInitialEcho,k=_e2eDmKey(${q(fresh)},${q(networkA)});
          _e2eNoteInitialEcho=(peer,blob)=>{
            if(peer!==k)return note(peer,blob);
            window.auditDeliverInitial=()=>{_e2eNoteInitialEcho=note;return note(peer,blob);};
          };
        })()`);
      }
      if(delayed){
        await phone.evaluate(`(()=>{const read=_e2eFetchSession,k=_e2eDmKey(${q(fresh)},${q(networkA)});
          let start=0;window.auditDelayedStateReads=0;
          _e2eFetchSession=async slot=>{
            if(slot==='__state__'&&_e2eInitialEchoes.has(k)){
              start||=Date.now();
              if(Date.now()-start<6500){window.auditDelayedStateReads++;return null;}
            }
            return read(slot);
          };
          window.auditRestoreStateRead=()=>{_e2eFetchSession=read;};
        })()`);
        await browser.evaluate(`setActive(${q(networkA)},${q(fresh)});void handleEncryptCommand(['on',${q(fresh)}],${q(networkA)},${q(fresh)});true`);
        const k=`_e2eDmKey(${q(fresh)},${q(networkA)})`;
        await waitFor(async()=>{
          await Promise.all([browser,device].map(acceptWhenAsked));
          return phone.evaluate(`E2E.dmSessions[${k}]?.Ns===0 && !!E2E.trustStore[${k}]?.fingerprint`);
        },'passive phone installs the approved initial session before any outgoing message',40000);
        check('the passive phone restores the independently saved pin after a delayed state read',
          await phone.evaluate('window.auditRestoreStateRead();window.auditDelayedStateReads>0'));
        await waitFor(()=>phone.evaluate(`!_e2eInitialEchoes.has(${k})`),'first-contact seed expires before any chat text is sent',70000);
      }
      await Promise.all(texts.map((text,i)=>compose([browser,phone][i],networkA,fresh,text)));
      try {
        await waitFor(async()=>{
          await Promise.all([browser,phone,device].map(acceptWhenAsked));
          return (await Promise.all(texts.map(text=>row(device,id,owner,text)))).every(Boolean);
        },'both first-contact drafts arrive after normal identity approval',70000);
      } catch (error) {
        const state=(b,conn,target)=>b.evaluate(`(()=>{const key=_e2eDmKey(${q(target)},${q(conn)}),s=E2E.dmSessions[key];
          return {ready:!!s,pin:!!E2E.trustStore[key]?.fingerprint,pending:!!E2E._pendingOn?.[key],hasDraft:!!document.getElementById('msg-input').value,
          reason:E2E.lastBlockReason,ui:getBuf(${q(conn)},${q(target)}).filter(m=>m.kind==='system'||m.kind==='error').slice(-3).map(m=>m.text.slice(0,140))};})()`);
        throw new Error(error.message+' '+JSON.stringify(await Promise.all([state(browser,networkA,fresh),state(phone,networkA,fresh),state(device,id,owner)])));
      }
      check('first-contact drafts arrive exactly once after identity confirmation',
        observer.events.filter(e=>e.type==='irc_message'&&e.from===owner&&e.text?.startsWith('[e2edm2]')).length===texts.length&&
        !observer.events.some(e=>texts.includes(e.text)));
      const reply='first-reply-'+stamp;
      if(reordered){
        await waitFor(()=>phone.evaluate('!!window.auditDeliverInitial'),'phone receives its first-contact notification');
        if(earlyReply){
          await compose(device,id,owner,reply);
          await waitFor(()=>row(browser,networkA,fresh,reply),'desktop authenticates the early return before the passive phone resyncs',30000);
        }
        await phone.evaluate('_e2eResync()');
        const restored=await phone.evaluate(`(()=>{const k=_e2eDmKey(${q(fresh)},${q(networkA)}),s=E2E.dmSessions[k];return ${earlyReply?'s?.Nr>=1':'s?.Ns===1'} &&
          !!E2E.trustStore[k]?.fingerprint;})()`);
        check('ordinary account resync adopts the committed first send before the delayed creation notice',restored);
        await phone.evaluate('window.auditDeliverInitial()');
      }
      if(passive){
        try {
          await waitFor(()=>row(phone,networkA,fresh,texts[0]),'passive phone can read the first outgoing message',20000);
        } catch(error) {
          const state=await phone.evaluate(`(()=>{const k=_e2eDmKey(${q(fresh)},${q(networkA)}),s=E2E.dmSessions[k],e=_e2eInitialEchoes.get(k);
            return {ready:E2E.keyReady,pin:!!E2E.trustStore[k]?.fingerprint,changed:!!E2E.trustStore[k]?.keyChanged,
              haveSession:!!s,epoch:s?.epoch,sent:s?.Ns,seed:!!e,floor:e?.floor,attempts:e?.attempts,keys:_e2eEchoKeys.size,
              moved:_e2eMovedPending(k),scoped:!!_e2eDmScope(k),rows:getBuf(${q(networkA)},${q(fresh)}).map(m=>m._dmHistoryState||m.kind)};})()`);
          throw new Error(error.message+' '+JSON.stringify(state));
        }
        check(earlyReply?'the passive phone reads the first outgoing message even when the reply overtakes the creation notice':
          'an already-open passive phone reads the first outgoing message before the contact replies',true);
      }
      if(!earlyReply) await compose(device,id,owner,reply);
      check('both devices read the fresh contact’s encrypted reply',await waitFor(async()=>
        await row(browser,networkA,fresh,reply)&&await row(phone,networkA,fresh,reply),'fresh contact replies to both',30000));
      check('the other open device reads the outgoing message on first contact',await waitFor(async()=>
        (passive||await row(browser,networkA,fresh,texts[1]))&&await row(phone,networkA,fresh,texts[0]),'the first-contact echoes become readable',30000));
      const checkReplacementSend=async({nick,contact,contactId,observer,text,phonePage,label})=>{
        const at=observer.events.length;
        await compose(browser,networkA,nick,text);
        check(label,await waitFor(()=>phone.evaluate(`performance.timeOrigin===${q(phonePage)}&&
          active?.conn_id===${q(networkA)}&&active.target===${q(nick)}&&
          Array.from(document.querySelectorAll('#chat-area .msg-row')).filter(
            row=>row._msgRef?.encrypted&&row._msgRef.text===${q(text)}).length===1`),
          'the open phone renders the first new encrypted message before any reply',30000));
        await waitFor(async()=>{
          await acceptWhenAsked(contact);
          return row(contact,contactId,owner,text);
        },'the contact reads the first message in the new session',30000);
        await waitFor(()=>observer.events.slice(at).some(e=>e.type==='irc_message'&&e.conn_id===contactId&&
          e.from===owner&&e.text?.startsWith('[e2edm2]')),'first new ciphertext reaches the contact on IRC');
        check('the new session carries one ciphertext message and no plaintext',
          observer.events.slice(at).filter(e=>e.type==='irc_message'&&e.conn_id===contactId&&e.from===owner&&
            e.text?.startsWith('[e2edm2]')).length===1&&!observer.events.slice(at).some(e=>e.text===text));
      };
      const waitForNewSession=async(nick,prior,label)=>{
        const k=`_e2eDmKey(${q(nick)},${q(networkA)})`;
        try {
          await waitFor(()=>browser.evaluate(`!_sendLock&&!E2E._pendingOn?.[${k}]&&
            !!E2E.dmSessions[${k}]?.x3dhPending&&E2E.dmSessions[${k}].startEph!==${q(prior)}&&
            E2E.state.dm[${k}]?.on===1`),label,40000);
        } catch(error) {
          const detail=await browser.evaluate(`({draft:document.getElementById('msg-input').value,
            pending:!!E2E._pendingOn?.[${k}],repair:E2E._sessionSyncRepair.has(${k}),on:E2E.state.dm[${k}]?.on,
            notices:getBuf(${q(networkA)},${q(nick)}).filter(m=>!m.encrypted).slice(-6).map(m=>m.text)})`);
          throw new Error(error.message+' '+JSON.stringify(detail));
        }
      };
      if(restart){
        const k=`_e2eDmKey(${q(fresh)},${q(networkA)})`;
        const prior=await waitFor(()=>browser.evaluate(`!E2E.dmSessions[${k}]?.x3dhPending&&E2E.dmSessions[${k}]?.startEph`),
          'the reply confirms the desktop’s initial session');
        check('the desktop and phone start the restart check with the same confirmed session',
          await waitFor(()=>phone.evaluate(`E2E.dmSessions[${k}]?.startEph===${q(prior)}`),
            'the open phone holds the same session that the desktop will restart'));
        await phone.evaluate(`setActive(${q(networkA)},${q(fresh)})`);
        const phonePage=await phone.evaluate('performance.timeOrigin');
        await compose(browser,networkA,fresh,'/encrypt restart '+fresh);
        await waitForNewSession(fresh,prior,'desktop prepares a replacement session through /encrypt restart');
        await checkReplacementSend({nick:fresh,contact:device,contactId:id,observer,text:'desktop-restart-'+stamp,phonePage,
          label:'the open phone reads the first desktop message after /encrypt restart before the contact replies'});
      }
      if(reenable){
        // The original peer already answered setup discovery and the first bundle lookup.
        if(onboardingWindowEnds>Date.now()) await new Promise(resolve=>setTimeout(resolve,onboardingWindowEnds-Date.now()));
        const remembered=await browser.evaluate(`${session}?.startEph`);
        check('the phone and desktop have the same active session before the phone turns it off',
          !!remembered&&await phone.evaluate(`${session}?.startEph===${q(remembered)}`));
        const phonePage=await phone.evaluate('performance.timeOrigin');
        await compose(phone,networkA,remote,'/encrypt off');
        await waitFor(()=>phone.evaluate(`!_sendLock&&!E2E._stateSaving&&E2E.state.dm[${key}]?.on===0&&!${session}`),
          'phone acknowledges disabling the conversation',30000);
        await compose(browser,networkA,remote,'/encrypt on '+remote);
        await waitForNewSession(remote,remembered,'the already-open desktop enables a fresh session after the phone turned it off');
        await checkReplacementSend({nick:remote,contact:peer,contactId:remoteNetwork,observer:remoteWs,
          text:'phone-off-desktop-on-'+stamp,phonePage,
          label:'the open phone reads the first desktop message after the phone turned encryption off and the desktop enabled it again'});
        const k=`_e2eDmKey(${q(fresh)},${q(networkA)})`;
        await browser.evaluate(`handleEncryptCommand(['off'],${q(networkA)},${q(fresh)})`);
        await waitFor(()=>browser.evaluate(`!E2E._stateSaving&&E2E.state.dm[${k}]?.on===0`),'desktop records the acknowledged off setting');
        await phone.send('Page.reload');
        await waitFor(()=>phone.evaluate(`window._appShown&&E2E.keyReady&&E2E.identityReady&&E2E.state?.dm?.[${k}]?.on===0`).catch(()=>false),
          'phone independently restores the disabled conversation');
        await browser.evaluate(`void handleEncryptCommand(['on',${q(fresh)}],${q(networkA)},${q(fresh)});true`);
        await waitFor(async()=>{
          await Promise.all([browser,device].map(acceptWhenAsked));
          return browser.evaluate(`!!E2E.dmSessions[${k}]?.startEph&&E2E.state.dm[${k}]?.on===1`);
        },'desktop establishes the re-enabled conversation',40000);
        const again='enabled-again-'+stamp;
        await compose(browser,networkA,fresh,again);
        check('the phone with a restored off setting reads the re-enabled conversation before a peer reply',
          await waitFor(()=>row(phone,networkA,fresh,again),'passive phone reads new outgoing message after explicit re-enable',30000));
        check('the remote contact reads the re-enabled message',await waitFor(()=>row(device,id,owner,again),'remote peer reads the new session',30000));
      }
      return;
    }
    const canary='AUDIT-1-0 before disconnect '+stamp;
    await compose(peer,remoteNetwork,owner,canary);
    try {
      check('audit preflight delivers one encrypted canary to both devices',await waitFor(async()=>
        await row(browser,networkA,remote,canary)&&await row(phone,networkA,remote,canary),'both canary rows decrypt',30000));
    } catch(error) {
      const probe=device=>device.evaluate(`({shown:getBuf(${cid},${nick}).some(row=>row.text===${q(canary)}),
        ready:E2E.keyReady,receive:${session}?.Nr,waiting:!!${session}?.x3dhPending,
        warning:getBuf(${cid},${nick}).slice(-3).find(row=>row.text.includes('could not be authenticated'))?.text})`);
      throw new Error(error.message+' '+JSON.stringify(await Promise.all([probe(browser),probe(phone)])));
    }
    if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='simultaneous-devices'){
      const summary=[];
      const senderCount=(m,e)=>e.type==='irc_message'&&e.from===m&&e.text?.startsWith('[e2edm2]');
      const sentWires=(device,at)=>device.frames.slice(at).flatMap(frame=>{
        try { const cmd=JSON.parse(frame);return cmd.type==='send'&&cmd.raw?.includes(' :[e2edm2]')?[cmd.raw.split(' :')[1]]:[]; }
        catch { return []; }
      });
      for(let i=0;i<4;i++){
        const left='desk'+i+'-'+stamp,right='mob'+i+'-'+stamp,answer='ans'+i+'-'+stamp;
        const incoming=remoteWs.events.length,back=ownerWs.events.length;
        const started=[browser.frames.length,phone.frames.length,peer.frames.length];
        await Promise.all([compose(browser,networkA,remote,left),compose(phone,networkA,remote,right)]);
        const texts=[left,right];
        const peerRows=()=>peer.evaluate('getBuf('+q(remoteNetwork)+','+q(owner)+').filter(m=>m.encrypted&&'+q(texts)+'.includes(m.text)).map(m=>m.text)');
        await waitFor(async()=>(await peerRows()).length>=2,'paired sends reach peer',30000).catch(()=>{});
        const visible=await peerRows();
        await compose(peer,remoteNetwork,owner,answer);
        const hasReply=()=>Promise.all([browser,phone].map(b=>row(b,networkA,remote,answer)));
        await waitFor(async()=>(await hasReply()).every(Boolean),'reply delivered to both',30000).catch(()=>{});
        const displayed=await hasReply();
        const siblingViews=()=>Promise.all([row(browser,networkA,remote,right),row(phone,networkA,remote,left)]);
        await waitFor(async()=>(await siblingViews()).every(Boolean),'outgoing messages reach the other open device',10000).catch(()=>{});
        const sibling=await siblingViews();
        const inputs=await Promise.all([browser,phone].map(b=>b.evaluate("document.getElementById('msg-input').value")));
        const typed=[left,right,answer],frames=[browser,phone,peer].flatMap((b,j)=>b.frames.slice(started[j]));
        const outgoing=[...sentWires(browser,started[0]),...sentWires(phone,started[1])];
        const response=sentWires(peer,started[2]);
        const received=remoteWs.events.slice(incoming).filter(e=>senderCount(owner,e)&&outgoing.includes(e.text));
        const observations={
          sentByDevices:outgoing.length,pairedMessages:received.length,
          desktopReadable:visible.filter(text=>text===left).length,
          phoneReadable:visible.filter(text=>text===right).length,
          replyMessages:ownerWs.events.slice(back).filter(e=>senderCount(remote,e)&&response.includes(e.text)).length,
          replyOnDesktop:displayed[0],replyOnPhone:displayed[1],
          mobileSendOnDesktop:sibling[0],desktopSendOnMobile:sibling[1],
          draftStillOnDevice:inputs.map((text,j)=>text===typed[j]),
          plaintextInTransit:frames.some(frame=>typed.some(text=>frame.includes(text))) ||
            [...remoteWs.events.slice(incoming),...ownerWs.events.slice(back)].some(e=>typed.includes(e.text))
        };
        if(visible.length!==2||received.length!==2||!sibling.every(Boolean)) {
          const status=await peer.evaluate(`(()=>{const b=getBuf(${q(remoteNetwork)},${q(owner)});
            const s=E2E.dmSessions[_e2eDmKey(${q(owner)},${q(remoteNetwork)})];
            return {received:s?.Nr,sent:s?.Ns,waiting:!!s?.x3dhPending,rows:b.slice(-7).map(m=>[m.kind,m._dmHistoryState||'',
              m.text?.includes('could not')||m.text?.includes('unavailable')]),errors:${q(peer.errors.slice(-3))}};})()`);
          const number=wire=>JSON.parse(Buffer.from(wire.slice(8),'base64').toString()).h.n;
          console.log('DEVICE-DELIVERY '+JSON.stringify({sent:outgoing.map(number),arrived:received.map(e=>number(e.text)),status}));
        }
        console.log('PAIRED '+(i+1)+' '+JSON.stringify(observations));
        summary.push(observations);
      }
      check('concurrent same-account phone and desktop sends each render exactly once and the peer replies to both',summary.every(r=>
        r.sentByDevices===2&&r.pairedMessages===2&&r.desktopReadable===1&&r.phoneReadable===1&&r.replyMessages===1&&r.replyOnDesktop&&r.replyOnPhone&&!r.plaintextInTransit));
      check('each open device can also read the messages sent by the other device', summary.every(r=>r.mobileSendOnDesktop&&r.desktopSendOnMobile));
      const crossed=['cross-desk-','cross-mobile-','cross-peer-'].map(label=>label+stamp);
      const traffic=[browser.frames.length,phone.frames.length,peer.frames.length];
      await Promise.all([compose(browser,networkA,remote,crossed[0]),compose(phone,networkA,remote,crossed[1]),
        compose(peer,remoteNetwork,owner,crossed[2])]);
      const counts=(device,connection,target,texts)=>device.evaluate(`(() => {
        const rows=getBuf(${q(connection)},${q(target)});
        return ${q(texts)}.map(text=>rows.filter(m=>m.encrypted&&m.text===text).length);
      })()`);
      const complete=async(device,connection,target,texts)=>(await counts(device,connection,target,texts)).every(n=>n===1);
      const allRead=async()=>await complete(peer,remoteNetwork,owner,crossed) &&
        await complete(browser,networkA,remote,crossed) && await complete(phone,networkA,remote,crossed);
      check('incoming and outgoing sends at the same time are readable exactly once on all three displays',
        await waitFor(allRead,'crossed sends rendered on desktop, phone and peer',30000) &&
        ![browser,phone,peer].flatMap((dev,i)=>dev.frames.slice(traffic[i])).some(frame=>crossed.some(text=>frame.includes(text))));
      const repeated='same-text-'+stamp;
      await Promise.all([compose(browser,networkA,remote,repeated),compose(phone,networkA,remote,repeated)]);
      const twoDistinct=(dev,connection,target)=>dev.evaluate(`(()=>{const messages=getBuf(${q(connection)},${q(target)}).filter(
        m=>m.encrypted&&m.text===${q(repeated)});
        return messages.length===2 && new Set(messages.map(m=>m._dmHistoryWire)).size===2 &&
          messages.every(m=>m.id>0) && messages[0].id!==messages[1].id;})()`);
      const checkBoth=async()=>await twoDistinct(browser,networkA,remote)&&await twoDistinct(phone,networkA,remote)&&
        await twoDistinct(peer,remoteNetwork,owner);
      check('identical simultaneous messages retain two distinct ciphertexts and two message IDs on all displays',
        await waitFor(checkBoth,'each device shows both identical messages',30000));
      const expected=[...Array.from({length:4},(_,i)=>['desk'+i+'-'+stamp,'mob'+i+'-'+stamp,'ans'+i+'-'+stamp]).flat(),...crossed];
      for (const device of [browser,phone]) {
        const before=await device.evaluate('performance.timeOrigin');
        await device.send('Page.reload');
        await waitFor(()=>device.evaluate(`performance.timeOrigin!==${before} && window._appShown && _wsReady() &&
          E2E.keyReady && E2E.identityReady`).catch(()=>false),'device reopens unlocked');
        await device.evaluate(`_sidebarActivate(${cid},${nick})`);
        await waitFor(()=>complete(device,networkA,remote,expected),'all own and peer messages survive the reload',30000);
        await waitFor(()=>twoDistinct(device,networkA,remote),'both identical messages survive the reload with their original IDs',30000);
      }
      check('both device profiles reopen their complete simultaneous conversation from encrypted history',true);
      const unsent='retry-once-'+stamp,sendsBefore=remoteWs.events.length;
      await phone.evaluate(`(()=>{
        const request=_e2eReq;
        window.auditUnconfirmedSend=false;
        _e2eReq=async(...args)=>{
          const result=await request(...args);
          if(args[0].type==='e2e_commit_session'&&args[0].snd&&result?.ok){
            window.auditUnconfirmedSend=true;return null;
          }
          return result;
        };
        window.auditRestoreSend=()=>{_e2eReq=request;};
      })()`);
      try {
        await compose(phone,networkA,remote,unsent);
        check('a lost outgoing commit acknowledgment leaves the draft available and emits no IRC message',
          await waitFor(()=>phone.evaluate(`window.auditUnconfirmedSend&&document.getElementById('msg-input').value===${q(unsent)}`),'unconfirmed draft remains editable')&&
          !remoteWs.events.slice(sendsBefore).some(e=>senderCount(owner,e)));
      } finally { await phone.evaluate('window.auditRestoreSend();delete window.auditRestoreSend;delete window.auditUnconfirmedSend'); }
      await compose(phone,networkA,remote,unsent);
      check('retrying the held draft delivers it exactly once',await waitFor(()=>complete(peer,remoteNetwork,owner,[unsent]),'recipient reads the retried draft'));
      for(const problem of ['lost acknowledgment','temporary storage failure']){
        const received=problem+'-'+stamp,next='after-'+received;
        await peer.evaluate(`(()=>{
          const request=_e2eReq, peerKey=_e2eDmKey(${q(owner)},${q(remoteNetwork)});
          window.auditDropAck=0;
          _e2eReq=async(...args)=>{
            if(window.auditDropAck || args[0].type!=='e2e_commit_session' || args[0].partner!==peerKey) return request(...args);
            window.auditDropAck++;
            if(${q(problem)}==='temporary storage failure')return {ok:false,storage_retry:true};
            const result=await request(...args);
            return result?.ok ? null : result;
          };
          window.auditRestoreAck=()=>{_e2eReq=request;};
        })()`);
        try {
          await compose(browser,networkA,remote,received);
          await waitFor(async()=>await peer.evaluate('window.auditDropAck===1')&&await row(peer,remoteNetwork,owner,received),
            'the authenticated message stays readable after '+problem);
          await compose(peer,remoteNetwork,owner,next);
          check(problem+' preserves the verified message and allows the next reply on both devices',
            await waitFor(async()=>await row(browser,networkA,remote,next)&&await row(phone,networkA,remote,next),'both devices read the next reply'));
        } finally { await peer.evaluate('window.auditRestoreAck();delete window.auditRestoreAck;delete window.auditDropAck'); }
      }
      const reorder=['late-zero-','late-one-','early-two-'].map(s=>s+stamp);
      const defer=device=>device.evaluate(`(()=>{
        const original=handleEvent,held=[];
        handleEvent=e=>{
          if(e.type==='irc_message' && e.conn_id===${cid} && e.from===${nick} && e.text?.startsWith('[e2edm2]')) held.push(e);
          else return original(e);
        };
        window.auditDeferred=held;
        window.auditRestoreOrder=()=>{handleEvent=original;};
      })()`);
      await Promise.all([defer(browser),defer(phone)]);
      try {
        for(const text of reorder) await compose(peer,remoteNetwork,owner,text);
        await waitFor(async()=>(await Promise.all([browser,phone].map(b=>b.evaluate('window.auditDeferred.length===3')))).every(Boolean),'all three encrypted messages reached both live sockets',30000);
        await Promise.all([browser,phone].map(b=>b.evaluate('window.auditRestoreOrder();handleEvent(window.auditDeferred[2]);')));
        await waitFor(async()=>await row(browser,networkA,remote,reorder[2])&&await row(phone,networkA,remote,reorder[2]),'both clients authenticate the newest message first',30000);
        await Promise.all([browser,phone].map(b=>b.evaluate('handleEvent(window.auditDeferred[0]);handleEvent(window.auditDeferred[1]);')));
        check('out-of-order receives on two devices preserve skipped keys and show each message once',
          await waitFor(async()=>await complete(browser,networkA,remote,reorder)&&await complete(phone,networkA,remote,reorder),'both devices read the two delayed messages',30000));
      } finally {
        await Promise.all([browser,phone].map(b=>b.evaluate('window.auditRestoreOrder();delete window.auditRestoreOrder;delete window.auditDeferred;')));
      }
      const old=await browser.evaluate(`${session}.startEph`);
      await new Promise(resolve=>setTimeout(resolve,61000)); // A separate key exchange gets a fresh prekey request window.
      await browser.evaluate(`handleEncryptCommand(['restart',${nick}],${cid},${nick})`);
      await waitFor(()=>browser.evaluate(`!!${session}.x3dhPending && ${session}.startEph!==${q(old)}`),'desktop prepares a new session');
      for(const part of ['old-in-flight-1-','old-in-flight-2-']){
        const text=part+stamp;
        await compose(peer,remoteNetwork,owner,text);
        await waitFor(async()=>await row(phone,networkA,remote,text)&&await row(browser,networkA,remote,text),'both devices read the in-flight old-session message');
      }
      const renewed='renewed-'+stamp;
      await compose(browser,networkA,remote,renewed);
      check('a desktop restart preserves in-flight replies on both devices and the new session sends normally',
        await waitFor(()=>row(peer,remoteNetwork,owner,renewed),'peer receives normal traffic on the new session'));
      return;
    }
    const initial=await browser.evaluate(`${session}.startEph`);
    await browser.evaluate(`(() => {
      setActive(${cid},${nick});
      const connect=connectWs, handler=handleEvent;
      window.signalAuditArchive=[];
      handleEvent=event=>{
        if(event.conn_id===${cid}&&event.target===${nick}&&(event.type==='sync_lines'||event.type==='log_lines'))
          window.signalAuditArchive.push(...event.lines.filter(line=>line.text.startsWith('[e2edm2]')).map(line=>line.text));
        return handler(event);
      };
      connectWs=()=>{};
      window.signalAuditResume=()=>{connectWs=connect;_onResume();};
      window.signalAuditCleanup=()=>{handleEvent=handler;};
      ws.close();
    })()`);
    const missed=Array.from({length:5},(_,i)=>`AUDIT-1-${i+1} missed reply ${stamp}`);
    const fromEvent=ownerWs.events.length;
    try {
      await waitFor(()=>browser.evaluate('!_wsReady()'),'only the desktop WebSocket is down');
      for(const text of missed){
        await compose(peer,remoteNetwork,owner,text);
        await waitFor(()=>row(phone,networkA,remote,text),'the live phone decrypts the numbered message');
      }
      const delivered=ownerWs.events.slice(fromEvent).filter(e=>e.from===remote&&e.type==='irc_message').map(e=>e.text);
      check('IRC delivered five ciphertexts while the desktop was absent',delivered.length===5&&delivered.every(text=>text?.startsWith('[e2edm2]')));
      const phoneBefore=await phone.evaluate(`JSON.stringify([${session}.startEph,${session}.Ns,${session}.Nr])`);
      const fromFrame=browser.frames.length;
      await browser.evaluate('window.signalAuditResume()');
      await waitFor(()=>browser.evaluate(`${q(delivered)}.every(text=>window.signalAuditArchive.includes(text))`),
        'the real desktop history response contains all five ciphertexts',30000);
      check('desktop opens all five replies after reconnect without disturbing the phone session',
        await waitFor(()=>browser.evaluate(`JSON.stringify(getBuf(${cid},${nick}).filter(m=>${q(missed)}.includes(m.text)&&m.encrypted)
          .map(m=>m.text))===${q(JSON.stringify(missed))}`),'desktop renders the recorded replies once and in order',30000)&&
        await browser.evaluate(`${session}.startEph`)===initial&&
        await phone.evaluate(`JSON.stringify([${session}.startEph,${session}.Ns,${session}.Nr])`)===phoneBefore&&
        !browser.frames.slice(fromFrame).some(frame=>frame.includes('e2e_fetch_bundle')||frame.includes('[e2ex3dh]')));
    } finally {
      await browser.evaluate('window.signalAuditResume();window.signalAuditCleanup();delete window.signalAuditResume;delete window.signalAuditCleanup');
    }
    return;
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='identity-gap'){
    // Avoid spending the same IRC-host prekey allowance as the setup canary.
    await new Promise(resolve=>setTimeout(resolve,61000));
    const cid=q(networkA), nick=q(remote), key=`_e2eDmKey(${nick},${cid})`;
    const peerCid=q(remoteNetwork), own=q(owner), peerKey=`_e2eDmKey(${own},${peerCid})`;
    await peer.evaluate(`handleEncryptCommand(['restart',${own}],${peerCid},${own})`);
    const replayedPeerOffer=await waitFor(()=>peer.evaluate(`E2E.dmSessions[${peerKey}]?.x3dhPending`),
      'the peer prepares its own signed offer on the old identity',35000);
    const earlier='AUDIT-2-P previously authenticated peer setup '+stamp;
    await compose(peer,remoteNetwork,owner,earlier);
    await waitFor(async()=>await row(browser,networkA,remote,earlier)&&
      browser.evaluate(`E2E.dmSessions[${key}]?.establishEph===${q(replayedPeerOffer.ephemeral_pub)}`),
      'the local device authenticates and installs the original peer offer');
    await new Promise(resolve=>setTimeout(resolve,61000));
    const original=await browser.evaluate(`({start:E2E.dmSessions[${key}].startEph,pin:E2E.trustStore[${key}].fingerprint})`);
    const held='AUDIT-2-Q draft queued before identity replacement '+stamp;
    const archived='AUDIT-2-1 message under replacement identity '+stamp;
    const live='AUDIT-2-2 live replacement identity message '+stamp;
    await browser.evaluate(`(() => {
      const connect=connectWs,drain=drainRateQueue,handler=handleEvent;
      window.identityAuditArchive=[];
      let deaf=true;
      handleEvent=event=>{
        if(deaf&&event.type==='irc_message'&&event.conn_id===${cid}&&event.from===${nick})return;
        if(event.conn_id===${cid}&&event.target===${nick}&&(event.type==='sync_lines'||event.type==='log_lines'))
          window.identityAuditArchive.push(...event.lines.map(line=>line.text));
        return handler(event);
      };
      drainRateQueue=()=>{};
      window.disconnectIdentityAudit=()=>{connectWs=()=>{};ws.close();};
      window.resumeIdentityAudit=()=>{deaf=false;connectWs=connect;_onResume();};
      window.finishIdentityAudit=()=>{drainRateQueue=drain;handleEvent=handler;_kickRateQueue();};
    })()`);
    try {
      await compose(browser,networkA,remote,held);
      const oldWire=await waitFor(()=>browser.evaluate(`_rateQueue.find(p=>p.raw.includes(' :[e2edm2]'))?.raw`),
        'the pre-rotation draft is encrypted and waiting in the application queue');
      await peer.evaluate(`(async()=>{
        const confirm=window.confirm;
        window.confirm=()=>true;
        try { await handleEncryptCommand(['reset-identity'],${peerCid},${own}); }
        finally { window.confirm=confirm; }
      })()`);
      await waitFor(()=>peer.evaluate(`E2E.identityReady&&!E2E.dmSessions[${peerKey}]`),'the disposable peer has published a separate identity');
      await peer.evaluate(`handleEncryptCommand(['on',${own}],${peerCid},${own})`);
      try {
        await waitFor(()=>peer.evaluate(`!!E2E.dmSessions[${peerKey}]?.x3dhPending&&!E2E._pendingOn[${peerKey}]`),
          'the peer prepares Signal with its replacement identity',35000);
      } catch(error) {
        const state=await peer.evaluate(`getBuf(${peerCid},${own}).slice(-6).filter(row=>row.from==='—'||row.kind==='system').map(row=>row.text)`);
        throw new Error(error.message+' '+JSON.stringify(state));
      }
      await browser.evaluate('window.disconnectIdentityAudit()');
      await waitFor(()=>browser.evaluate('!_wsReady()'),'the desktop is disconnected before the new identity sends');
      const start=ownerWs.events.length;
      await peer.evaluate(`for(const wire of _e2eHeaderLines(${q(replayedPeerOffer)},${own},${peerCid})){
        rateLimitedSend({type:'send',conn_id:${peerCid},raw:'PRIVMSG '+${own}+' :'+wire});
      }`);
      await compose(peer,remoteNetwork,owner,archived);
      const record=await waitFor(()=>ownerWs.events.slice(start).find(e=>e.type==='irc_message'&&e.from===remote&&e.text?.startsWith('[e2edm2]'))?.text,
        'the replacement identity ciphertext crosses IRC while the desktop is offline');
      await browser.evaluate('window.resumeIdentityAudit()');
      await waitFor(()=>browser.evaluate(`window.identityAuditArchive.includes(${q(record)})&&getBuf(${cid},${nick}).some(
        row=>row._dmHistoryWire===${q(record)})`),'the exact replacement-identity ciphertext reaches desktop history');
      await browser.evaluate(`_e2eEnqueue(${cid},${nick},()=>{})`);
      check('history and the used offer leave the old pinned identity and session intact',
        !await row(browser,networkA,remote,archived)&&await browser.evaluate(`E2E.trustStore[${key}].fingerprint===${q(original.pin)}&&
          E2E.dmSessions[${key}].startEph===${q(original.start)}`));
      await peer.evaluate(`delete E2E._hdrSent[${peerKey}]`);
      await compose(peer,remoteNetwork,owner,live);
      await waitFor(()=>browser.evaluate(`E2E.trustStore[${key}].keyChanged`),'a live signed offer shows the identity dispute');
      const sentAt=browser.frames.length;
      await browser.evaluate('window.finishIdentityAudit()');
      await waitFor(()=>browser.evaluate('_rateQueue.length===0'),'the desktop resolves the pre-rotation queued frame');
      check('a queued draft is withheld after the recipient identity changes',
        !browser.frames.slice(sentAt).some(frame=>JSON.parse(frame).raw===oldWire||frame.includes(held))&&
        !await row(browser,networkA,remote,live));
    } finally {
      await browser.evaluate(`window.resumeIdentityAudit();window.finishIdentityAudit();delete window.disconnectIdentityAudit;
        delete window.resumeIdentityAudit;delete window.finishIdentityAudit`);
    }
    return;
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_AUDIT==='mixed-split'){
    const ctl=action=>promisify(execFile)(process.env.CRYPTIRC_TEST_IRC_LINK_CTL,[action],{timeout:25000});
    check('the split test has a patched desktop and previous-release peer',
      !!process.env.CRYPTIRC_PEER_BIN&&!!process.env.CRYPTIRC_TEST_IRC_LINK_CTL&&
      await browser.evaluate("typeof e2eRetryQueuedDm==='function'")&&
      !await peer.evaluate("typeof e2eRetryQueuedDm==='function'"));
    await new Promise(resolve=>setTimeout(resolve,61000));
    const cid=q(networkA), nick=q(remote), key=`_e2eDmKey(${nick},${cid})`;
    const startEph=`E2E.dmSessions[${key}].startEph`;
    const before=await browser.evaluate(startEph);
    const queued='AUDIT-3-1 queued across an IRC link outage '+stamp;
    const fromPhone='AUDIT-3-0 phone starts the new session '+stamp;
    const phone=await chromium('signal-audit-split-phone');
    const beforeWire=browser.frames.length;
    await browser.evaluate(`(() => {
      if(_rateQueue.length) throw new Error('Expected an empty send queue');
      const drain=drainRateQueue;
      drainRateQueue=()=>{};
      window.releaseSplitAudit=()=>{drainRateQueue=drain;_kickRateQueue();};
    })()`);
    try {
      await compose(browser,networkA,remote,queued);
      const oldWire=await waitFor(()=>browser.evaluate(`_rateQueue.find(p=>p.raw.includes(' :[e2edm2]'))?.raw`),
        'the desktop has an encrypted frame queued before the netsplit');
      await ctl('split');
      await login(phone,owner,password,waitFor);
      await waitFor(()=>phone.evaluate('E2E._vaultUp&&E2E._krReceived'),'phone signs in while the test IRC link is down');
      await phone.evaluate('void e2ePromptDeviceUnlock()');
      await waitPrompt(phone,waitFor,unlockText);
      await fillPrompt(phone,ownerCode);
      await waitFor(()=>phone.evaluate(`E2E.identityReady&&_wsReady()&&${startEph}===${q(before)}`),
        'phone restores the pinned session while the link is split');
      await ctl('down');
      await ctl('heal');
      await phone.evaluate(`handleEncryptCommand(['restart',${nick}],${cid},${nick})`);
      let changed;
      try {
        changed=await waitFor(()=>phone.evaluate(`${startEph}!==${q(before)}&&!E2E._pendingOn[${key}]&&${startEph}`),
          'the phone prepares a replacement Signal session on the restored link',35000);
      } catch(error) {
        const state=await phone.evaluate(`getBuf(${cid},${nick}).slice(-6).filter(row=>row.from==='—'||row.kind==='system').map(row=>row.text)`);
        throw new Error(error.message+' '+JSON.stringify(state));
      }
      await compose(phone,networkA,remote,fromPhone);
      await waitFor(()=>row(peer,remoteNetwork,owner,fromPhone),'the previous release reads the phone canary across the restored link');
      await waitFor(()=>browser.evaluate(`${startEph}===${q(changed)}`),'the desktop adopts the confirmed new sending state');
      const atPeer=remoteWs.events.length;
      await browser.evaluate('window.releaseSplitAudit()');
      await waitFor(()=>row(peer,remoteNetwork,owner,queued),'the previous release reads the queued desktop encrypt after relink');
      check('mixed builds deliver the queued Signal message once after a real IRC netsplit and relink',
        await peer.evaluate(`getBuf(${q(remoteNetwork)},${q(owner)}).filter(m=>m.text===${q(queued)}&&m.encrypted).length===1`)&&
        remoteWs.events.slice(atPeer).filter(e=>e.from===owner&&e.text?.startsWith('[e2edm2]')).length===1&&
        !browser.frames.slice(beforeWire).some(frame=>JSON.parse(frame).raw===oldWire||frame.includes(queued)));
    } finally {
      await ctl('heal');
      await browser.evaluate('window.releaseSplitAudit();delete window.releaseSplitAudit');
    }
    return;
  }
  if(process.env.CRYPTIRC_TEST_SIGNAL_QUEUE_RECOVERY==='1'){
    // Model a suspended phone missing the live WebSocket items. The server still
    // receives and logs both real IRC messages, without any fresh X3DH frames.
    const missed=['missed established reply one '+stamp,'missed established reply two '+stamp];
    const start=ownerWs.events.length;
    await browser.evaluate(`(() => {
      setActive(${q(networkA)},${q(remote)});
      const connect=connectWs;
      connectWs=()=>{};
      window.resumeFixture=()=>{connectWs=connect;_onResume();};
      ws.close();
    })()`);
    await waitFor(()=>browser.evaluate('!_wsReady()'),'phone WebSocket is disconnected');
    let traffic;
    try {
      for(const text of missed) await compose(peer,remoteNetwork,owner,text);
      traffic=await waitFor(()=>{
        const events=ownerWs.events.slice(start).filter(e=>e.type==='irc_message'&&e.from===remote);
        return events.filter(e=>e.text?.startsWith('[e2edm2]')).length===2&&events;
      },'two established-session ciphertexts reach the first IRC core');
      check('the suspended phone missed both live messages while IRC logged only ciphertext',
        traffic.length===2&&traffic.every(e=>e.text.startsWith('[e2edm2]'))&&
        !(await Promise.all(missed.map(text=>row(browser,networkA,remote,text)))).some(Boolean));
    } finally { await browser.evaluate('window.resumeFixture();delete window.resumeFixture'); }
    const history=traffic.map(e=>({id:e.msg_id,ts:e.ts,from:e.from,kind:'privmsg',text:e.text}));
    check('reconnect history opens two missed Signal replies without a new handshake',
      await waitFor(async()=>(await Promise.all(missed.map(text=>row(browser,networkA,remote,text)))).every(Boolean),
        'both missed messages become readable after history sync',30000));
    await browser.evaluate(`prependLogs(${q(networkA)},${q(remote)},${q(history)})`);
    check('replaying the same history does not create duplicate Signal rows',await browser.evaluate(`(() => {
      const rows=getBuf(${q(networkA)},${q(remote)});
      return ${q(missed)}.every(text=>rows.filter(row=>row.text===text&&row.encrypted).length===1);
    })()`));
    const next='reply after reconnect catch-up '+stamp;
    await compose(browser,networkA,remote,next);
    check('the peer still decrypts replies after the device catches up from history',
      await waitFor(()=>row(peer,remoteNetwork,owner,next),'reply after history catch-up'));
  }
  if(mixedFirst)await peer.evaluate(`(async()=>{
    if(!await removeChannelKey(${mixedName},[${mixedName}]))throw new Error('Could not remove the shared-key fixture');
    _e2eStateOp('dm',${mixedKey},entry=>({on:1,n:(entry.n|0)+1}));
  })()`);
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:first,target:'cross-instance PM',emoji:'❤️'});
  }
  const remoteTarget=q(remote), localConn=q(networkA);
  check('the encryption panel recognizes a network-scoped Signal session',await browser.evaluate(`(() => {
    setActive(${localConn},${remoteTarget});
    showEncryptPanel();
    const body=document.getElementById('encrypt-panel-body');
    const result=body.textContent.includes('Signal encryption')&&!!body.querySelector('[data-encrypt-cmd=restart]');
    closeEncryptPanel();
    return result;
  })()`));
  const beforeBlockedRestart=browser.frames.length;
  check('Signal setup and restart preserve a configured DM shared key',await browser.evaluate(`(async () => {
    const target=${remoteTarget}, cid=${localConn}, key=_e2eCanon(target,cid);
    const signal=E2E.dmSessions[_e2eDmKey(target,cid)];
    const {key:shared}=await generateChannelKey();
    E2E.channelKeys[key]=shared;
    try {
      await handleEncryptCommand(['on',target],cid,target);
      await handleEncryptCommand(['restart',target],cid,target);
      return E2E.channelKeys[key]===shared&&E2E.dmSessions[_e2eDmKey(target,cid)]===signal&&
        !E2E._pendingOn?.[_e2eDmKey(target,cid)]&&
        getBuf(cid,target).some(row=>row.text.includes('A shared key is configured'));
    } finally {delete E2E.channelKeys[key];}
  })()`));
  check('refusing mixed encryption sends no bundle request',
    !browser.frames.slice(beforeBlockedRestart).some(frame=>JSON.parse(frame).type==='e2e_fetch_bundle'));
  check('the panel identifies a configured shared key missing on this device',await browser.evaluate(`(() => {
    const target=${remoteTarget}, cid=${localConn}, name=_e2eCanon(target,cid);
    E2E.state.ch[name]={on:1,g:1};
    try {
      showEncryptPanel();
      const body=document.getElementById('encrypt-panel-body');
      return body.textContent.includes('The shared key is missing')&&!body.querySelector('[data-encrypt-cmd=restart]');
    } finally {delete E2E.state.ch[name]; closeEncryptPanel();}
  })()`));
  const localSharedKey=`_e2eCanon(${remoteTarget},${localConn})`;
  const peerSharedKey=`_e2eCanon(${q(owner)},${q(remoteNetwork)})`;
  await Promise.all([
    browser.evaluate(`(async()=>{E2E.channelKeys[${localSharedKey}]=(await generateChannelKey()).key})()`),
    peer.evaluate(`(async()=>{E2E.channelKeys[${peerSharedKey}]=(await generateChannelKey()).key})()`),
  ]);
  try {
    const wrongKey='shared-key fixture with mismatched keys '+stamp;
    const messagesAt=ownerWs.events.length;
    await compose(peer,remoteNetwork,owner,wrongKey);
    check('a mismatched shared-key DM reports the mode and stays encrypted on IRC',
      await waitFor(()=>browser.evaluate(`getBuf(${localConn},${remoteTarget}).some(
        m=>m.from===${remoteTarget}&&m.text.includes('Shared-key message could not be opened'))`),'shared-key mismatch is readable')&&
      !ownerWs.events.some(e=>e.text?.includes(wrongKey)));
    const wire=ownerWs.events.slice(messagesAt).find(e=>e.type==='irc_message'&&e.from===remote&&e.text?.startsWith('sd8~'))?.text;
    const historyAt=remoteWs.events.length;
    remoteWs.send({type:'get_logs',conn_id:remoteNetwork,target:owner,limit:30});
    const archivedShared=await waitFor(()=>remoteWs.events.slice(historyAt)
      .find(event=>event.type==='log_lines'&&event.conn_id===remoteNetwork&&event.target===owner&&event.lines?.some(line=>line.text===wire))
      ?.lines.find(line=>line.text===wire),'shared-key echo with its originally addressed nick');
    check('shared-key history uses the recorded IRC recipient after our nick changes',
      archivedShared.irc_recipient===owner&&await peer.evaluate(`(async()=>{
        const cid=${q(remoteNetwork)}, net=networks.find(n=>n.config.id===cid), current=net.nick;
        net.nick=current+'-changed';
        try {
          const [row]=await _decryptLogLines(${q(owner)},[${q(archivedShared)}],cid);
          return row._pskHistoryState==='ready'&&row.text===${q(wrongKey)};
        } finally {net.nick=current;}
      })()`));
    check('history shows a readable shared-key failure while retaining the encrypted row',!!wire&&await browser.evaluate(`(async()=>{
      const [row]=await _decryptLogLines(${remoteTarget},[{id:2600,ts:1,from:${remoteTarget},kind:'privmsg',text:${q(wire)}}],${localConn});
      return row.encrypted&&row._pskHistoryWire===${q(wire)}&&row._pskHistoryState==='needs-key'&&
        row.text.includes('Check the shared key and IRC conversation')&&!row.text.includes('sd8~');
    })()`));
    check('history displays a locked shared-key row and decrypts it while unlocked',await peer.evaluate(`(async()=>{
      const line={id:2600,ts:1,from:${remoteTarget},kind:'privmsg',text:${q(wire)}};
      const decoded=await _decryptLogLines(${q(owner)},[line],${q(remoteNetwork)});
      const hiddenAction=pskHistoryRow({...decoded[0],kind:'action'},undefined,false);
      const restored=await _decryptPskHistoryRow(${q(owner)},hiddenAction,${q(remoteNetwork)},true);
      const ready=E2E.keyReady;
      let locked;
      try{E2E.keyReady=false;locked=await _decryptLogLines(${q(owner)},[line],${q(remoteNetwork)});}
      finally{E2E.keyReady=ready;}
      return decoded[0].text===${q(wrongKey)}&&locked[0]._pskHistoryState==='locked'&&locked[0].text.includes('Unlock')&&
        hiddenAction.kind==='privmsg'&&!hiddenAction.text.includes(${q(wrongKey)})&&
        restored.text===${q(wrongKey)}&&(!reactionEnabled(${q(remoteNetwork)})||restored.reactionRef===await hashChatReactionReference(${q(wire)}));
    })()`));
    check('wrong-sender history stays refused and a literal sd8~ prefix stays readable',await peer.evaluate(`(async()=>{
      const [refused,literal]=await _decryptLogLines(${q(owner)},[
        {id:2601,ts:1,from:'OtherNick',kind:'privmsg',text:${q(wire)}},
        {id:2602,ts:1,from:${remoteTarget},kind:'privmsg',text:'sd8~ example'}
      ],${q(remoteNetwork)});
      return ['refused','needs-key'].includes(refused._pskHistoryState)&&!refused.text.includes(${q(wrongKey)})&&
        !refused.text.includes('sd8~')&&literal.text==='sd8~ example';
    })()`));
    const otherEventCount=otherWs.events.length;
    await peer.evaluate(`setActive(${q(remoteNetwork)},'status')`);
    await browser.evaluate(`setActive(${localConn},${remoteTarget});showEncryptPanel()`);
    await clickVisible(browser,'[data-encrypt-cmd="suggest-signal"]');
    await remoteWs.wait(e=>e.type==='e2e_signal_suggestion'&&!e.sent&&e.conn_id===remoteNetwork&&e.nick===owner,
      'Signal suggestion reaches the real linked peer privately');
    check('a Signal suggestion marks only the private conversation unread',await waitFor(()=>peer.evaluate(`
      active?.target==='status'&&unread.has(bk(${q(remoteNetwork)},${q(owner)}))&&
      getBuf(${q(remoteNetwork)},${q(owner)}).some(m=>m.e2eSetupAction==='method-request')&&
      !getBuf(${q(remoteNetwork)},'status').some(m=>m.e2eSetupAction==='method-request')`),'suggestion stays in the DM'));
    check('a Signal suggestion leaves the recipient on their shared key and opens no popup',await peer.evaluate(`
      e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='psk'&&!(${promptOpen})`)&&
      !otherWs.events.slice(otherEventCount).some(e=>e.type==='e2e_signal_suggestion'));
    const choose='[data-encrypt-cmd="use-signal"]';
    const methodDialog='[role=alertdialog][aria-label="Confirm encryption method"]';
    const confirmation=`[...document.querySelectorAll('${methodDialog} button')].find(button=>button.textContent==='Use Signal')`;
    check('sending a Signal suggestion does not switch the sender’s shared key',await browser.evaluate(`
      e2eTargetState(${remoteTarget},{conn_id:${localConn}}).mode==='psk'`));
    await clickVisible(browser,choose);
    await waitFor(()=>browser.evaluate(`!!(${confirmation})`),'sender also confirms the Signal method');
    await browser.evaluate(`(${confirmation}).click()`);
    await waitFor(()=>browser.evaluate(`e2eTargetState(${remoteTarget},{conn_id:${localConn}}).mode==='dm'`),'sender selected Signal');
    await browser.evaluate('closeEncryptPanel()');
    await peer.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:3,mobile:true});
    await peer.send('Emulation.setTouchEmulationEnabled',{enabled:true});
    await peer.evaluate(`(document.querySelector('#pwa-banner .pwa-b-x')||document.querySelector('#pwa-banner .pwa-b-btn'))?.click();
      setActive(${q(remoteNetwork)},${q(owner)});closeSidebar()`);
    await waitFor(()=>peer.evaluate(`!document.getElementById('pwa-banner')&&
      document.getElementById('sidebar').getBoundingClientRect().right<=2`),'mobile overlays settle before tapping the conversation');
    const reviewButton='#chat-area [data-e2e-method="review"]';
    await waitFor(()=>peer.evaluate(`!!document.querySelector(${q(reviewButton)})`),'recipient can review the Signal suggestion');
    await clickVisible(peer,reviewButton,true);
    await clickVisible(peer,choose,true);
    await waitFor(()=>peer.evaluate(`!!(${confirmation})`),'Signal switch requires confirmation');
    await peer.evaluate(`(${confirmation}).previousElementSibling.click()`);
    await waitFor(()=>peer.evaluate(`!(${confirmation})`),'Cancel dismissed the encryption confirmation');
    check('Cancel leaves the shared key selected',await peer.evaluate(`e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='psk'`));
    await peer.evaluate(`window.testRetainedSharedKey=E2E.channelKeys[${peerSharedKey}];showEncryptPanel()`);
    await clickVisible(peer,choose,true);
    await waitFor(()=>peer.evaluate(`!!(${confirmation})`),'second Signal switch confirmation');
    await peer.evaluate(`(${confirmation}).click()`);
    check('choosing Signal retains the shared key for older messages and switches new sends',await waitFor(()=>peer.evaluate(`
      E2E.channelKeys[${peerSharedKey}]===window.testRetainedSharedKey&&
      e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='dm'`),'Signal selected with old key present'));
    await peer.evaluate('closeEncryptPanel();delete window.testRetainedSharedKey');
    const afterChoice='Signal after choosing an encryption method '+stamp;
    await compose(peer,remoteNetwork,owner,afterChoice);
    check('the switched peer sends readable Signal messages without a plaintext copy',
      await waitFor(()=>row(browser,networkA,remote,afterChoice),'peer decrypts after switching to Signal')&&
      !ownerWs.events.some(e=>e.text?.includes(afterChoice)));
    await peer.evaluate('showEncryptPanel()');
    await clickVisible(peer,'[data-encrypt-cmd="use-shared-key"]',true);
    const confirmShared=`[...document.querySelectorAll('${methodDialog} button')].find(button=>button.textContent==='Use shared key')`;
    await waitFor(()=>peer.evaluate(`!!(${confirmShared})`),'returning to the saved key requires confirmation');
    await peer.evaluate(`(${confirmShared}).click()`);
    check('explicit confirmation can switch back to the retained shared key',await waitFor(()=>peer.evaluate(`
      e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='psk'`),'shared-key mode restored'));
    await peer.evaluate('showEncryptPanel()');
    await clickVisible(peer,choose,true);
    await waitFor(()=>peer.evaluate(`!!(${confirmation})`),'returning to Signal requires confirmation');
    await peer.evaluate(`(${confirmation}).click()`);
    await waitFor(()=>peer.evaluate(`e2eTargetState(${q(owner)},{conn_id:${q(remoteNetwork)}}).mode==='dm'`),'Signal mode restored');
    await peer.evaluate('closeEncryptPanel()');
  } finally {
    await Promise.all([
      browser.evaluate(`delete E2E.channelKeys[${localSharedKey}]`),
      peer.evaluate(`delete E2E.channelKeys[${peerSharedKey}]`),
      peer.send('Emulation.clearDeviceMetricsOverride'),
    ]);
    await peer.send('Emulation.setTouchEmulationEnabled',{enabled:false});
  }

  await browser.send('Emulation.setDeviceMetricsOverride', {width:390,height:844,deviceScaleFactor:3,mobile:true});
  await browser.send('Emulation.setTouchEmulationEnabled', {enabled:true});
  // The setup probe counted toward the bridge's rolling lookup limit.
  if(onboardingWindowEnds>Date.now())await new Promise(resolve=>setTimeout(resolve,onboardingWindowEnds-Date.now()));
  const readyToRestart=await browser.evaluate(`(async () => {
    const target=${remoteTarget}, cid=${localConn}, key=_e2eDmKey(target,cid);
    window.testBeforeRestart={
      start:E2E.dmSessions[key].startEph,
      pin:E2E.trustStore[key].fingerprint,
      queued:await e2eEncryptOutgoing(target,'message queued before restart',cid),
    };
    setActive(cid,target);
    showEncryptPanel();
    return !!document.querySelector('#encrypt-panel-body [data-encrypt-cmd=restart]');
  })()`);
  check('a Signal chat can restart from its encryption panel at iPhone dimensions',readyToRestart);
  await clickVisible(browser,'#encrypt-panel-body [data-encrypt-cmd=restart]',true);
  await waitFor(()=>browser.evaluate(`(() => {
    const key=_e2eDmKey(${remoteTarget},${localConn}), session=E2E.dmSessions[key];
    return !!session?.startEph&&session.startEph!==window.testBeforeRestart.start&&!!session.x3dhPending&&!!session.restartPrev&&!E2E._pendingOn[key];
  })()`),'restart prepared a fresh Signal session');
  check('Signal restart preserves the pin and rejects ciphertext queued under the old session',
    await browser.evaluate(`(() => {
      const target=${remoteTarget},cid=${localConn},key=_e2eDmKey(target,cid);
      const before=window.testBeforeRestart;
      delete window.testBeforeRestart;
      closeEncryptPanel();
      return E2E.trustStore[key].fingerprint===before.pin&&
        e2eQueuedWireVerdict(target,cid,before.queued)?.refuse===true&&
        document.getElementById('e2e-lock').title.includes('reply');
    })()`));
  const beforeRepeatedRestart=browser.frames.length;
  const sameOffer=await browser.evaluate(`(async () => {
      const target=${remoteTarget},cid=${localConn},key=_e2eDmKey(target,cid);
      const session=E2E.dmSessions[key];
      (E2E._hdrSent ||= Object.create(null))[key]={ephemeral:session.x3dhPending.ephemeral_pub,at:Date.now()};
      await handleEncryptCommand(['restart',target],cid,target);
      // Rechecking the device copy can deserialize the same saved session.
      const current=E2E.dmSessions[key],fallback=current?.restartPrev;
      return current?.startEph===session.startEph && current?._storeRevision===session._storeRevision &&
        current?.x3dhPending?.ephemeral_pub===session.x3dhPending.ephemeral_pub && !E2E._pendingOn[key]&&!E2E._hdrSent[key]&&
        fallback && !fallback.CKs&&!fallback.recent&&fallback.until>Date.now() &&
        getBuf(cid,target).some(row=>row.text.includes('Your next message will retry the key exchange.'));
    })()`);
  check('repeated restart taps retry the existing handshake without fetching more prekeys',sameOffer &&
    !browser.frames.slice(beforeRepeatedRestart).map(JSON.parse).some(f=>f.type==='e2e_fetch_bundle'||f.type==='e2e_commit_session'));
  await browser.send('Emulation.clearDeviceMetricsOverride');
  await browser.send('Emulation.setTouchEmulationEnabled', {enabled:false});
  await reopen(browser,waitFor,'window._appShown && E2E.keyReady && E2E.identityReady',
    'same device reopens during an unconfirmed Signal restart');
  const framesBeforeFallback=browser.frames.length;
  for (const index of [1,2]) {
    const inFlight='encrypted reply already in flight at restart '+index+' '+stamp;
    await compose(peer,remoteNetwork,owner,inFlight);
    check('the old receive session opens in-flight reply '+index+' during restart',
      await waitFor(()=>row(browser,networkA,remote,inFlight),'old-session reply arrives during a restart'));
  }
  check('an older reply cannot confirm the new session',await browser.evaluate(`(() => {
    const session=E2E.dmSessions[_e2eDmKey(${remoteTarget},${localConn})];
    return !!session.x3dhPending&&!!session.restartPrev;
  })()`));
  check('receiving on the previous session never republishes the primary session',
    !browser.frames.slice(framesBeforeFallback).some(frame=>{
      const message=JSON.parse(frame);
      return message.type==='e2e_commit_session'&&message.partner===`@${networkA}:${remote}`;
    }));
  const restarted='first encrypted message after restart '+stamp;
  const restartEventIndex=remoteWs.events.length;
  if(mixedFirst){
    await peer.evaluate(`(() => {
      window.testOriginalDmReceive=e2eDecryptIncoming;
      window.testOriginalDmEvent=handleEvent;
      window.testDelayedOffers=[];
      const previous=${q(priorOffer)};
      (E2E._pendingIncomingX3DH ||= Object.create(null))[${mixedKey}]=previous;
      _e2ePendHdrAt.set(previous,Date.now());
      _e2eHeaderNetworks.set(previous,${q(remoteNetwork)});
      handleEvent=event=>{
        if(event.conn_id===${q(remoteNetwork)}&&event.target===${q(owner)}&&
          (event.type==='sync_lines'||event.type==='log_lines'))return;
        return window.testOriginalDmEvent(event);
      };
      e2eDecryptIncoming=(from,target,text,opts)=>{
        if(from===${q(owner)}&&opts.conn_id===${q(remoteNetwork)}&&text.startsWith('[e2ex3dh]')){
          window.testDelayedOffers.push([from,target,text,opts]);
          return Promise.resolve({plaintext:null,encrypted:false});
        }
        return window.testOriginalDmReceive(from,target,text,opts);
      };
    })()`);
  }
  try {
    await compose(browser,networkA,remote,restarted);
    if(mixedFirst){
      const restartWire=await waitFor(()=>remoteWs.events.slice(restartEventIndex).find(e=>e.type==='irc_message'&&
        e.from===owner&&e.text?.startsWith('[e2edm2]'))?.text,'restart ciphertext crossed IRC');
      try {
        check('a restart ciphertext arriving before its offer waits without changing the established session',
          await waitFor(()=>peer.evaluate(`window.testDelayedOffers.length>=2&&E2E._orphans?.[${mixedKey}]?.some(
            item=>_e2eDmHistoryWires.get(item.envelope)?.text===${q(restartWire)})&&!!E2E.dmSessions[${mixedKey}]&&
            getBuf(${q(remoteNetwork)},${q(owner)}).some(m=>m._dmHistoryState==='pending'&&m._dmHistoryWire===${q(restartWire)})`),
            'restart ciphertext waits while its setup fragments are delayed'));
        check('a previously used handshake offer is cleared while the new message waits',
          await peer.evaluate(`!_e2ePendingHeader(${mixedKey})`));
      } catch(error) {
        const state=await peer.evaluate(`({fragments:window.testDelayedOffers.length,offer:!!_e2ePendingHeader(${mixedKey}),
          held:E2E._orphans?.[${mixedKey}]?.length||0,
          row:getBuf(${q(remoteNetwork)},${q(owner)}).find(m=>m._dmHistoryWire===${q(restartWire)})?._dmHistoryState,
          readable:getBuf(${q(remoteNetwork)},${q(owner)}).some(m=>m.text===${q(restarted)})})`);
        throw new Error(error.message+' '+JSON.stringify(state));
      }
      if(process.env.CRYPTIRC_TEST_SIGNAL_HISTORY_RECOVERY==='1'){
        const recorded = remoteWs.events.slice(restartEventIndex).filter(e=>e.type==='irc_message'&&e.from===owner&&
          /^(?:\[e2ex3dh\]|\[e2edm2\])/.test(e.text||'')).map(e=>({id:e.msg_id||0,ts:e.ts,from:e.from,kind:'privmsg',text:e.text}));
        const beforeRecovery=peer.frames.length;
        check('the IRC transport captured the full missed setup and ciphertext',recorded.length>=3);
        const lastFragment=recorded.findLast(line=>line.text.startsWith('[e2ex3dh]'));
        const incomplete=recorded.filter(line=>line!==lastFragment);
        await peer.evaluate(`e2eDecryptIncoming=window.testOriginalDmReceive;
          prependLogs(${q(remoteNetwork)},${q(owner)},${q(incomplete)})`);
        await peer.evaluate(`_e2eEnqueue(${q(remoteNetwork)},${q(owner)},()=>{})`);
        check('incomplete setup in scrollback does not authenticate the held ciphertext',
          !await row(peer,remoteNetwork,owner,restarted));
        await peer.evaluate(`prependLogs(${q(remoteNetwork)},${q(owner)},${q([lastFragment])})`);
        check('trusted Signal chats recover automatically when the missed setup appears in scrollback',
          await waitFor(()=>row(peer,remoteNetwork,owner,restarted),'trusted automatic recovery')&&
          !peer.frames.slice(beforeRecovery).some(frame=>JSON.parse(frame).type==='e2e_fetch_bundle')&&
          await peer.evaluate("!document.querySelector('#e2e-id-accept')"));
      } else {
        await peer.evaluate(`(async()=>{
          e2eDecryptIncoming=window.testOriginalDmReceive;
          for(const args of window.testDelayedOffers)await e2eDecryptIncoming(...args);
        })()`);
      }
    }
  } finally {
    if(mixedFirst)await peer.evaluate(`e2eDecryptIncoming=window.testOriginalDmReceive;handleEvent=window.testOriginalDmEvent;
      delete window.testOriginalDmReceive;delete window.testOriginalDmEvent;delete window.testDelayedOffers`);
  }
  await waitFor(()=>row(peer,remoteNetwork,owner,restarted),'peer decrypts after Signal restart');
  const restartedReply='encrypted reply after restart '+stamp;
  await compose(peer,remoteNetwork,owner,restartedReply);
  check('the re-established cross-instance session decrypts in both directions',
    await waitFor(()=>row(browser,networkA,remote,restartedReply),'peer replies after Signal restart'));
  check('a reply under the new session discards the previous receive keys',await browser.evaluate(`(() => {
    const session=E2E.dmSessions[_e2eDmKey(${remoteTarget},${localConn})];
    return !session.x3dhPending&&!session.restartPrev;
  })()`));
  check('the linked IRC testnet receives only ciphertext after restart',
    !remoteWs.events.some(e=>e.text?.includes(restarted))&&!ownerWs.events.some(e=>e.text?.includes(restartedReply)));
  const bridgeReplyWindowEnds=Date.now()+61000;
  check('bridge discovery is private to the intended IRC users',!otherWs.events.some(e=>e.type==='e2e_bundle'&&e.username===remote));
  const alternate = 'deadbeef-1234-4cce-8b52-555555555555';
  check('a cross-instance session and pin are isolated from the same nick on another network',await browser.evaluate(`
    e2eTargetState(${q(remote)},{conn_id:${q(networkA)}}).mode==='dm' &&
    e2eTargetState(${q(remote)},{conn_id:${q(alternate)}}).mode==='none' &&
    !E2E.trustStore[_e2eDmKey(${q(remote)},${q(alternate)})]`));
  check('scoped encrypted chat fails closed without its network',await browser.evaluate(
    `e2eTargetState(${q(remote)}).mode==='blocked'`));
  check('a legacy pin alone does not turn a new conversation into a global session',await browser.evaluate(`(() => {
    const nick=${q(remote)};
    E2E.trustStore[nick]={fingerprint:'legacy test pin'};
    try { return _e2eDmKey(nick,${q(alternate)})===${q('@'+alternate+':'+remote)}; }
    finally { delete E2E.trustStore[nick]; }
  })()`));
  await browser.evaluate(`handleEncryptCommand(['off',${q(remote)}],${q(alternate)},${q(remote)})`);
  check('disabling a same-nick conversation only affects its own network',await browser.evaluate(`
    E2E.state.dm[_e2eDmKey(${q(remote)},${q(alternate)})]?.on===0 &&
    e2eTargetState(${q(remote)},{conn_id:${q(networkA)}}).mode==='dm'`));
  const plain = 'ordinary IRC DM '+stamp;
  await compose(browser,networkA,ordinary,plain);
  await waitFor(()=>ordinaryLines.some(line=>line.endsWith(' :'+plain)),
    'silent IRC client on the bridge receives ordinary plaintext automatically');
  check('a silent bridged-network client gets one plaintext PM with no modal and a cleared composer',
    ordinaryLines.filter(line=>line.endsWith(' :'+plain)).length===1&&
    await browser.evaluate(`!document.getElementById('msg-input').value&&!(${plainPrompt})`));
  await compose(browser,networkA,ordinary,'/encrypt on '+ordinary);
  await waitFor(()=>browser.evaluate(`document.querySelector(${q(setupButton)})?.textContent==='Send setup instructions'`),
    'an explicit encryption command still offers manual setup instructions',30000);
  check('no ordinary IRC setup note leaves until the sender chooses it',
    !ordinaryLines.some(line=>line.includes('/encrypt unlock')));
  await clickVisible(browser,setupButton);
  check('the ordinary IRC peer receives private instructions only when requested',
    await waitFor(()=>ordinaryLines.some(line=>line.includes(' NOTICE '+ordinary+' :')&&line.includes('/encrypt unlock')),
      'ordinary IRC receives the explicit private notice')&&
    ordinaryLines.filter(line=>line.endsWith(' :'+plain)).length===1);
  const busyNick='pkq'+stamp;
  const busyDraft='held during bridge throttling '+stamp;
  const busyFrames=browser.frames.length;
  const manualBusyNick='pkm'+stamp;
  const fixtureReasons={ [busyNick]:'peer-busy', [manualBusyNick]:'peer-busy' };
  await browser.evaluate(`(() => {
    window.testBridgeWsend=wsend;
    const fixture=${q(fixtureReasons)};
    window.testBridgeRequests=[];
    wsend=message=>{
      if(message.type==='e2e_fetch_bundle' && Object.hasOwn(fixture,message.username)){
        window.testBridgeRequests.push(message.username);
        queueMicrotask(()=>e2eHandleEvent({type:'e2e_bundle_missing',conn_id:message.conn_id,req:message.req,reason:fixture[message.username]}));
        return true;
      }
      return window.testBridgeWsend(message);
    };
  })()`);
  try {
    await compose(browser,networkA,busyNick,busyDraft);
    await waitFor(()=>browser.evaluate(`E2E.lastBlockReason?.includes('temporarily busy')`),'busy bridge response');
    check('bridge throttling keeps the draft and gives no plaintext prompt',
      !browser.frames.slice(busyFrames).some(frame=>frame.includes(busyDraft)) && await browser.evaluate(
        `!(${plainPrompt}) && document.getElementById('msg-input').value===${q(busyDraft)}`));
    await new Promise(resolve=>setTimeout(resolve,250));
    await compose(browser,networkA,busyNick,busyDraft);
    await new Promise(resolve=>setTimeout(resolve,250));
    check('retrying a busy bridge peer preserves the hold through the cooldown',await browser.evaluate(
      `window.testBridgeRequests.filter(nick=>nick===${q(busyNick)}).length===1 && !(${plainPrompt}) &&
       document.getElementById('msg-input').value===${q(busyDraft)}`));
    await browser.evaluate(`handleEncryptCommand(['on',${q(manualBusyNick)}],${q(networkA)},${q(manualBusyNick)})`);
    await waitFor(()=>browser.evaluate(`getBuf(${q(networkA)},${q(manualBusyNick)}).some(m=>m.text.includes('temporarily busy'))`),'busy reply to manual encryption');
    await compose(browser,networkA,manualBusyNick,busyDraft);
    await new Promise(resolve=>setTimeout(resolve,250));
    check('a manual encryption request uses the same busy cooldown as the composer',await browser.evaluate(
      `window.testBridgeRequests.filter(nick=>nick===${q(manualBusyNick)}).length===1 && !(${plainPrompt}) &&
       document.getElementById('msg-input').value===${q(busyDraft)}`));
  } finally {
    await browser.evaluate(`wsend=window.testBridgeWsend;delete window.testBridgeWsend;delete window.testBridgeRequests;document.getElementById('msg-input').value=''`);
  }
  const localSessionKey=`_e2eDmKey(${remoteTarget},${localConn})`;
  check('an unresolved identity change blocks restart and preserves the old pin',await browser.evaluate(`(async () => {
    const key=${localSessionKey},pin=E2E.trustStore[key],session=E2E.dmSessions[key];
    pin.keyChanged=true;
    try {
      await handleEncryptCommand(['restart',${remoteTarget}],${localConn},${remoteTarget});
      return E2E.trustStore[key]===pin&&E2E.dmSessions[key]===session&&!E2E._pendingOn[key];
    } finally {pin.keyChanged=false;}
  })()`));
  const beforeExpiry=await browser.evaluate(`E2E.dmSessions[${localSessionKey}].startEph`);
  await browser.evaluate(`(() => {
    window.testRestartWsend=wsend;
    window.testRestartBundleFailed=0;
    wsend=message=>{
      if(message.type==='e2e_fetch_bundle'&&message.username===${remoteTarget}){
        queueMicrotask(async()=>{
          await e2eHandleEvent({type:'e2e_bundle_missing',username:${remoteTarget},conn_id:message.conn_id,
            req:message.req,reason:'peer-busy'});
          window.testRestartBundleFailed++;
        });
        return true;
      }
      return window.testRestartWsend(message);
    };
  })()`);
  try {
    await browser.evaluate(`_e2eRestartRequested.clear();handleEncryptCommand(['restart',${remoteTarget}],${localConn},${remoteTarget})`);
    check('a temporarily unavailable bundle leaves the existing Signal session usable',
      await waitFor(()=>browser.evaluate(`window.testRestartBundleFailed&&!E2E._pendingOn[${localSessionKey}]&&
        E2E.dmSessions[${localSessionKey}].startEph===${q(beforeExpiry)}&&
        e2eTargetState(${remoteTarget},{conn_id:${localConn}}).mode==='dm'`),'failed restart preserves the working ratchet'));
    check('a busy bridge holds repeated manual restarts without sending another request',await browser.evaluate(`(async () => {
      _e2eRestartRequested.clear();
      await handleEncryptCommand(['restart',${remoteTarget}],${localConn},${remoteTarget});
      return window.testRestartBundleFailed===1&&!E2E._pendingOn[${localSessionKey}];
    })()`));
  } finally {
    await browser.evaluate(`wsend=window.testRestartWsend;delete window.testRestartWsend;delete window.testRestartBundleFailed;_e2eAutoBusy.clear()`);
  }
  // The bridge serves two bundles per requester host in a rolling minute.
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,bridgeReplyWindowEnds-Date.now())));
  await browser.evaluate(`_e2eRestartRequested.clear();handleEncryptCommand(['restart',${remoteTarget}],${localConn},${remoteTarget})`);
  const newStart=await waitFor(()=>browser.evaluate(`(() => {
    const key=${localSessionKey},session=E2E.dmSessions[key];
    return session?.restartPrev&&session.startEph!==${q(beforeExpiry)}&&!E2E._pendingOn[key] ? session.startEph : null;
  })()`),'second restart prepares the expiry fixture');
  check('expiry removes the old receive keys and keeps the new session protected',await browser.evaluate(`(async () => {
    const key=${localSessionKey};
    await _withRatchetLock(key,async () => {
      const session=E2E.dmSessions[key];
      session.restartPrev.until=Date.now()-1;
      await _e2eWriteDeviceSession(key,session);
    });
    await _withRatchetLock(key,()=>{});
    const current=E2E.dmSessions[key];
    return current.startEph===${q(newStart)}&&!!current.x3dhPending&&!current.restartPrev&&
      e2eTargetState(${remoteTarget},{conn_id:${localConn}}).mode==='dm';
  })()`));
  const tooLate='old encrypted reply after the receive window '+stamp;
  const errorsBeforeExpiry=await browser.evaluate(`getBuf(${localConn},${remoteTarget}).filter(
    m=>m.text.includes('Signal message could not be authenticated')).length`);
  await compose(peer,remoteNetwork,owner,tooLate);
  check('a late old reply stays unreadable after the previous receive keys expire',
    await waitFor(()=>browser.evaluate(`getBuf(${localConn},${remoteTarget}).filter(
      m=>m.text.includes('Signal message could not be authenticated')).length>${errorsBeforeExpiry}`),'expired session gives the Signal recovery message')&&
    !await row(browser,networkA,remote,tooLate));
  const originalUrl=await browser.evaluate('location.href');
  await browser.send('Page.navigate',{url:'about:blank'});
  await waitFor(()=>browser.evaluate("location.href==='about:blank'"),'the original device closes its CryptIRC page');
  try {
    const secondDevice=await chromium('encrypted-restart-second-device');
    await login(secondDevice,owner,password,waitFor);
    await waitFor(()=>secondDevice.evaluate('E2E._vaultUp && E2E._krReceived'),'second device is ready to unlock');
    await secondDevice.evaluate('void e2ePromptDeviceUnlock()');
    await waitPrompt(secondDevice,waitFor,unlockText);
    await fillPrompt(secondDevice,ownerCode);
    check('a second device restores the pending session without receiving old receive keys',
      await waitFor(()=>secondDevice.evaluate(`(() => {
        const session=E2E.dmSessions[${localSessionKey}];
        return E2E.identityReady&&session?.startEph===${q(newStart)}&&!!session.x3dhPending&&!session.restartPrev;
      })()`),'second device restores the pending Signal session')&&!secondDevice.frames.some(frame=>frame.includes(ownerCode)));
    await waitFor(()=>secondDevice.evaluate(`window._appShown&&_wsReady()&&!E2E._resyncPending&&
      networks.some(n=>n.config.id===${localConn}&&n.connected)`),'second device is ready to send IRC messages');
    const fromSecondDevice='first encrypted send from the second device after restart, long enough to span multiple IRC messages '+stamp;
    const partsFromSecondDevice=await secondDevice.evaluate(`_e2eSplit(${q(fromSecondDevice)},
      _e2eMaxPlain('dm',_e2eWireBudget(${remoteTarget},${localConn})))`);
    check('the second-device fixture requires multiple encrypted IRC messages',partsFromSecondDevice.length>1);
    const secondSendStart=secondDevice.frames.length;
    const secondReceiveStart=remoteWs.events.length;
    await compose(secondDevice,networkA,remote,fromSecondDevice);
    try {
      await waitFor(async()=>(await Promise.all(partsFromSecondDevice.map(text=>row(peer,remoteNetwork,owner,text)))).every(Boolean),
        'every part of the second-device message decrypts');
    } catch (error) {
      const state=await secondDevice.evaluate(`({
        ready:E2E.keyReady,phase:E2E._bootPhase,resync:E2E._resyncPending,mode:e2eTargetState(${remoteTarget},{conn_id:${localConn}}).mode,
        block:E2E.lastBlockReason||null,connected:networks.some(n=>n.config.id===${localConn}&&n.connected)
      })`);
      const sent=secondDevice.frames.slice(secondSendStart).filter(frame=>{
        const msg=JSON.parse(frame);
        return msg.type==='send'&&msg.raw?.includes(' :[e2e');
      }).length;
      const received=remoteWs.events.slice(secondReceiveStart).filter(ev=>ev.from===owner&&ev.text?.startsWith('[e2e')).length;
      const peerWarning=await peer.evaluate(`getBuf(${q(remoteNetwork)},${q(owner)}).slice(-6).map(m=>m.text).find(
        text=>/(key exchange|decrypt|encryption unavailable|prekey|wrong key|out of order|identity)/i.test(text))||null`);
      throw new Error(`${error.message}; sender state ${JSON.stringify(state)}; encrypted send frames ${sent}; peer received ${received}; peer warning ${peerWarning}`);
    }
    const toSecondDevice='encrypted reply to second device after restart '+stamp;
    await compose(peer,remoteNetwork,owner,toSecondDevice);
    check('changing devices mid-handshake completes the restart in both directions',
      await waitFor(()=>row(secondDevice,networkA,remote,toSecondDevice),'second device decrypts the peer reply')&&
      !remoteWs.events.some(e=>partsFromSecondDevice.includes(e.text))&&!ownerWs.events.some(e=>e.text?.includes(toSecondDevice)));
    if(await peer.evaluate("typeof _e2eRestartFrom==='function'")){
      // The preceding cases deliberately exhaust the bridge's prekey budget.
      // This case measures simultaneous valid restarts after that window closes.
      await new Promise(resolve=>setTimeout(resolve,61000));
      const left=`E2E.dmSessions[${localSessionKey}]`;
      const peerSessionKey=`_e2eDmKey(${q(owner)},${q(remoteNetwork)})`;
      const right=`E2E.dmSessions[${peerSessionKey}]`;
      const [leftBefore,rightBefore]=await Promise.all([secondDevice.evaluate(left+'.startEph'),peer.evaluate(right+'.startEph')]);
      await Promise.all([
        secondDevice.evaluate(`handleEncryptCommand(['restart',${remoteTarget}],${localConn},${remoteTarget})`),
        peer.evaluate(`handleEncryptCommand(['restart',${q(owner)}],${q(remoteNetwork)},${q(owner)})`),
      ]);
      await waitFor(async()=>{
        const [a,b]=await Promise.all([
          secondDevice.evaluate(`!E2E._pendingOn[${localSessionKey}]&&${left}.startEph`),
          peer.evaluate(`!E2E._pendingOn[${peerSessionKey}]&&${right}.startEph`),
        ]);
        return a&&b&&a!==leftBefore&&b!==rightBefore;
      },'both peers prepare independent Signal restarts');
      const leftFirst='simultaneous encrypted restart left '+stamp;
      const rightFirst='simultaneous encrypted restart right '+stamp;
      const holdPeerInput=(device,nick)=>device.evaluate(`(() => {
        const original=e2eDecryptIncoming;
        let release;
        const gate=new Promise(resolve=>{release=resolve;});
        e2eDecryptIncoming=async (...args)=>{
          if(args[0]===${q(nick)}&&(args[2].startsWith('[e2ex3dh]')||args[2].startsWith('[e2edm2]'))) await gate;
          return original(...args);
        };
        window.releaseSimultaneousRestart=()=>{e2eDecryptIncoming=original;release();delete window.releaseSimultaneousRestart;};
      })()`);
      await Promise.all([holdPeerInput(secondDevice,remote),holdPeerInput(peer,owner)]);
      try {
        const atOwner=ownerWs.events.length,atPeer=remoteWs.events.length;
        await Promise.all([compose(secondDevice,networkA,remote,leftFirst),compose(peer,remoteNetwork,owner,rightFirst)]);
        await waitFor(()=>ownerWs.events.slice(atOwner).some(e=>e.from===remote&&e.text?.startsWith('[e2edm2]'))&&
          remoteWs.events.slice(atPeer).some(e=>e.from===owner&&e.text?.startsWith('[e2edm2]')),
          'both first restart messages cross IRC before either peer processes them',45000);
      } finally {
        await Promise.all([secondDevice.evaluate('window.releaseSimultaneousRestart()'),peer.evaluate('window.releaseSimultaneousRestart()')]);
      }
      try {
        await Promise.all([
          waitFor(()=>row(peer,remoteNetwork,owner,leftFirst),'peer reads the simultaneous restart message'),
          waitFor(()=>row(secondDevice,networkA,remote,rightFirst),'second device reads the simultaneous restart message'),
        ]);
      } catch (error) {
        const describe=(device,cid,nick)=>device.evaluate(`(() => {
          const k=_e2eDmKey(${q(nick)},${q(cid)}),s=E2E.dmSessions[k];
          return {initiator:s?.isInitiator,waiting:!!s?.x3dhPending,received:s?.Nr,alternate:!!E2E._glareAlt?.[k],
            diagnostic:getBuf(${q(cid)},${q(nick)}).slice(-8).map(m=>m.text).filter(t=>/🔐|🔒/.test(t)).slice(-3)};
        })()`);
        const [a,b]=await Promise.all([describe(secondDevice,networkA,remote),describe(peer,remoteNetwork,owner)]);
        throw new Error(`${error.message}; second device ${JSON.stringify(a)}; peer ${JSON.stringify(b)}`);
      }
      const followup='one shared Signal session after both restart '+stamp;
      await compose(secondDevice,networkA,remote,followup);
      check('simultaneous restarts keep messages readable and converge on one session',
        await waitFor(()=>row(peer,remoteNetwork,owner,followup),'follow-up after simultaneous restart')&&
        await waitFor(async()=>{
          const [a,b]=await Promise.all([secondDevice.evaluate(left+'.startEph'),peer.evaluate(right+'.startEph')]);
          return a&&a===b;
        },'both sides agree on the same Signal session'));
    }
    check('the bridge browser reports no unhandled exceptions',peer.errors.length===0);
  } finally {
    if(await browser.evaluate('location.href')!==originalUrl) await browser.send('Page.navigate',{url:originalUrl});
    await waitFor(()=>browser.evaluate('window._appShown&&_wsReady()&&E2E.keyReady'),'the original test device reopens');
  }
}
