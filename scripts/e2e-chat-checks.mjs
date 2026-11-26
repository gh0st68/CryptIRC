import fs from 'node:fs/promises';
import path from 'node:path';
import {checkSealedReaction} from './reaction-checks.mjs';

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

const fillPrompt = (browser, value) => browser.evaluate(input + '.value=' + q(value) + ';' + acceptPrompt);
const waitPrompt = (browser, waitFor, text) => waitFor(
  () => browser.evaluate(promptOpen + '&&' + promptText + '.includes(' + q(text) + ')'), text);

async function unlockVault(browser, vault) {
  await browser.evaluate("document.getElementById('vault-pass').value=" + q(vault) + ';doUnlock()');
}

async function login(browser, user, password, waitFor) {
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

async function setUpRecovery(browser, waitFor, check) {
  await waitPrompt(browser, waitFor, setupText);
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
  check('migration browser had no unhandled exceptions', browser.errors.length === 0);
}

async function compose(browser, network, target, text) {
  await browser.evaluate('setActive(' + q(network) + ',' + q(target) + ');' +
    "document.getElementById('msg-input').focus();document.getElementById('msg-input').value=" + q(text));
  await browser.send('Input.dispatchKeyEvent', {type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await browser.send('Input.dispatchKeyEvent', {type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
}

async function clickVisible(browser, selector) {
  const point = await browser.evaluate(`(() => {
    const el = document.querySelector(${q(selector)});
    const r = el.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    if (!el.contains(document.elementFromPoint(x, y))) throw new Error('Control is covered: ' + ${q(selector)});
    return {x, y};
  })()`);
  await browser.send('Input.dispatchMouseEvent', {type:'mousePressed', button:'left', clickCount:1, ...point});
  await browser.send('Input.dispatchMouseEvent', {type:'mouseReleased', button:'left', clickCount:1, ...point});
}

const row = (browser, net, target, text, kind) => browser.evaluate(
  `getBuf(${q(net)},${q(target)}).some(m=>m.text===${q(text)}${kind ? `&&m.kind===${q(kind)}` : ''})`);
const hasKey = (browser, channel) => browser.evaluate('!!E2E.channelKeys[' + q(channel) + ']');

async function acceptIdentity(browser, waitFor) {
  await waitFor(() => browser.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"), 'identity confirmation');
  await browser.evaluate("document.getElementById('e2e-id-accept').click()");
}

async function shareKey(browser, waitFor, cmd, network, channel) {
  await browser.evaluate('void handleEncryptCommand([' + q(cmd) + '],' + q(network) + ',' + q(channel) + ')');
  await waitPrompt(browser, waitFor, 'Copy this key and share it');
  const words = await browser.evaluate(input + '.value');
  await browser.evaluate(acceptPrompt);
  return words;
}

export async function checkE2eChat({
  browser, chromium, check, waitFor, pause, owner, other, password, vault, tmp, ownerWs, otherWs,
  networkA, networkB, channel, stamp, request, ownerSession,
}) {
  await browser.send('Emulation.clearDeviceMetricsOverride');
  await browser.send('Emulation.setTouchEmulationEnabled', {enabled:false});
  const peer = await chromium('encrypted-peer');
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
  await peer.evaluate('void handleEncryptCommand(["unlock"],' + q(networkB) + ',' + q(channel) + ')');
  await setUpRecovery(peer, waitFor, check);
  const keyring = await keyringOnDisk(tmp, owner);
  check('new account stores only a wrapped v3 keyring',
    keyring.blob.startsWith('e2k3.') && !JSON.stringify(keyring).includes(ownerCode));
  check('new account vault unlock response contains no E2E pepper or key',
    ownerWs.events.some(ev => ev.type === 'vault_unlocked' && ev.vault_verified &&
      !ev.e2e_pepper && !ev.e2e_legacy_key && !ev.e2e_enc_key));

  await waitFor(() => browser.evaluate('E2E._txq.length===0'), 'initiator prekeys sent');
  await waitFor(() => peer.evaluate('E2E._txq.length===0'), 'responder prekeys sent');
  await browser.evaluate('_e2eAutoMiss.clear()');
  const dm = 'encrypted DM '+stamp;
  const peerKey = `_e2eDmKey(${q(other)},${q(networkA)})`;
  await compose(browser, networkA, other, dm);
  await waitFor(() => browser.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"), 'same-instance automatic identity prompt');
  check('first same-instance PM starts encryption and holds the message for identity confirmation',
    !otherWs.events.some(ev=>ev.text?.includes(dm)));
  await acceptIdentity(browser, waitFor);
  await waitFor(() => browser.evaluate(`!!E2E.dmSessions[${peerKey}]`), 'initiator session');
  await waitFor(() => otherWs.events.some(ev => ev.text?.startsWith('[e2ex3dh]')), 'X3DH header reached the peer');
  await acceptIdentity(peer, waitFor);
  await waitFor(() => row(peer, networkB, owner, dm), 'recipient decrypted first DM');
  check('testnet receives authenticated DM ciphertext',
    otherWs.events.some(ev => ev.type === 'irc_message' && ev.text?.startsWith('[e2edm2]')) &&
    !otherWs.events.some(ev => ev.text?.includes(dm)));
  const reply = 'ratchet reply '+stamp;
  await compose(peer, networkB, owner, reply);
  await waitFor(() => row(browser, networkA, other, reply), 'initiator decrypted ratchet reply');
  check('Double Ratchet works in both directions on the linked IRC testnet', true);
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:dm,target:'PM',emoji:'👍'});
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:dm,target:'PM thumbs-down',emoji:'👎'});
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

  const words = await shareKey(browser, waitFor, 'keygen', networkA, channel);
  await peer.evaluate('handleEncryptCommand(' + q(['add', ...words.split(' ')]) + ',' + q(networkB) + ',' + q(channel) + ')');
  await waitFor(() => hasKey(peer, channel), 'peer imported channel PSK');
  check('channel key stays out of the chat buffer and WebSocket frames',
    !await browser.evaluate('getBuf(' + q(networkA) + ',' + q(channel) + ').some(m=>m.text?.includes(' + q(words) + '))') &&
    ![...browser.frames,...peer.frames].some(frame => frame.includes(words)));
  const channelText = 'encrypted channel '+stamp;
  await compose(browser, networkA, channel, channelText);
  await waitFor(() => row(peer, networkB, channel, channelText), 'recipient decrypted shared-key message');
  check('testnet receives shared-key ciphertext',
    otherWs.events.some(ev => ev.type === 'irc_message' && ev.text?.startsWith('sd8~')) &&
    !otherWs.events.some(ev => ev.text?.includes(channelText)));
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
    await peer.evaluate('setActive('+q(networkB)+','+q(channel)+')');
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:channelText,target:'channel',emoji:'❤️'});
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:channelText,target:'channel thumbs-down',emoji:'👎'});
  }
  const action = 'encrypted action '+stamp;
  await compose(browser, networkA, channel, '/me '+action);
  await waitFor(() => row(peer, networkB, channel, action), 'recipient decrypted action');
  const notice = 'encrypted notice '+stamp;
  await compose(browser, networkA, channel, '/notice '+channel+' '+notice);
  await waitFor(() => row(peer, networkB, channel, notice), 'recipient decrypted notice');
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
  await compose(browser, networkA, channel, lastChannelText);
  await waitFor(() => row(peer, networkB, channel, lastChannelText), 'peer decrypted with the rotated key');
  check('channel resumes encrypted chat after both members update the PSK', true);

  const freshDevice = await chromium('encrypted-recovery');
  await login(freshDevice, owner, password, waitFor);
  await waitFor(() => freshDevice.evaluate('E2E._bootPhase==="locked" && E2E._krReceived'), 'new device stays locked');
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
  await waitFor(() => hasKey(freshDevice, channel), 'new device loaded channel PSK');
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
    await browser.evaluate('e2eTargetState(' + q(channel) + ').mode==="none"'));
  const afterOff = 'explicitly unencrypted after off '+stamp;
  await compose(browser, networkA, channel, afterOff);
  await otherWs.wait(ev => ev.type === 'irc_message' && ev.text === afterOff,'channel send after acknowledged disable');
  check('server permits ordinary chat after explicit, acknowledged disable', true);
}

export async function checkCrossInstanceE2e({browser,peer,check,waitFor,owner,ownerWs,remote,password,networkA,remoteNetwork,remoteWs,stamp,otherWs,remoteData,ordinary,ordinaryLines}) {
  await login(peer,remote,password,waitFor);
  await waitFor(() => peer.evaluate('E2E._vaultUp && E2E._krReceived'), 'bridge peer discovery');
  await peer.evaluate(openEncryptionSettings);
  await setUpRecovery(peer,waitFor,check);
  await peer.evaluate('closeEncryptPanel()');
  await waitFor(()=>fs.stat(path.join(remoteData,'e2e',remote,'bundle.json')).catch(()=>null),'remote prekey bundle stored');

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
  await acceptIdentity(peer,waitFor);
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
  await compose(peer,remoteNetwork,owner,reply);
  check('the cross-instance Double Ratchet decrypts the reply',await waitFor(()=>row(browser,networkA,remote,reply),'cross-instance reply'));
  if(process.env.CRYPTIRC_TEST_REACTIONS==='1'){
    await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:first,target:'cross-instance PM',emoji:'❤️'});
  }
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
  const allow = `Array.from(document.querySelectorAll('button')).find(button=>button.textContent==='Allow unencrypted')`;
  await waitFor(()=>browser.evaluate(`!!(${allow})`),'plaintext confirmation for a client without bridge support');
  check('the ordinary IRC client receives no message before plaintext consent',!ordinaryLines.some(line=>line.endsWith(' :'+plain)));
  await browser.evaluate(`(${allow}).click()`);
  check('ordinary IRC DMs work on the bridge network after explicit consent',await waitFor(
    ()=>ordinaryLines.some(line=>line.endsWith(' :'+plain)),'ordinary IRC client received the authorized plaintext'));
  const busyNick='pkq'+stamp;
  const busyDraft='held during bridge throttling '+stamp;
  const busyFrames=browser.frames.length;
  const manualBusyNick='pkm'+stamp;
  const unsupportedNick='pku'+stamp;
  const unsupportedDraft='held pending plaintext consent '+stamp;
  const fixtureReasons={ [busyNick]:'peer-busy', [manualBusyNick]:'peer-busy', [unsupportedNick]:'unsupported' };
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
        `!(${allow}) && document.getElementById('msg-input').value===${q(busyDraft)}`));
    await new Promise(resolve=>setTimeout(resolve,250));
    await compose(browser,networkA,busyNick,busyDraft);
    await new Promise(resolve=>setTimeout(resolve,250));
    check('retrying a busy bridge peer preserves the hold through the cooldown',await browser.evaluate(
      `window.testBridgeRequests.filter(nick=>nick===${q(busyNick)}).length===1 && !(${allow}) &&
       document.getElementById('msg-input').value===${q(busyDraft)}`));
    await browser.evaluate(`handleEncryptCommand(['on',${q(manualBusyNick)}],${q(networkA)},${q(manualBusyNick)})`);
    await waitFor(()=>browser.evaluate(`getBuf(${q(networkA)},${q(manualBusyNick)}).some(m=>m.text.includes('temporarily busy'))`),'busy reply to manual encryption');
    await compose(browser,networkA,manualBusyNick,busyDraft);
    await new Promise(resolve=>setTimeout(resolve,250));
    check('a manual encryption request uses the same busy cooldown as the composer',await browser.evaluate(
      `window.testBridgeRequests.filter(nick=>nick===${q(manualBusyNick)}).length===1 && !(${allow}) &&
       document.getElementById('msg-input').value===${q(busyDraft)}`));
    const unsupportedFrames=browser.frames.length;
    await compose(browser,networkA,unsupportedNick,unsupportedDraft);
    await waitFor(()=>browser.evaluate(`!!(${allow})`),'plaintext confirmation when no bridge is advertised');
    await browser.evaluate(`(${allow}).previousElementSibling.click()`);
    check('missing CAP cannot silently send a first DM in plaintext',
      !browser.frames.slice(unsupportedFrames).some(frame=>frame.includes(unsupportedDraft)) && await browser.evaluate(
        `document.getElementById('msg-input').value===${q(unsupportedDraft)}`));
  } finally {
    await browser.evaluate(`wsend=window.testBridgeWsend;delete window.testBridgeWsend;delete window.testBridgeRequests;document.getElementById('msg-input').value=''`);
  }
  check('the bridge browser reports no unhandled exceptions',peer.errors.length===0);
}
