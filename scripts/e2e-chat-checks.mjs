import fs from 'node:fs/promises';
import path from 'node:path';

const q = JSON.stringify;
const promptOpen = "document.getElementById('custom-prompt-overlay').classList.contains('open')";
const promptText = "document.getElementById('custom-prompt-msg').textContent";
const input = "document.getElementById('custom-prompt-input')";
const acceptPrompt = "document.getElementById('custom-prompt-ok').click()";
const setupText = 'Copy this E2E recovery code';
const unlockText = 'Enter your E2E recovery code';

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

const row = (browser, net, target, text) => browser.evaluate(
  'getBuf(' + q(net) + ',' + q(target) + ').some(m=>m.text===' + q(text) + ')');
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
  const competitor = await chromium('encrypted-setup-race');
  await login(competitor, owner, password, waitFor);
  await waitFor(() => competitor.evaluate('E2E._vaultUp === true && E2E._krReceived'), 'second setup device ready');
  await competitor.evaluate('setActive(' + q(networkA) + ',' + q(channel) + ');void e2ePromptDeviceUnlock()');
  await waitPrompt(competitor, waitFor, setupText);
  const losingCode = await competitor.evaluate(input + '.value');
  await browser.evaluate('void handleEncryptCommand(["unlock"],' + q(networkA) + ',' + q(channel) + ')');
  const ownerCode = await setUpRecovery(browser, waitFor, check);
  await competitor.evaluate(acceptPrompt);
  await waitPrompt(competitor, waitFor, 'Paste your saved E2E recovery code');
  await fillPrompt(competitor, losingCode);
  await waitFor(() => competitor.evaluate('getBuf(' + q(networkA) + ',' + q(channel) +
    ').some(m=>m.text.includes("Discard it"))'), 'losing setup shows a discard message');
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
  await browser.evaluate('handleEncryptCommand(["on",' + q(other) + '],' + q(networkA) + ',' + q(other) + ')');
  await acceptIdentity(browser, waitFor);
  await waitFor(() => browser.evaluate('!!E2E.dmSessions[' + q(other) + ']'), 'initiator session');
  const dm = 'encrypted DM '+stamp;
  await compose(browser, networkA, other, dm);
  await acceptIdentity(peer, waitFor);
  await waitFor(() => row(peer, networkB, owner, dm), 'recipient decrypted first DM');
  check('testnet receives authenticated DM ciphertext',
    otherWs.events.some(ev => ev.type === 'irc_message' && ev.text?.startsWith('[e2edm2]')) &&
    !otherWs.events.some(ev => ev.text?.includes(dm)));
  const reply = 'ratchet reply '+stamp;
  await compose(peer, networkB, owner, reply);
  await waitFor(() => row(browser, networkA, other, reply), 'initiator decrypted ratchet reply');
  check('Double Ratchet works in both directions on the linked IRC testnet', true);
  const pinnedFingerprint=await browser.evaluate('E2E.trustStore['+q(other)+'].fingerprint');
  check('confirmed peer can be marked verified on this device',
    await browser.evaluate('e2eMarkVerified('+q(other)+')'));
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
  await waitPrompt(freshDevice, waitFor, unlockText);
  await fillPrompt(freshDevice, losingCode);
  await waitFor(() => freshDevice.evaluate("E2E._bootPhase==='locked'&& !("+promptOpen+")"), 'incorrect code rejected');
  check('a recovery code from the losing setup cannot unlock the keyring', !await freshDevice.evaluate('E2E.keyReady'));
  await freshDevice.evaluate('void e2ePromptDeviceUnlock()');
  await waitPrompt(freshDevice, waitFor, unlockText);
  const freshCount = freshDevice.frames.length;
  await fillPrompt(freshDevice, ownerCode);
  await waitFor(() => freshDevice.evaluate("E2E._bootPhase==='ready'&&E2E.identityReady"), 'new device recovered E2E keys');
  await waitFor(() => hasKey(freshDevice, channel), 'new device loaded channel PSK');
  check('recovered device restores the verified peer pin from encrypted state',
    await freshDevice.evaluate('E2E.trustStore['+q(other)+']?.verified===true && E2E.trustStore['+
      q(other)+'].fingerprint==='+q(pinnedFingerprint)));
  check('new device recovers identity, DM ratchet and channel key without sending the code or a vault unlock',
    await freshDevice.evaluate('!!E2E.dmSessions[' + q(other) + ']') &&
    !freshDevice.frames.slice(freshCount).some(frame => frame.includes(ownerCode) || frame.includes('"type":"unlock_vault"')));
  const afterRestore = 'DM after recovery '+stamp;
  await compose(freshDevice, networkA, other, afterRestore);
  await waitFor(() => row(peer, networkB, owner, afterRestore), 'ratchet resumed on recovered device');
  check('recovered device sends through the restored DM ratchet', true);

  await freshDevice.evaluate('_deviceLockNow(false)');
  await waitFor(() => freshDevice.evaluate('!E2E.keyReady'), 'device lock erased E2E keys from memory');
  const blocked = 'must not reach IRC '+stamp;
  const sentBefore = freshDevice.frames.length;
  await compose(freshDevice, networkA, channel, blocked);
  await pause(300);
  check('locked browser does not put protected chat on the wire',
    !freshDevice.frames.slice(sentBefore).some(frame => frame.includes(blocked)));
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
