const CHAT_REACTIONS = new Map([
  ['❤️', 'Love'], ['👍', 'Like'], ['😂', 'Laugh'], ['🎉', 'Celebrate'],
  ['🔥', 'Fire'], ['👀', 'Watching'], ['✅', 'Got it'], ['🙏', 'Thanks'],
]);
const CHAT_REACTION_EMOJI = [...CHAT_REACTIONS.keys()];
const reactionAnchors = new Map();
const reactionAnchorTargets = new Map();
const chatReactions = new Map();
const pendingChatReactions = new Map();
const reactionReference = value => typeof value === 'string' && /^[A-Za-z0-9_+.\/-]{1,80}$/.test(value);
const reactionConnection = id => networks.find(network => network.config.id === id);
const reactionEnabled = id => reactionConnection(id)?.reactions === true;
const reactionFold = (id, target) => _chanKeyFold(id)(target);
const reactionKey = (id, target, reference, encrypted) => JSON.stringify([id, reactionFold(id,target), reference, encrypted]);
const reactionAnchorKey = (id, msgId) => `${id}/${msgId}`;
const encryptedReactionReference = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);

async function hashChatReactionReference(wire) {
  if (!/^(?:sd8~|\[e2edm2\])/.test(wire)) return null;
  try {
    const hash = await crypto.subtle.digest('SHA-256',new TextEncoder().encode(wire));
    return Array.from(new Uint8Array(hash,0,16), byte=>byte.toString(16).padStart(2,'0')).join('');
  } catch (_) { return null; }
}

function rememberReactionAnchor({conn_id, target, msg_id, reference}) {
  if (!reactionEnabled(conn_id) || !msg_id || !reactionReference(reference)) return;
  const targetKey = JSON.stringify([conn_id,reactionFold(conn_id,target)]);
  const group = reactionAnchorTargets.get(targetKey) || {connId:conn_id,target,ids:new Map()};
  reactionAnchorTargets.delete(targetKey);
  reactionAnchorTargets.set(targetKey,group);
  if (reactionAnchorTargets.size > 48) {
    const [oldKey, oldGroup] = reactionAnchorTargets.entries().next().value;
    reactionAnchorTargets.delete(oldKey);
    for (const id of oldGroup.ids.values()) reactionAnchors.delete(reactionAnchorKey(oldGroup.connId,id));
    refreshReactionRows(oldGroup.connId,oldGroup.target);
  }
  if (!group.ids.has(reference) && group.ids.size >= 256) {
    const [oldReference, oldId] = group.ids.entries().next().value;
    group.ids.delete(oldReference);
    reactionAnchors.delete(reactionAnchorKey(conn_id,oldId));
    refreshReactionRows(conn_id,target,null,oldId);
  }
  const earlier = group.ids.get(reference);
  if (earlier && earlier !== msg_id) return;
  group.ids.set(reference,msg_id);
  reactionAnchors.set(reactionAnchorKey(conn_id,msg_id), {target,reference});
  refreshReactionRows(conn_id,target,null,msg_id);
}

function resetChatReactions(connId) {
  for (const [id, pending] of pendingChatReactions) {
    if (!connId || pending.connId === connId) pendingChatReactions.delete(id);
  }
  if (!connId) { reactionAnchors.clear(); reactionAnchorTargets.clear(); chatReactions.clear(); return; }
  for (const [key, group] of reactionAnchorTargets) if (group.connId === connId) reactionAnchorTargets.delete(key);
  for (const key of reactionAnchors.keys()) if (key.startsWith(`${connId}/`)) reactionAnchors.delete(key);
  for (const [key, entry] of chatReactions) if (entry.connId === connId) chatReactions.delete(key);
}

function clearEncryptedChatReactions() {
  for (const [id, pending] of pendingChatReactions) if (pending.encrypted) pendingChatReactions.delete(id);
  const changed = new Set();
  for (const [key, entry] of chatReactions) {
    if (!entry.encrypted) continue;
    chatReactions.delete(key);
    changed.add(entry.connId);
  }
  for (const connId of changed) refreshReactionRows(connId);
}

function reactionSupport(connId, enabled) {
  const network = reactionConnection(connId);
  if (network) network.reactions = enabled;
  if (!enabled) resetChatReactions(connId);
  refreshReactionRows(connId);
}

function applyChatReaction(connId, target, reference, emoji, remove, sender, own, encrypted) {
  if (!reactionEnabled(connId) || !reactionReference(reference) || !CHAT_REACTIONS.has(emoji)) return;
  const key = reactionKey(connId,target,reference,encrypted);
  let state = chatReactions.get(key);
  if (!state) {
    if (remove) return;
    if (chatReactions.size >= 2048) chatReactions.delete(chatReactions.keys().next().value);
    state = {connId, encrypted, entries:new Map()};
    chatReactions.set(key,state);
  }
  if (state.encrypted !== encrypted) return;
  let names = state.entries.get(emoji);
  if (!names) { names = new Map(); state.entries.set(emoji,names); }
  const actor = own ? '' : reactionFold(connId,sender);
  if (remove) names.delete(actor);
  else if (names.size < 64 || own || names.has(actor)) names.set(actor,sender);
  if (!names.size) state.entries.delete(emoji);
  if (!state.entries.size) chatReactions.delete(key);
  refreshReactionRows(connId,target,reference);
}

function receiveChatReaction(ev) {
  if (reactionMode(ev.conn_id,ev.target) !== 'none') return;
  if (ev.own || !isIgnored(ev.from,ev.prefix)) {
    if (ev.own) {
      const pending = [...pendingChatReactions].find(([,p])=>
        !p.encrypted && p.connId === ev.conn_id && p.reference === ev.reference && p.emoji === ev.emoji &&
        p.remove === ev.remove && reactionFold(ev.conn_id,p.target) === reactionFold(ev.conn_id,ev.target));
      if (pending) pendingChatReactions.delete(pending[0]);
    }
    applyChatReaction(ev.conn_id,ev.target,ev.reference,ev.emoji,ev.remove===true,ev.from,ev.own===true,false);
  }
}

function receiveSealedReaction(ev) {
  if (!reactionEnabled(ev.conn_id) || !window.E2E?.keyReady || !/^[A-Za-z0-9_-]{12,900}$/.test(ev.body) ||
      ev.body.length % 4 === 1) return;
  const generation = E2E._lockGen;
  if (ev.own) {
    const pending = [...pendingChatReactions].find(([,p])=>p.connId === ev.conn_id && p.body === ev.body &&
      reactionFold(ev.conn_id,p.target) === reactionFold(ev.conn_id,ev.target));
    if (pending) {
      const [id, p] = pending;
      pendingChatReactions.delete(id);
      if (p.generation === generation) applyChatReaction(p.connId,p.target,p.reference,p.emoji,p.remove,ev.from,true,true);
    }
    return;
  }
  const mode = reactionMode(ev.conn_id,ev.target);
  if (mode !== 'dm' && mode !== 'psk') return;
  if (mode === 'psk' && isIgnored(ev.from,ev.prefix)) return;
  _e2eEnqueue(ev.conn_id,ev.target,async()=>{
    if (!E2E.keyReady || E2E._lockGen !== generation || !reactionEnabled(ev.conn_id)) return;
    try {
      const wire = atob(ev.body.replace(/-/g,'+').replace(/_/g,'/'));
      if (reactionMode(ev.conn_id,ev.target) !== mode ||
          !wire.startsWith(mode === 'psk' ? E2E_REACTION_PSK_PREFIX : E2E_REACTION_DM_PREFIX)) return;
      const result = await e2eDecryptIncoming(ev.from,ev.target,wire,{conn_id:ev.conn_id,live:true,prefix:ev.prefix,kind:'Privmsg',reaction:true});
      if (!result.encrypted || result.duplicate || typeof result.plaintext !== 'string' || !E2E.keyReady ||
          E2E._lockGen !== generation || isIgnored(ev.from,ev.prefix)) return;
      const data = JSON.parse(result.plaintext);
      if (data?.v !== 1 || !encryptedReactionReference(data.ref) || !Number.isInteger(data.emoji) ||
          data.emoji < 0 || data.emoji >= CHAT_REACTION_EMOJI.length ||
          (data.remove !== 0 && data.remove !== 1) || !getBuf(ev.conn_id,ev.target).some(m=>m.reactionRef === data.ref)) return;
      applyChatReaction(ev.conn_id,ev.target,data.ref,CHAT_REACTION_EMOJI[data.emoji],data.remove===1,ev.from,false,true);
    } catch (_) { /* Ignore invalid reaction payloads. */ }
  });
}

function reactionMode(connId, target) {
  return typeof e2eTargetState === 'function' ? e2eTargetState(target,{conn_id:connId}).mode : 'blocked';
}

async function sendChatReaction(connId, target, reference, emoji, remove, encrypted) {
  if (!reactionEnabled(connId) || !reactionReference(reference) || !CHAT_REACTIONS.has(emoji)) return;
  if (!_wsReady()) { showToast('Connect to IRC to react.'); return; }
  const foldedTarget = reactionFold(connId,target);
  if (pendingChatReactions.size >= 64 || [...pendingChatReactions.values()].some(p =>
    p.connId === connId && reactionFold(connId,p.target) === foldedTarget && p.reference === reference && p.emoji === emoji)) return;
  const mode = reactionMode(connId,target);
  const request_id = crypto.randomUUID();
  const generation = window.E2E?._lockGen;
  const pending = {connId,target,reference,emoji,remove,encrypted,generation};
  pendingChatReactions.set(request_id,pending);
  let queued = false;
  let reaction = {kind:'plain',reference,emoji,remove};
  try {
    if (encrypted) {
      if (mode !== 'dm' && mode !== 'psk') { showToast('Unlock encrypted chat to react.'); return; }
      if (!encryptedReactionReference(reference)) return;
      const wire = await e2eEncryptReaction(target,JSON.stringify({v:1,ref:reference,emoji:CHAT_REACTION_EMOJI.indexOf(emoji),remove:remove?1:0}),connId,mode);
      if (E2E._lockGen !== generation || reactionMode(connId,target) !== mode || !reactionEnabled(connId)) {
        showToast('Encrypted chat is unavailable.'); return;
      }
      const body = btoa(wire).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      if (body.length > 900) { showToast('This reaction is too large to send.'); return; }
      reaction = {kind:'sealed',body};
      pending.body = body;
    } else if (mode !== 'none') { showToast('React to messages in the current encryption mode.'); return; }
    if (!pendingChatReactions.has(request_id)) return;
    queued = wsend({type:'react',conn_id:connId,target,request_id,reaction});
    if (!queued) { showToast('Connect to IRC to react.'); return; }
    setTimeout(()=>{ if (pendingChatReactions.has(request_id)) showToast('Waiting for IRC to confirm this reaction.'); },15000);
    setTimeout(()=>pendingChatReactions.delete(request_id),60000);
  } catch (_) { showToast('Could not send this reaction.'); }
  finally { if (!queued) pendingChatReactions.delete(request_id); }
}

function receiveReactionResult({request_id,error}) {
  const pending = pendingChatReactions.get(request_id);
  if (!pending || !error) return;
  pendingChatReactions.delete(request_id);
  showToast(error);
}

function mountChatReactions(row, message, conversation) {
  if (!conversation || !['privmsg','action'].includes(message.kind)) return;
  row._chatReaction = {message, connId:conversation.conn_id||conversation.connId, target:message._tgt||conversation.target};
  renderReactionRow(row);
}

function refreshReactionRows(connId,target,reference,msgId) {
  const folded = target && reactionFold(connId,target);
  for (const row of document.querySelectorAll('#chat-area .msg-row, #split-chat-area .msg-row')) {
    const info = row._chatReaction;
    if (info?.connId !== connId || (msgId && info.message.id !== msgId) ||
        (folded && reactionFold(connId,info.target) !== folded)) continue;
    if (reference && info.message.reactionRef !== reference &&
        reactionAnchors.get(reactionAnchorKey(connId,info.message.id))?.reference !== reference) continue;
    renderReactionRow(row);
  }
}

function renderReactionRow(row) {
  const {message,connId,target} = row._chatReaction;
  const anchor = reactionAnchors.get(reactionAnchorKey(connId,message.id));
  const old = row.querySelector('.message-reactions');
  if (!reactionEnabled(connId) || !anchor || reactionFold(connId,anchor.target) !== reactionFold(connId,target)) {
    old?.remove();
    return;
  }
  const encrypted = message.encrypted === true;
  const reference = encrypted ? message.reactionRef : anchor.reference;
  if (!reference) { old?.remove(); return; }
  const state = chatReactions.get(reactionKey(connId,target,reference,encrypted));
  const counts = state?.encrypted === encrypted ? state.entries : new Map();
  const body = row.querySelector('.msg-body');
  if (!body) return;
  const controls = document.createElement('span');
  controls.className = 'message-reactions';
  const menu = document.createElement('span');
  menu.className = 'reaction-choices';
  menu.hidden = !old || old.querySelector('.reaction-choices')?.hidden !== false;
  menu.setAttribute('role','group');
  menu.setAttribute('aria-label','Choose a reaction');
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'reaction-picker';
  toggle.textContent = '☺';
  toggle.title = 'React to message';
  toggle.setAttribute('aria-label','React to message');
  toggle.setAttribute('aria-expanded',String(!menu.hidden));
  toggle.onclick = () => {
    menu.hidden = !menu.hidden;
    toggle.setAttribute('aria-expanded',String(!menu.hidden));
  };
  for (const [emoji,label] of CHAT_REACTIONS) {
    const names = counts.get(emoji);
    const pressed = names?.has('') === true;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'reaction-choice';
    button.textContent = emoji;
    button.title = label;
    button.setAttribute('aria-label',label);
    button.setAttribute('aria-pressed',String(pressed));
    button.onclick = () => {
      menu.hidden = true;
      toggle.setAttribute('aria-expanded','false');
      void sendChatReaction(connId,target,reference,emoji,pressed,encrypted);
    };
    menu.append(button);
    if (names?.size) {
      const chip = button.cloneNode(false);
      chip.className = 'reaction-count';
      chip.textContent = `${emoji} ${names.size}`;
      const actors = [...names.values()].join(', ');
      chip.title = actors;
      chip.setAttribute('aria-label',`${label}, ${names.size}: ${actors}`);
      chip.onclick = button.onclick;
      controls.append(chip);
    }
  }
  controls.append(toggle,menu);
  if (old) old.replaceWith(controls); else body.append(controls);
}

const CHAT_EFFECTS_PREF = 'cryptirc_chat_effects';
const CHAT_EFFECT_CUES = new Map([
  ['fireworks','fireworks'], ['congrats!','confetti'], ['confetti','confetti'],
  ['happy birthday!','balloons'], ['balloons','balloons'], ['hearts','hearts'],
]);
let lastChatEffect = -Infinity;
let chatEffectLayer = null;

function chatEffectsEnabled() {
  try { return localStorage.getItem(CHAT_EFFECTS_PREF) !== 'off'; } catch (_) { return true; }
}
function saveChatEffectsPreference(control) {
  try { localStorage.setItem(CHAT_EFFECTS_PREF,control.checked ? 'on' : 'off'); } catch (_) {}
  if (!control.checked) clearChatEffect();
}
function clearChatEffect() {
  chatEffectLayer?.remove();
  chatEffectLayer = null;
}

function playChatEffect(connId,target,text) {
  if (typeof text !== 'string' || !isActive(connId,target) || document.visibilityState !== 'visible' ||
      _historyView?.bk === bk(connId,target) || !chatEffectsEnabled() || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const effect = CHAT_EFFECT_CUES.get(text.trim().toLowerCase());
  const now = performance.now();
  if (!effect || now - lastChatEffect < 7000) return;
  const rect = document.getElementById('chat-area')?.getBoundingClientRect();
  if (!rect?.width || !rect.height) return;
  lastChatEffect = now;
  clearChatEffect();
  const layer = document.createElement('div');
  layer.className = 'chat-effect-layer';
  layer.setAttribute('aria-hidden','true');
  Object.assign(layer.style,{left:`${rect.left}px`,top:`${rect.top}px`,width:`${rect.width}px`,height:`${rect.height}px`});
  document.body.append(layer);
  chatEffectLayer = layer;
  const colors = ['#ffcb6b','#ff6eaa','#78e9ef','#b9a3ff','#acf071'];
  const count = {fireworks:36,confetti:32,balloons:9,hearts:12}[effect];
  for (let i=0; i<count; i++) {
    const particle = document.createElement('i');
    const fireworks = effect === 'fireworks';
    const rising = effect === 'balloons' || effect === 'hearts';
    const group = i % 3;
    const angle = i * 2.39996;
    const distance = 30 + Math.random() * Math.min(rect.width,rect.height) * .24;
    const x = fireworks ? (25 + group * 25) : 8 + Math.random()*84;
    const y = fireworks ? (38 + (group%2)*22) : rising ? 95 : -5;
    const dx = fireworks ? Math.cos(angle)*distance : Math.random()*100-50;
    const dy = fireworks ? Math.sin(angle)*distance : (rising ? -1 : 1)*rect.height*(.6+Math.random()*.5);
    Object.assign(particle.style,{left:`${x}%`,top:`${y}%`,color:colors[i%colors.length]});
    if (rising) particle.textContent = effect === 'hearts' ? '♥' : '🎈';
    else particle.className = fireworks ? 'effect-spark' : 'effect-paper';
    layer.append(particle);
    particle.animate([
      {transform:'translate(0,0) scale(.45)',opacity:.9},
      {transform:`translate(${dx*.7}px,${dy*.7}px) rotate(${i*18}deg)`,opacity:.8,offset:.6},
      {transform:`translate(${dx}px,${dy}px) rotate(${i*27}deg) scale(.65)`,opacity:0},
    ],{duration:fireworks?900:1900,delay:fireworks?group*280:i*32,easing:'cubic-bezier(.2,.6,.4,1)',fill:'both'});
  }
  setTimeout(()=>{ if (chatEffectLayer === layer) clearChatEffect(); },3000);
}
