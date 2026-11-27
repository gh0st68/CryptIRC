const CHAT_REACTIONS = new Map([
  ['❤️', 'Love'], ['👍', 'Like'], ['😂', 'Haha'], ['🎉', 'Celebrate'],
  ['🔥', 'Fire'], ['👀', 'Watching'], ['✅', 'Got it'], ['🙏', 'Thanks'],
  ['👎', 'Dislike'],
]);
// Existing positions are part of the encrypted reaction format.
const CHAT_REACTION_EMOJI = [...CHAT_REACTIONS.keys()];
const CHAT_MESSAGE_REACTIONS = new Map([['👍', 'Like'], ['👎', 'Dislike'], ['❤️', 'Heart'], ['😂', 'Haha']]);
const reactionAnchors = new Map();
const reactionAnchorTargets = new Map();
const chatReactions = new Map();
const pendingChatReactions = new Map();
const reactionReference = value => typeof value === 'string' && /^[A-Za-z0-9_+.\/-]{1,80}$/.test(value);
const reactionConnection = id => networks.find(network => network.config.id === id);
const reactionEnabled = id => reactionConnection(id)?.reactions === true;
const reactionAllows = (id, emoji) => emoji !== '👎' || reactionConnection(id)?.reaction_dislike === true;
const reactionFold = (id, target) => _chanKeyFold(id)(target);
const reactionKey = (id, target, reference, encrypted) => JSON.stringify([id, reactionFold(id,target), reference, encrypted]);
const reactionAnchorKey = (id, msgId) => `${id}/${msgId}`;
const encryptedReactionReference = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const REACTION_HISTORY_LIMIT = 512;
const REACTION_RECEIPT_LIMIT = 64;
const reactionHistory = new Map();
const reactionHistoryQueues = new Map();

function reactionHistoryKey(connId,target,msgId) {
  return JSON.stringify([connId,reactionFold(connId,target),msgId]);
}

function reactionHistorySlot(encrypted) {
  return ['chat-reactions-v1',currentUser,encrypted ? 'sealed' : 'plain'];
}

const reactionReceiptKey = id => 'receipt:'+id;
const reactionReceiptId = key => typeof key === 'string' && /^receipt:[a-f0-9-]{36}$/.test(key) ? key.slice(8) : null;

async function readReactionHistory(slot,master) {
  const data = await _e2eIdbOp('readonly',store=>store.get(slot),2000);
  if (!data) return new Map();
  if (!master) return new Map(data);
  const aad = _e2eBlobAAD('chat-reactions-v1\n'+slot[1]);
  const bytes = await _e2eGcmDec(master,data,aad);
  try { return new Map(JSON.parse(new TextDecoder().decode(bytes))); }
  finally { bytes.fill(0); }
}

function refreshReactionHistoryRows() {
  for (const network of networks) if (network.reactions) refreshReactionRows(network.config.id);
}

function loadReactionHistory(encrypted) {
  if (!currentUser || !_wsAuthed || typeof _e2eIdbOp !== 'function') return null;
  const master = encrypted ? window.E2E?.e2eEncKey : null;
  if (encrypted && (!master || !E2E.keyReady)) return null;
  const prior = reactionHistory.get(encrypted);
  if (prior?.user === currentUser && prior.master === master) return prior;
  const slot = reactionHistorySlot(encrypted);
  const cache = {user:currentUser,master,records:new Map()};
  reactionHistory.set(encrypted,cache);
  cache.ready = readReactionHistory(slot,master).then(records=>{
    if (reactionHistory.get(encrypted) !== cache || currentUser !== cache.user) return;
    if (encrypted && (!E2E.keyReady || E2E.e2eEncKey !== master)) return;
    cache.records = records;
    refreshReactionHistoryRows();
  }).catch(()=>{ if (reactionHistory.get(encrypted) === cache) reactionHistory.delete(encrypted); });
  return cache;
}

function storedReaction(connId,target,msgId,encrypted) {
  const record = loadReactionHistory(encrypted)?.records.get(reactionHistoryKey(connId,target,msgId));
  if (!record || !Array.isArray(record.entries) || (encrypted ? !encryptedReactionReference(record.reference) :
      !reactionReference(record.anchor) || record.reference !== record.anchor)) return null;
  return record;
}

function updateReactionHistory(slot, master, change, clear = false) {
  const lane = JSON.stringify(slot);
  const encrypted = slot[2] === 'sealed';
  const current = () => currentUser === slot[1] && (!master || window.E2E?.e2eEncKey === master);
  const task = (reactionHistoryQueues.get(lane) || Promise.resolve()).then(()=>_e2eXLock('chat-reaction-history:'+slot[2],async()=>{
    if (!current()) return false;
    if (clear || (encrypted && !master)) {
      await _e2eIdbOp('readwrite',store=>store.delete(slot),2000);
      return true;
    }
    // A failed read is not an empty store. Leave earlier reactions intact.
    const records = await readReactionHistory(slot,master);
    if (change(records) === false) return false;
    const receipts=[],history=[];
    // Reopen may be days after the IRC server confirmed the click. Keep the
    // outstanding actions bounded by count independently of time spent away.
    for (const key of records.keys()) {
      if (!reactionReceiptId(key)) history.push(key);
      else receipts.push(key);
    }
    for (const key of receipts.slice(0,Math.max(0,receipts.length-REACTION_RECEIPT_LIMIT))) records.delete(key);
    for (const key of history.slice(0,Math.max(0,history.length-REACTION_HISTORY_LIMIT))) records.delete(key);
    let contents = [...records];
    if (master) {
      const plain = new TextEncoder().encode(JSON.stringify(contents));
      try { contents = await _e2eGcmEnc(master,plain,_e2eBlobAAD('chat-reactions-v1\n'+slot[1])); }
      finally { plain.fill(0); }
    }
    if (!current()) return false;
    await _e2eIdbOp('readwrite',store=>contents.length ? store.put(contents,slot) : store.delete(slot),2000);
    const cache = reactionHistory.get(encrypted);
    if (current() && cache?.user === slot[1] && cache.master === master) cache.records = records;
    return current();
  })).catch(()=>false);
  reactionHistoryQueues.set(lane,task);
  void task.then(()=>{ if (reactionHistoryQueues.get(lane) === task) reactionHistoryQueues.delete(lane); });
  return task;
}

function forgetSavedReactions(connId,target) {
  if (!currentUser || typeof _e2eIdbOp !== 'function') return;
  const scope = connId ? JSON.stringify([connId,reactionFold(connId,target)]).slice(0,-1)+',' : '';
  for (const key of chatReactions.keys()) if (!scope || key.startsWith(scope)) chatReactions.delete(key);
  for (const encrypted of [false,true]) {
    const remove = records=>{
      for (const [key,entry] of records) {
        const row = reactionReceiptId(key) ? reactionHistoryKey(entry.connId,entry.target,entry.msgId) : key;
        if (!scope || row.startsWith(scope)) records.delete(key);
      }
    };
    const cache = reactionHistory.get(encrypted);
    if (cache) remove(cache.records);
    updateReactionHistory(reactionHistorySlot(encrypted),encrypted ? window.E2E?.e2eEncKey : null,remove,!scope);
  }
}

async function hashChatReactionReference(wire) {
  if (!/^(?:sd8~|\[e2edm2\])/.test(wire)) return null;
  try {
    const hash = await crypto.subtle.digest('SHA-256',new TextEncoder().encode(wire));
    return Array.from(new Uint8Array(hash,0,16), byte=>byte.toString(16).padStart(2,'0')).join('');
  } catch (_) { return null; }
}

function rememberReactionAnchor({conn_id, target, msg_id, reference}) {
  if (!reactionEnabled(conn_id) || !msg_id || !reactionReference(reference)) return;
  target = _dmTarget(target);
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

// The IRC msgid anchor for our own row is issued only after the IRCd echoes
// the ordinary PRIVMSG. A web-server echo or an optimistic row can arrive earlier.
async function hasEchoedSignalMessage(peer,session) {
  const scope = _e2eDmScope(peer), connId = scope?.[1] || session.connId, target = _dmTarget(_e2eDmNick(peer));
  if (!connId || !session.isInitiator || !session.startEph || session.startEph !== session.x3dhPending?.ephemeral_pub ||
      !session.DHs?.pub || !session.Ns || (session.connId && session.connId !== connId)) return false;
  const self = reactionFold(connId,getNick(connId)), folded = reactionFold(connId,target);
  const rows = getBuf(connId,target);
  for (let i = rows.length - 1; i >= 0; i--) {
    const row = rows[i], wire = row._dmHistoryWire;
    if (!row.encrypted || !row.id || !row.from || reactionFold(connId,row.from) !== self ||
        typeof wire !== 'string' || !wire.startsWith(E2E_DM_PREFIX) || wire.length > 8192) continue;
    const anchor = reactionAnchors.get(reactionAnchorKey(connId,row.id));
    if (!anchor || reactionFold(connId,anchor.target) !== folded) continue;
    try {
      const env = JSON.parse(atob(wire.slice(E2E_DM_PREFIX.length)));
      if (_e2eEnvelopeOk(env) && env.h?.d === session.DHs.pub && env.h.n < session.Ns &&
          _e2eOwnDigestMatches(peer,session,{dh:env.h.d,n:env.h.n},await _e2eSentDigest(env))) return true;
    } catch (_) { /* An unrecognized history row cannot confirm this chain. */ }
  }
  return false;
}

function resetChatReactions(connId) {
  for (const [id, pending] of pendingChatReactions) {
    if (!connId || pending.connId === connId) pendingChatReactions.delete(id);
  }
  if (!connId) { reactionAnchors.clear(); reactionAnchorTargets.clear(); chatReactions.clear(); reactionHistory.clear(); return; }
  for (const [key, group] of reactionAnchorTargets) if (group.connId === connId) reactionAnchorTargets.delete(key);
  for (const key of reactionAnchors.keys()) if (key.startsWith(`${connId}/`)) reactionAnchors.delete(key);
  for (const [key, entry] of chatReactions) if (entry.connId === connId) chatReactions.delete(key);
}

function clearEncryptedChatReactions() {
  reactionHistory.delete(true);
  for (const [id, pending] of pendingChatReactions) if (pending.encrypted) pendingChatReactions.delete(id);
  for (const [key, entry] of chatReactions) if (entry.encrypted) chatReactions.delete(key);
  refreshReactionHistoryRows();
}

function reactionSupport(connId, enabled, dislike = false) {
  const network = reactionConnection(connId);
  if (network) {
    network.reactions = enabled;
    network.reaction_dislike = enabled && dislike;
  }
  if (!enabled) resetChatReactions(connId);
  else if (!dislike) {
    for (const [id,pending] of pendingChatReactions) {
      if (pending.connId===connId && pending.emoji==='👎') pendingChatReactions.delete(id);
    }
    for (const [key,state] of chatReactions) {
      if (state.connId===connId && state.entries.delete('👎') && !state.entries.size) chatReactions.delete(key);
    }
  }
  refreshReactionRows(connId);
}

async function journalReaction(requestId, pending) {
  const cache = loadReactionHistory(pending.encrypted);
  if (!cache) return false;
  await cache.ready;
  if (currentUser !== cache.user || reactionHistory.get(pending.encrypted) !== cache) return false;
  const {connId,target,reference,emoji,remove,msgId,body} = pending;
  return updateReactionHistory(reactionHistorySlot(pending.encrypted),cache.master,records=>{
    // Older open tabs prune entries without an until value on their next write.
    records.set(reactionReceiptKey(requestId),{connId,target,reference,emoji,remove,msgId,body,sender:getNick(connId),until:Number.MAX_SAFE_INTEGER});
  });
}

function forgetReactionReceipt(requestId, encrypted) {
  const cache = loadReactionHistory(encrypted);
  if (!cache) return;
  return updateReactionHistory(reactionHistorySlot(encrypted),cache.master,records=>records.delete(reactionReceiptKey(requestId)));
}

function recoverReactionReceipts(encrypted) {
  if (!_wsReady()) return;
  const cache = loadReactionHistory(encrypted), socket = ws;
  if (!cache) return;
  if (cache.receiptSocket !== socket) {
    cache.receiptSocket = socket;
    cache.receiptQueries = new Map();
  }
  void cache.ready.then(()=>{
    if (reactionHistory.get(encrypted) !== cache || currentUser !== cache.user || ws !== socket || !_wsReady()) return;
    const byConnection = new Map();
    for (const [key,pending] of cache.records) {
      const id = reactionReceiptId(key);
      if (!id || cache.receiptQueries.has(pending.connId) || !reactionConnection(pending.connId)) continue;
      if (!byConnection.has(pending.connId)) byConnection.set(pending.connId,[]);
      byConnection.get(pending.connId).push(id);
    }
    for (const [conn_id,request_ids] of byConnection) {
      if (wsend({type:'get_reaction_receipts',conn_id,request_ids})) cache.receiptQueries.set(conn_id,'sent');
    }
  });
}

async function receiveReactionReceipts({conn_id,receipts,retry_after_ms}) {
  if (Number.isSafeInteger(retry_after_ms) && retry_after_ms > 0) {
    const socket = ws;
    for (const [encrypted,cache] of reactionHistory) {
      if (cache.receiptSocket !== socket || cache.receiptQueries?.get(conn_id) !== 'sent') continue;
      cache.receiptQueries.set(conn_id,'waiting');
      setTimeout(()=>{
        if (ws !== socket || reactionHistory.get(encrypted) !== cache || currentUser !== cache.user) return;
        cache.receiptQueries.delete(conn_id);
        recoverReactionReceipts(encrypted);
      },Math.min(retry_after_ms,120000));
    }
    return;
  }
  if (!Array.isArray(receipts)) return;
  for (const receipt of receipts) {
    if (!await settleReactionReceipt(conn_id,receipt,false)) await settleReactionReceipt(conn_id,receipt,true);
  }
}

async function settleReactionReceipt(connId, receipt, encrypted, matches = null) {
  if (!receipt || !reactionReceiptId(reactionReceiptKey(receipt.request_id)) || !Number.isSafeInteger(receipt.expires_at)) return false;
  const cache = loadReactionHistory(encrypted), key = reactionReceiptKey(receipt.request_id);
  if (!cache) return false;
  await cache.ready;
  if (currentUser !== cache.user || reactionHistory.get(encrypted) !== cache) return false;
  let pending, alreadySaved;
  const committed = await updateReactionHistory(reactionHistorySlot(encrypted),cache.master,records=>{
    const entry = records.get(key);
    if (!entry) {
      // Another tab in this browser can commit the IRC echo first. Repaint
      // from the durable row even when our copy never saw the pending action.
      for (const [historyKey,row] of records) {
        if (!row.ownReceipts || !Object.values(row.ownReceipts).includes(receipt.request_id)) continue;
        const [savedConn,target,msgId]=JSON.parse(historyKey);
        if (savedConn===connId) alreadySaved={historyKey,row,target,msgId};
        break;
      }
      return false;
    }
    if (entry.connId !== connId || (matches && !matches(entry))) return false;
    records.delete(key);
    pending = entry;
    const {target,msgId,reference,emoji,remove,sender} = entry;
    saveReactionChange(records,reactionHistoryKey(connId,target,msgId),encrypted ? null : reference,
      reference,emoji,remove,sender,'',receipt.expires_at,receipt.request_id);
  });
  if (reactionHistory.get(encrypted)!==cache||currentUser!==cache.user) return false;
  if (alreadySaved) {
    const {historyKey,row,target,msgId}=alreadySaved;
    cache.records.delete(key);
    cache.records.set(historyKey,row);
    pendingChatReactions.delete(receipt.request_id);
    refreshCommittedReaction(cache,connId,target,msgId,row.reference,encrypted);
    return true;
  }
  if (!committed || !pending) return false;
  pendingChatReactions.delete(receipt.request_id);
  refreshCommittedReaction(cache,connId,pending.target,pending.msgId,pending.reference,encrypted);
  return true;
}

function saveReactionChange(records, historyKey, anchor, reference, emoji, remove, sender, actor, order, receiptId) {
  const prior = records.get(historyKey);
  const record = prior?.reference === reference ? prior : null;
  const ownOrder = record?.ownOrder || {};
  if (order && (ownOrder[emoji] || 0) >= order) return false;
  if (order) ownOrder[emoji] = order;
  const ownReceipts={...record?.ownReceipts};
  if (receiptId) ownReceipts[emoji]=receiptId;
  else if (order) delete ownReceipts[emoji];
  const entries = reactionEntryMap(record?.entries || []);
  updateReactionActors(entries,emoji,actor,sender,remove);
  records.delete(historyKey);
  if (entries.size || Object.keys(ownOrder).length) records.set(historyKey,{
    ...(anchor ? {anchor} : {}),reference,ownOrder,ownReceipts,entries:[...entries].map(([code,names])=>[code,[...names]])
  });
  return true;
}

function refreshCommittedReaction(cache,connId,target,msgId,reference,encrypted) {
  const key = reactionKey(connId,target,reference,encrypted);
  const state = chatReactions.get(key);
  if (state) {
    const row = cache.records.get(reactionHistoryKey(connId,target,msgId));
    state.entries = reactionEntryMap(row?.entries);
    state.ownOrder = {...row?.ownOrder};
  }
  refreshReactionRows(connId,target,reference);
}

function applyChatReaction(connId, target, reference, emoji, remove, sender, own, encrypted, order = 0) {
  if (!reactionEnabled(connId) || !reactionAllows(connId,emoji) || !CHAT_REACTIONS.has(emoji) ||
      !(encrypted ? encryptedReactionReference(reference) : reactionReference(reference))) return;
  const key = reactionKey(connId,target,reference,encrypted);
  const group = reactionAnchorTargets.get(JSON.stringify([connId,reactionFold(connId,target)]));
  const message = (!encrypted && group?.ids.has(reference) ? {id:group.ids.get(reference)} : getBuf(connId,target).find(m=>
    m.id && (!encrypted || m.encrypted === true) &&
    ((encrypted && m.reactionRef === reference) || storedReaction(connId,target,m.id,encrypted)?.reference === reference)));
  const saved = message && storedReaction(connId,target,message.id,encrypted);
  const anchor = message && (reactionAnchors.get(reactionAnchorKey(connId,message.id))?.reference || saved?.anchor);
  const cache = message && (encrypted || anchor) && loadReactionHistory(encrypted);
  const actor = own ? '' : reactionFold(connId,sender);
  const display = () => {
    let state = chatReactions.get(key);
    if (!state) {
      if (chatReactions.size >= 2048) chatReactions.delete(chatReactions.keys().next().value);
      const row = saved?.reference === reference ? saved : null;
      state = {connId,encrypted,entries:reactionEntryMap(row?.entries),ownOrder:{...row?.ownOrder}};
      chatReactions.set(key,state);
    }
    if (state.encrypted !== encrypted || (order && (state.ownOrder?.[emoji] || 0) >= order)) return;
    if (order) (state.ownOrder ||= {})[emoji] = order;
    updateReactionActors(state.entries,emoji,actor,sender,remove);
    refreshReactionRows(connId,target,reference);
  };
  if (cache) {
    const historyKey = reactionHistoryKey(connId,target,message.id);
    let newer;
    const write = updateReactionHistory(reactionHistorySlot(encrypted),cache.master,records=>{
      const changed = saveReactionChange(records,historyKey,anchor,reference,emoji,remove,sender,actor,order);
      if (!changed && order) newer = records.get(historyKey);
      return changed;
    });
    if (order) {
      const socket = ws;
      void write.then(committed=>{
        if (currentUser !== cache.user || ws !== socket || (encrypted && E2E.e2eEncKey !== cache.master)) return;
        const current = reactionHistory.get(encrypted);
        if (current !== cache) { if (!current) display(); return; }
        if (newer) cache.records.set(historyKey,newer);
        if (committed || newer) refreshCommittedReaction(cache,connId,target,message.id,reference,encrypted);
        else display();
      });
      return;
    }
  }
  display();
}

function reactionEntryMap(entries) {
  const result = new Map();
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!Array.isArray(entry) || !CHAT_REACTIONS.has(entry[0]) || !Array.isArray(entry[1])) continue;
    const actors = entry[1].filter(actor=>Array.isArray(actor) && typeof actor[0] === 'string' && typeof actor[1] === 'string');
    if (actors.length) result.set(entry[0],new Map(actors.slice(0,65)));
  }
  return result;
}

function updateReactionActors(entries,emoji,actor,sender,remove) {
  let names = entries.get(emoji);
  if (!names) { names = new Map(); entries.set(emoji,names); }
  if (remove) names.delete(actor);
  else if (names.size < 64 || !actor || names.has(actor)) names.set(actor,sender);
  if (!names.size) entries.delete(emoji);
}

async function receiveChatReaction(ev) {
  if (reactionMode(ev.conn_id,ev.target) !== 'none') return;
  const target = _dmTarget(ev.target);
  const account = currentUser, socket = ws;
  await loadReactionHistory(false)?.ready;
  if (currentUser !== account || ws !== socket || reactionMode(ev.conn_id,ev.target) !== 'none') return;
  if (ev.own || !isIgnored(ev.from,ev.prefix)) {
    if (ev.own) {
      const matches = p => p.connId === ev.conn_id && p.reference === ev.reference && p.emoji === ev.emoji &&
        p.remove === ev.remove && reactionFold(ev.conn_id,p.target) === reactionFold(ev.conn_id,target);
      const pending = [...pendingChatReactions].find(([,p])=>!p.encrypted && matches(p));
      const receipt = ev.receipt || (pending && {request_id:pending[0],expires_at:0});
      if (receipt && await settleReactionReceipt(ev.conn_id,receipt,false,matches)) return;
      if (currentUser !== account || ws !== socket) return;
      if (pending) pendingChatReactions.delete(pending[0]);
    }
    applyChatReaction(ev.conn_id,target,ev.reference,ev.emoji,ev.remove===true,ev.from,ev.own===true,false,
      ev.own && ev.receipt?.expires_at || 0);
  }
}

async function receiveSealedReaction(ev) {
  if (!reactionEnabled(ev.conn_id) || !window.E2E?.keyReady || !/^[A-Za-z0-9_-]{12,900}$/.test(ev.body) ||
      ev.body.length % 4 === 1) return;
  const generation = E2E._lockGen, account = currentUser, socket = ws;
  // IRC supplies the wire nickname. Only buffer and receipt lookups use the query alias.
  const target = _dmTarget(ev.target);
  if (ev.own) {
    const matches = p => p.connId === ev.conn_id && p.body === ev.body &&
      reactionFold(ev.conn_id,p.target) === reactionFold(ev.conn_id,target);
    const pending = [...pendingChatReactions].find(([,p])=>p.encrypted && matches(p));
    const receipt = ev.receipt || (pending && {request_id:pending[0],expires_at:0});
    if (receipt && await settleReactionReceipt(ev.conn_id,receipt,true,matches)) return;
    if (currentUser !== account || ws !== socket || generation !== E2E._lockGen) return;
    if (pending) {
      const [id, p] = pending;
      pendingChatReactions.delete(id);
      if (p.generation === generation) applyChatReaction(p.connId,p.target,p.reference,p.emoji,p.remove,ev.from,true,true,receipt?.expires_at || 0);
    }
    return;
  }
  let wire;
  try { wire=atob(ev.body.replace(/-/g,'+').replace(/_/g,'/')); } catch (_) { return; }
  const resume=wire.startsWith(E2E_REACTION_DM_PREFIX) && !_e2eIsChan(ev.target) ? e2eLiveResumeCheck(ev.from,ev.conn_id) : null;
  const pin=resume && E2E.trustStore[resume.peer]?.fingerprint;
  if (resume && (!pin || E2E.trustStore[resume.peer].keyChanged || !_e2eAllowHeldDm(ev.conn_id,ev.from,ev.prefix))) return;
  const options={conn_id:ev.conn_id,live:true,prefix:ev.prefix,kind:'Privmsg',reaction:true,resume};
  const approved=()=>!resume || (resume.accepted?.pin===pin && _e2eAcceptedResumeCurrent(resume.peer,ev.from,options));
  const current = () => E2E.keyReady && E2E._lockGen === generation && ws === socket &&
    currentUser === account && reactionEnabled(ev.conn_id);
  // A new socket can deliver a sealed gesture before its authenticated chat
  // settings arrive. Bound the wait from receipt so a burst cannot hold the
  // conversation queue for another full timeout per gesture.
  const receivedAt=performance.now(), syncDeadline=receivedAt+30000;
  _e2eEnqueue(ev.conn_id,ev.target,async()=>{
    while (current() && E2E._resyncPending && performance.now() < syncDeadline) {
      _e2eKickResync();
      await _e2eResyncWait(Math.min(5000,syncDeadline-performance.now()));
    }
    if (!current() || E2E._resyncPending) return;
    if (resume && !(await _e2eWaitForResumeDecision(resume,receivedAt+10000-performance.now()))) return;
    if (!current() || !approved()) return;
    // The preceding ordinary message on this queue may establish the Signal session.
    const mode = reactionMode(ev.conn_id,ev.target,true);
    if ((mode !== 'dm' && mode !== 'psk') || (mode === 'psk' && isIgnored(ev.from,ev.prefix))) return;
    try {
      if (!wire.startsWith(mode === 'psk' ? E2E_REACTION_PSK_PREFIX : E2E_REACTION_DM_PREFIX)) return;
      const result = await e2eDecryptIncoming(ev.from,ev.target,wire,options);
      if (!result.encrypted || result.duplicate || typeof result.plaintext !== 'string' ||
          !current() || !approved() || isIgnored(ev.from,ev.prefix)) return;
      await loadReactionHistory(true)?.ready;
      if (!current() || !approved()) return;
      const data = JSON.parse(result.plaintext);
      if (data?.v !== 1 || !encryptedReactionReference(data.ref) || !Number.isInteger(data.emoji) ||
          data.emoji < 0 || data.emoji >= CHAT_REACTION_EMOJI.length ||
          (data.remove !== 0 && data.remove !== 1) || !getBuf(ev.conn_id,target).some(m=>m.reactionRef === data.ref ||
            storedReaction(ev.conn_id,target,m.id,true)?.reference === data.ref)) return;
      applyChatReaction(ev.conn_id,target,data.ref,CHAT_REACTION_EMOJI[data.emoji],data.remove===1,ev.from,false,true);
    } catch (_) { /* Ignore invalid reaction payloads. */ }
  });
}

function reactionMode(connId, target, receivedReaction=false) {
  return typeof e2eTargetState === 'function' ? e2eTargetState(target,{conn_id:connId,receivedReaction}).mode : 'blocked';
}

async function sendChatReaction(connId, target, reference, emoji, remove, encrypted, msgId) {
  if (target==='status' || !reactionEnabled(connId) || !reactionAllows(connId,emoji) || !reactionReference(reference) || !CHAT_REACTIONS.has(emoji)) return;
  if (!Number.isSafeInteger(msgId) || msgId <= 0) { showToast('Wait for the original message to finish sending.'); return; }
  if (!_wsReady()) { showToast('Connect to IRC to react.'); return; }
  const foldedTarget = reactionFold(connId,target);
  if (pendingChatReactions.size >= 64 || [...pendingChatReactions.values()].some(p =>
    p.connId === connId && reactionFold(connId,p.target) === foldedTarget && p.reference === reference && p.emoji === emoji)) return;
  const mode = reactionMode(connId,target);
  const request_id = crypto.randomUUID();
  const generation = window.E2E?._lockGen;
  const signalIdentity = encrypted && mode==='dm' ? E2E.identityKeys : null;
  const wireTarget = _e2eRealTarget(target);
  const peer = signalIdentity && _e2eDmKey(_e2eCanon(wireTarget,connId) || _e2eK(wireTarget),connId);
  const peerFingerprint = peer && E2E.trustStore[peer]?.fingerprint;
  const start = peer && E2E.dmSessions[peer]?.startEph;
  const account = currentUser, socket = ws;
  const pending = {connId,target,reference,emoji,remove,encrypted,generation,msgId};
  pendingChatReactions.set(request_id,pending);
  const stillCurrent = () => {
    if (account !== currentUser || socket !== ws || !_wsReady() || !pendingChatReactions.has(request_id) ||
        (encrypted && (!E2E.keyReady || E2E._serverLocked || encryptionDeviceLocked()))) return false;
    if (signalIdentity && (signalIdentity !== E2E.identityKeys || generation !== E2E._lockGen)) {
      showToast('Reaction not sent. Your encryption identity changed. Reopen the conversation and try again.');
      return false;
    }
    if (peer && (!peerFingerprint || E2E.trustStore[peer]?.fingerprint !== peerFingerprint || E2E.trustStore[peer].keyChanged ||
        E2E.dmSessions[peer]?.startEph !== start || _e2eSessPinMismatch(peer,E2E.dmSessions[peer]) !== false)) {
      showToast('Reaction not sent. Check this contact’s Signal identity and session in Encryption.');
      return false;
    }
    return true;
  };
  let queued = false, journaled = false;
  let reaction = {kind:'plain',reference,emoji,remove};
  try {
    if (!stillCurrent()) return;
    if (encrypted) {
      if (mode !== 'dm' && mode !== 'psk') { showToast('Unlock encrypted chat to react.'); return; }
      if (!encryptedReactionReference(reference)) return;
      const wire = await e2eEncryptReaction(wireTarget,JSON.stringify({v:1,ref:reference,emoji:CHAT_REACTION_EMOJI.indexOf(emoji),remove:remove?1:0}),connId,mode);
      if (!stillCurrent()) return;
      if (E2E._lockGen !== generation || reactionMode(connId,target) !== mode || !reactionEnabled(connId) || !reactionAllows(connId,emoji)) {
        showToast('Encrypted chat is unavailable.'); return;
      }
      const body = btoa(wire).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      if (body.length > 900) { showToast('This reaction is too large to send.'); return; }
      reaction = {kind:'sealed',body,...(signalIdentity ? {e2e_identity_revision:_e2eIdentityRevisions.get(signalIdentity)} : {})};
      pending.body = body;
    } else if (mode !== 'none') { showToast('React to messages in the current encryption mode.'); return; }
    journaled = await journalReaction(request_id,pending);
    if (!stillCurrent()) return;
    if (reactionMode(connId,target) !== mode) {
      showToast(signalIdentity && E2E._resyncPending ? 'Reaction not sent. Encryption is syncing. Try again when the chat is ready.' :
        'Reaction not sent. The encryption setting for this chat changed.');
      return;
    }
    if (!reactionEnabled(connId) || !reactionAllows(connId,emoji)) return;
    if (!journaled) showToast('Device storage is unavailable. This reaction may be lost when you close the app.');
    queued = wsend({type:'react',conn_id:connId,target:wireTarget,request_id,reaction});
    if (!queued) { showToast('Connect to IRC to react.'); return; }
    setTimeout(()=>{ if (pendingChatReactions.has(request_id)) showToast('Waiting for IRC to confirm this reaction.'); },15000);
    setTimeout(()=>pendingChatReactions.delete(request_id),60000);
  } catch (error) {
    if (stillCurrent()) showToast(typeof E2EReactionWait !== 'undefined' && error instanceof E2EReactionWait ? error.message : 'Could not send this reaction.');
  }
  finally {
    if (!queued) {
      pendingChatReactions.delete(request_id);
      if (journaled && account === currentUser) void forgetReactionReceipt(request_id,encrypted);
    }
  }
}

async function receiveReactionResult({request_id,error}) {
  if (!error || !reactionReceiptId(reactionReceiptKey(request_id))) return;
  const pending = pendingChatReactions.get(request_id);
  if (pending) {
    pendingChatReactions.delete(request_id);
    void forgetReactionReceipt(request_id,pending.encrypted);
    showToast(error);
    return;
  }
  // A web/core reattach or another tab can deliver the refusal after this
  // browser lost its in-memory request. Match only this account's journal.
  const account=currentUser, socket=ws;
  const current=()=>currentUser===account&&ws===socket;
  const deleted=await Promise.all([false,true].map(async encrypted=>{
    const cache=loadReactionHistory(encrypted);
    if (!cache) return false;
    await cache.ready;
    return current() && reactionHistory.get(encrypted)===cache && await forgetReactionReceipt(request_id,encrypted);
  }));
  if (current() && deleted.some(Boolean)) showToast(error);
}

let openMessageActions = null;

function closeChatMessageActions(restoreFocus = false) {
  if (!openMessageActions) return;
  const {row, menu} = openMessageActions;
  openMessageActions = null;
  menu.remove();
  if (restoreFocus && row.isConnected) row.focus({preventScroll:true});
}

document.addEventListener('click',event=>{
  if (openMessageActions && !openMessageActions.row.contains(event.target)) closeChatMessageActions();
});

document.addEventListener('keydown',event=>{
  if (event.key !== 'Escape' || !openMessageActions?.menu.isConnected) return;
  if (!openMessageActions.row.contains(event.target)) { closeChatMessageActions(); return; }
  closeChatMessageActions(true);
  event.preventDefault();
  event.stopImmediatePropagation();
},true);

document.addEventListener('focusin',event=>{
  if (openMessageActions && !openMessageActions.row.contains(event.target)) closeChatMessageActions();
});

document.addEventListener('selectionchange',()=>{
  const selection = window.getSelection();
  if (selection && !selection.isCollapsed && openMessageActions?.row.contains(selection.anchorNode)) {
    closeChatMessageActions();
  }
});

function mountChatMessageActions(row, message, conversation) {
  if (!conversation || message.from === '*' || !['privmsg','action'].includes(message.kind) ||
      (message._dmHistoryState && message._dmHistoryState!=='ready') ||
      (message._pskHistoryState && message._pskHistoryState!=='ready')) return;
  row._chatReaction = {message, connId:conversation.conn_id||conversation.connId, target:message._tgt||conversation.target};
  row.tabIndex = -1;
  row.setAttribute('aria-keyshortcuts','Enter Space');
  row.addEventListener('click',event=>{
    if (event.button !== 0 || event.defaultPrevented || event.detail > 1 ||
        event.target.closest('a,button,input,label,select,textarea,summary,audio,video,img,iframe,[contenteditable],[role="button"],[data-nick],[data-cryptirc-click],.msg-link-preview,.tweet-card') ||
        window.getSelection()?.isCollapsed === false) return;
    toggleChatMessageActions(row,event.detail === 0);
  });
  row.addEventListener('keydown',event=>{
    if (event.target !== row || !['Enter',' '].includes(event.key) || event.repeat) return;
    event.preventDefault();
    toggleChatMessageActions(row,true);
  });
  renderReactionRow(row);
}

for (const id of ['chat-area','split-chat-area']) {
  const pane = document.getElementById(id);
  pane?.addEventListener('keydown',event=>{
    const focused = document.activeElement;
    if (focused!==pane && !focused._chatReaction) return;
    const key = event.key;
    if (!['ArrowUp','ArrowDown','Home','End','Enter',' '].includes(key) || event.altKey || event.ctrlKey || event.metaKey) return;
    const rows = [...pane.querySelectorAll('.msg-row[tabindex="-1"]')];
    if (!rows.length) return;
    const index = rows.indexOf(focused);
    if (index>=0 && (key==='Enter'||key===' ')) return; // The row handles activation.
    event.preventDefault();
    if (index<0 && (key==='Enter'||key===' ')) {
      toggleChatMessageActions(rows.at(-1),true);
      return;
    }
    const next = key==='Home'?0:key==='End'?rows.length-1:key==='ArrowDown'?index+1:index<0?rows.length-1:index-1;
    closeChatMessageActions();
    rows[Math.max(0,Math.min(rows.length-1,next))].focus();
  });
}

function refreshReactionRows(connId,target,reference,msgId) {
  const folded = target && reactionFold(connId,target);
  for (const row of document.querySelectorAll('#chat-area .msg-row, #split-chat-area .msg-row')) {
    const info = row._chatReaction;
    if (info?.connId !== connId || (msgId && info.message.id !== msgId) ||
        (folded && reactionFold(connId,info.target) !== folded)) continue;
    if (reference && messageReactionFor(row)?.reference !== reference) continue;
    renderReactionRow(row);
  }
}

function messageReactionFor(row) {
  const {message,connId,target} = row._chatReaction;
  if (target==='status' || !reactionEnabled(connId)) return null;
  const encrypted = message.encrypted === true;
  if (encrypted && !window.E2E?.keyReady) return null;
  if (encrypted && ((message._dmHistoryState && message._dmHistoryState !== 'ready') ||
                    (message._pskHistoryState && message._pskHistoryState !== 'ready'))) return null;
  const saved = message.id && storedReaction(connId,target,message.id,encrypted);
  const anchor = reactionAnchors.get(reactionAnchorKey(connId,message.id));
  if (anchor && reactionFold(connId,anchor.target) !== reactionFold(connId,target)) return null;
  // Sealed reactions address the authenticated ciphertext directly. A restored
  // message can have that reference even after its IRC anchor has left memory.
  if (!anchor && !saved && !(encrypted && message.reactionRef)) return null;
  const reference = encrypted ? message.reactionRef || saved?.reference : anchor?.reference || saved?.reference;
  if (!reference) return null;
  const state = chatReactions.get(reactionKey(connId,target,reference,encrypted));
  let counts = state?.entries || (saved?.reference === reference ? reactionEntryMap(saved.entries) : undefined);
  if (counts?.has('👎') && !reactionAllows(connId,'👎')) {
    counts = new Map(counts);
    counts.delete('👎');
  }
  return {connId,target,reference,encrypted,counts};
}

function reactToMessage(row,emoji) {
  const reaction = messageReactionFor(row);
  if (!reaction) return;
  const {connId,target,reference,encrypted,counts} = reaction;
  void sendChatReaction(connId,target,reference,emoji,counts?.get(emoji)?.has('')===true,encrypted,row._chatReaction.message.id);
}

function toggleChatMessageActions(row,keyboard) {
  const wasOpen = openMessageActions?.row === row;
  closeChatMessageActions(wasOpen && keyboard);
  if (wasOpen) return;
  const body = row.querySelector('.msg-body');
  if (!body) return;
  const menu = document.createElement('span');
  menu.className = 'message-actions';
  menu.setAttribute('role','group');
  menu.setAttribute('aria-label','Message actions');
  const reply = document.createElement('button');
  reply.type = 'button';
  reply.textContent = 'Reply';
  reply.onclick = () => {
    const {message,connId,target} = row._chatReaction;
    closeChatMessageActions();
    setReply(message.from,message.text,{conn_id:connId,target});
  };
  menu.append(reply);
  syncMessageReactionChoices(row,menu,messageReactionFor(row));
  openMessageActions = {row,menu};
  body.append(menu);
  if (keyboard) reply.focus({preventScroll:true});
  menu.scrollIntoView({block:'nearest',inline:'nearest'});
}

function syncMessageReactionChoices(row,menu,reaction) {
  for (const [emoji,label] of CHAT_MESSAGE_REACTIONS) {
    const existing = [...menu.querySelectorAll('.reaction-choice')].find(button=>button.dataset.emoji===emoji);
    if (!reaction || !reactionAllows(reaction.connId,emoji)) { existing?.remove(); continue; }
    const pressed = String(reaction.counts?.get(emoji)?.has('')===true);
    if (existing) { existing.setAttribute('aria-pressed',pressed); continue; }
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'reaction-choice';
    button.dataset.emoji = emoji;
    button.textContent = `${emoji} ${label}`;
    button.setAttribute('aria-label',label);
    button.setAttribute('aria-pressed',pressed);
    button.onclick = event => {
      closeChatMessageActions(event.detail===0);
      reactToMessage(row,emoji);
    };
    menu.append(button);
  }
}

function renderReactionRow(row) {
  const reaction = messageReactionFor(row);
  if (openMessageActions?.row === row) {
    syncMessageReactionChoices(row,openMessageActions.menu,reaction);
  }
  const old = row.querySelector('.message-reactions');
  const body = row.querySelector('.msg-body');
  if (!reaction?.counts?.size || !body) { old?.remove(); return; }
  const controls = document.createElement('span');
  controls.className = 'message-reactions';
  for (const [emoji,names] of reaction.counts) {
    if (!CHAT_REACTIONS.has(emoji)) continue;
    const actionable = reactionAllows(reaction.connId,emoji) && (CHAT_MESSAGE_REACTIONS.has(emoji) || names.has(''));
    const chip = document.createElement(actionable ? 'button' : 'span');
    chip.className = 'reaction-count';
    chip.textContent = `${emoji} ${names.size}`;
    const actors = [...names.values()].join(', ');
    chip.title = actors;
    chip.setAttribute('aria-label',`${CHAT_REACTIONS.get(emoji)}, ${names.size}: ${actors}`);
    if (actionable) {
      chip.type = 'button';
      chip.setAttribute('aria-pressed',String(names.has('')));
      chip.onclick = ()=>{ closeChatMessageActions(); reactToMessage(row,emoji); };
    }
    controls.append(chip);
  }
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
