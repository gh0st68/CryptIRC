
// ─── Quota-exceeded guard ────────────────────────────────────────────────────
// Safari (esp. in private mode) and some Android browsers throw QuotaExceeded
// when localStorage fills up (~5MB). Surface that to the user exactly once so
// they know some settings will stop persisting. Still re-throw so existing
// try/catches around writes continue their normal fallback.
(function(){
  try{
    const orig = localStorage.setItem.bind(localStorage);
    let _lastQuotaToast = 0;
    localStorage.setItem = function(k, v){
      try { return orig(k, v); }
      catch(e){
        const isQuota = e && (e.name === 'QuotaExceededError'
                           || e.code === 22 || e.code === 1014);
        // Throttle to once/10s — and don't "burn" the toast attempt if
        // showToast isn't defined yet (early-load error). Only update the
        // timestamp when we actually show something.
        if(isQuota && Date.now() - _lastQuotaToast > 10000){
          try{
            if(typeof showToast==='function'){
              showToast('Storage full — some settings may not save. Clear browser data if this persists.');
              _lastQuotaToast = Date.now();
            }
          }catch(_){}
        }
        throw e;
      }
    };
  }catch(_){}
})();

// ─── State ────────────────────────────────────────────────────────────────────
let ws=null, sessionToken=null, currentUser=null;
let networks=[], active=null;
let buffers={}, unread=new Map(), mentionUnread=new Map(), queryBufs={};
// PM/query windows the user explicitly CLOSED, keyed "conn_id|targetLower" → close
// timestamp (unix seconds). Used so a closed query isn't re-opened by old/replayed
// messages on reconnect — only a genuinely newer message reopens it. Synced + local.
let closedQueries={};
let _historyView=null; // history-view state: {bk,conn_id,target} when the active buffer is a past window (see jumpToMessage)
// Restore unread counts
try{const ur=JSON.parse(localStorage.getItem('cryptirc_unread')||'{}');for(const[k,v] of Object.entries(ur))unread.set(k,v);}catch(e){}
function saveUnread(){try{const o={};for(const[k,v] of unread)o[k]=v;localStorage.setItem('cryptirc_unread',JSON.stringify(o));}catch(e){} savePrefsToServer();}
// Persist open DM windows across refresh
function saveQueryBufs(){
  try{
    const obj={};
    for(const[connId,m] of Object.entries(queryBufs)){
      obj[connId]=[...m.entries()];
    }
    localStorage.setItem('cryptirc_queries',JSON.stringify(obj));
    localStorage.setItem('cryptirc_queries_ts',String(Date.now()));
  }catch(e){} savePrefsToServer();
}
function loadQueryBufs(){
  try{
    const obj=JSON.parse(localStorage.getItem('cryptirc_queries')||'{}');
    for(const[connId,entries] of Object.entries(obj)){
      queryBufs[connId]=new Map(entries);
    }
  }catch(e){}
  try{ closedQueries=JSON.parse(localStorage.getItem('cryptirc_closed_queries')||'{}')||{}; }catch(e){ closedQueries={}; }
}
function saveClosedQueries(){
  try{
    localStorage.setItem('cryptirc_closed_queries',JSON.stringify(closedQueries));
    localStorage.setItem('cryptirc_closed_queries_ts',String(Date.now()));
  }catch(e){} savePrefsToServer();
}
// Mark a query closed (so replays can't reopen it); clears its open buffer entry.
function markQueryClosed(conn_id,lc){ closedQueries[conn_id+'|'+lc]=Math.floor(Date.now()/1000); saveClosedQueries(); }
// User explicitly (re)opened a query → forget any closed marker so it behaves normally.
function clearQueryClosed(conn_id,lc){ if(closedQueries[conn_id+'|'+lc]!=null){ delete closedQueries[conn_id+'|'+lc]; saveClosedQueries(); } }
function loadLastActive(){
  try{return JSON.parse(localStorage.getItem('cryptirc_active'));}catch{return null;}
}
loadQueryBufs();

// ─── Detached pop-out windows ────────────────────────────────────────────────
// Detached mode loads the SAME index.html in a second window with ?detached=1.
// That second window runs as a full CryptIRC client (own WS + state) so all
// features (nick menus, slash commands, E2E, uploads) work without duplication.
// This module only tracks which targets are currently "popped out" so the main
// sidebar can show a ⧉ indicator and route clicks to focus the existing popup.
const _qsDet = new URLSearchParams(location.search);
const _detMode = _qsDet.get('detached') === '1';
const _detConn = _qsDet.get('conn') || '';
const _detTarget = _qsDet.get('target') || '';
if(_detMode) document.documentElement.classList.add('detached-mode');

const _detachedChannel = (typeof BroadcastChannel!=='undefined') ? new BroadcastChannel('cryptirc-detached') : null;
let _detachedTargets = new Set();
const _detachedWindows = Object.create(null);
function _detKey(conn_id,target){return conn_id+':'+String(target||'').toLowerCase();}
function isDetached(conn_id,target){return _detachedTargets.has(_detKey(conn_id,target));}
function _loadDetached(){
  try{
    const arr=JSON.parse(localStorage.getItem('cryptirc_detached')||'[]');
    for(const e of arr) if(e&&e.conn_id&&e.target) _detachedTargets.add(_detKey(e.conn_id,e.target));
  }catch(e){}
}
function _saveDetached(){
  const arr=[..._detachedTargets].map(k=>{const i=k.indexOf(':');return {conn_id:k.slice(0,i),target:k.slice(i+1)};});
  try{localStorage.setItem('cryptirc_detached',JSON.stringify(arr));}catch(e){}
}
_loadDetached();
function openDetachedWindow(conn_id,target){
  const k=_detKey(conn_id,target);
  const existing=_detachedWindows[k];
  if(existing && !existing.closed){try{existing.focus();}catch(_){} return;}
  const basePath=(document.location.pathname.match(/^\/[^\/]+/)||[''])[0]||'';
  const url=basePath+'/?detached=1&conn='+encodeURIComponent(conn_id)+'&target='+encodeURIComponent(target);
  const name='cryptirc-d-'+conn_id+'-'+target.toLowerCase().replace(/[^a-z0-9_-]/g,'_');
  const w=window.open(url,name,'width=900,height=700,resizable=yes,scrollbars=yes');
  if(w) _detachedWindows[k]=w;
  else showToast('Pop-up blocked — allow popups for this site');
}
function detachView(conn_id,target){
  if(_detMode){showToast('Already in a detached window');return;}
  _detachedTargets.add(_detKey(conn_id,target));
  _saveDetached(); renderSidebar();
  openDetachedWindow(conn_id,target);
  if(active && active.conn_id===conn_id && String(active.target).toLowerCase()===String(target).toLowerCase()){
    setActive(conn_id,'status');
  }
}
function reattachView(conn_id,target){
  const k=_detKey(conn_id,target);
  _detachedTargets.delete(k);
  _saveDetached(); renderSidebar();
  const w=_detachedWindows[k];
  if(w && !w.closed){try{w.close();}catch(_){}}
  delete _detachedWindows[k];
  try{_detachedChannel && _detachedChannel.postMessage({type:'close',conn_id,target});}catch(_){}
}
if(_detachedChannel){
  _detachedChannel.addEventListener('message',e=>{
    const d=e.data; if(!d) return;
    if(d.type==='bye' && !_detMode){
      // Popup notified us it's closing — drop from detached set.
      const k=_detKey(d.conn_id,d.target);
      _detachedTargets.delete(k);
      delete _detachedWindows[k];
      _saveDetached(); renderSidebar();
    } else if(d.type==='close' && _detMode && d.conn_id===_detConn &&
              String(d.target||'').toLowerCase()===_detTarget.toLowerCase()){
      try{window.close();}catch(_){}
    }
  });
}
// Detached-window bootstrap: emit `bye` on close; auto-setActive handled in state handler.
if(_detMode && _detachedChannel){
  window.addEventListener('beforeunload',()=>{
    try{_detachedChannel.postMessage({type:'bye',conn_id:_detConn,target:_detTarget});}catch(_){}
  });
}
function _detachedReattachSelf(){try{window.close();}catch(_){}}
function _sidebarActivate(conn_id,target){
  if(!_detMode && isDetached(conn_id,target)){
    openDetachedWindow(conn_id,target);
    closeSidebar();
    return;
  }
  setActive(conn_id,target);
  closeSidebar();
}
function _canPopOut(){return !_detMode && !!_detachedChannel && !window.matchMedia('(max-width: 768px)').matches;}

let inputHistory=[], historyIdx=-1;
try{inputHistory=JSON.parse(localStorage.getItem('cryptirc_input_history')||'[]');}catch(e){}
function saveInputHistory(){
  // Filter out commands that may contain passwords before persisting
  const SENSITIVE=/^\/(identify|nickserv|ns|oper|msg\s+nickserv|msg\s+chanserv|pass)/i;
  const safe=inputHistory.filter(l=>!SENSITIVE.test(l)).slice(-100);
  try{localStorage.setItem('cryptirc_input_history',JSON.stringify(safe));}catch(e){}
  savePrefsToServer();
}
let lagMap={};
let pushSubscription=null;
let swRegistration=null;
const IMG_EXTS=/\.(jpg|jpeg|png|gif|webp|avif)(\?.*)?$/i;
const VID_EXTS=/\.(mp4|webm|mov)(\?.*)?$/i;

// ─── M2: iOS keyboard fix ────────────────────────────────────────────────────
function initViewportFix() {
  const app = document.getElementById('app');

  // Prevent body-level scrolling. Walks ancestors looking for ANY scrollable
  // container (vertical OR horizontal). Previously only checked overflowY,
  // which killed horizontal-scroll elements like the Giphy picker — every
  // horizontal swipe on a thumb got preventDefault'd, and iOS subsequently
  // suppressed the synthetic click.
  document.body.addEventListener('touchmove', e => {
    let el = e.target;
    while (el && el !== document.body) {
      const cs = getComputedStyle(el);
      const scrollY = (cs.overflowY === 'auto' || cs.overflowY === 'scroll') && el.scrollHeight > el.clientHeight;
      const scrollX = (cs.overflowX === 'auto' || cs.overflowX === 'scroll') && el.scrollWidth  > el.clientWidth;
      if (scrollY || scrollX) return;
      el = el.parentElement;
    }
    if (e.cancelable) e.preventDefault();
  }, { passive: false });

  // Use visualViewport to resize app when keyboard opens (critical for iOS PWA)
  const iw = document.getElementById('input-wrap');
  if (window.visualViewport) {
    const vv = window.visualViewport;
    // rAF-throttle — keyboard dismiss / rotation can fire resize dozens of
    // times in rapid succession. Coalesce into one layout per frame.
    let _vvPending = false;
    function syncHeight() {
      if (_vvPending) return;
      _vvPending = true;
      requestAnimationFrame(() => {
        _vvPending = false;
        app.style.height = vv.height + 'px';
        window.scrollTo(0, 0);
        // If the user was near the bottom before the viewport resized,
        // re-anchor so they don't lose the latest message when the
        // keyboard opens/closes or browser chrome hides.
        if(!_userScrolledAway){
          const area = document.getElementById('chat-area');
          if(area) area.scrollTop = area.scrollHeight;
        }
      });
    }
    vv.addEventListener('resize', syncHeight);
    vv.addEventListener('scroll', () => window.scrollTo(0, 0));
  }

  // Auto-scroll chat to bottom when keyboard opens, remove safe-area padding
  const inp = document.getElementById('msg-input');
  if (inp) {
    inp.addEventListener('focus', () => {
      // Remove safe-area bottom padding when keyboard is open (home bar is hidden)
      if(iw) iw.style.paddingBottom = '0';
      [200, 500, 1000].forEach(ms => setTimeout(() => {
        if(!_userScrolledAway){
          const area = document.getElementById('chat-area');
          if (area) area.scrollTop = area.scrollHeight;
        }
        window.scrollTo(0, 0);
      }, ms));
    });
    inp.addEventListener('blur', () => {
      // Restore safe-area padding when keyboard closes
      if(iw) iw.style.paddingBottom = '';
      app.style.height = '';
      setTimeout(() => {
        window.scrollTo(0, 0);
        // Chat area just grew (keyboard gone) — if the user was reading the
        // tail before typing, put them back at the latest message.
        if(!_userScrolledAway) scrollBottom();
      }, 150);
    });
  }
}

// ─── M6: Swipe gesture for sidebar ───────────────────────────────────────────
function initSwipeGesture() {
  if(_detMode) return; // no sidebar in detached mode — gesture makes no sense
  let startX=0, startY=0, swiping=false;
  const THRESHOLD=60, EDGE_ZONE=40;
  const sidebar=document.getElementById('sidebar');
  const app=document.getElementById('app');

  app.addEventListener('touchstart', e=>{
    if(e.touches.length!==1) return;
    // Ignore swipes that start inside a horizontal scroller — those are meant
    // to scroll the picker/list, not drag the sidebar. Otherwise swipes on
    // the leftmost Giphy thumb would open the sidebar instead of scrolling.
    if(e.target.closest && e.target.closest('#giphy-picker')) return;
    startX=e.touches[0].clientX; startY=e.touches[0].clientY; swiping=true;
  }, {passive:true});

  app.addEventListener('touchmove', e=>{
    if(!swiping||e.touches.length!==1) return;
    const dx=e.touches[0].clientX-startX;
    const dy=Math.abs(e.touches[0].clientY-startY);
    // Only handle horizontal swipes
    if(dy>Math.abs(dx)*1.5) { swiping=false; return; }
    // Open: swipe right from left edge
    if(!sidebar.classList.contains('open') && startX<EDGE_ZONE && dx>0) {
      const pct=Math.min(dx/THRESHOLD,1);
      sidebar.style.transform=`translateX(${-100+pct*100}%)`;
    }
    // Close: swipe left when sidebar open
    if(sidebar.classList.contains('open') && dx<0) {
      const pct=Math.min(Math.abs(dx)/THRESHOLD,1);
      sidebar.style.transform=`translateX(${-pct*100}%)`;
    }
  }, {passive:true});

  app.addEventListener('touchend', e=>{
    if(!swiping) return; swiping=false;
    const dx=e.changedTouches[0].clientX-startX;
    const np=document.getElementById('nick-panel');
    sidebar.style.transform=''; // let CSS transition take over
    if(np) np.style.transform='';
    if(!sidebar.classList.contains('open') && startX<EDGE_ZONE && dx>THRESHOLD/2) openSidebar();
    else if(sidebar.classList.contains('open') && dx<-THRESHOLD/2) closeSidebar();
    // Nick panel: swipe left from right edge to open, swipe right to close
    else if(np && !np.classList.contains('open') && startX>window.innerWidth-EDGE_ZONE && dx<-THRESHOLD/2) {
      closeSidebar(); np.classList.add('open'); document.getElementById('sidebar-backdrop').classList.add('show');
    }
    else if(np && np.classList.contains('open') && dx>THRESHOLD/2) {
      np.classList.remove('open'); document.getElementById('sidebar-backdrop').classList.remove('show');
    }
  }, {passive:true});
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
function switchAuthTab(tab) {
  document.getElementById('login-form').style.display      = tab==='login'    ? '' : 'none';
  document.getElementById('register-form').style.display   = tab==='register' ? '' : 'none';
  document.getElementById('forgot-form').style.display     = tab==='forgot'   ? '' : 'none';
  document.getElementById('forgot-success').style.display  = 'none';
  document.getElementById('reg-success').style.display     = 'none';
  document.getElementById('tab-login').classList.toggle('active',    tab==='login' || tab==='forgot');
  document.getElementById('tab-register').classList.toggle('active', tab==='register');
}
async function doLogin() {
  const user=document.getElementById('l-user').value.trim();
  const pass=document.getElementById('l-pass').value;
  if(!user||!pass){setErr('login-err','Fill in all fields');return;}
  const btn=document.getElementById('login-btn');
  const lights=document.getElementById('login-lights');
  btn.disabled=true; btn.textContent='Signing in…';
  lights.classList.add('active');
  try {
    const r=await fetch('/cryptirc/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    const d=await r.json();
    if(!r.ok){setErr('login-err',d.message||'Login failed');lights.classList.remove('active');return;}
    sessionToken=d.token; currentUser=d.username;
    localStorage.setItem('cryptirc_token',sessionToken);
    localStorage.setItem('cryptirc_user',currentUser);
    document.cookie=`cryptirc_token=${sessionToken};path=/cryptirc;max-age=31536000;SameSite=Strict${location.protocol==='https:'?';Secure':''}`;
    await new Promise(r=>setTimeout(r,1500));
    lights.classList.remove('active');
    showApp();
  } catch(e){setErr('login-err','Network error');lights.classList.remove('active');}
  finally{btn.disabled=false;btn.textContent='Sign In';}
}
async function doForgot() {
  const email=document.getElementById('f-email').value.trim();
  if(!email){setErr('forgot-err','Enter your email address');return;}
  const btn=document.getElementById('forgot-btn');
  btn.disabled=true; btn.textContent='Sending…';
  try {
    const r=await fetch('/cryptirc/auth/forgot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
    await r.json();
    document.getElementById('forgot-form').style.display='none';
    document.getElementById('forgot-success').style.display='';
  } catch(e){setErr('forgot-err','Network error');}
  finally{btn.disabled=false;btn.textContent='Send Reset Link';}
}
async function doRegister() {
  const user=document.getElementById('r-user').value.trim();
  const email=document.getElementById('r-email').value.trim();
  const pass=document.getElementById('r-pass').value;
  const pass2=document.getElementById('r-pass2').value;
  if(!user||!email||!pass||!pass2){setErr('reg-err','Fill in all fields');return;}
  if(pass!==pass2){setErr('reg-err','Passwords do not match');return;}
  if(pass.length<10){setErr('reg-err','Password must be at least 10 characters');return;}
  const btn=document.getElementById('reg-btn');
  btn.disabled=true; btn.textContent='Creating…';
  try {
    const code=document.getElementById('r-code')?.value?.trim()||'';
    const r=await fetch('/cryptirc/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,email,password:pass,code})});
    const d=await r.json();
    if(!r.ok){setErr('reg-err',d.message||'Registration failed');return;}
    document.getElementById('register-form').style.display='none';
    document.getElementById('reg-success').style.display='';
    setErr('reg-err','');
  } catch(e){setErr('reg-err','Network error');}
  finally{btn.disabled=false;btn.textContent='Create Account';}
}
async function doLogout() {
  if(!(await customConfirm('Sign out?','Sign out'))) return;
  if(sessionToken) fetch('/cryptirc/auth/logout',{method:'POST',headers:{'Authorization':'Bearer '+sessionToken}}).catch(()=>{});
  sessionToken=null; currentUser=null;
  localStorage.removeItem('cryptirc_token'); localStorage.removeItem('cryptirc_user');
  if(ws) ws.close();
  document.getElementById('auth-screen').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('vault-overlay').classList.remove('show');
}
function setErr(id,msg){document.getElementById(id).textContent=msg;}
async function checkAuth() {
  // Check if registration is open
  try{
    const sr=await fetch('/cryptirc/auth/status');
    if(sr.ok){
      const sd=await sr.json();
      if(!sd.registration_open){
        const regTab=document.querySelector('[onclick*="switchAuthTab(\'register\')"]');
        if(regTab) regTab.style.display='none';
      }
      if(sd.requires_code){
        const cf=document.getElementById('reg-code-field');
        if(cf) cf.style.display='';
      }
    }
  }catch(e){}
  const token=localStorage.getItem('cryptirc_token');
  if(!token){document.getElementById('auth-screen').style.display='flex';return;}
  try {
    const r=await fetch('/cryptirc/auth/me',{headers:{'Authorization':'Bearer '+token}});
    if(!r.ok){localStorage.removeItem('cryptirc_token');document.getElementById('auth-screen').style.display='flex';return;}
    const d=await r.json();
    sessionToken=token; currentUser=d.username;
    document.cookie=`cryptirc_token=${sessionToken};path=/cryptirc;max-age=31536000;SameSite=Strict${location.protocol==='https:'?';Secure':''}`;
    showApp();
  } catch(e){document.getElementById('auth-screen').style.display='flex';}
}
function showApp() {
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  connectWs();
  checkAdmin();
  // Check for notification_click from SW (URL params path)
  const params=new URLSearchParams(location.search);
  const openTarget=params.get('open');
  if(openTarget) {
    const [cid,tgt]=decodeURIComponent(openTarget).split('/');
    const ts=params.get('ts');
    const from=params.get('from');
    // Stash as pending nav — will execute once networks load via the state handler.
    // (jumpToMessage re-stashes if networks aren't ready yet.)
    _pendingNotifNav={conn_id:cid, target:tgt, ts:ts?parseInt(ts):null, from:from||null};
    // Clean the URL so a refresh doesn't re-trigger the nav
    try{history.replaceState(null,'',location.pathname+location.hash);}catch(e){}
  }
  // Also check the SW cache bridge (in case SW wrote intent but postMessage was missed)
  _readNotifClickCache();
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
let _wsRetries=0;
let _lastWsActivity=Date.now();
function connectWs() {
  if(!sessionToken) return;
  // Close any existing connection to prevent duplicate event streams
  if(ws){try{ws.onclose=null;ws.onerror=null;ws.onmessage=null;ws.close();}catch(e){}}
  const proto=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(`${proto}://${location.host}/cryptirc/ws`);
  ws.onopen=()=>{_wsRetries=0;_lastWsActivity=Date.now();
    // In-flight get_logs/sync requests are dead after a (re)connect — their
    // responses were lost (iOS silently drops WS messages). Clearing the pending
    // sets prevents a stale key from making jumpToMessage's tick wait forever,
    // which showed up as "clicking a notification sometimes doesn't jump".
    _pendingLogs.clear(); _pendingSyncs.clear();
  };
  ws.onmessage=e=>{_lastWsActivity=Date.now();_rxBytes+=(e.data||'').length;_rxCount++;flashLed('rx');updateStarfieldTitle();try{handleEvent(JSON.parse(e.data));}catch(err){console.error('WS parse error:',err);}};
  ws.onclose=()=>{_rateQueue=[];if(_rateTimer){clearTimeout(_rateTimer);_rateTimer=null;}const d=Math.min(1000*Math.pow(2,_wsRetries),60000);setTimeout(connectWs,d+Math.random()*1000);_wsRetries++;};
  ws.onerror=()=>ws.close();
}
// React to browser-level network state changes so the user sees a reconnect
// happen immediately instead of waiting 30-90s for the WS to notice.
window.addEventListener('offline', ()=>{
  try{ showToast('Network offline — messages will queue when reconnected.'); }catch(_){}
  if(ws && ws.readyState===1){ try{ ws.close(); }catch(_){}}
});
window.addEventListener('online', ()=>{
  try{ showToast('Network restored — reconnecting…'); }catch(_){}
  if(!ws || ws.readyState===3) { _wsRetries = 0; connectWs(); }
  else if(ws && ws.readyState!==1){ try{ ws.close(); }catch(_){}}
});

// ─── Android hardware-back-button / popstate overlay stack ───────────────────
// On Android PWA, pressing the hardware back button while a sidebar/modal is
// open exits the entire app — bad UX. We push a history state when any
// overlay opens so the next back event pops our state (closing the overlay)
// instead of leaving the app.
const _overlayStack = [];
// Counter (not bool) so stacked manual-close calls don't let a real back
// event leak through. Incremented on every _overlayClose; the popstate
// handler decrements it and skips one event per increment.
let _popSkipCount = 0;
function _overlayOpen(name, closeFn){
  if(_overlayStack.some(o => o.name === name)) return;  // already open, no-op
  _overlayStack.push({name, closeFn});
  try{ history.pushState({_overlay: _overlayStack.length}, ''); }catch(_){}
}
function _overlayClose(name){
  const idx = _overlayStack.findIndex(o => o.name === name);
  if(idx < 0) return;
  _overlayStack.splice(idx, 1);
  _popSkipCount++;
  try{ history.back(); }catch(_){ _popSkipCount = Math.max(0, _popSkipCount-1); }
}
window.addEventListener('popstate', () => {
  if(_popSkipCount > 0){ _popSkipCount--; return; }
  if(_overlayStack.length > 0){
    const top = _overlayStack.pop();
    try{ top.closeFn(); }catch(_){}
  }
});
// iOS PWA WebSocket-zombie watchdog: iOS Safari throttles backgrounded JS and
// silently drops WS messages without firing onclose, so the connection looks
// alive but no events arrive. Periodically poll for missed messages on the
// active channel, and force-reconnect if the WS has been quiet for too long.
function _syncActiveChannel(){
  if(!sessionToken||!ws||ws.readyState!==1)return;
  if(!active?.conn_id||!active?.target||active.target==='status')return;
  const _sk=bk(active.conn_id,active.target),_lid=_lastMsgId[_sk];
  if(_lid>0) wsend({type:'sync',conn_id:active.conn_id,target:active.target,after_id:_lid});
  else wsend({type:'get_logs',conn_id:active.conn_id,target:active.target,limit:50});
}
setInterval(()=>{
  _syncActiveChannel();
  // Staleness check: if WS hasn't had activity in 30s, it's likely a zombie — reconnect
  if(sessionToken&&ws&&ws.readyState===1&&Date.now()-_lastWsActivity>30000){
    try{ws.close();}catch(e){} // onclose will trigger reconnect via the handler chain
  }
},5000);
// Touch/interaction-based sync: iOS may throttle setInterval but touch events
// always fire. Debounced to avoid spamming on every tap.
let _lastTouchSync=0;
function _onTouchSync(){
  const now=Date.now();
  if(now-_lastTouchSync<3000)return; // at most once per 3s
  _lastTouchSync=now;
  _syncActiveChannel();
}
document.addEventListener('touchstart',_onTouchSync,{passive:true});
document.addEventListener('click',_onTouchSync,{passive:true});
// Reconnect + catch up when app comes back from background (iOS PWA, minimized desktop, etc.)
function _onResume(){
  if(!sessionToken)return;
  if(!ws || ws.readyState !== 1){
    connectWs(); // WS dead — reconnect (logs will load via state handler)
  } else {
    // WS alive but may have missed messages while frozen — sync ALL channels
    // so unread badges populate, not just the active one.
    for(const net of networks){
      const id=net.config.id;
      // Sync each joined channel
      for(const ch of (net.channels||[])){
        const k=bk(id,ch.name);
        const lastId=_lastMsgId[k];
        if(lastId>0) wsend({type:'sync',conn_id:id,target:ch.name,after_id:lastId});
      }
      // Sync open PM/query buffers
      if(queryBufs[id]){
        for(const [lc] of queryBufs[id]){
          const k=bk(id,lc);
          const lastId=_lastMsgId[k];
          if(lastId>0) wsend({type:'sync',conn_id:id,target:lc,after_id:lastId});
        }
      }
    }
    // Sync active channel with full fallback if no lastId
    if(active?.conn_id && active?.target){
      const k=bk(active.conn_id,active.target);
      const lastId=_lastMsgId[k];
      if(!lastId){
        wsend({type:'get_logs',conn_id:active.conn_id,target:active.target,limit:200});
      }
      // Refresh the nick list for the active channel — we may have missed JOIN/PART/QUIT
      // events while the tab was frozen (common on mobile PWA when backgrounded).
      if(active.target.startsWith('#')||active.target.startsWith('&')){
        wsend({type:'send',conn_id:active.conn_id,raw:`NAMES ${active.target}`});
      }
    }
  }
  scrollBottom();
  updateTypingIndicator();
  // Safety net: re-render sidebar after sync responses arrive to ensure
  // unread badges are up to date. Sync responses are async (irc_message events
  // through the E2E queue), so schedule a sidebar refresh after they settle.
  [500,1500,3000].forEach(ms=>setTimeout(()=>renderSidebar(),ms));
}
document.addEventListener('visibilitychange',()=>{
  if(!document.hidden){_onResume();_resetIdleTimer();}
  else{
    // Tab backgrounded — go idle after 60s instead of full 20min
    clearTimeout(_idleTimer);
    _idleTimer=setTimeout(()=>{
      if(!_isIdle){_isIdle=true;if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'idle'}));}
    },60000);
  }
});
window.addEventListener('pageshow',e=>{
  if(e.persisted) _onResume();
});
window.addEventListener('focus',_onResume);
// ─── Idle detection for push notification gating ──────────────────────────────
let _idleTimer=null, _isIdle=false;
const IDLE_TIMEOUT_MS=20*60*1000; // 20 minutes
function _resetIdleTimer(){
  if(_isIdle){_isIdle=false;if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'active'}));}
  clearTimeout(_idleTimer);
  _idleTimer=setTimeout(()=>{
    if(!_isIdle){_isIdle=true;if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'idle'}));}
  },IDLE_TIMEOUT_MS);
}
['mousemove','mousedown','keydown','touchstart','scroll','wheel'].forEach(evt=>
  document.addEventListener(evt,_resetIdleTimer,{passive:true,capture:true})
);
_resetIdleTimer();
// ─── Starfield (Ubiquiti-style) ───────────────────────────────────────────────
let _starBurst=0,_txBytes=0,_rxBytes=0,_txCount=0,_rxCount=0;
try{const sc=JSON.parse(localStorage.getItem('cryptirc_stats')||'{}');_txBytes=sc.tx||0;_rxBytes=sc.rx||0;_txCount=sc.tc||0;_rxCount=sc.rc||0;}catch(e){}
function saveStats(){try{localStorage.setItem('cryptirc_stats',JSON.stringify({tx:_txBytes,rx:_rxBytes,tc:_txCount,rc:_rxCount}));}catch(e){} savePrefsToServer();}
function flashLed(dir){
  _starBurst=dir==='tx'?1:2;
  setTimeout(()=>{_starBurst=0;},300);
}
function fmtBytes(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB';}
let _statsSaveTimer=null;
function updateStarfieldTitle(){
  const hdr=document.getElementById('sidebar-header');
  if(hdr) hdr.title=`TX: ${fmtBytes(_txBytes)} (${_txCount} msgs)\nRX: ${fmtBytes(_rxBytes)} (${_rxCount} msgs)`;
  if(!_statsSaveTimer)_statsSaveTimer=setTimeout(()=>{saveStats();_statsSaveTimer=null;},5000);
}
(function(){
  const cv=document.getElementById('starfield');
  if(!cv)return;
  const ctx=cv.getContext('2d');
  const W=cv.width, H=cv.height;
  const stars=[];
  for(let i=0;i<30;i++){
    stars.push({
      x:Math.random()*W, y:Math.random()*H,
      r:Math.random()*1.2+0.3,
      dx:(Math.random()-0.5)*0.15,
      dy:(Math.random()-0.5)*0.1,
      phase:Math.random()*Math.PI*2,
      speed:Math.random()*0.02+0.01
    });
  }
  let _sfRaf=0;
  function draw(){
    if(document.hidden){_sfRaf=0;return;} // pause when tab/window hidden — don't burn a CPU core drawing an unseen canvas
    ctx.clearRect(0,0,W,H);
    const t=Date.now()*0.001;
    for(const s of stars){
      s.x+=s.dx; s.y+=s.dy;
      if(s.x<0)s.x=W; if(s.x>W)s.x=0;
      if(s.y<0)s.y=H; if(s.y>H)s.y=0;
      const twinkle=0.4+0.6*Math.abs(Math.sin(t*s.speed*10+s.phase));
      let alpha=twinkle*0.7;
      let color='255,255,255';
      if(_starBurst===1){alpha=Math.min(1,alpha+0.5);color='74,222,128';}
      else if(_starBurst===2){alpha=Math.min(1,alpha+0.5);color='96,165,250';}
      ctx.beginPath();
      ctx.arc(s.x,s.y,s.r*(0.8+twinkle*0.4),0,Math.PI*2);
      ctx.fillStyle=`rgba(${color},${alpha})`;
      ctx.fill();
    }
    _sfRaf=requestAnimationFrame(draw);
  }
  draw();
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden&&!_sfRaf) _sfRaf=requestAnimationFrame(draw); });
})();
// Track pending log/sync requests so we ignore responses from other sessions.
// _pendingLogs is a Map of "conn/target" -> send-time(ms) so jumpToMessage can
// tell a young in-flight request (worth waiting for) from a stale key whose
// response was dropped (must be abandoned, not waited on forever).
const _pendingLogs=new Map();
const _pendingSyncs=new Set();
function wsend(obj){
  if(ws&&ws.readyState===1){
    const s=JSON.stringify(obj);_txBytes+=s.length;_txCount++;ws.send(s);flashLed('tx');updateStarfieldTitle();
    // Track log/sync requests from THIS session
    if(obj.type==='get_logs') _pendingLogs.set(obj.conn_id+'/'+obj.target, Date.now());
    if(obj.type==='sync') _pendingSyncs.add(obj.conn_id+'/'+obj.target);
    // Track sent PRIVMSG/NOTICE for irc_echo dedup
    if(obj.type==='send'&&obj.raw){
      const upper=obj.raw.toUpperCase();
      if(upper.startsWith('PRIVMSG ')||upper.startsWith('NOTICE ')){
        const parts=obj.raw.split(/\s+/,3);
        if(parts.length>=3){
          let txt=obj.raw.slice(obj.raw.indexOf(':',obj.raw.indexOf(' '))+1);
          // Strip CTCP ACTION wrapper so it matches the server's cleaned text
          if(txt.startsWith('\x01ACTION ')&&txt.endsWith('\x01')) txt=txt.slice(8,-1);
          if(!window._sentMsgs) window._sentMsgs=[];
          window._sentMsgs.push({t:Date.now(),conn:obj.conn_id,target:parts[1],text:txt});
        }
      }
    }
    return true;
  }
  // Not connected. For user-initiated actions, warn the user so they don't
  // think their action went through — throttled to once per 3 seconds.
  // Allowlist over denylist: only clearly user-initiated operational commands
  // get a toast; background/auto-save/query traffic stays silent.
  const _toastTypes = new Set([
    'send','join_channel','part_channel',
    'connect','disconnect','add_network','remove_network','update_network',
    'lock_vault','unlock_vault','change_passphrase',
    'generate_cert','delete_cert',
    'clear_all_data','clear_target_logs','delete_account',
    'upload_remove','search_logs',
  ]);
  if(obj && _toastTypes.has(obj.type)){
    const now = Date.now();
    if(now - (window._lastSendFailToast||0) > 3000){
      window._lastSendFailToast = now;
      try{ showToast('Not connected — action not sent. Waiting for reconnect…'); }catch(_){}
    }
  }
  return false;
}

// ─── Events ───────────────────────────────────────────────────────────────────
function handleEvent(ev) {
  switch(ev.type){
    case 'auth_required': wsend({type:'auth',token:sessionToken||''}); break;
    case 'auth_ok':
      currentUser=ev.username;
      // If idle on reconnect, tell server immediately after auth
      if(_isIdle&&ws&&ws.readyState===1)ws.send(JSON.stringify({type:'idle'}));
      wsend({type:'load_appearance'}); wsend({type:'load_preferences'}); wsend({type:'upload_list_get'});
      // Re-check push subscription after auth
      setTimeout(async()=>{
        if(swRegistration && Notification?.permission==='granted'){
          await loadNotifPrefs();
          if(_notifPrefs?.enabled && !pushSubscription){
            pushSubscription=await swRegistration.pushManager.getSubscription();
            if(!pushSubscription) await subscribePush();
          }
        }
      },2000);
      break;
    case 'auth_failed': sessionToken=null; localStorage.removeItem('cryptirc_token'); document.getElementById('auth-screen').style.display='flex'; break;
    case 'vault_unlocked':
      document.getElementById('vault-overlay').classList.remove('show'); renderSidebar();
      {const vb=document.getElementById('vault-lock-btn');if(vb){vb.textContent='🔓';vb.title='Lock vault';}}
      if(ev.e2e_enc_key) e2eInit(ev.e2e_enc_key);
      if(!_chanStatsLoaded) loadStatsFromServer();
      // Prefs are server-side encrypted; the initial load_preferences fired
      // before unlock returned empty. Re-request now that vault is open so
      // the server can decrypt and send the real prefs blob.
      wsend({type:'load_preferences'});
      // Note: log loading is handled by the 'state' event handler which fires
      // before vault_unlocked — no need to request logs here (avoids double delivery)
      break;
    case 'vault_error': document.getElementById('vault-err').textContent=ev.message; break;
    case 'state':
      networks=ev.networks||[];
      if(!ev.vault_unlocked) document.getElementById('vault-overlay').classList.add('show');
      else { document.getElementById('vault-overlay').classList.remove('show'); const vb=document.getElementById('vault-lock-btn');if(vb){vb.textContent='🔓';vb.title='Lock vault';} if(!_chanStatsLoaded)loadStatsFromServer(); }
      renderSidebar();
      // Detached-mode auto-activation: force the requested target; ignore any
      // saved last-active so the popup always lands on the chat it was opened for.
      if(_detMode && _detConn && _detTarget){
        const dNet=networks.find(n=>n.config.id===_detConn);
        if(dNet){
          active={conn_id:_detConn,target:_detTarget};
          renderSidebar(); renderChat(); updateTopbar(); updateLagDisplay();
          updateInputPlaceholder();
        }
      }
      // Restore last active view after page refresh (skipped in detached mode)
      if(!_detMode && !active){
        const saved=loadLastActive();
        if(saved&&saved.conn_id&&saved.target){
          if(isUploadsConn(saved.conn_id)){
            active={conn_id:UPLOAD_CONN,target:UPLOAD_TARGET};
            renderSidebar(); renderChat(); updateTopbar(); updateInputPlaceholder();
          } else {
            const net=networks.find(n=>n.config.id===saved.conn_id);
            if(net){
              active={conn_id:saved.conn_id,target:saved.target};
              renderSidebar(); renderChat(); updateTopbar(); updateLagDisplay();
              updateInputPlaceholder();
            }
          }
        }
      }
      // Load logs for all channels + status when vault is unlocked
      if(ev.vault_unlocked){
        for(const net of networks){
          // Load status logs
          if(getBuf(net.config.id,'status').length===0)
            wsend({type:'get_logs',conn_id:net.config.id,target:'status',limit:200});
          for(const ch of net.channels||[]){
            if(getBuf(net.config.id,ch.name).length===0)
              wsend({type:'get_logs',conn_id:net.config.id,target:ch.name,limit:200});
          }
        }
        // Also load for active if it's a PM (not in channels list)
        if(active&&getBuf(active.conn_id,active.target).length===0)
          wsend({type:'get_logs',conn_id:active.conn_id,target:active.target,limit:200});
      }
      // Drain any pending notification-click nav now that networks are loaded
      _drainPendingNotifNav();
      break;
    case 'connecting':   sysMsg(ev.conn_id,'status',`Connecting to ${ev.server}…`,'system'); setNetDot(ev.conn_id,'connecting'); break;
    case 'connected':    sysMsg(ev.conn_id,'status',`Connected to ${ev.server} as ${ev.nick}`,'system'); setNetDot(ev.conn_id,'online'); updateNick(ev.conn_id,ev.nick); keepnickStartPoll(ev.conn_id); break;
    case 'disconnected':
      sysMsg(ev.conn_id,'status',`Disconnected: ${ev.reason}`,'error'); setNetDot(ev.conn_id,'offline'); lagMap[ev.conn_id]=null; if(active&&active.conn_id===ev.conn_id) updateLagDisplay();
      if(ev.reason&&ev.reason.includes('certificate verify failed')&&!window._certWarnShown?.[ev.conn_id]){
        if(!window._certWarnShown)window._certWarnShown={};
        window._certWarnShown[ev.conn_id]=true;
        showCertWarning(ev.conn_id);
      }
      break;
    case 'reconnecting': {
      sysMsg(ev.conn_id,'status',`↻ Reconnecting in ${ev.delay_secs}s (attempt ${ev.attempt})…`,'system');
      // Detect self-signed cert error and show helpful popup (once per network)
      if(ev.reason&&ev.reason.includes('certificate verify failed')&&!window._certWarnShown?.[ev.conn_id]){
        if(!window._certWarnShown)window._certWarnShown={};
        window._certWarnShown[ev.conn_id]=true;
        showCertWarning(ev.conn_id);
      }
      break;
    }
    case 'lag_update': lagMap[ev.conn_id]=ev.ms; if(active&&active.conn_id===ev.conn_id) updateLagDisplay(); break;
    case 'sasl_status': sysMsg(ev.conn_id,'status', ev.success?`✓ SASL: ${ev.message}`:`✗ SASL failed: ${ev.message}`, ev.success?'system':'error'); break;
    case 'irc_echo': {
      trackMsgId(ev.conn_id,ev.target,ev.msg_id||0);
      // Server-side echo of our own sent message — for multi-device sync
      // Skip if this device already displayed it (tracked by _sentMsgs)
      if(!window._sentMsgs) window._sentMsgs=[];
      const now=Date.now();
      // Clean old entries (>5s)
      window._sentMsgs=window._sentMsgs.filter(s=>now-s.t<5000);
      // Check if this device sent this exact message
      const idx=window._sentMsgs.findIndex(s=>s.conn===ev.conn_id&&s.target===ev.target&&s.text===ev.text);
      if(idx>=0){
        // This device sent it — already displayed, skip. Stamp the buffer
        // entry with msg_id so any duplicate echo that arrives later (e.g.
        // from a second WS subscription) gets caught by addMessage's
        // internal dedup-by-id at the buf.push() path.
        window._sentMsgs.splice(idx,1);
        const _eb=getBuf(ev.conn_id,ev.target);
        let _ei=_eb.findIndex(m=>m.ts===ev.ts&&m.from===ev.from&&(m.text||'').slice(0,50)===(ev.text||'').slice(0,50));
        if(_ei<0){
          // Fallback covering two failure modes of the strict-equality
          // findIndex above:
          //   • clock skew: optimistic add used Date.now()/1000 (client)
          //     while ev.ts is server time — strict m.ts===ev.ts fails when
          //     they differ by even 1 second.
          //   • E2E channels: optimistic stored plaintext but ev.text is
          //     the sd8~… ciphertext.
          // We're inside the `idx>=0` branch, so _sentMsgs already
          // confirmed this echo corresponds to one of OUR sends. Walk
          // backwards and pick the OLDEST unstamped self-sent entry in
          // the 30s window — echoes arrive in send order, so for rapid
          // A/B/C fires we want to stamp A first, then B, then C.
          for(let i=_eb.length-1;i>=0;i--){
            const m=_eb[i];
            if(m.ts<ev.ts-30) break;
            if(m.from===ev.from && !m.id) _ei=i;
          }
        }
        if(_ei>=0&&ev.msg_id) _eb[_ei].id=ev.msg_id;
        break;
      }
      // From another device — OR a duplicate echo where _sentMsgs was already
      // consumed by a prior fire (e.g. two WS connections, reconnect race).
      // E2E: ev.text is the sd8~ channel ciphertext (the server holds no key),
      // so this OTHER device must decrypt it the same way the live irc_message
      // path does — otherwise it renders raw ciphertext until a refresh pulls
      // decrypted history. Serialize through _e2eQueue like the live path, and
      // dedup on the DECRYPTED text. If the key isn't loaded yet we keep the
      // ciphertext so redecryptChannelHistory fixes it when the key arrives.
      {
        const _eConn=ev.conn_id, _eTarget=ev.target, _eText=ev.text;
        const _eFrom=ev.from, _eTs=ev.ts, _eId=ev.msg_id||0, _eKind=ev.kind;
        if(!window._e2eQueue) window._e2eQueue=Promise.resolve();
        window._e2eQueue=window._e2eQueue.then(async()=>{
          let dtext=_eText, enc=false;
          if(typeof _eText==='string'&&_eText.startsWith('sd8~')&&typeof channelDecrypt==='function'){
            try{
              const kn=(typeof _resolveChanKeyName==='function')?_resolveChanKeyName(_eTarget):null;
              if(kn){ const pt=await channelDecrypt(kn,_eText); if(pt!==null){dtext=pt;enc=true;} }
            }catch(_){}
          }
          const echoBuf=getBuf(_eConn,_eTarget);
          const echoKey=_eTs+'|'+_eFrom+'|'+(dtext||'').slice(0,50);
          if(echoBuf.some(m=>m.ts+'|'+m.from+'|'+(m.text||'').slice(0,50)===echoKey)) return;
          addMessage(_eConn,_eTarget,{
            id:_eId, ts:_eTs, from:_eFrom, text:dtext, encrypted:enc,
            kind:_eKind==='Action'?'action':_eKind==='Notice'?'notice':'privmsg',
          });
        });
      }
      break;
    }
    case 'irc_message':
      trackMsgId(ev.conn_id,ev.target,ev.msg_id||0);
      // Route incoming user notices to the active channel instead of opening a PM
      // (e.g. NickServ, ChanServ replies) — but let our OWN outgoing notices
      // go to the target's PM window (e.g. PM protection responses)
      if(ev.kind==='Notice'&&ev.target&&ev.target!=='status'&&!ev.target.startsWith('#')&&!ev.target.startsWith('&')&&ev.from!=='*'&&!ev.from.includes('.')){
        if(ev.from!==getNick(ev.conn_id)){
          ev.target=active&&active.conn_id===ev.conn_id?active.target:'status';
        }
      }
      // Suppress noisy 401 "No such nick/channel" errors
      // Suppress noisy server errors (typing on unsupported networks, offline nicks, etc)
      if(ev.text&&(ev.text.includes('No such nick/channel')||ev.text.includes('Command disabled')||ev.text.includes('Unknown command')||ev.text.includes('@+typing'))) break;
      // Intercept ISON (303) replies for keepnick — narrow window to prevent swallowing other messages
      if(ev.target==='status'&&_keepnickIsonPending[ev.conn_id]){
        const pendingTs=_keepnickIsonPending[ev.conn_id];
        // Only intercept within 5 seconds of sending ISON and if text is short (nicks only)
        if(typeof pendingTs==='number'&&Date.now()-pendingTs<5000){
          const t=(ev.text||'').replace(/^:\s*/,'').trim();
          if(t.length<200){
            const kn=loadKeepNicks();
            if(kn[ev.conn_id]){
              const words=t?t.split(/\s+/):[];
              const allNickChars=words.length<=10&&words.every(w=>/^[a-zA-Z0-9_\-\[\]\\`^|{}]+$/.test(w));
              if(allNickChars||t===''){
                delete _keepnickIsonPending[ev.conn_id];
                keepnickHandleIson(ev.conn_id,t);
                break;
              }
            }
          }
        }
        delete _keepnickIsonPending[ev.conn_id]; // Expire stale pending flag
      }
      // Intercept links data for /links overlay
      if(ev.from==='links'&&window._linksData!=null){
        if(ev.text==='End of /LINKS'){renderLinksOverlay();}
        else{addLinkEntry(ev.text);}
        break;
      }
      // Serialize E2E decrypt to prevent race between x3dh header and encrypted message
      if(!window._e2eQueue) window._e2eQueue=Promise.resolve();
      window._e2eQueue=window._e2eQueue.then(async()=>{
        const { plaintext, encrypted } = await e2eDecryptIncoming(ev.from, ev.target, ev.text);
        // Suppress x3dh header messages (handled internally, not displayed)
        if (plaintext === null && !encrypted && ev.text.startsWith('[e2ex3dh]')) return;
        const displayText = plaintext !== null ? plaintext : ev.text;
        // Block PMs if enabled — per-network settings with global fallback; allow list bypasses
        const _isDmIncoming=ev.target!=='status'&&!ev.target.startsWith('#')&&!ev.target.startsWith('&')&&ev.from!==getNick(ev.conn_id)&&ev.from!=='*';
        if(_isDmIncoming){
          const _pm=getPmSettings(ev.conn_id);
          if(_pm.enabled&&!isPmAllowedFor(ev.conn_id,ev.from)){
            const cooldownHrs=_pm.cooldown;
            const notify=_pm.notify;
            const deliverFirst=_pm.deliverFirst;
            const _bpKey='bp:'+ev.conn_id+':'+ev.from.toLowerCase();
            const _bpLast=parseInt(localStorage.getItem(_bpKey)||'0');
            const _bpFirst=Date.now()-_bpLast>cooldownHrs*3600*1000;
            if(_bpFirst){
              localStorage.setItem(_bpKey,String(Date.now()));
              if(notify){
                const hrTxt=cooldownHrs===1?'hour':cooldownHrs<24?cooldownHrs+' hours':cooldownHrs===24?'24 hours':Math.round(cooldownHrs/24)+' days';
                const _pmOffText=`This CryptIRC user has their private messages turned off.${deliverFirst?' They will receive your first message and if they feel like it they will get back to you.':''} All${deliverFirst?' further':''} messages from you will be silently dropped for the next ${hrTxt}.`;
                wsend({type:'send',conn_id:ev.conn_id,raw:`NOTICE ${ev.from} :${_pmOffText}`});
                // Echo the auto-notice into the sender's PM window so the user
                // can see what their client replied with.
                addMessage(ev.conn_id, ev.from, {
                  ts: Math.floor(Date.now()/1000),
                  from: getNick(ev.conn_id),
                  text: _pmOffText,
                  kind: 'notice',
                });
              }
              if(!deliverFirst){
                recordBlockedPm(ev.conn_id, ev.from, displayText, ev.ts);
                return; // drop even the first message
              }
              // Let the first message through — don't return
            } else {
              recordBlockedPm(ev.conn_id, ev.from, displayText, ev.ts);
              return; // silently drop all further messages during cooldown
            }
          }
        }
        const mentioned=checkMention(ev.conn_id,ev.target,ev.from,displayText,ev.ts);
        // ZNC playback detection — batch old messages silently
        const zncMsg={id:ev.msg_id||0,ts:ev.ts,from:ev.from,text:displayText,kind:ev.kind==='Action'?'action':ev.kind==='Notice'?'notice':'privmsg',encrypted,mentioned,prefix:ev.prefix||null};
        if(zncDetectBatch(ev.conn_id,ev.target,zncMsg)){
          // Filter ignored users in ZNC batch path too
          if(isIgnored(ev.from, ev.prefix)) return;
          // Still add to buffer but don't trigger notifications/sounds — dedup by msg_id + fuzzy
          const _zbuf=getBuf(ev.conn_id,ev.target);
          let _zdup=false;
          const _zts=Math.max(0,_zbuf.length-30);
          // id match: scan the WHOLE buffer (ZNC/bouncer replay can re-deliver a
          // line whose original is far from the tail). Fuzzy match below stays
          // windowed so genuinely repeated identical text isn't wrongly dropped.
          if(zncMsg.id){
            for(let _zi=0;_zi<_zbuf.length;_zi++){
              if(_zbuf[_zi].id===zncMsg.id){_zdup=true;break;}
            }
          }
          if(!_zdup){
            const _zfk=zncMsg.ts+'|'+zncMsg.from+'|'+(zncMsg.text||'').slice(0,50);
            for(let _zi=_zts;_zi<_zbuf.length;_zi++){
              if(_zbuf[_zi].ts+'|'+_zbuf[_zi].from+'|'+(_zbuf[_zi].text||'').slice(0,50)===_zfk){_zdup=true;break;}
            }
          }
          if(!_zdup){_zbuf.push(zncMsg);if(_zbuf.length>2000)_zbuf.splice(0,_zbuf.length-2000);}
          // Only track stats/seen for non-duplicate playback messages. Previously
          // counted duplicates, which inflated channel stats every time ZNC replayed
          // the same buffered history on reconnect.
          if(!_zdup){
            trackSeen(ev.from,ev.target,ev.ts);
            trackStat(ev.conn_id,ev.target,ev.from);
          }
          if(!_zdup&&isActive(ev.conn_id,ev.target))appendMsgRow(zncMsg);
          return;
        }
        addMessage(ev.conn_id, ev.target, {
          id:        ev.msg_id||0,
          ts:        ev.ts,
          from:      ev.from,
          text:      displayText,
          kind:      ev.kind==='Action'?'action':ev.kind==='Notice'?'notice':'privmsg',
          encrypted: encrypted,
          mentioned: mentioned,
          prefix: ev.prefix||null,
        });
        // Auto-open query for pending WHOIS
        if(window._pendingWhois&&window._pendingWhois[ev.conn_id]){
          const pnick=window._pendingWhois[ev.conn_id].toLowerCase();
          if(ev.from==='*'&&ev.target&&ev.target.toLowerCase()===pnick){
            setActive(ev.conn_id,ev.target);
            delete window._pendingWhois[ev.conn_id];
          }
        }
      });
      break;
    // E2E events — routed to the E2E engine
    case 'e2e_identity_blob':
    case 'e2e_session':
    case 'e2e_bundle':
    case 'e2e_channel_key':
    case 'e2e_channel_list':
    case 'e2e_trust':
    case 'e2e_otpk_low':
    case 'e2e_x3dh_header':
      if (window.E2E) e2eHandleEvent(ev);
      break;
    case 'irc_join': // fallthrough to irc_join_ex
    case 'irc_join_ex': {
      monitorUpdate(ev.nick,ev.conn_id,ev.channel,null);
      // extended-join: show account + realname if available
      let joinMsg = `→ ${ev.nick} joined`;
      if(ev.account && ev.account !== '*') joinMsg += ` (${ev.account})`;
      if(ev.realname) joinMsg += ` — ${ev.realname}`;
      sysMsg(ev.conn_id,ev.channel,joinMsg,'join',{ts:ev.ts,from:ev.nick,self:ev.nick===getNick(ev.conn_id),subject:ev.nick});
      const jNet=networks.find(n=>n.config.id===ev.conn_id);
      const jCh=jNet?.channels.find(c=>c.name===ev.channel);
      if(jCh&&!jCh.names.some(n=>stripPfx(n)===ev.nick)) jCh.names.push(ev.nick);
      renderSidebar(); refreshUserCount(ev.conn_id,ev.channel); blinkUserCount('join');
      if(ev.nick===getNick(ev.conn_id)) setActive(ev.conn_id,ev.channel);
      break;
    }
    case 'irc_part': {
      sysMsg(ev.conn_id,ev.channel,`← ${ev.nick} left${ev.reason?' ('+ev.reason+')':''}`,'part',{ts:ev.ts,from:ev.nick,self:ev.nick===getNick(ev.conn_id),subject:ev.nick});
      const pNet=networks.find(n=>n.config.id===ev.conn_id);
      const pCh=pNet?.channels.find(c=>c.name===ev.channel);
      if(pCh) pCh.names=pCh.names.filter(n=>stripPfx(n)!==ev.nick);
      // If WE parted, remove channel and switch away
      if(ev.nick===getNick(ev.conn_id)){
        if(pNet) pNet.channels=pNet.channels.filter(c=>c.name!==ev.channel);
        // Keep buffer so history loads when rejoined
        unread.delete(bk(ev.conn_id,ev.channel));
        mentionUnread.delete(bk(ev.conn_id,ev.channel));
        // Remove from favorites if favorited
        const favs=loadFavorites();
        const newFavs=favs.filter(f=>!(f.conn_id===ev.conn_id&&f.target===ev.channel));
        if(newFavs.length!==favs.length) saveFavorites(newFavs);
        if(isActive(ev.conn_id,ev.channel)){
          const altCh=pNet?.channels.find(c=>c.name!==ev.channel);
          setActive(ev.conn_id,altCh?altCh.name:'status');
        }
      }
      renderSidebar(); refreshUserCount(ev.conn_id,ev.channel); blinkUserCount('part');
      monitorOffline(ev.nick);
      break;
    }
    case 'irc_quit': {
      const net=networks.find(n=>n.config.id===ev.conn_id);
      const quitChans=(net?.channels||[]).filter(ch=>ch.names.some(n=>stripPfx(n)===ev.nick));
      const quitSelf=ev.nick===getNick(ev.conn_id);
      for(const ch of quitChans){
        sysMsg(ev.conn_id,ch.name,`⊗ ${ev.nick} quit${ev.reason?' ('+ev.reason+')':''}`,'quit',{ts:ev.ts,from:ev.nick,self:quitSelf,subject:ev.nick});
        ch.names=ch.names.filter(n=>stripPfx(n)!==ev.nick);
        refreshUserCount(ev.conn_id,ch.name);
      }
      if(!quitChans.length) sysMsg(ev.conn_id,'status',`⊗ ${ev.nick} quit${ev.reason?' ('+ev.reason+')':''}`,'quit',{ts:ev.ts,from:ev.nick,self:quitSelf,subject:ev.nick});
      renderSidebar(); blinkUserCount('part');
      monitorOffline(ev.nick);
      keepnickOnQuit(ev.conn_id,ev.nick);
      break;
    }
    case 'irc_nick': {
      const nNet=networks.find(n=>n.config.id===ev.conn_id);
      const nickChans=(nNet?.channels||[]).filter(ch=>ch.names.some(n=>stripPfx(n)===ev.old||stripPfx(n)===ev.new));
      const nickSelf=(ev.old===getNick(ev.conn_id)||ev.new===getNick(ev.conn_id));
      for(const ch of nickChans){
        sysMsg(ev.conn_id,ch.name,`• ${ev.old} is now known as ${ev.new}`,'nick',{ts:ev.ts,from:ev.new,self:nickSelf,subject:ev.new,subject2:ev.old});
        ch.names=ch.names.map(n=>{const pfx=n.match(/^[@+~&%]*/)[0];return stripPfx(n)===ev.old?pfx+ev.new:n;});
        refreshUserCount(ev.conn_id,ch.name);
      }
      if(!nickChans.length) sysMsg(ev.conn_id,'status',`• ${ev.old} is now known as ${ev.new}`,'nick',{ts:ev.ts,from:ev.new,self:nickSelf,subject:ev.new,subject2:ev.old});
      if(ev.old===getNick(ev.conn_id)||ev.new===getNick(ev.conn_id)){
        updateNick(ev.conn_id,ev.new);
        keepnickOnOwnNickChange(ev.conn_id,ev.old,ev.new);
      } else {
        keepnickOnNickChange(ev.conn_id,ev.old,ev.new);
      }
      renderSidebar();
      break;
    }
    case 'irc_topic': {
      if(ev.channel){
        sysMsg(ev.conn_id,ev.channel,`Topic: ${ev.topic}${ev.set_by?' ('+ev.set_by+')':''}`, 'topic');
        const tNet=networks.find(n=>n.config.id===ev.conn_id);
        if(tNet){
          const tCh=tNet.channels.find(c=>c.name===ev.channel);
          if(tCh) tCh.topic=ev.topic;
          else tNet.channels.push({name:ev.channel,topic:ev.topic,names:[]});
        }
        if(isActive(ev.conn_id,ev.channel)) updateTopbar();
      }
      break;
    }
    case 'irc_names':  updateNames(ev.conn_id,ev.channel,ev.names); renderSidebar(); monitorRefreshOnline(); break;
    case 'irc_kick':
      sysMsg(ev.conn_id,ev.channel,`✗ ${ev.kicked} kicked by ${ev.by}${ev.reason?' ('+ev.reason+')':''}`, 'kick',{ts:ev.ts,from:ev.kicked,self:(ev.kicked===getNick(ev.conn_id)||ev.by===getNick(ev.conn_id)),subject:ev.kicked,subject2:ev.by});
      // Auto-rejoin on kick if enabled
      if(ev.kicked===getNick(ev.conn_id) && localStorage.getItem('cryptirc_autorejoin')!=='false'){
        const _rjKey=bk(ev.conn_id,ev.channel),_rjSavedKey=localStorage.getItem('cryptirc_chankeys');
        let _rjKeyVal=null;try{const ks=JSON.parse(_rjSavedKey||'{}');_rjKeyVal=ks[_rjKey]||null;}catch(e){}
        setTimeout(()=>{wsend({type:'join_channel',conn_id:ev.conn_id,channel:ev.channel,key:_rjKeyVal||''});sysMsg(ev.conn_id,ev.channel,'Auto-rejoining after kick...','system');},3000);
      }
      break;
    case 'irc_mode': {
      // Parse setter|modes format (e.g. "gh0st|+v felon_1" or just "+v felon_1")
      let modeSetter='', rawModes=ev.modes;
      if(ev.modes.includes('|')){
        const pipeIdx=ev.modes.indexOf('|');
        modeSetter=ev.modes.slice(0,pipeIdx);
        rawModes=ev.modes.slice(pipeIdx+1);
      }
      const modeDisplay=modeSetter?`${modeSetter} sets mode ${rawModes}`:`MODE ${rawModes}`;
      sysMsg(ev.conn_id,ev.target,modeDisplay,'mode',{ts:ev.ts,from:modeSetter||'*',self:modeSetter===getNick(ev.conn_id),rawModes:rawModes,subject:modeSetter||''});
      // Update nick prefixes in names list when channel modes change
      const mNet=networks.find(n=>n.config.id===ev.conn_id);
      const mCh=mNet?.channels.find(c=>c.name===ev.target);
      if(mCh){
        const modeMap={o:'@',v:'+',h:'%',a:'&',q:'~'};
        const parts=rawModes.split(' ');
        const modeStr=parts[0]||'';
        let argIdx=1,adding=true;
        for(const c of modeStr){
          if(c==='+'){adding=true;continue;}
          if(c==='-'){adding=false;continue;}
          if('ovhaq'.includes(c)){
            const tNick=parts[argIdx++];
            if(!tNick)continue;
            const pfxChar=modeMap[c];
            const idx=mCh.names.findIndex(n=>stripPfx(n).toLowerCase()===tNick.toLowerCase());
            if(idx===-1)continue;
            const oldEntry=mCh.names[idx];
            let oldPfx='';for(let j=0;j<oldEntry.length;j++){if('~&@%+'.includes(oldEntry[j]))oldPfx+=oldEntry[j];else break;}
            const bare=stripPfx(oldEntry);
            if(adding){
              if(!oldPfx.includes(pfxChar)){
                // Insert prefix in correct hierarchy order
                const order='~&@%+';
                let newPfx='';
                const allPfx=oldPfx+pfxChar;
                for(const ch of order){if(allPfx.includes(ch))newPfx+=ch;}
                mCh.names[idx]=newPfx+bare;
              }
            } else {
              mCh.names[idx]=oldPfx.replace(pfxChar,'')+bare;
            }
          } else if('beIkl'.includes(c)){argIdx++;} // modes that consume an arg
        }
        renderSidebar(); refreshUserCount(ev.conn_id,ev.target);
        if(isActive(ev.conn_id,ev.target)) renderNickPanel(mCh.names);
      }
      // Keep the Channel Modes dialog in sync when modes change live.
      if(_cmMatch(ev.conn_id,ev.target)) cmRefresh();
      break;
    }
    // ── IRCv3: away-notify ──────────────────────────────
    case 'irc_away': {
      // Send away/back notices to status only (not every channel)
      const aNet=networks.find(n=>n.config.id===ev.conn_id);
      const awaySelf=ev.nick===getNick(ev.conn_id);
      if(ev.away){
        addMessage(ev.conn_id,'status',{ts:ev.ts,from:ev.nick,text:`${ev.nick} is away: ${ev.message}`,kind:'away',noUnread:true,self:awaySelf,subject:ev.nick});
      } else {
        addMessage(ev.conn_id,'status',{ts:ev.ts,from:ev.nick,text:`${ev.nick} is back`,kind:'back',noUnread:true,self:awaySelf,subject:ev.nick});
      }
      // Track away state for nick panel
      if(!window._awayNicks) window._awayNicks={};
      const awayKey=ev.conn_id+'/'+ev.nick;
      if(ev.away) window._awayNicks[awayKey]=ev.message;
      else delete window._awayNicks[awayKey];
      // Re-render nick panel if active channel contains this nick
      if(aNet&&active&&active.conn_id===ev.conn_id){
        const actCh=aNet.channels.find(c=>c.name===active.target);
        if(actCh&&actCh.names.some(n=>stripPfx(n)===ev.nick)){
          renderNickPanel(actCh.names);
        }
      }
      break;
    }
    // ── Away snapshot from a WHO poll (servers without away-notify) ──
    // Reconciles the away (grayed-out) state for a whole channel at once:
    // members listed in away_nicks are away, all other current members are back.
    case 'irc_away_snapshot': {
      if(!window._awayNicks) window._awayNicks={};
      const snNet=networks.find(n=>n.config.id===ev.conn_id);
      if(!snNet) break;
      const snCh=snNet.channels.find(c=>c.name===ev.channel);
      if(!snCh) break;
      const awaySet=new Set((ev.away_nicks||[]).map(x=>x.toLowerCase()));
      let changed=false;
      for(const member of snCh.names){
        const bare=stripPfx(member);
        const key=ev.conn_id+'/'+bare;
        const nowAway=awaySet.has(bare.toLowerCase());
        const wasAway=!!window._awayNicks[key];
        if(nowAway&&!wasAway){ window._awayNicks[key]=true; changed=true; }
        else if(!nowAway&&wasAway){ delete window._awayNicks[key]; changed=true; }
      }
      if(changed&&active&&active.conn_id===ev.conn_id&&active.target===ev.channel){
        renderNickPanel(snCh.names);
      }
      break;
    }
    // ── IRCv3: account-notify ─────────────────────────
    case 'irc_account': {
      const acNet=networks.find(n=>n.config.id===ev.conn_id);
      if(acNet){
        for(const ch of acNet.channels){
          if(ch.names.some(n=>stripPfx(n)===ev.nick)){
            if(ev.account){
              sysMsg(ev.conn_id,ch.name,`★ ${ev.nick} logged in as ${ev.account}`,'system');
            } else {
              sysMsg(ev.conn_id,ch.name,`★ ${ev.nick} logged out`,'system');
            }
          }
        }
      }
      break;
    }
    // ── IRCv3: invite-notify ──────────────────────────
    case 'irc_invite': {
      const myNick=getNick(ev.conn_id);
      if(ev.target===myNick){
        sysMsg(ev.conn_id,'status',`📩 ${ev.from} has invited you to ${ev.channel}`,'system');
        // Show desktop notification for invites
        if(Notification.permission==='granted'){
          new Notification('CryptIRC — Invite',{body:`${ev.from} invited you to ${ev.channel}`,icon:'/cryptirc/icon.svg'});
        }
      } else {
        sysMsg(ev.conn_id,'status',`📩 ${ev.from} has invited ${ev.target} to ${ev.channel}`,'system');
      }
      break;
    }
    // ── IRCv3: setname ────────────────────────────────
    case 'irc_setname': {
      const snNet=networks.find(n=>n.config.id===ev.conn_id);
      if(snNet){
        for(const ch of snNet.channels){
          if(ch.names.some(n=>stripPfx(n)===ev.nick)){
            sysMsg(ev.conn_id,ch.name,`★ ${ev.nick} changed their name to: ${ev.realname}`,'system');
          }
        }
      }
      break;
    }
    // ── IRCv3: typing indicator ───────────────────────
    case 'irc_typing': {
      if(!window._typingState) window._typingState={};
      const tKey=ev.conn_id+'/'+ev.target+'/'+ev.nick;
      if(ev.state==='active'){
        window._typingState[tKey]=Date.now();
        // Auto-clear after 6 seconds
        setTimeout(()=>{
          if(window._typingState[tKey]&&Date.now()-window._typingState[tKey]>=5500){
            delete window._typingState[tKey];
            updateTypingIndicator();
          }
        },6000);
      } else {
        delete window._typingState[tKey];
      }
      updateTypingIndicator();
      break;
    }
    // ── IRCv3: MONITOR online/offline ─────────────────
    case 'irc_monitor_online': {
      monitorUpdate(ev.nick,ev.conn_id,null,'online');
      sysMsg(ev.conn_id,'status',`● ${ev.nick} is now online`,'join');
      break;
    }
    case 'irc_monitor_offline': {
      monitorUpdate(ev.nick,ev.conn_id,null,'offline');
      sysMsg(ev.conn_id,'status',`○ ${ev.nick} is now offline`,'part');
      break;
    }
    case 'irc_list_entry': handleListEntry(ev); break;
    case 'irc_list_end': handleListEnd(); break;
    case 'irc_channel_modes': {
      // Current channel modes (324). Feed the dialog if open for this channel;
      // otherwise show it for manual /mode users.
      if (_cmMatch(ev.conn_id, ev.channel)) { cmParseModes(ev.modes); cmRender(); }
      else sysMsg(ev.conn_id, ev.channel, `Modes: ${ev.modes || '(none)'}`, 'mode', { ts: Math.floor(Date.now()/1000), from: '*' });
      break;
    }
    case 'irc_ban_entry': {
      const key = ev.conn_id + '/' + ev.channel;
      // Channel Modes dialog is collecting this list — route the entry into it
      // and suppress the per-entry channel sysMsg.
      if (_cmMatch(ev.conn_id, ev.channel) && _cm.collecting && _cm.collecting[ev.list]) {
        _cm.lists[ev.list].push({ mask: ev.mask, by: ev.set_by, ts: ev.ts });
        cmRenderList();
        break;
      }
      // Check if this is for /unbanall
      if (pendingUnbanAll[key]) {
        if (!banListAccum[key]) banListAccum[key] = [];
        banListAccum[key].push(ev.mask);
      }
      // Check if this is for /unexemptall (348 reuses ban_entry event)
      if (window._pendingUnexempt?.[key]) {
        if (!window._exemptAccum[key]) window._exemptAccum[key] = [];
        window._exemptAccum[key].push(ev.mask);
        sysMsg(ev.conn_id, ev.channel, `Exempt: ${ev.mask}${ev.set_by ? ' (set by '+ev.set_by+')' : ''}`, 'system');
      } else {
        sysMsg(ev.conn_id, ev.channel, `Ban: ${ev.mask}${ev.set_by ? ' (set by '+ev.set_by+')' : ''}`, 'system');
      }
      break;
    }
    case 'irc_ban_end': {
      const key  = ev.conn_id + '/' + ev.channel;
      // Channel Modes dialog finished collecting this list
      if (_cmMatch(ev.conn_id, ev.channel) && _cm.collecting && _cm.collecting[ev.list]) {
        _cm.collecting[ev.list] = false;
        cmRenderList();
        break;
      }
      // Check if this is for /unbanall (368)
      if (pendingUnbanAll[key]) {
        delete pendingUnbanAll[key];
        const masks = banListAccum[key] || [];
        delete banListAccum[key];
        if (!masks.length) {
          sysMsg(ev.conn_id, ev.channel, 'Ban list is already empty.', 'system');
        } else {
          sysMsg(ev.conn_id, ev.channel, `Removing ${masks.length} ban${masks.length===1?'':'s'}…`, 'system');
          batchMode(ev.conn_id, ev.channel, '-b', masks);
        }
      }
      // Check if this is for /unexemptall (349)
      if (window._pendingUnexempt?.[key]) {
        delete window._pendingUnexempt[key];
        const masks = window._exemptAccum?.[key] || [];
        delete window._exemptAccum?.[key];
        if (!masks.length) {
          sysMsg(ev.conn_id, ev.channel, 'Exempt list is already empty.', 'system');
        } else {
          sysMsg(ev.conn_id, ev.channel, `Removing ${masks.length} exempt${masks.length===1?'':'s'}…`, 'system');
          batchMode(ev.conn_id, ev.channel, '-e', masks);
        }
      }
      break;
    }
    case 'log_lines': {
      const _lk=ev.conn_id+'/'+ev.target;
      if(!_pendingLogs.has(_lk)) break; // Response from another session — ignore
      _pendingLogs.delete(_lk);
      prependLogs(ev.conn_id,ev.target,ev.lines);
      break;
    }
    case 'search_results': {
      // Drop stale/late responses (newer query typed, or channel switched).
      const sr=window._searchReq;
      if(!sr || sr.conn_id!==ev.conn_id || sr.target!==ev.target || sr.query!==ev.query) break;
      renderSearchResults(ev.conn_id,ev.target,ev.query,ev.lines);
      break;
    }
    case 'sync_lines': {
      const _sk=ev.conn_id+'/'+ev.target;
      if(!_pendingSyncs.has(_sk)) break; // Response from another session — ignore
      _pendingSyncs.delete(_sk);
      appendSyncLines(ev.conn_id,ev.target,ev.lines);
      break;
    }
    case 'stats_data': handleStatsData(ev.data); break;
    case 'password_safe': handlePasswordSafeData(ev.data); break;
    case 'cert_info':  onCertInfo(ev); break;
    case 'appearance':
      try{
        const cfg={...APPEAR_DEFAULTS,...JSON.parse(ev.settings)};
        localStorage.setItem('cryptirc_appear',ev.settings);
        invalidateAppearCache(); // so an open Appearance modal / next load sees synced custom themes
        // Reap device-local background blobs for themes deleted on another device,
        // so localStorage doesn't accumulate orphans we can never reach again.
        try{
          const live=new Set(Object.keys(cfg.customThemes||{}));
          for(let i=localStorage.length-1;i>=0;i--){
            const k=localStorage.key(i);
            if(k&&k.indexOf('cryptirc_cbg_')===0 && !live.has(k.slice(13))) localStorage.removeItem(k);
          }
        }catch(_){}
        applyThemeCSS(cfg);
      }catch(e){}
      break;
    case 'preferences':
      try{ restorePreferences(JSON.parse(ev.prefs)); }catch(e){}
      break;
    case 'notepad': {
      const ta=document.getElementById('notepad-area');
      if(ta) ta.value=ev.content||'';
      break;
    }
    case 'data_cleared':
      buffers={}; _historyView=null;
      unread.clear();
      mentionUnread.clear();
      for(const k of Object.keys(_lastMsgId)) delete _lastMsgId[k];
      renderChat();
      renderSidebar();
      break;
    case 'upload_state':  _onUploadState(ev.records||[]); break;
    case 'upload_update': _onUploadUpdate(ev.record);     break;
    case 'upload_removed':_onUploadRemoved(ev.id);        break;
    case 'target_cleared': {
      // Server confirmed on-disk logs for this target are gone. Drop the
      // buffer + sync state on every session so reload/resync can't bring
      // the conversation back.
      const k=bk(ev.conn_id,ev.target);
      buffers[k]=[];
      if(_historyView && _historyView.bk===k) _historyView=null;
      delete _lastMsgId[k];
      unread.delete(k);
      mentionUnread.delete(k);
      saveUnread();
      clearNoticesForTarget(ev.conn_id,ev.target);
      if(isActive(ev.conn_id,ev.target)) renderChat();
      renderSidebar();
      break;
    }
    case 'account_deleted':
      customAlert('Your account has been deleted.').then(()=>{
        localStorage.clear();
        document.cookie='cryptirc_token=;max-age=0;path=/cryptirc';document.cookie='cryptirc_token=;max-age=0;path=/';
        location.reload();
      });
      break;
    case 'error':      console.error(ev.message); break;
  }
}

// ─── Buffer helpers ────────────────────────────────────────────────────────────
function bk(c,t){return `${c}/${t.toLowerCase()}`;}
function getBuf(c,t){const k=bk(c,t);if(!buffers[k])buffers[k]=[];return buffers[k];}
// Per-channel last known msg_id for ID-based sync
const _lastMsgId={};
function trackMsgId(conn_id,target,id){if(id>0){const k=bk(conn_id,target);if(!_lastMsgId[k]||id>_lastMsgId[k])_lastMsgId[k]=id;}}
// ─── Notification sounds ──────────────────────────────────────────────────────
let _audioCtx=null,_lastSoundAt=0;
// Chromium (including Electron) starts AudioContexts in "suspended" state until
// the user interacts with the page. A one-time capture listener resumes the
// context on the first click/keydown so notification sounds fire thereafter.
(function(){
  const wake=()=>{try{if(_audioCtx&&_audioCtx.state==='suspended')_audioCtx.resume();}catch(e){}};
  document.addEventListener('click',wake,{capture:true,passive:true});
  document.addEventListener('keydown',wake,{capture:true,passive:true});
})();
// Catalog advertised in the notification-settings dropdown.
const NOTIF_SOUNDS=[
  // Real samples (CC0 community sources)
  {id:'water-drop',    label:'Water drop (default)'},
  {id:'ding',          label:'Ding'},
  {id:'bell',          label:'Bell'},
  {id:'pop',           label:'Pop'},
  {id:'click',         label:'Click'},
  {id:'ping',          label:'Ping'},
  {id:'alert',         label:'Alert'},
  {id:'notice',        label:'Notice'},
  {id:'correct',       label:'Correct'},
  {id:'swoosh',        label:'Swoosh'},
  {id:'door-knock',    label:'Door knock'},
  {id:'icq-uhoh',      label:'ICQ uh-oh'},
  {id:'splash',        label:'Water splash'},
  {id:'thud',          label:'Thud'},
  {id:'pebble',        label:'Pebble'},
  {id:'cash-register', label:'Cash register'},
  {id:'explosion',     label:'Explosion'},
  {id:'lightning',     label:'Lightning'},
  // Synthesized tones (WebAudio — kept for variety / fallback)
  {id:'water',    label:'Water drop (synth)'},
  {id:'imessage', label:'Crystal bell (synth)'},
  {id:'discord',  label:'Descending ping (synth)'},
  {id:'arp',      label:'Pluck arp (synth)'},
  {id:'chime',    label:'Glass chime (synth)'},
  {id:'r2d2',     label:'R2-D2 chirp (synth)'},
  {id:'cyber',    label:'Cyberpunk blip (synth)'},
  {id:'laser',    label:'Laser zap (synth)'},
  {id:'packet',   label:'Data packet (synth)'},
  {id:'knock',    label:'Soft knock (synth)'},
  {id:'aim',      label:'AIM ding (synth)'},
  {id:'icq',      label:'ICQ uh-oh (synth)'},
  {id:'chirp',    label:'Classic chirp (synth)'},
];
// File-based sounds are bundled into the binary; served at /sounds/<name>.mp3.
// `sounds/` is relative to the current page so it works regardless of base_path.
const _sampleCache=Object.create(null);
function _playSample(name){
  let a=_sampleCache[name];
  if(!a){a=new Audio('sounds/'+name);a.preload='auto';_sampleCache[name]=a;}
  try{a.currentTime=0; const p=a.play(); if(p&&p.catch)p.catch(()=>{});}catch(_){}
}
// Tiny helper: schedule a single oscillator with an exponential gain decay.
function _tone(offset,freqStart,freqEnd,dur,waveType,gainPeak){
  const t0=_audioCtx.currentTime+offset;
  const osc=_audioCtx.createOscillator();
  const g=_audioCtx.createGain();
  osc.type=waveType||'sine';
  osc.connect(g); g.connect(_audioCtx.destination);
  osc.frequency.setValueAtTime(freqStart,t0);
  if(freqEnd!==freqStart) osc.frequency.exponentialRampToValueAtTime(Math.max(1,freqEnd),t0+dur);
  g.gain.setValueAtTime(gainPeak||0.12,t0);
  g.gain.exponentialRampToValueAtTime(0.001,t0+dur);
  osc.start(t0);
  osc.stop(t0+dur+0.02);
}
const SOUND_IMPL={
  // File-based samples
  'water-drop':    ()=>_playSample('water-drop.mp3'),
  'ding':          ()=>_playSample('ding.mp3'),
  'bell':          ()=>_playSample('bell.mp3'),
  'pop':           ()=>_playSample('pop.mp3'),
  'click':         ()=>_playSample('click.mp3'),
  'ping':          ()=>_playSample('ping.mp3'),
  'alert':         ()=>_playSample('alert.mp3'),
  'notice':        ()=>_playSample('notice.mp3'),
  'correct':       ()=>_playSample('correct.mp3'),
  'swoosh':        ()=>_playSample('swoosh.mp3'),
  'door-knock':    ()=>_playSample('door-knock.mp3'),
  'icq-uhoh':      ()=>_playSample('icq-uhoh.mp3'),
  'splash':        ()=>_playSample('splash.mp3'),
  'thud':          ()=>_playSample('thud.mp3'),
  'pebble':        ()=>_playSample('pebble.mp3'),
  'cash-register': ()=>_playSample('cash-register.mp3'),
  'explosion':     ()=>_playSample('explosion.mp3'),
  'lightning':     ()=>_playSample('lightning.mp3'),
  // Synthesized tones
  water:    ()=>{ _tone(0,800,400,0.15,'sine',0.14); },
  imessage: ()=>{ _tone(0,523.25,523.25,0.55,'sine',0.12); _tone(0,1046.5,1046.5,0.55,'sine',0.07); },
  discord:  ()=>{ _tone(0,988,988,0.10,'sine',0.12); _tone(0.07,784,784,0.10,'sine',0.12); _tone(0.14,659,659,0.20,'sine',0.12); },
  arp:      ()=>{ _tone(0,523.25,523.25,0.09,'triangle',0.12); _tone(0.07,659.25,659.25,0.09,'triangle',0.12); _tone(0.14,783.99,783.99,0.18,'triangle',0.12); },
  chime:    ()=>{ _tone(0,1760,1760,0.8,'sine',0.10); _tone(0,1975,1975,0.8,'sine',0.05); },
  r2d2:     ()=>{
    const t0=_audioCtx.currentTime;
    const osc=_audioCtx.createOscillator();
    const g=_audioCtx.createGain();
    osc.type='sawtooth';
    osc.connect(g); g.connect(_audioCtx.destination);
    osc.frequency.setValueAtTime(400,t0);
    osc.frequency.exponentialRampToValueAtTime(1200,t0+0.08);
    osc.frequency.exponentialRampToValueAtTime(700,t0+0.14);
    osc.frequency.exponentialRampToValueAtTime(1800,t0+0.22);
    g.gain.setValueAtTime(0.08,t0);
    g.gain.exponentialRampToValueAtTime(0.001,t0+0.26);
    osc.start(t0); osc.stop(t0+0.28);
  },
  cyber:    ()=>{ _tone(0,880,880,0.06,'square',0.10); _tone(0.08,1320,1320,0.05,'square',0.08); },
  laser:    ()=>{ _tone(0,2000,200,0.18,'triangle',0.12); },
  packet:   ()=>{ _tone(0,1200,1200,0.05,'square',0.09); _tone(0.08,1600,1600,0.05,'square',0.09); },
  knock:    ()=>{ _tone(0,220,150,0.04,'triangle',0.15); _tone(0.11,220,150,0.04,'triangle',0.15); },
  aim:      ()=>{ _tone(0,700,700,0.09,'sine',0.12); _tone(0.11,1100,1100,0.14,'sine',0.12); },
  icq:      ()=>{ _tone(0,900,700,0.08,'square',0.08); _tone(0.10,700,500,0.14,'square',0.08); },
  chirp:    (type)=>{
    if(type==='pm'){ _tone(0,880,880,0.08,'sine',0.15); _tone(0.08,1100,1100,0.12,'sine',0.15); }
    else { _tone(0,660,660,0.15,'sine',0.10); }
  },
};
function _ensureAudioCtx(){
  if(!_audioCtx) _audioCtx=new(window.AudioContext||window.webkitAudioContext)();
  if(_audioCtx.state==='suspended') _audioCtx.resume();
}
function playNotifSound(type){
  const now=Date.now();if(now-_lastSoundAt<500)return;_lastSoundAt=now;
  try{
    _ensureAudioCtx();
    const cfg=loadAppearance();
    const id=cfg.notifSound||'water-drop';
    (SOUND_IMPL[id]||SOUND_IMPL['water-drop'])(type);
  }catch(e){}
}
// Preview bypasses the 500ms throttle so the ▶ button always plays.
function previewNotifSound(id){
  try{
    _ensureAudioCtx();
    (SOUND_IMPL[id]||SOUND_IMPL['water-drop'])('pm');
  }catch(e){}
}

function addMessage(conn_id,target,msg){
  const buf=getBuf(conn_id,target);
  // History view: the buffer is a focused window from the past, not the live
  // tail. The user's OWN message means they're chatting again → snap back to
  // present so it lands in the live view. Anyone else's message must NOT be
  // grafted onto the window (it would appear with a misleading time gap); it's
  // persisted server-side and shows when the user taps "jump to present".
  if(_historyView && _historyView.bk===bk(conn_id,target)){
    if(msg && msg.from && msg.from===getNick(conn_id)){ _exitHistoryView(); }
    else { return; }
  }
  // Dedup by msg_id only. Server-delivered messages carry a unique ID — if
  // we see the same ID twice it's a genuine duplicate (multiple delivery paths,
  // the server fanning events to ALL sessions, bouncer/ZNC replay) and should
  // be dropped. Scan the WHOLE buffer, not just the tail: a re-delivered copy
  // can land far from the end (the original may sit >30 rows back, or a history
  // load may have buf.sort()-ed an earlier copy ahead of the tail), so a
  // last-N window misses it and the row gets duplicated. A server msg_id is
  // unique per logical message, so a full-buffer id match is always a real dup.
  // Self-sent local additions have no ID and are always pushed (rapid-fire
  // identical messages like sending "lol" twice must still appear twice).
  // irc_echo / echo-message reconciliation is handled separately in its own
  // handler via _sentMsgs, not here.
  if(msg&&msg.id&&msg.from!=='*'&&msg.kind!=='system'&&msg.kind!=='error'){
    for(let i=0;i<buf.length;i++){
      if(buf[i].id===msg.id) return;
    }
  }
  buf.push(msg);
  if(buf.length>2000)buf.splice(0,buf.length-2000);
  // Track channel stats and seen database
  if(msg.kind==='privmsg'||msg.kind==='action'){trackStat(conn_id,target,msg.from);trackSeen(msg.from,target,msg.ts);trackLastSpoke(conn_id,target,msg.from,msg.ts);}
  const isDM=target!=='status'&&!target.startsWith('#')&&!target.startsWith('&')&&!target.startsWith('+')&&!target.startsWith('!');
  // Track query/PM buffers — but don't auto-reopen a query the user explicitly
  // closed unless this is a genuinely NEWER message (not a replay/old line
  // re-delivered on reconnect / server restart).
  if(isDM){
    const _lc=target.toLowerCase(), _ck=conn_id+'|'+_lc, _closedTs=closedQueries[_ck];
    if(_closedTs && (msg.ts||0)<=_closedTs){
      // Stale replay for an explicitly-closed query (reconnect/restart): the line is
      // already kept in the buffer for history, but it must NOT re-open the sidebar
      // row OR bump unread / fire a notice / play a sound. Bail out entirely.
      return;
    }
    if(_closedTs) clearQueryClosed(conn_id,_lc);       // genuinely newer message → reopen
    if(!queryBufs[conn_id])queryBufs[conn_id]=new Map();
    queryBufs[conn_id].set(_lc, target);
    saveQueryBufs();
  }
  if(isActive(conn_id,target)){appendMsgRow(msg);const isOwn=msg.from&&msg.from===getNick(conn_id);if(isOwn)scrollForce();else scrollBottom();}
  else{
    const _ownMsg=msg.from&&msg.from===getNick(conn_id);
    // Status events (join/part/quit/nick/mode/kick/away/back) never bump unread
    // or trigger notifications — matches The Lounge's behavior where only real
    // chat (privmsg/action/notice) counts as unread.
    const _isStatus=['join','part','quit','nick','mode','kick','away','back'].includes(msg.kind);
    if(!msg.noUnread && !_ownMsg && !_isStatus){
      const uk=bk(conn_id,target);
      unread.set(uk,(unread.get(uk)||0)+1);
      if(msg.mentioned||isDM) mentionUnread.set(uk,(mentionUnread.get(uk)||0)+1);
      saveUnread();renderSidebar();
    }
    // Notices inbox: one row per PM sender, first message only; only if that
    // PM view isn't currently active (handled by the enclosing else).
    if(isDM && !_ownMsg && !_isStatus && (msg.kind==='privmsg'||msg.kind==='action')){
      addPmNotice(conn_id,target,msg);
    }
    // Play sound for unread DMs and mentions — never for own or status messages.
    const isMutedChan=isMuted(conn_id+'/'+target)||isMuted('net:'+conn_id);
    if(!isMutedChan && !_ownMsg && !_isStatus){
      const soundCfg=loadAppearance();
      if(isDM && soundCfg.soundPM!==false) playNotifSound('pm');
      else if(msg.mentioned && soundCfg.soundMention!==false) playNotifSound('mention');
      // Browser desktop notification (popup bubble)
      if(soundCfg.desktopNotif!==false && (isDM || msg.mentioned) && !isDndActive()){
        const title=isDM?`DM from ${msg.from}`:`${msg.from} in ${target}`;
        const body=msg.text?.slice(0,120)||'';
        const notifMeta={conn_id, target, ts:msg.ts, from:msg.from};
        if(window.electronAPI?.isElectron){
          window.electronAPI.showNotification(title, body, notifMeta);
        } else if(Notification?.permission==='granted'){
          try{
            const n=new Notification(title,{body,icon:'/cryptirc/icon-192.png',tag:conn_id+'/'+target,requireInteraction:true,silent:true});
            n.onclick=()=>{window.focus();jumpToMessage(conn_id,target,msg.ts,msg.from);n.close();};
            setTimeout(()=>n.close(),60000);
          }catch(e){console.error('Notification error:',e);}
        } else if(Notification?.permission!=='denied'){
          Notification.requestPermission?.();
        }
      }
    }
  }
}
function sysMsg(c,t,text,kind='system',extras){
  // Allow extras to override `from` (e.g. subject nick for join/part/etc so
  // the reload path can derive `self` from msg.from === getNick).
  const m={ts:Date.now()/1000|0,from:(extras&&extras.from)||'*',text,kind};
  if(extras){for(const k in extras){if(k!=='from')m[k]=extras[k];}}
  addMessage(c,t,m);
}
// Reconstruct `self`/`subject`/`subject2` on log replay (server stores from + text
// + kind only; we recover the structured fields from `from` + text parsing).
function _reconstructStatusFields(m,conn_id){
  if(!['join','part','quit','nick','kick','mode','away','back'].includes(m.kind)) return m;
  if(m.from && m.from!=='*'){
    m.subject=m.from;
    const own=getNick(conn_id);
    if(own && m.from===own) m.self=true;
  }
  // For nick changes, recover subject2 (the OLD nick) by parsing "X is now known as Y"
  if(m.kind==='nick'){
    const mt=(m.text||'').match(/^[•·*]?\s*(\S+)\s+is now known as\s+(\S+)/);
    if(mt){m.subject=mt[2];m.subject2=mt[1];const own=getNick(conn_id);if(own&&(mt[1]===own||mt[2]===own))m.self=true;}
  }
  // For kicks, recover subject2 (the kicker)
  if(m.kind==='kick'){
    const mt=(m.text||'').match(/^[✗*]?\s*(\S+)\s+kicked by\s+(\S+)/);
    if(mt){m.subject=mt[1];m.subject2=mt[2];const own=getNick(conn_id);if(own&&(mt[1]===own||mt[2]===own))m.self=true;}
  }
  return m;
}
async function clearCurrentHistory(){
  if(!active)return;
  if(!(await customConfirm('Permanently delete chat history for '+active.target+'? This removes the logs from the server and cannot be undone.','Delete')))return;
  // Server will reply with target_cleared which wipes buffer + sync state.
  wsend({type:'clear_target_logs',conn_id:active.conn_id,target:active.target});
}
async function clearBufHistory(connId,target){
  if(!(await customConfirm('Permanently delete chat history for '+target+'? This removes the logs from the server and cannot be undone.','Delete')))return;
  wsend({type:'clear_target_logs',conn_id:connId,target});
}
// ─── E2E history decryption ─────────────────────────────────────────────────
// Channel/DM PSK ciphertext (sd8~…) is what's persisted to the server logs for
// EVERY sender — the server holds no key and never decrypts. The live message
// path decrypts on arrival, but history replayed from logs (and search results)
// used to land here as raw ciphertext. That's invisible for other people (their
// recent lines are also re-delivered live and the decrypted copy wins dedup)
// yet very visible for your OWN messages, whose only post-reload source is the
// log. Decrypt sd8~ lines here so replayed history matches the live path.
// Sender-agnostic: keyed purely on the channel/DM target, so self lines decrypt
// exactly like everyone else's.
function _resolveChanKeyName(target){
  const ck=window.E2E&&window.E2E.channelKeys;
  if(!ck||target==null) return null;
  if(ck[target]) return target;            // exact case (matches the live path)
  const lc=String(target).toLowerCase();   // fall back to case-insensitive
  for(const k in ck){ if(k.toLowerCase()===lc) return k; }
  return null;
}
async function _decryptLogLines(target,lines){
  if(!Array.isArray(lines)||!lines.length) return lines;
  if(typeof channelDecrypt!=='function') return lines;
  const keyName=_resolveChanKeyName(target);
  if(!keyName) return lines; // key not loaded yet — leave ciphertext for the re-decrypt pass on key arrival
  const out=new Array(lines.length);
  for(let i=0;i<lines.length;i++){
    const l=lines[i];
    if(l&&typeof l.text==='string'&&l.text.startsWith('sd8~')){
      try{
        const pt=await channelDecrypt(keyName,l.text);
        if(pt!==null){ out[i]=Object.assign({},l,{text:pt,encrypted:true}); continue; }
      }catch(_){}
    }
    out[i]=l;
  }
  return out;
}
// Re-decrypt already-buffered sd8~ lines once a channel PSK finally loads —
// covers the race where get_logs returns before e2e_channel_key arrives.
async function redecryptChannelHistory(channel){
  const keyName=_resolveChanKeyName(channel);
  if(!keyName||typeof channelDecrypt!=='function') return;
  const lc=String(channel).toLowerCase();
  for(const k in buffers){
    const slash=k.lastIndexOf('/');                 // buffer key = `${conn_id}/${target.toLowerCase()}`
    if(slash<0||k.slice(slash+1)!==lc) continue;
    const buf=buffers[k];
    let changed=false;
    for(const m of buf){
      if(m&&typeof m.text==='string'&&m.text.startsWith('sd8~')){
        try{
          const pt=await channelDecrypt(keyName,m.text);
          if(pt!==null){ m.text=pt; m.encrypted=true; changed=true; }
        }catch(_){}
      }
    }
    if(changed){
      const conn_id=k.slice(0,slash);
      if(active&&active.conn_id===conn_id&&typeof active.target==='string'&&active.target.toLowerCase()===lc) renderChat();
    }
  }
}
window.redecryptChannelHistory=redecryptChannelHistory;
async function prependLogs(conn_id,target,lines){
  lines=await _decryptLogLines(target,lines);
  const buf=getBuf(conn_id,target);
  const wasEmpty=buf.length===0;
  const newMsgs=lines.map(l=>_reconstructStatusFields({id:l.id||0,ts:l.ts,from:l.from,text:l.text,kind:l.kind,encrypted:l.encrypted},conn_id));
  // Track highest msg_id from log lines
  for(const m of newMsgs) trackMsgId(conn_id,target,m.id);
  // Deduplicate: use msg_id when available, fall back to ts+from+text
  const existingIds=new Set(buf.filter(m=>m.id>0).map(m=>m.id));
  const existingKeys=new Set(buf.map(m=>m.ts+'|'+m.from+'|'+(m.text||'').slice(0,50)));
  const unique=newMsgs.filter(m=>{
    if(m.id>0&&existingIds.has(m.id)) return false;
    if(m.id>0) return true;
    return !existingKeys.has(m.ts+'|'+m.from+'|'+(m.text||'').slice(0,50));
  });
  if(unique.length>0){
    buf.unshift(...unique);
    buf.sort((a,b)=>a.ts-b.ts);
    /* Hard ceiling so repeated "Load older" clicks can't grow the buffer
       indefinitely. 5000 = ~25 Load-older clicks at 200/page — well past any
       reasonable scrollback need, but bounded enough to defend memory. Cap is
       higher than addMessage's 2000 so a single Load-older isn't immediately
       trimmed back out. */
    if(buf.length>5000) buf.splice(0,buf.length-5000);
  }
  if(isActive(conn_id,target)){
    const area=document.getElementById('chat-area');
    const oldHeight=area?.scrollHeight||0;
    renderChat();
    if(wasEmpty){
      // Initial load — scroll to bottom to show latest messages
      scrollForce();
    } else if(area&&unique.length>0){
      // Loading older messages — preserve scroll position. iOS momentum-
      // scroll can swallow a bare scrollTop assignment here; briefly set
      // overflowY to hidden to flush momentum, then restore.
      const newHeight=area.scrollHeight;
      area.style.overflowY='hidden';
      void area.offsetHeight;
      area.scrollTop=newHeight-oldHeight;
      area.style.overflowY='';
      requestAnimationFrame(()=>{
        area.scrollTop=newHeight-oldHeight;
      });
    }
  }
}
async function appendSyncLines(conn_id,target,lines){
  lines=await _decryptLogLines(target,lines);
  const buf=getBuf(conn_id,target);
  const existingIds=new Set(buf.filter(m=>m.id>0).map(m=>m.id));
  const existingKeys=new Set(buf.map(m=>m.ts+'|'+m.from+'|'+(m.text||'').slice(0,50)));
  let added=0;
  for(const l of lines){
    const id=l.id||0;
    trackMsgId(conn_id,target,id);
    if(id>0&&existingIds.has(id)) continue;
    // Exact fuzzy key — catches the common case where ts/from/text match.
    const fk=l.ts+'|'+l.from+'|'+(l.text||'').slice(0,50);
    if(existingKeys.has(fk)) continue;
    // Clock-skew + E2E fuzzy match: an optimistic self-sent entry in the
    // buffer has m.ts = client clock (Date.now()/1000) while l.ts is the
    // server clock — they diverge by 1-2s commonly, breaking the strict
    // key match above. Walk the tail looking for an unstamped (no id)
    // entry from the same `from` with matching text within ±30s of l.ts.
    // If found, stamp it with l.id and skip the dup.
    let _matched=false;
    const _tailStart=Math.max(0,buf.length-30);
    const _slice=(l.text||'').slice(0,50);
    for(let i=buf.length-1;i>=_tailStart;i--){
      const m=buf[i];
      if(Math.abs((m.ts||0)-l.ts)>30) continue;
      if(m.id) continue;
      if(m.from!==l.from) continue;
      if((m.text||'').slice(0,50)!==_slice) continue;
      if(l.id) m.id=l.id;
      // Also seed existingIds so a second copy of this msg in the same
      // sync batch can't slip past the id check above.
      if(l.id) existingIds.add(l.id);
      _matched=true;
      break;
    }
    if(_matched) continue;
    buf.push(_reconstructStatusFields({id,ts:l.ts,from:l.from,text:l.text,kind:l.kind,encrypted:l.encrypted},conn_id));
    added++;
  }
  if(added>0){
    buf.sort((a,b)=>a.ts-b.ts);
    if(buf.length>2000) buf.splice(0,buf.length-2000);
    if(isActive(conn_id,target)){renderChat();scrollForce();}
  }
}
function isActive(c,t){return !!active&&active.conn_id===c&&typeof t==='string'&&active.target.toLowerCase()===t.toLowerCase();}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
let _sidebarRenderTimer=null,_sidebarDragLock=false;
function renderSidebar(){
  if(_sidebarRenderTimer||_sidebarDragLock)return;
  _sidebarRenderTimer=setTimeout(()=>{_sidebarRenderTimer=null;_renderSidebarNow();},50);
}
function _renderSidebarNow(){
  // Native desktop unread badge (Electron v0.3.1+): count of mentions/DMs awaiting.
  // Old shells lack setUnread — the optional check makes this a no-op there.
  try{ if(window.electronAPI&&window.electronAPI.setUnread){ let _b=0; for(const v of mentionUnread.values()) _b+=(v||0); window.electronAPI.setUnread(_b); } }catch(_){}
  const el=document.getElementById('network-list');
  el.innerHTML='';
  for(const net of networks){
    const id=net.config.id;
    const g=document.createElement('div'); g.className='net-group'; g.dataset.netId=id;
    // draggable handled by SortableJS
    const sk=bk(id,'status'),sa=isActive(id,'status'),sc=unread.get(sk)||0;
    const netMuted=isMuted('net:'+id)||isMuted(id+'/status');
    g.innerHTML=`<div class="net-label${sa?' active':''}" onclick="setActive('${id}','status');closeSidebar();" style="${sa?'background:var(--bg4);':''}">
      <span class="net-dot ${net.connected?'online':''}" id="dot-${id}"></span>
      <span class="net-name">${esc(net.config.label||net.config.server)}</span>
      ${sc&&!netMuted?`<span class="chan-unread-badge${mentionUnread.get(sk)?` highlight`:''}">${sc>99?'99+':sc}</span>`:''}
      <span class="net-actions">
        <button class="net-btn net-kebab" data-net-id="${id}" title="Options">⋮</button>
      </span>
    </div>`;
    // Attach net kebab listener safely (no inline onclick with user data)
    const netKebab=g.querySelector('.net-kebab');
    if(netKebab){netKebab.addEventListener('click',e=>{e.stopPropagation();toggleNetMenu(e.currentTarget,id,net.config.label||net.config.server);});}
    // Sort channels by saved order
    const order=net.config.channel_order||[];
    const sorted=[...(net.channels||[])].sort((a,b)=>{
      const ai=order.indexOf(a.name),bi=order.indexOf(b.name);
      if(ai===-1&&bi===-1) return 0;
      if(ai===-1) return 1;
      if(bi===-1) return -1;
      return ai-bi;
    });
    const chanContainer=document.createElement('div');
    chanContainer.className='chan-list';
    chanContainer.dataset.connId=id;
    for(const ch of sorted){
      if(isFavorite(id,ch.name)) continue; // shown in favorites section
      const k=bk(id,ch.name),isA=isActive(id,ch.name),uc=unread.get(k)||0;
      const ci=document.createElement('div');
      ci.className=`chan-item${isA?' active':''}`;
      ci.dataset.target=ch.name;
      ci.dataset.connId=id;
      // draggable handled by SortableJS
      ci.style.position='relative';
      const chMuted=isMuted(id+'/'+ch.name)||isMuted('net:'+id);
      const mc=mentionUnread.get(k)||0;
      const chEnc=(()=>{const ck=window.E2E?.channelKeys;if(!ck)return null;if(ck[ch.name])return ck[ch.name];const lk=ch.name.toLowerCase();for(const k in ck)if(k.toLowerCase()===lk)return ck[k];return null;})();
      const chLock=chEnc?'<svg width="10" height="10" viewBox="0 0 24 24" fill="var(--accent)" stroke="var(--accent)" stroke-width="1" style="opacity:.7;margin-right:2px;flex-shrink:0;vertical-align:middle"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4" fill="none" stroke-width="2.5"/></svg>':'<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.2;margin-right:2px;flex-shrink:0;vertical-align:middle"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9 0"/></svg>';
      const chDet=isDetached(id,ch.name)?'<span class="chan-detached" title="Popped out" style="color:var(--accent);font-size:11px;margin-right:4px;opacity:.85">⧉</span>':'';
      ci.innerHTML=`${chLock}${esc(ch.name)}<span class="chan-right">${chDet}${uc&&!chMuted?`<span class="chan-unread-badge${mc?' highlight':''}">${uc>99?'99+':uc}</span>`:''}${chMuted?'<span style="font-size:10px;opacity:.4">🔇</span>':''}<span class="chan-kebab">⋮</span></span>`;
      ci.querySelector('.chan-kebab').addEventListener('click',e=>{e.stopPropagation();toggleChanMenu(e.currentTarget,id,ch.name,'channel');});
      ci.onclick=()=>_sidebarActivate(id,ch.name);
      // a11y (#58): channel rows are keyboard-focusable buttons — Enter/Space open them.
      ci.tabIndex=0;ci.setAttribute('role','button');ci.setAttribute('aria-label','Channel '+ch.name);
      ci.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();_sidebarActivate(id,ch.name);}});
      chanContainer.appendChild(ci);
    }
    g.appendChild(chanContainer);
    // Render query/PM buffers (NickServ, private messages, etc.)
    if(queryBufs[id]){
      for(const [lc, display] of queryBufs[id]){
        if(isFavorite(id,lc)) continue; // shown in favorites section
        const k=bk(id,lc),isA=isActive(id,lc),uc=unread.get(k)||0;
        const qi=document.createElement('div');
        qi.className=`chan-item${isA?' active':''}`;
        qi.dataset.target=lc;
        qi.dataset.connId=id;
        qi.dataset.kind='pm';
        qi.style.fontStyle='italic';
        qi.style.position='relative';
        const pmMuted=isMuted(id+'/'+lc)||isMuted('net:'+id);
        const dmEnc=(()=>{const ds=window.E2E?.dmSessions;if(!ds)return null;if(ds[lc])return ds[lc];if(ds[display])return ds[display];const lk=lc.toLowerCase();for(const k in ds)if(k.toLowerCase()===lk)return ds[k];return null;})();
        const dmLock=dmEnc?'<svg width="10" height="10" viewBox="0 0 24 24" fill="var(--accent)" stroke="var(--accent)" stroke-width="1" style="opacity:.7;margin-right:2px;flex-shrink:0;vertical-align:middle"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4" fill="none" stroke-width="2.5"/></svg>':'<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.2;margin-right:2px;flex-shrink:0;vertical-align:middle"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9 0"/></svg>';
        const qDet=isDetached(id,display)?'<span class="chan-detached" title="Popped out" style="color:var(--accent);font-size:11px;margin-right:4px;opacity:.85">⧉</span>':'';
        qi.innerHTML=`${dmLock}${esc(display)}<span class="chan-right">${qDet}${uc&&!pmMuted?`<span class="chan-unread-badge highlight">${uc>99?'99+':uc}</span>`:''}${pmMuted?'<span style="font-size:10px;opacity:.4">🔇</span>':''}<span class="chan-kebab">⋮</span></span>`;
        qi.querySelector('.chan-kebab').addEventListener('click',e=>{e.stopPropagation();toggleChanMenu(e.currentTarget,id,lc,'pm');});
        qi.onclick=()=>_sidebarActivate(id,display);
        // a11y (#58): PM rows are keyboard-focusable buttons — Enter/Space open them.
        qi.tabIndex=0;qi.setAttribute('role','button');qi.setAttribute('aria-label','Direct message '+display);
        qi.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();_sidebarActivate(id,display);}});
        g.appendChild(qi);
      }
    }
    el.appendChild(g);
  }
  // Upload Status pseudo-channel — rendered into its own #uploads-pin
  // container (sibling of #network-list), so it stays visible even when
  // favorites-only mode hides the rest of the network list.
  const pin=document.getElementById('uploads-pin');
  if(pin){
    pin.innerHTML='';
    const upEntry=_renderUploadsSidebarEntry();
    if(upEntry) pin.appendChild(upEntry);
  }
  updateCertBtn();
  renderFavorites();
  renderPMList();
  applyFavsOnly();
}
function updateInputPlaceholder(){
  const inp=document.getElementById('msg-input');
  if(!inp)return;
  if(!active){inp.placeholder='Select a channel…';inp.disabled=true;return;}
  if(isUploadsConn(active.conn_id)){
    inp.placeholder='Upload Status — pick a chat to send messages';
    inp.disabled=true;
    return;
  }
  const net=networks.find(n=>n.config.id===active.conn_id);
  inp.disabled=!net?.connected;
  if(!net?.connected){inp.placeholder='Not connected';return;}
  const nick=net.nick||net.config.nick||currentUser||'me';
  inp.placeholder=`Message ${active.target} as ${nick}…`;
}
function setNetDot(conn_id,state){
  const net=networks.find(n=>n.config.id===conn_id);
  if(net)net.connected=state==='online';
  renderSidebar();
  if(active&&active.conn_id===conn_id)updateInputPlaceholder();
}
function updateNick(conn_id,nick){
  const net=networks.find(n=>n.config.id===conn_id);
  if(net)net.nick=nick;
  if(active&&active.conn_id===conn_id){const _in=document.getElementById('input-nick');if(_in)_in.textContent=nick;updateInputPlaceholder();}
}
function updateNames(conn_id,channel,names){
  const net=networks.find(n=>n.config.id===conn_id);
  if(!net)return;
  const ch=net.channels.find(c=>c.name===channel);
  if(ch){ch.names=names;}
  else{net.channels.push({name:channel,topic:'',names});}
  if(isActive(conn_id,channel)){renderNickPanel(names);updateTopbar();}
}
function updateLagDisplay(){
  if(!active)return;
  const ms=lagMap[active.conn_id];
  const cls='lag-dot'+(ms!=null?(ms<100?' good':ms<300?' ok':' bad'):'');
  // Topbar lag indicator (both desktop and mobile)
  const ml=document.getElementById('lag-mobile');
  const md=document.getElementById('lag-mobile-dot');
  const mv=document.getElementById('lag-mobile-val');
  if(ml&&md&&mv){
    if(ms==null){
      ml.setAttribute('data-empty','1');
      mv.textContent='';
    } else {
      ml.removeAttribute('data-empty');
      md.className=cls;
      mv.textContent=ms+'ms';
    }
  }
}
function setActive(conn_id,target){
  active={conn_id,target};
  // Uploads pseudo-channel doesn't live in IRC space — skip unread/sync/E2E
  // bookkeeping entirely. It still uses the same active/render plumbing.
  if(isUploadsConn(conn_id)){
    if(!_detMode){
      try{localStorage.setItem('cryptirc_active',JSON.stringify({conn_id,target}));}catch(e){}
    }
    renderSidebar(); renderChat(); updateTopbar(); updateInputPlaceholder();
    return;
  }
  // Track the last real IRC view so files dropped/picked while on the Uploads
  // channel still associate with a sensible source for "Insert into chat".
  _lastIrcActive={conn_id,target};
  // Leaving a history-view target for a DIFFERENT target → drop the stale
  // historical window so reopening that channel loads present fresh.
  if(_historyView && _historyView.bk!==bk(conn_id,target)){
    getBuf(_historyView.conn_id,_historyView.target).length=0;
    _lastMsgId[_historyView.bk]=0;
    _historyView=null;
  }
  unread.delete(bk(conn_id,target)); mentionUnread.delete(bk(conn_id,target)); saveUnread();
  clearNoticesForTarget(conn_id,target);
  // Persist active view and open queries — skipped in detached mode so the
  // popup's target doesn't overwrite the main window's last-active on reload.
  if(!_detMode){
    try{localStorage.setItem('cryptirc_active',JSON.stringify({conn_id,target}));}catch(e){} flushPrefsToServer();
  }
  saveQueryBufs();
  renderSidebar(); renderChat(); updateTopbar(); updateLagDisplay(); scrollForce();
  if(typeof updateE2EIndicator==='function') updateE2EIndicator(target);
  if(getBuf(conn_id,target).length===0){
    wsend({type:'get_logs',conn_id,target,limit:200});
  } else {
    // Sync missed messages for channels we already have history for
    const _sk=bk(conn_id,target),_lid=_lastMsgId[_sk];
    if(_lid>0) wsend({type:'sync',conn_id,target,after_id:_lid});
  }
  updateInputPlaceholder();
  const net=networks.find(n=>n.config.id===conn_id);
  const inpNick=document.getElementById('input-nick');if(inpNick)inpNick.textContent=net?.nick||net?.config.nick||currentUser||'—';
  updateCertBtn();
}

function renderChat(){
  const area=document.getElementById('chat-area');
  const welcome=document.getElementById('welcome');
  if(!active){area.style.display='none';welcome.style.display='flex';return;}
  // Uploads pseudo-channel uses its own renderer; bail before IRC paths run.
  if(isUploadsActive()){ welcome.style.display='none'; renderUploadsView(); updateTopbar(); updateInputPlaceholder(); return; }
  area.style.display='block'; welcome.style.display='none'; area.innerHTML='';
  const buf=getBuf(active.conn_id,active.target);
  // History-view banner — buffer is a window from the past; tap to return to live.
  if(_historyView && _historyView.bk===bk(active.conn_id,active.target)){
    const hb=document.createElement('div');
    hb.className='history-view-banner';
    hb.textContent='⏷ Viewing older history — tap to jump to present';
    hb.onclick=()=>_exitHistoryView();
    area.appendChild(hb);
  }
  // "Load more" button at top
  if(active.target!=='status'&&buf.length>0){
    const loadMore=document.createElement('div');
    loadMore.className='load-more-btn';
    loadMore.textContent='↑ Load older messages';
    loadMore.onclick=()=>loadOlderMessages();
    area.appendChild(loadMore);
  }
  let lastDate=null;
  const rmKey=bk(active.conn_id,active.target);
  const lastReadTs=parseFloat(localStorage.getItem('cryptirc_lastread_'+rmKey)||'0');
  let markerInserted=false;
  const statusMsgMode=(loadAppearance().statusMsg)||'condense';
  // Match The Lounge's `condensedTypes` set — `chghost` excluded since CryptIRC
  // doesn't surface it as its own event yet.
  const isStatusKind=k=>['away','back','join','kick','mode','nick','part','quit'].includes(k);
  // The Lounge break rule: `self`, `highlight`, or unread-marker crossing breaks
  // a condense run so the user never misses personally-relevant context.
  const isCondensable=m=>isStatusKind(m.kind)&&!m.self&&!m.mentioned;
  let i=0;
  while(i<buf.length){
    const msg=buf[i];
    const d=new Date(msg.ts*1000).toDateString();
    if(d!==lastDate){const div=document.createElement('div');div.className='day-div';div.textContent=d;area.appendChild(div);lastDate=d;}
    if(!markerInserted && lastReadTs>0 && msg.ts>lastReadTs && msg.from!=='*'){
      const marker=document.createElement('div');marker.className='read-marker';marker.textContent='NEW MESSAGES';area.appendChild(marker);markerInserted=true;
    }
    // Condense consecutive status messages (Lounge-style)
    if(statusMsgMode==='condense'&&isCondensable(msg)){
      const group=[msg];
      while(i+1<buf.length&&isCondensable(buf[i+1])){
        // Also break if the next msg crosses the unread marker into "new" territory
        if(!markerInserted && lastReadTs>0 && buf[i+1].ts>lastReadTs) break;
        i++;group.push(buf[i]);
      }
      if(group.length>=2){
        area.appendChild(buildCondensedRow(group));
      } else {
        area.appendChild(buildRow(msg));
      }
    } else {
      area.appendChild(buildRow(msg));
    }
    i++;
  }
  // Update last-read timestamp
  if(buf.length>0) localStorage.setItem('cryptirc_lastread_'+rmKey,String(buf[buf.length-1].ts));
  scrollForce();
  // iOS PWA: images/videos often finish loading AFTER scrollForce's 3s window
  // closes, leaving the user stranded above the true bottom. For 8 seconds
  // after render, any media that hasn't loaded yet re-scrolls to bottom on
  // load — but only if the user hasn't deliberately scrolled up.
  const _activeAtRender=active&&active.conn_id+'|'+active.target;
  const _mediaScrollDeadline=Date.now()+8000;
  const _mediaScrollFn=()=>{
    if(_userScrolledAway)return;
    if(!active||active.conn_id+'|'+active.target!==_activeAtRender)return;
    if(Date.now()>_mediaScrollDeadline)return;
    scrollBottom();
  };
  area.querySelectorAll('img,video').forEach(el=>{
    if(el.tagName==='IMG'?el.complete:(el.readyState>=1))return;
    el.addEventListener('load',_mediaScrollFn,{once:true});
    el.addEventListener('loadedmetadata',_mediaScrollFn,{once:true});
    el.addEventListener('error',()=>{},{once:true});
  });
  // Seed the burst timer: a freshly-rendered buffer (e.g. the WHOIS auto-switch)
  // is immediately followed by the reply's numerics — treat those first appends
  // as part of the burst so they don't pulse in one-by-one after the view swap.
  _lastAppendTs=Date.now();
}
function loadOlderMessages(){
  if(!active)return;
  const buf=getBuf(active.conn_id,active.target);
  const oldest=buf.length>0?buf[0].ts:Math.floor(Date.now()/1000);
  const btn=document.querySelector('.load-more-btn');
  if(btn){btn.textContent='Loading…';btn.style.opacity='.5';}
  wsend({type:'get_logs',conn_id:active.conn_id,target:active.target,limit:200,before:oldest});
}
/* Cap the chat DOM at MAX rows. Buffer is bounded at 2000 (addMessage line ~3638)
   but the DOM had no cap — appendMsgRow only ever appends, never removes, so a
   long Electron session in a busy channel could accumulate tens of thousands of
   rows and start freezing on layout/GC. Trim the oldest rows from the front,
   but only when the user is near the bottom — don't yank content out from under
   someone scrolled up reading older history. The Load-older button stays. */
function _pruneChatDOM(area){
  const MAX=1000;
  const n=area.children.length;
  if(n<=MAX)return;
  const dist=area.scrollHeight-area.scrollTop-area.clientHeight;
  if(dist>600)return; // user is scrolled up — don't disturb their view
  let toRemove=n-MAX;
  while(toRemove>0){
    let node=area.firstChild;
    if(!node)break;
    if(node.classList&&node.classList.contains('load-more-btn')){
      node=node.nextSibling;
      if(!node)break;
    }
    area.removeChild(node);
    toRemove--;
  }
}
// Rows appended within this many ms of the previous one are treated as a burst
// and skip the fade-in animation (see .msg-row.no-anim). Tuned above typical
// server numeric spacing (WHOIS) but well under conversational message spacing.
const BURST_NO_ANIM_MS=120;
let _lastAppendTs=0;
// Stable per-message fingerprint for DOM idempotency. id-bearing messages key on
// their unique server id (so genuinely-repeated text with distinct ids survives);
// id-less ones key on ts|from|kind|text.
function _msgFp(m){ return (m && m.id>0) ? 'id:'+m.id : 'k:'+((m&&m.ts)|0)+'|'+((m&&m.from)||'')+'|'+((m&&m.kind)||'')+'|'+((m&&m.text)||'').slice(0,80); }
function appendMsgRow(msg){
  const area=document.getElementById('chat-area');if(area.style.display==='none')return;
  // Idempotency guard against the transient duplicate-row bug: if an identical
  // chat/notice row is already among the last few rendered, skip the append.
  // renderChat() stays authoritative (this only touches the live append path), own
  // messages are exempt (optimistic echo + intentional repeats are reconciled
  // elsewhere), and id-bearing rows fingerprint by their unique id so legitimate
  // repeats are never swallowed.
  if((msg.kind==='privmsg'||msg.kind==='action'||msg.kind==='notice') && msg.from && msg.from!=='*' && !msg.self && msg.from!==getNick(active&&active.conn_id)){
    const fp=_msgFp(msg);
    for(let i=area.children.length-1, seen=0; i>=0 && seen<12; i--, seen++){
      const c=area.children[i];
      if(c.dataset && c.dataset.fp===fp){ scrollBottom(); return; }
    }
  }
  // Compute the burst window for EVERY append up front — including the condensed-
  // status early-returns below — so _lastAppendTs is always current and a chat
  // message right after a join/part still gets correct burst detection.
  const _ts=Date.now();
  const _burst=(_ts-_lastAppendTs)<BURST_NO_ANIM_MS;
  _lastAppendTs=_ts;
  const statusMsgMode=(loadAppearance().statusMsg)||'condense';
  const isStatus=['away','back','join','kick','mode','nick','part','quit'].includes(msg.kind);
  const isCondensable=isStatus&&!msg.self&&!msg.mentioned;
  if(statusMsgMode==='condense'&&isCondensable){
    // Try to merge with an existing condensed row at the bottom
    const lastChild=area.lastElementChild;
    if(lastChild&&lastChild.classList.contains('status-condensed')){
      // Append one event in O(1): fold into running counts + append a single
      // capped detail row. (Previously this JSON-parsed/stringified the whole
      // group and rebuilt EVERY child via buildRow on every event — O(n²) growth
      // with no size cap that froze long-lived tabs in channels with join/quit or
      // away/back churn, since this one block evades the _pruneChatDOM cap too.)
      _condenseAppend(lastChild,_condenseStashMsg(msg));
      scrollBottom();return;
    }
    // Previous element is a single status row — convert it + new one into condensed
    // (skip if the previous was self/highlighted — Lounge keeps those standalone).
    if(lastChild&&lastChild.classList.contains('msg-row')&&!lastChild.dataset.self&&!lastChild.dataset.mentioned&&['row-away','row-back','row-join','row-part','row-quit','row-nick','row-mode','row-kick'].some(c=>lastChild.classList.contains(c))){
      const prevKind=(lastChild.className.match(/row-(\w+)/)||[])[1]||'system';
      const prevTs=parseFloat(lastChild.dataset.ts||'0')||msg.ts;
      const prevMsg={kind:prevKind,ts:prevTs,from:lastChild.dataset.from||'*',text:lastChild.querySelector('.msg-body')?.textContent||''};
      const grp=[prevMsg,_condenseStashMsg(msg)];
      const condensed=buildCondensedRow(grp);
      area.replaceChild(condensed,lastChild);
      scrollBottom();return;
    }
  }
  const r=buildRow(msg);
  // Burst suppression: when rows land back-to-back (a WHOIS reply's ~10 numerics,
  // a paste flood, history playback), skip the per-row fade so the view doesn't
  // visibly pulse/flash. Single messages (gap > BURST) keep their fade-in.
  // Exclude mentions: their .flash highlight also uses the animation property, so
  // a no-anim (animation:none) would swallow it. Mentions are never part of a
  // WHOIS-style numeric burst anyway. (_burst/_ts computed at function top.)
  if(_burst && !msg.mentioned) r.classList.add('no-anim');
  area.appendChild(r);
  if(msg.mentioned){r.classList.add('flash');setTimeout(()=>r.classList.remove('flash'),3000);}
  _pruneChatDOM(area);
  scrollBottom();
}
// Stash just the fields we need to (a) build the summary and (b) re-render via buildRow when expanded.
function _condenseStashMsg(m){
  return {kind:m.kind,ts:m.ts,from:m.from||'*',text:m.text||'',subject:m.subject||'',subject2:m.subject2||'',rawModes:m.rawModes||''};
}
// Detail rows kept (and re-buildable) inside an expanded condensed block. The
// SUMMARY counts stay exact regardless of this cap (they're folded incrementally,
// never re-derived from the retained tail); only the expandable per-event history
// is bounded so a long status run can't grow unbounded DOM/memory and freeze the
// tab. This block is one top-level child, so _pruneChatDOM never trims it.
const SC_CAP=300;
function _condenseCounts(){return {join:0,part:0,quit:0,nick:0,kick:0,mode:0,away:0,back:0,chghost:0};}
// Fold one stashed status msg into a running counts object (same per-kind logic
// buildCondensedSummary used to run over the whole group on every event).
function _condenseFold(c,m){
  if(m.kind==='mode'){
    // Lounge counts the mode-letters in the first whitespace-delimited modechunk.
    let chunk=m.rawModes||'';
    if(!chunk){const t=(m.text||'').replace(/^.*?(?:sets mode|MODE)\s+/,'');chunk=t.split(/\s+/)[0]||'';}
    else chunk=chunk.split(/\s+/)[0]||'';
    const letters=chunk.replace(/[+\-]/g,'').length;
    c.mode+=Math.max(1,letters);
  } else if(c[m.kind]!==undefined){
    c[m.kind]+=1;
  }
}
// Render the Lounge-style summary string from a counts object.
function _condenseSummary(c0){
  const c=Object.assign({},c0);
  c.part+=c.quit; c.quit=0; // Lounge folds quit into part to reduce clutter
  const out=[];
  const push=(n,sing,plur)=>{ if(n>0) out.push(n===1?sing.replace('{n}',1):plur.replace('{n}',n)); };
  push(c.join,    '{n} user has joined',          '{n} users have joined');
  push(c.part,    '{n} user has left',            '{n} users have left');
  push(c.nick,    '{n} user has changed nick',    '{n} users have changed nick');
  push(c.kick,    '{n} user was kicked',          '{n} users were kicked');
  push(c.mode,    '{n} mode was set',             '{n} modes were set');
  push(c.chghost, '{n} user has changed hostname','{n} users have changed hostname');
  if(c.away===1) out.push('marked away once'); else if(c.away>1) out.push(`marked away ${c.away} times`);
  if(c.back===1) out.push('marked back once'); else if(c.back>1) out.push(`marked back ${c.back} times`);
  if(out.length<=1) return out[0]||'';
  const last=out.pop();
  return out.join(', ')+', and '+last;
}
function _scWriteSummary(row){
  const lastTs=row._scLastTs;
  let tsTxt='';
  if(lastTs){const t=new Date(lastTs*1000);const h=t.getHours(),hr=h%12||12,ampm=h<12?'am':'pm';tsTxt=`${hr}:${t.getMinutes().toString().padStart(2,'0')}${ampm}`;}
  const tsEl=row.querySelector('.sc-summary .msg-ts');
  if(tsEl) tsEl.textContent=tsTxt;
  const txtEl=row.querySelector('.sc-summary .sc-summary-text');
  if(txtEl) txtEl.textContent=_condenseSummary(row._scCounts);
}
// Initial render of a condensed block from a (bounded) group: exact counts over
// the whole group, but only the last SC_CAP entries materialized as detail DOM.
function _renderCondensed(row,group){
  const counts=_condenseCounts();
  for(const m of group) _condenseFold(counts,m);
  row._scCounts=counts;
  row._scTail=group.length>SC_CAP?group.slice(-SC_CAP):group.slice();
  row._scLastTs=group.length?group[group.length-1].ts:0;
  _scWriteSummary(row);
  // Expanded view re-renders each retained child via buildRow (Lounge fidelity).
  const expand=row.querySelector('.sc-expand');
  expand.innerHTML='';
  for(const m of row._scTail) expand.appendChild(buildRow(m));
}
// Append a single event to an existing condensed block in O(1): fold its counts,
// refresh the summary, and append exactly one detail row (trimming the oldest
// past SC_CAP). No whole-group re-parse or re-render.
function _condenseAppend(row,stash){
  if(!row._scCounts) row._scCounts=_condenseCounts();
  if(!row._scTail) row._scTail=[];
  _condenseFold(row._scCounts,stash);
  row._scLastTs=stash.ts;
  _scWriteSummary(row);
  row._scTail.push(stash);
  while(row._scTail.length>SC_CAP) row._scTail.shift();
  const expand=row.querySelector('.sc-expand');
  if(expand){
    expand.appendChild(buildRow(stash));
    while(expand.children.length>SC_CAP) expand.removeChild(expand.firstChild);
  }
}
// Match The Lounge's MessageCondensed phrasing exactly:
//   "N user has joined" / "N users have joined"
//   part includes quits ("N user has left")
//   "N user has changed nick", "N user was kicked", "N modes were set",
//   "marked away once" / "marked away N times" / same for back
// Joiner: ", " between clauses, ", and " before the last.
function buildCondensedSummary(group){
  const c=_condenseCounts();
  for(const m of group) _condenseFold(c,m);
  return _condenseSummary(c);
}
function buildCondensedRow(group){
  // Normalize each entry to the stash shape so re-renders stay consistent.
  const stash=group.map(m=>({kind:m.kind,ts:m.ts,from:m.from||'*',text:m.text||'',subject:m.subject||'',subject2:m.subject2||'',rawModes:m.rawModes||''}));
  const row=document.createElement('div');
  row.className='status-condensed';
  // Block state (counts/tail) lives on the element via _renderCondensed below —
  // no JSON blob in the DOM (a big stringified group used to grow per-event).
  // Summary uses the same .msg-row column structure (ts | nick | body) so it
  // aligns with normal chat rows. Chevron sits in the nick column.
  row.innerHTML=`<div class="msg-row sc-summary"><span class="msg-ts"></span><span class="msg-nick"><span class="sc-chevron">›</span></span><span class="msg-body sc-summary-text"></span></div><div class="sc-expand"></div>`;
  _renderCondensed(row,stash);
  // Toggle only on summary click (clicks inside expanded children — like a nick
  // → showNickMenu — must not collapse the block).
  const summaryEl=row.querySelector('.sc-summary');
  summaryEl.addEventListener('click',()=>{
    row.classList.toggle('expanded');
    if(row.classList.contains('expanded'))requestAnimationFrame(()=>row.scrollIntoView({block:'end',behavior:'smooth'}));
  });
  return row;
}
function buildRow(msg){
  const row=document.createElement('div'); row.className=`msg-row row-${msg.kind}`; row.dataset.ts=msg.ts; row.dataset.from=msg.from||''; row.dataset.fp=_msgFp(msg);
  if(msg.self) row.dataset.self='1';
  if(msg.mentioned) row.dataset.mentioned='1';
  const t=new Date(msg.ts*1000);
  const h=t.getHours(),hr=h%12||12,ampm=h<12?'am':'pm';
  // mIRC theme: classic 24-hour bracketed [HH:MM] timestamp; every other theme keeps 12h.
  const ts=(document.documentElement.dataset.theme==='mirc')
    ?`[${h.toString().padStart(2,'0')}:${t.getMinutes().toString().padStart(2,'0')}]`
    :`${hr}:${t.getMinutes().toString().padStart(2,'0')}${ampm}`;
  const isChat=msg.kind==='privmsg'||msg.kind==='action';
  const isSelf=isChat&&active&&msg.from===getNick(active.conn_id);
  const nc=isChat?(isSelf?'nc-self':`nc${nickHash(msg.from)}`):'';
  const isSys=['system','error','join','part','quit','nick','mode','topic','kick','notice','away','back'].includes(msg.kind)||msg.from==='*';
  // Get user's channel prefix (@, +, ~, &, %) for display
  let userPfx='';
  if(isChat&&active&&(active.target.startsWith('#')||active.target.startsWith('&'))){
    const _net=networks.find(n=>n.config.id===active.conn_id);
    const _ch=_net?.channels?.find(c=>c.name===active.target);
    if(_ch){const entry=(_ch.names||[]).find(n=>stripPfx(n)===msg.from);if(entry){let pi=0;while(pi<entry.length&&'~&@%+'.includes(entry[pi]))pi++;if(pi>0)userPfx=entry[0];}}
  }
  const pfxHtml=userPfx?`<span class="nick-pfx${'~&@'.includes(userPfx)?' op':''}">${userPfx}</span>`:'';
  let nickHtml,bodyHtml;
  if(isSys){nickHtml=`<span class="msg-nick" style="color:var(--text3)">—</span>`;bodyHtml=`<span class="msg-body">${renderStatusText(msg)}</span>`;}
  else if(msg.kind==='action'){nickHtml=`<span class="msg-nick ${nc}">* ${pfxHtml}${esc(msg.from)}</span>`;bodyHtml=`<span class="msg-body">${renderText(msg.text)}</span>`;}
  else{
    // SECURITY: the nick is attacker-controlled (IRC prefix, no char validation)
    // so it must NOT be interpolated into an inline event-handler JS-string —
    // esc() is correct for the HTML *attribute* context (data-nick) but the
    // parser decodes &#39;→' before an onclick body is compiled as JS, re-enabling
    // breakout. We store the nick in data-nick and open the menu via the delegated
    // document-level click/contextmenu listener (see below).
    nickHtml=`<span class="msg-nick ${nc}" data-nick="${esc(msg.from)}" style="cursor:pointer">${pfxHtml}${esc(msg.from)}</span>`;
    bodyHtml=`<span class="msg-body">${renderText(msg.text)}</span>`;
  }
  row.innerHTML=`<span class="msg-ts">${ts}</span>${nickHtml}${bodyHtml}`;
  // Small lock badge on encrypted messages
  const msgBody=row.querySelector('.msg-body');
  if (msg.encrypted && msgBody) {
    const lock = document.createElement('span');
    lock.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4" fill="none" stroke-width="2"/></svg>';
    lock.title = 'E2E encrypted';
    lock.style.cssText = 'opacity:.5;margin-left:4px;flex-shrink:0;color:var(--accent);';
    msgBody.appendChild(lock);
  }
  if(msgBody){for(const url of extractMediaUrls(msg.text)){const el=buildMediaEl(url);if(el)msgBody.appendChild(el);}}
  // Reply button on chat messages
  if(isChat&&msg.from!=='*'){
    const replyBtn=document.createElement('span');
    replyBtn.className='msg-reply-btn';
    replyBtn.title='Reply';
    replyBtn.innerHTML='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 17H4V12"/><path d="M4 17L15 6"/><path d="M15 6H20V11"/></svg>';
    replyBtn.onclick=(e)=>{e.stopPropagation();setReply(msg.from,msg.text);};
    row.appendChild(replyBtn);
  }
  return row;
}
// Delegated click handler for nick list — attached once, works for all nicks.
// iOS quirk: when the message input is focused, a tap on a nick fires
// touchend → synthetic mousedown → input blur → keyboard dismiss → visualViewport
// resize → layout shift → the synthetic `click` then lands at stale coords (or a
// stray synthetic click instantly closes the just-opened overlay). Net effect:
// the first tap appears to do nothing and you have to tap twice. We commit the
// tap on touchend with preventDefault() to cancel that whole cascade, and guard
// the click handler so it doesn't double-fire on touch devices.
(function(){
  const nl=document.getElementById('nick-list');
  if(nl&&!nl._delegated){
    nl._delegated=true;
    let _touchHandled=false,_tStart=null;
    nl.addEventListener('touchstart',function(e){
      _tStart=e.touches.length?[e.touches[0].clientX,e.touches[0].clientY]:null;
    },{passive:true});
    nl.addEventListener('touchend',function(e){
      const entry=e.target.closest('.nick-entry');
      // Only treat as a tap if the finger barely moved — otherwise this was a
      // scroll of the member list and must not open the menu on release.
      const t=e.changedTouches&&e.changedTouches[0];
      const moved=_tStart&&t?_distPts(_tStart,[t.clientX,t.clientY])>10:false;
      _tStart=null;
      if(entry&&entry.dataset.nick&&!moved){
        e.preventDefault();   // cancel synthetic mousedown/click + input-blur cascade
        e.stopPropagation();
        _touchHandled=true;
        setTimeout(()=>{_touchHandled=false;},700);
        showNickMenu(e,entry.dataset.nick);
      }
    },{passive:false});
    nl.addEventListener('click',function(e){
      const entry=e.target.closest('.nick-entry');
      if(entry&&entry.dataset.nick){
        e.stopPropagation();
        if(_touchHandled)return;   // touchend already opened it on this device
        showNickMenu(e,entry.dataset.nick);
      }
    });
  }
})();
// SECURITY: delegated open-menu handler for nicks rendered inside chat message
// bodies (the per-message .msg-nick clickable nick + in-body .nick-mention spans).
// These carry an HTML-attribute-escaped data-nick instead of an inline onclick,
// so an attacker-controlled nick can never reach a JS-string/code context
// (replaces the old onclick="showNickMenu(event,'…')" sinks — findings #3/#9/#10).
// Document-level so it covers the main chat, split view and detached windows
// uniformly. Guarded against double-fire on touch via _touchHandledBody.
(function(){
  if(document._nickBodyDelegated)return;
  document._nickBodyDelegated=true;
  let _touchHandledBody=false;
  const _findNick=(el)=>{const n=el.closest('.msg-nick[data-nick],.nick-mention[data-nick]');return n&&n.dataset.nick?n:null;};
  document.addEventListener('touchend',function(e){
    const n=_findNick(e.target);
    if(n){
      e.preventDefault();
      e.stopPropagation();
      _touchHandledBody=true;
      setTimeout(()=>{_touchHandledBody=false;},700);
      showNickMenu(e,n.dataset.nick);
    }
  },{passive:false});
  document.addEventListener('click',function(e){
    const n=_findNick(e.target);
    if(n){
      e.stopPropagation();
      if(_touchHandledBody)return;   // touchend already opened it on this device
      showNickMenu(e,n.dataset.nick);
    }
  });
  document.addEventListener('contextmenu',function(e){
    const n=_findNick(e.target);
    if(n){
      e.preventDefault();
      e.stopPropagation();
      showNickMenu(e,n.dataset.nick);
    }
  });
})();
function renderNickPanel(names){
  const list=document.getElementById('nick-list');
  const cnt=document.getElementById('nick-panel-count');
  list.innerHTML=''; cnt.textContent=`(${names.length})`;
  const sorted=[...names].sort((a,b)=>{const pa=nickPri(a),pb=nickPri(b);return pa!==pb?pa-pb:stripPfx(a).localeCompare(stripPfx(b),undefined,{sensitivity:'base'});});
  // Group by role
  const groups={owners:[],admins:[],ops:[],halfops:[],voiced:[],users:[]};
  for(const n of sorted){
    let pi=0;while(pi<n.length&&'~&@%+'.includes(n[pi]))pi++;
    const pfx=n.slice(0,pi);
    if(pfx.includes('~'))groups.owners.push(n);
    else if(pfx.includes('&'))groups.admins.push(n);
    else if(pfx.includes('@'))groups.ops.push(n);
    else if(pfx.includes('%'))groups.halfops.push(n);
    else if(pfx.includes('+'))groups.voiced.push(n);
    else groups.users.push(n);
  }
  const sections=[
    {label:'Owners',nicks:groups.owners},
    {label:'Admins',nicks:groups.admins},
    {label:'Operators',nicks:groups.ops},
    {label:'Half-Ops',nicks:groups.halfops},
    {label:'Voiced',nicks:groups.voiced},
    {label:'Users',nicks:groups.users},
  ];
  for(const sec of sections){
    if(!sec.nicks.length)continue;
    const hdr=document.createElement('div');
    hdr.className='nick-group-hdr';
    hdr.textContent=sec.label;
    list.appendChild(hdr);
    for(const n of sec.nicks){
      let pi=0;while(pi<n.length&&'~&@%+'.includes(n[pi]))pi++;
      const pfx=n.slice(0,pi);
      // Show only highest-ranking prefix (multi-prefix sends all)
      const topPfx=pfx?pfx[0]:'';
      const nick=n.slice(pi);
      const el=document.createElement('div');
      const awayKey=(active?active.conn_id:'')+'/'+nick;
      const isAway=window._awayNicks&&window._awayNicks[awayKey];
      el.className=`nick-entry nc${nickHash(nick)}${isAway?' nick-away':''}`;
      el.dataset.nick=nick;
      el.innerHTML=topPfx?`<span class="nick-pfx${'~&@'.includes(topPfx)?' op':''}">${topPfx}</span>${esc(nick)}`:esc(nick);
      el.style.cursor='pointer';
      list.appendChild(el);
    }
  }
}
function updateTypingIndicator(){
  const el=document.getElementById('typing-indicator');
  if(!el||!window._typingState)return;
  if(!active){el.className='';el.textContent='';return;}
  const prefix=(active.conn_id+'/'+active.target+'/').toLowerCase();
  const myNick=(getNick(active.conn_id)||'').toLowerCase();
  const typers=[];
  const now=Date.now();
  for(const[k,t]of Object.entries(window._typingState)){
    if(k.toLowerCase().startsWith(prefix)&&now-t<6000){
      const nick=k.slice(prefix.length);
      if(nick.toLowerCase()===myNick) continue;
      typers.push(nick);
    }
  }
  if(typers.length===0){
    el.className='';el.textContent='';el._typingBase='';
    return;
  }
  const wasHidden=el.className!=='visible';
  el.className='visible';
  if(typers.length===1) el._typingBase=typers[0]+' is typing';
  else if(typers.length===2) el._typingBase=typers[0]+' and '+typers[1]+' are typing';
  else el._typingBase=typers.slice(0,-1).join(', ')+' and '+typers[typers.length-1]+' are typing';
  if(wasHidden){el._dc=0;el.textContent=el._typingBase+'.';scrollBottom();}
}
// Global typing dot ticker — cycles . .. ... on the indicator whenever visible
setInterval(()=>{
  const el=document.getElementById('typing-indicator');
  if(!el||el.className!=='visible'||!el._typingBase)return;
  el._dc=((el._dc||0)%3)+1;
  el.textContent=el._typingBase+'.'.repeat(el._dc);
},400);
function updateTopbar(){
  if(!active)return;
  const topicInline=document.getElementById('topic-inline');
  const topicSep=document.getElementById('topic-sep');
  const topicMenuBtn=document.getElementById('topic-menu-btn');
  const topbarSpacer=document.getElementById('topbar-spacer');
  if(isUploadsConn(active.conn_id)){
    document.getElementById('chan-title').textContent='Upload Status';
    document.getElementById('chan-title').style.color='var(--text)';
    topicInline.style.display='none';
    topicSep.style.display='none';
    topicMenuBtn.style.display='none';
    topbarSpacer.style.display='';
    document.getElementById('usercount').textContent='';
    return;
  }
  const net=networks.find(n=>n.config.id===active.conn_id);
  document.getElementById('chan-title').textContent=active.target;
  document.getElementById('chan-title').style.color='var(--text)';
  if(net){
    const ch=net.channels.find(c=>c.name===active.target);
    const topic=ch?.topic||'';
    topicMenuBtn.style.display='';
    if(topic){
      topicInline.innerHTML=parseMircColors(topic);
      topicInline.title=topic;
      topicInline.style.display='';
      topicSep.style.display='';
      topbarSpacer.style.display='none';
    } else {
      topicInline.style.display='none';
      topicSep.style.display='none';
      topbarSpacer.style.display='';
    }
    document.getElementById('usercount').textContent=ch?`${ch.names.length} users`:'';
    renderNickPanel(ch?.names||[]);
    const _in2=document.getElementById('input-nick');if(_in2)_in2.textContent=net.nick||net.config.nick;
  } else {
    topicInline.style.display='none';
    topicSep.style.display='none';
    topicMenuBtn.style.display=active?'':'none';
    topbarSpacer.style.display='';
  }
}

// ─── Media ────────────────────────────────────────────────────────────────────
function extractMediaUrls(text){const urls=[];const re=/(https?:\/\/[^\s<>"]+)/g;let m;while((m=re.exec(text))!==null)urls.push(m[1]);return urls;}
function appendFileToken(url){
  if(sessionToken&&url.includes('/files/')){
    const sep=url.includes('?')?'&':'?';
    return url+sep+'token='+encodeURIComponent(sessionToken);
  }
  return url;
}
function buildMediaEl(url){
  const authedUrl=appendFileToken(url);
  // Images
  if(IMG_EXTS.test(url)||url.includes('/files/')){
    const wrap=document.createElement('div');wrap.className='msg-media';
    // Chat images load eagerly: they're appended at the bottom of the chat
    // (always in viewport), and `loading="lazy"` combined with the default
    // `aspect-ratio: auto` left them at 0×0 — IntersectionObserver never
    // fired in older Chromium (Electron lags stable Chrome), so giphy/etc
    // never decoded. Click-to-lightbox worked because that path didn't use
    // lazy. Eager load is fine here; perf cost is negligible on a chat tail.
    const img=document.createElement('img');img.className='msg-img';img.src=authedUrl;img.alt='image';img.decoding='async';
    img.onclick=e=>{e.stopPropagation();openLightbox(authedUrl);};
    img.onload=()=>{if(!_userScrolledAway)scrollBottom();};
    img.onerror=()=>wrap.style.display='none';
    wrap.appendChild(img);
    return wrap;
  }
  // Audio
  if(AUDIO_EXTS.test(url)){
    const wrap=document.createElement('div');wrap.className='msg-audio';
    const aud=document.createElement('audio');aud.src=authedUrl;aud.controls=true;aud.preload='metadata';
    wrap.appendChild(aud);
    return wrap;
  }
  // Videos
  if(VID_EXTS.test(url)){
    const wrap=document.createElement('div');wrap.className='msg-media';
    const vid=document.createElement('video');vid.src=authedUrl;vid.controls=true;vid.preload='metadata';vid.onloadedmetadata=()=>{if(!_userScrolledAway)scrollBottom();};
    wrap.appendChild(vid);
    return wrap;
  }
  // YouTube — rich card with thumbnail + info
  const ytId=extractYouTubeId(url);
  if(ytId){
    const _ytUid=ytId+'_'+(Date.now()%1000000);
    const wrap=document.createElement('div');
    wrap.className='msg-yt';
    wrap.innerHTML=`<div class="msg-yt-thumb"><img src="https://img.youtube.com/vi/${ytId}/hqdefault.jpg" alt="YouTube" loading="lazy"><span class="yt-play"></span></div><div class="msg-yt-info"><div class="msg-yt-title" id="yt-t-${_ytUid}">Loading...</div><div class="msg-yt-desc" id="yt-d-${_ytUid}"></div><div class="msg-yt-meta" id="yt-m-${_ytUid}"><span>YouTube</span></div></div>`;
    wrap.querySelector('img').onload=()=>{if(!_userScrolledAway)scrollBottom();};
    wrap.querySelector('img').onerror=()=>wrap.style.display='none';
    // Click thumbnail to play inline — click title/info to open in browser
    wrap.querySelector('.msg-yt-thumb').addEventListener('click',(e)=>{
      e.preventDefault();e.stopPropagation();
      const thumb=wrap.querySelector('.msg-yt-thumb');
      thumb.innerHTML=`<iframe src="https://www.youtube.com/embed/${ytId}?autoplay=1&rel=0&modestbranding=1" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen referrerpolicy="no-referrer-when-downgrade"></iframe>`;
      if(!_userScrolledAway)scrollBottom();
    });
    wrap.querySelector('.msg-yt-info').addEventListener('click',()=>window.open(url,'_blank'));
    // Fetch video info via noembed (no API key needed, privacy-friendly)
    const _ac=new AbortController();const _to=setTimeout(()=>_ac.abort(),10000);
    fetch(`https://noembed.com/embed?url=https://www.youtube.com/watch?v=${ytId}`,{signal:_ac.signal}).then(r=>{clearTimeout(_to);return r.json();}).then(d=>{
      const titleEl=document.getElementById('yt-t-'+_ytUid);
      const metaEl=document.getElementById('yt-m-'+_ytUid);
      if(titleEl&&d.title) titleEl.textContent=d.title;
      if(metaEl){
        const parts=[];
        if(d.author_name) parts.push(esc(d.author_name));
        parts.push('YouTube');
        metaEl.innerHTML=parts.map(p=>`<span>${p}</span>`).join('');
      }
      if(d.title) wrap.title=d.title+(d.author_name?' — '+d.author_name:'');
    }).catch(()=>{
      const titleEl=document.getElementById('yt-t-'+_ytUid);
      if(titleEl) titleEl.textContent='YouTube Video';
    });
    // Fetch views/likes via Return YouTube Dislike API (no API key needed)
    fetch(`https://returnyoutubedislikeapi.com/votes?videoId=${ytId}`).then(r=>r.ok?r.json():null).then(d=>{
      if(!d) return;
      const metaEl=document.getElementById('yt-m-'+_ytUid);
      if(metaEl){
        const parts=[];
        const existing=metaEl.textContent;
        if(existing&&!existing.includes('views')) {
          // Preserve author + YouTube label, append stats
          const author=metaEl.querySelector('span')?.textContent;
          if(author&&author!=='YouTube') parts.push(esc(author));
          parts.push('YouTube');
          if(d.viewCount) parts.push(d.viewCount.toLocaleString()+' views');
          if(d.likes) parts.push(d.likes.toLocaleString()+' likes');
          metaEl.innerHTML=parts.map(p=>`<span>${p}</span>`).join('');
          if(!_userScrolledAway)scrollBottom();
        }
      }
    }).catch(()=>{});
    return wrap;
  }
  // Link preview — fetch metadata from server for non-media HTTPS links
  if(url.startsWith('https://') && loadAppearance().linkPreviews!==false){
    const previewId='lp-'+Math.random().toString(36).slice(2,10);
    const card=document.createElement('a');
    card.href=url;card.target='_blank';card.rel='noopener noreferrer';
    card.className='msg-link-preview';card.id=previewId;
    card.style.display='none'; // Hidden until metadata loads
    // Fetch preview asynchronously
    fetch(`/cryptirc/preview?url=${encodeURIComponent(url)}`,{headers:{'Authorization':'Bearer '+sessionToken}})
      .then(r=>r.ok?r.json():null).then(d=>{
        if(!d||!d.title){card.remove();return;}
        const el=document.getElementById(previewId);
        if(!el)return;
        let html=`<div class="msg-link-preview-domain">${esc(d.site_name||d.domain)}</div>`;
        html+=`<div class="msg-link-preview-title">${esc(d.title)}</div>`;
        if(d.description) html+=`<div class="msg-link-preview-desc">${esc(d.description)}</div>`;
        if(d.image&&d.image.startsWith('https://')) html+=`<img class="msg-link-preview-img" src="${esc(d.image)}" loading="lazy" onload="if(!_userScrolledAway)scrollBottom()" onerror="this.remove()">`;
        el.innerHTML=html;
        el.style.display='';
        // Card just materialized — may have added meaningful height. If the
        // user is near the bottom, re-anchor to the latest message. 500px
        // threshold covers a revealed preview + small image without
        // snapping users who deliberately scrolled up.
        if(!_userScrolledAway) scrollBottom();
      }).catch(()=>card.remove());
    return card;
  }
  return null;
}
function extractYouTubeId(url){
  const m=url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/);
  return m?m[1]:null;
}
// openLightbox/closeLightbox defined in lightbox zoom/pan section below

// ─── Input ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',()=>{
  checkAuth();
  registerPwa();
  initViewportFix();
  initSwipeGesture();

  // Track input bar height for toast positioning
  const inputWrap=document.getElementById('input-wrap');
  new ResizeObserver(()=>{
    document.documentElement.style.setProperty('--input-bar-h',inputWrap.offsetHeight+'px');
  }).observe(inputWrap);

  // iOS PWA: keyboard-dismiss reflow eats the click; send on pointerdown so the
  // input stays focused. preventDefault also suppresses the compat click so the
  // onclick fallback (for keyboard Enter/Space) doesn't double-fire.
  const _sendBtn=document.getElementById('send-btn');
  if(_sendBtn){
    _sendBtn.addEventListener('pointerdown',e=>{
      if(e.button!==0)return;
      e.preventDefault();
      doSend();
    });
  }

  const inp=document.getElementById('msg-input');
  inp.addEventListener('keydown', async e=>{
    if(e.key==='Enter')          {
      // Defer to any open autocomplete picker (slash, nick, emoji, chan).
      // Those pickers register their own keydown handlers AFTER this one,
      // so they run later in dispatch order — without this early return,
      // the main submit path would always fire first and ship a half-typed
      // /command, @nick, :emoji or #channel before the picker had a chance
      // to complete it.
      const _slashAc = document.getElementById('slash-autocomplete');
      const _nickAc  = document.getElementById('nick-autocomplete');
      const _emojiAc = document.getElementById('emoji-autocomplete');
      const _chanAc  = document.getElementById('chan-autocomplete');
      const _acOpen = (el) => el && el.style.display && el.style.display!=='none';
      if(_acOpen(_slashAc)||_acOpen(_nickAc)||_acOpen(_emojiAc)||_acOpen(_chanAc)) return;
      sendTypingDone(); await handleInput(inp.value); inp.value=''; historyIdx=-1;
    }
    else if(e.key==='ArrowUp')   {if(historyIdx<inputHistory.length-1){historyIdx++;inp.value=inputHistory[inputHistory.length-1-historyIdx];}e.preventDefault();}
    else if(e.key==='ArrowDown') {if(historyIdx>0){historyIdx--;inp.value=inputHistory[inputHistory.length-1-historyIdx];}else{historyIdx=-1;inp.value='';}e.preventDefault();}
    else if(e.key==='Tab')       {e.preventDefault();tabComplete(inp);}
    // mIRC formatting shortcuts
    else if(e.ctrlKey&&e.key==='b'){e.preventDefault();insertAtCursor(inp,'^B');}        // Bold
    else if(e.ctrlKey&&e.key==='u'){e.preventDefault();insertAtCursor(inp,'^U');}        // Underline
    else if(e.ctrlKey&&e.key==='i'){e.preventDefault();insertAtCursor(inp,'^I');}        // Italic
    else if(e.ctrlKey&&e.key==='o'){e.preventDefault();insertAtCursor(inp,'^O');}        // Reset
    else if(e.ctrlKey&&e.key==='k'){e.preventDefault();showMircColorPicker(inp);}         // Color
    else { sendTypingActive(); }
  });
  ['l-user','l-pass'].forEach(id=>document.getElementById(id)?.addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();}));
  // Scroll auth inputs into view on iOS when keyboard opens
  document.querySelectorAll('.auth-input').forEach(inp=>{
    inp.addEventListener('focus',()=>{
      setTimeout(()=>inp.scrollIntoView({behavior:'smooth',block:'center'}),400);
    });
  });
  document.getElementById('f-email')?.addEventListener('keydown',e=>{if(e.key==='Enter')doForgot();});
  document.getElementById('vault-pass')?.addEventListener('keydown',e=>{if(e.key==='Enter')doUnlock();});

  // Drag & drop
  document.addEventListener('dragover',e=>{e.preventDefault();if(!active)return;if(!e.dataTransfer.types.includes('Files'))return;document.getElementById('drop-overlay').classList.add('show');});
  document.addEventListener('dragleave',e=>{if(!e.relatedTarget)document.getElementById('drop-overlay').classList.remove('show');});
  document.addEventListener('drop',e=>{e.preventDefault();document.getElementById('drop-overlay').classList.remove('show');if(active&&e.dataTransfer.files.length)handleFileSelect(e.dataTransfer.files);});
  // Paste image
  document.addEventListener('paste',e=>{
    if(!active)return;
    const items=Array.from(e.clipboardData?.items||[]);
    const imgItem=items.find(i=>i.type.startsWith('image/'));
    if(imgItem){e.preventDefault();const f=imgItem.getAsFile();if(f)uploadFile(f);return;}
    // Smart paste: detect multi-line text and offer pastebin
    const txt=e.clipboardData?.getData('text/plain')||'';
    if(txt && txt.split('\n').length>=5 && document.activeElement===document.getElementById('msg-input')){
      e.preventDefault();
      _smartPasteText=txt;
      const dlg=document.getElementById('smart-paste-dialog');
      dlg.querySelector('.sp-info').textContent='Pasted text has '+txt.split('\n').length+' lines. Send as pastebin?';
      dlg.classList.add('show');
    }
  });
  // SW messages
  navigator.serviceWorker?.addEventListener('message',e=>{
    if(e.data?.type==='notification_click'){
      // jumpToMessage auto-stashes to _pendingNotifNav if state isn't ready
      if(e.data.ts){ jumpToMessage(e.data.conn_id, e.data.target, parseInt(e.data.ts)||e.data.ts, e.data.from); }
      else if(networks&&networks.length){ setActive(e.data.conn_id, e.data.target); }
      else { _pendingNotifNav={conn_id:e.data.conn_id, target:e.data.target, ts:null, from:null}; }
    }
    if(e.data?.type==='push_resubscribe'&&e.data.subscription){reregisterPushSubscription(e.data.subscription);}
  });
  // Electron notification click
  if(window.electronAPI?.onNotificationClick){
    window.electronAPI.onNotificationClick(meta=>{
      if(!meta)return;
      if(meta.ts) jumpToMessage(meta.conn_id, meta.target, meta.ts, meta.from);
      else if(networks&&networks.length) setActive(meta.conn_id, meta.target);
      else _pendingNotifNav={conn_id:meta.conn_id, target:meta.target, ts:null, from:null};
    });
  }
  // Also drain pending nav when the window becomes visible (in case SW message
  // arrived while page was in bfcache or hidden). Also re-read the SW cache
  // bridge — iOS PWA wake-ups often miss postMessage but the cache entry persists.
  document.addEventListener('visibilitychange',()=>{
    if(!document.hidden){
      _readNotifClickCache();
      if(networks && networks.length) _drainPendingNotifNav();
    }
  });
});

// ─── IRCv3 typing indicator sender ───────────────────────────────────────────
let _lastTypingSent=0;
// ─── Reply system ────────────────────────────────────────────────────────────
let _replyTo=null; // {nick, text}
function setReply(nick,text){
  _replyTo={nick,text:text.slice(0,200)};
  const bar=document.getElementById('reply-bar');
  document.getElementById('reply-bar-nick').textContent=nick;
  document.getElementById('reply-bar-text').textContent=text.slice(0,100);
  bar.classList.add('show');
  document.getElementById('msg-input').focus();
}
function cancelReply(){
  _replyTo=null;
  document.getElementById('reply-bar').classList.remove('show');
}
function getReplyPrefix(){
  if(!_replyTo) return '';
  const quote=_replyTo.text.slice(0,80).replace(/\n/g,' ');
  const prefix=`> <${_replyTo.nick}> ${quote}\n`;
  cancelReply();
  return prefix;
}

function sendTypingActive(){
  if(!active||!ws||ws.readyState!==1) return;
  const now=Date.now();
  if(now-_lastTypingSent<3000) return;
  _lastTypingSent=now;
  const target=active.target;
  if(!target||target==='status') return;
  ws.send(JSON.stringify({type:'send',conn_id:active.conn_id,raw:`@+typing=active TAGMSG ${target}`}));
}
function sendTypingDone(){
  if(!active||!ws||ws.readyState!==1) return;
  _lastTypingSent=0;
  const target=active.target;
  if(!target||target==='status') return;
  ws.send(JSON.stringify({type:'send',conn_id:active.conn_id,raw:`@+typing=done TAGMSG ${target}`}));
}

let _sendLock=false;
async function doSend(){
  if(_sendLock)return;
  const inp=document.getElementById('msg-input');
  if(!inp||!inp.value.trim())return;
  _sendLock=true;
  try{await handleInput(inp.value);inp.value='';}
  finally{setTimeout(()=>{_sendLock=false;},200);}
  inp.focus();
}
async function handleInput(raw){
  raw=raw.trim(); if(!raw||!active)return;
  inputHistory.push(raw); if(inputHistory.length>500)inputHistory.splice(0,inputHistory.length-500); saveInputHistory();
  const{conn_id,target}=active;
  if(raw.startsWith('/')){
    const parts=raw.slice(1).split(' ');const cmd=parts[0].toUpperCase();const args=parts.slice(1);
    switch(cmd){
      // ── Navigation ──────────────────────────────────────────────────
      case 'JOIN': {
        const chans=(args[0]||'').split(',').filter(Boolean);
        const keys=(args[1]||'').split(',');
        const ks=loadChanKeys();
        for(let i=0;i<chans.length;i++){
          let ch=chans[i];
          if(ch&&!ch.startsWith('#')&&!ch.startsWith('&')&&!ch.startsWith('+')&&!ch.startsWith('!')) ch='#'+ch;
          let jKey=keys[i]||null;
          if(!jKey){jKey=ks[bk(conn_id,ch)]||null;}
          if(keys[i]){ks[bk(conn_id,ch)]=keys[i];}
          wsend({type:'join_channel',conn_id,channel:ch,key:jKey});
        }
        if(keys.some(Boolean)) saveChanKeys(ks);
        break;
      }
      case 'PART': case 'LEAVE':
        wsend({type:'part_channel',conn_id,channel:args[0]||target}); break;
      case 'CYCLE': case 'REJOIN': {
        // Part and immediately rejoin the current channel
        const cycleKey = args[0]||target;
        wsend({type:'part_channel',conn_id,channel:cycleKey});
        setTimeout(()=>wsend({type:'join_channel',conn_id,channel:cycleKey,key:null}),500);
        break;
      }
      case 'QUERY': {
        const qnick = args[0];
        if(!qnick){sysMsg(conn_id,target,'Usage: /query <nick>','error');break;}
        clearQueryClosed(conn_id, qnick.toLowerCase());
        if(!queryBufs[conn_id])queryBufs[conn_id]=new Map();
        queryBufs[conn_id].set(qnick.toLowerCase(), qnick);
        saveQueryBufs(); renderSidebar();
        setActive(conn_id,qnick);
        if(args.slice(1).length) {
          const qtext = toMircChars(args.slice(1).join(' '));
          // L2: route through E2E if session exists
          const qwire = (window.E2E?.ready || window.E2E?.channelKeys?.[qnick]) ? await e2eEncryptOutgoing(qnick, qtext) : null;
          if (qwire) {
            wsend({type:'send',conn_id,raw:`PRIVMSG ${qnick} :${qwire}`});
            addMessage(conn_id,qnick,{ts:Date.now()/1000|0,from:getNick(conn_id),text:qtext,kind:'privmsg',encrypted:true});
          } else {
            wsend({type:'send',conn_id,raw:`PRIVMSG ${qnick} :${qtext}`});
          }
        }
        break;
      }
      case 'LIST':
        chanListData=[]; chanListConnId=conn_id;
        document.getElementById('chanlist-body').innerHTML='<div class="chanlist-loading">Waiting for server response...</div>';
        document.getElementById('chanlist-count').textContent='';
        document.getElementById('chanlist-search').value='';
        document.getElementById('chanlist-overlay').classList.add('show');
        _overlayOpen('chanlist', closeChanList);
        wsend({type:'send',conn_id,raw:args[0]?`LIST ${args[0]}`:'LIST'}); break;

      case 'LINKS': {
        window._linksData=[];window._linksConnId=conn_id;
        showLinksOverlay();
        wsend({type:'send',conn_id,raw:args[0]?`LINKS ${args[0]}`:'LINKS'});
        // Auto-close with "no data" after 5 seconds if no response
        setTimeout(()=>{
          if(window._linksData&&window._linksData.length===0){
            document.getElementById('links-body').innerHTML='<div style="color:var(--text3);padding:20px;text-align:center">No links data received. The server may not support /links or it requires operator privileges.</div>';
          }
        },5000);
        break;
      }

      // ── Identity ────────────────────────────────────────────────────
      case 'NICK':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /nick <newnick>','error');break;}
        // KeepNick: if user manually changes AWAY from the kept nick, deactivate
        {const kn=loadKeepNicks();
        if(kn[conn_id]&&kn[conn_id].active&&getNick(conn_id).toLowerCase()===kn[conn_id].nick.toLowerCase()&&args[0].toLowerCase()!==kn[conn_id].nick.toLowerCase()){
          keepnickDeactivate(conn_id);sysMsg(conn_id,target,`KeepNick deactivated (you changed away from ${kn[conn_id].nick}). Use /keepnick to reactivate.`,'system');
        }}
        wsend({type:'send',conn_id,raw:`NICK ${args[0]}`}); break;
      case 'AWAY':
        wsend({type:'send',conn_id,raw:`AWAY :${args.join(' ')||'Away'}`});
        sysMsg(conn_id,target,`Away: ${args.join(' ')||'Away'}`,'system'); break;
      case 'BACK': case 'UNAWAY':
        wsend({type:'send',conn_id,raw:'AWAY'});
        sysMsg(conn_id,target,'Back','system'); break;

      // ── Messaging ───────────────────────────────────────────────────
      case 'ME': {
        const t=toMircChars(args.join(' '));
        // L3: /me goes through E2E if session is active for this target
        const meWire = (window.E2E?.ready || window.E2E?.channelKeys?.[target]) ? await e2eEncryptOutgoing(target, `\x01ACTION ${t}\x01`) : null;
        if (meWire) {
          wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${meWire}`});
        } else {
          wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :\x01ACTION ${t}\x01`});
        }
        addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'action',encrypted:!!meWire});
        break;
      }
      case 'SAY': {
        const t=toMircChars(args.join(' '));
        // L3: /say goes through E2E if active
        const sayWire = (window.E2E?.ready || window.E2E?.channelKeys?.[target]) ? await e2eEncryptOutgoing(target, t) : null;
        if (sayWire) {
          wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${sayWire}`});
          addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg',encrypted:true});
        } else {
          wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});
          addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});
        }
        break;
      }
      case 'MSG': case 'PRIVMSG': {
        const to=args[0],t=toMircChars(args.slice(1).join(' '));
        if(!to||!t){sysMsg(conn_id,target,'Usage: /msg <target> <message>','error');break;}
        // Open query window for non-channel targets
        if(!to.startsWith('#')&&!to.startsWith('&')&&!to.startsWith('+')&&!to.startsWith('!')){
          clearQueryClosed(conn_id, to.toLowerCase());
          if(!queryBufs[conn_id])queryBufs[conn_id]=new Map();
          queryBufs[conn_id].set(to.toLowerCase(), to);
          saveQueryBufs();
        }
        // L4: encrypt if E2E session exists for the destination
        const msgWire = (window.E2E?.ready || window.E2E?.channelKeys?.[to]) ? await e2eEncryptOutgoing(to, t) : null;
        wsend({type:'send',conn_id,raw:`PRIVMSG ${to} :${msgWire||t}`});
        addMessage(conn_id,to,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg',encrypted:!!msgWire});
        setActive(conn_id,to);
        break;
      }
      case 'NOTICE': {
        const to=args[0],t=toMircChars(args.slice(1).join(' '));
        if(!to||!t){sysMsg(conn_id,target,'Usage: /notice <target> <message>','error');break;}
        wsend({type:'send',conn_id,raw:`NOTICE ${to} :${t}`}); break;
      }
      case 'CTCP': {
        // /ctcp nick VERSION  or  /ctcp nick PING
        const to=args[0],ctcpcmd=args[1]?.toUpperCase()||'VERSION';
        const ctcpdata=args.slice(2).join(' ');
        wsend({type:'send',conn_id,raw:`PRIVMSG ${to} :\x01${ctcpcmd}${ctcpdata?' '+ctcpdata:''}\x01`});
        sysMsg(conn_id,target,`CTCP ${ctcpcmd} → ${to}`,'system'); break;
      }

      // ── Channel info ────────────────────────────────────────────────
      case 'TOPIC':
        if(!args.length) wsend({type:'send',conn_id,raw:`TOPIC ${target}`}); // fetch topic
        else wsend({type:'send',conn_id,raw:`TOPIC ${target} :${args.join(' ')}`});
        break;
      case 'NAMES':
        wsend({type:'send',conn_id,raw:`NAMES ${args[0]||target}`}); break;
      case 'WHO':
        wsend({type:'send',conn_id,raw:`WHO ${args[0]||target}`}); break;
      case 'WHOIS':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /whois <nick>','error');break;}
        // Track pending whois to auto-open query
        if(!window._pendingWhois)window._pendingWhois={};
        window._pendingWhois[conn_id]=args[0];
        wsend({type:'send',conn_id,raw:`WHOIS ${args[0]}`}); break;
      case 'WHOWAS':
        wsend({type:'send',conn_id,raw:`WHOWAS ${args[0]||''}`}); break;
      case 'BANLIST': case 'BANS':
        wsend({type:'send',conn_id,raw:`MODE ${args[0]||target} +b`}); break;
      case 'UNBANALL': {
        // Fetch the ban list then unban each mask in sequence
        const ubChan = args[0] || target;
        const net    = networks.find(n => n.config.id === conn_id);
        if (!net) break;
        // We collect MODE +b replies (367) until we get 368 (end of ban list)
        // then send a MODE -b for each mask in batches of MODE_BATCH
        sysMsg(conn_id, target, `Fetching ban list for ${ubChan}…`, 'system');
        pendingUnbanAll[conn_id + '/' + ubChan] = true;
        wsend({type:'send', conn_id, raw:`MODE ${ubChan} +b`});
        break;
      }

      case 'UNEXEMPTALL': case 'REMOVEEXEMPT': case 'CLEAREXEMPT': {
        const exChan = args[0] || target;
        sysMsg(conn_id, target, `Fetching exempt list for ${exChan}…`, 'system');
        if(!window._pendingUnexempt) window._pendingUnexempt={};
        if(!window._exemptAccum) window._exemptAccum={};
        const exKey=conn_id+'/'+exChan;
        window._pendingUnexempt[exKey]=true;
        window._exemptAccum[exKey]=[];
        wsend({type:'send', conn_id, raw:`MODE ${exChan} +e`});
        break;
      }

      // ── Mode shortcuts ───────────────────────────────────────────────
      case 'MODE':
        wsend({type:'send',conn_id,raw:`MODE ${args.join(' ')}`}); break;
      case 'OP':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /op <nick> [nick2...]','error');break;}
        batchMode(conn_id,target,'+o',args); break;
      case 'DEOP':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /deop <nick> [nick2...]','error');break;}
        batchMode(conn_id,target,'-o',args); break;
      case 'VOICE': case 'V':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /voice <nick> [nick2...]','error');break;}
        batchMode(conn_id,target,'+v',args); break;
      case 'DEVOICE': case 'DV':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /devoice <nick> [nick2...]','error');break;}
        batchMode(conn_id,target,'-v',args); break;
      case 'HALFOP': case 'HOP':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /halfop <nick> [nick2...]','error');break;}
        batchMode(conn_id,target,'+h',args); break;
      case 'DEHALFOP': case 'DEHOP':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /dehalfop <nick> [nick2...]','error');break;}
        batchMode(conn_id,target,'-h',args); break;
      case 'PROTECT': case 'ADMIN':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /protect <nick>','error');break;}
        batchMode(conn_id,target,'+a',args); break;
      case 'DEPROTECT': case 'DEADMIN':
        batchMode(conn_id,target,'-a',args); break;
      case 'OWNER':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /owner <nick>','error');break;}
        batchMode(conn_id,target,'+q',args); break;
      case 'DEOWNER':
        batchMode(conn_id,target,'-q',args); break;

      // ── Mass operations ──────────────────────────────────────────────
      case 'OPALL': {
        const nicks = getChannelNonOps(conn_id, target);
        if(!nicks.length){sysMsg(conn_id,target,'No non-ops to op','system');break;}
        batchMode(conn_id,target,'+o',nicks);
        sysMsg(conn_id,target,`Opping ${nicks.length} users…`,'system'); break;
      }
      case 'DEOPALL': {
        const nicks = getChannelOps(conn_id, target);
        if(!nicks.length){sysMsg(conn_id,target,'No ops to deop','system');break;}
        batchMode(conn_id,target,'-o',nicks);
        sysMsg(conn_id,target,`Deopping ${nicks.length} ops…`,'system'); break;
      }
      case 'MDOP': case 'MASSDEOP': case 'DROP': {
        const self=getNick(conn_id);
        const net=networks.find(n=>n.config.id===conn_id);
        const ch=net?.channels?.find(c=>c.name===target);
        if(!ch){sysMsg(conn_id,target,'Not in a channel','error');break;}
        let count=0;
        // Remove owners (~) → -q
        const owners=ch.names.filter(n=>n.startsWith('~')).map(n=>stripPfx(n)).filter(n=>n!==self);
        if(owners.length){batchMode(conn_id,target,'-q',owners);count+=owners.length;}
        // Remove admins (&) → -a
        const admins=ch.names.filter(n=>n.startsWith('&')||n.startsWith('~&')).map(n=>stripPfx(n)).filter(n=>n!==self&&!owners.includes(n));
        if(admins.length){batchMode(conn_id,target,'-a',admins);count+=admins.length;}
        // Remove ops (@) → -o
        const ops=ch.names.filter(n=>n.includes('@')).map(n=>stripPfx(n)).filter(n=>n!==self&&!owners.includes(n)&&!admins.includes(n));
        if(ops.length){batchMode(conn_id,target,'-o',ops);count+=ops.length;}
        // Remove halfops (%) → -h
        const hops=ch.names.filter(n=>n.includes('%')).map(n=>stripPfx(n)).filter(n=>n!==self);
        if(hops.length){batchMode(conn_id,target,'-h',hops);count+=hops.length;}
        // Remove voice (+) → -v
        const voiced=ch.names.filter(n=>n.startsWith('+')||n.includes('+')).map(n=>stripPfx(n)).filter(n=>n!==self);
        if(voiced.length){batchMode(conn_id,target,'-v',voiced);count+=voiced.length;}
        sysMsg(conn_id,target,count?`Stripping all status from ${count} users…`:'No users to strip','system');
        break;
      }
      case 'VOICEALL': {
        const nicks = getChannelNonVoiced(conn_id, target);
        if(!nicks.length){sysMsg(conn_id,target,'Everyone is already voiced','system');break;}
        batchMode(conn_id,target,'+v',nicks);
        sysMsg(conn_id,target,`Voicing ${nicks.length} users…`,'system'); break;
      }
      case 'DEVOICEALL': {
        const nicks = getChannelVoiced(conn_id, target);
        if(!nicks.length){sysMsg(conn_id,target,'No voiced users','system');break;}
        batchMode(conn_id,target,'-v',nicks);
        sysMsg(conn_id,target,`Devoicing ${nicks.length} users…`,'system'); break;
      }
      case 'KICKALL': {
        // Kick everyone except yourself
        const self = getNick(conn_id);
        const reason = args.join(' ') || 'Kicked';
        const nicks = getChannelNicks(conn_id, target).filter(n => n !== self);
        if(!nicks.length){sysMsg(conn_id,target,'No one else to kick','system');break;}
        // Stagger kicks to avoid flood protection
        nicks.forEach((n,i)=>setTimeout(()=>wsend({type:'send',conn_id,raw:`KICK ${target} ${n} :${reason}`}),i*200));
        sysMsg(conn_id,target,`Kicking ${nicks.length} users…`,'system'); break;
      }
      case 'MASSVOICE': case 'MVALL': {
        // Voice everyone including ops (all non-voiced)
        const all = getChannelNicks(conn_id, target);
        batchMode(conn_id,target,'+v',all);
        sysMsg(conn_id,target,`Voicing all ${all.length} users…`,'system'); break;
      }

      // ── Kick / Ban ───────────────────────────────────────────────────
      case 'KICK': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /kick <nick> [reason]','error');break;}
        wsend({type:'send',conn_id,raw:`KICK ${target} ${args[0]} :${args.slice(1).join(' ')||'Kicked'}`}); break;
      }
      case 'BAN': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /ban <nick|mask>','error');break;}
        const mask = args[0].includes('!') ? args[0] : `${args[0]}!*@*`;
        wsend({type:'send',conn_id,raw:`MODE ${target} +b ${mask}`}); break;
      }
      case 'UNBAN': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /unban <nick|mask>','error');break;}
        const mask = args[0].includes('!') ? args[0] : `${args[0]}!*@*`;
        wsend({type:'send',conn_id,raw:`MODE ${target} -b ${mask}`}); break;
      }
      case 'KICKBAN': case 'KB': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /kickban <nick> [reason]','error');break;}
        const kbnick=args[0], kbreason=args.slice(1).join(' ')||'Banned';
        const kbmask=`${kbnick}!*@*`;
        wsend({type:'send',conn_id,raw:`MODE ${target} +b ${kbmask}`});
        setTimeout(()=>wsend({type:'send',conn_id,raw:`KICK ${target} ${kbnick} :${kbreason}`}),300);
        break;
      }
      case 'TBAN': case 'TEMPBAN': {
        // Temporary ban — ban, wait N seconds, unban
        if(args.length<2){sysMsg(conn_id,target,'Usage: /tban <nick> <seconds> [reason]','error');break;}
        const tbnick=args[0]; let tbsecs=parseInt(args[1])||60;
        tbsecs=Math.min(tbsecs,86400);
        const tbreason=args.slice(2).join(' ')||'Temporary ban';
        const tbmask=`${tbnick}!*@*`;
        wsend({type:'send',conn_id,raw:`MODE ${target} +b ${tbmask}`});
        setTimeout(()=>wsend({type:'send',conn_id,raw:`KICK ${target} ${tbnick} :${tbreason} (${tbsecs}s ban)`}),300);
        setTimeout(()=>wsend({type:'send',conn_id,raw:`MODE ${target} -b ${tbmask}`}),tbsecs*1000);
        sysMsg(conn_id,target,`Temp-banned ${tbnick} for ${tbsecs}s`,'system'); break;
      }

      // ── Invite ──────────────────────────────────────────────────────
      case 'INVITE': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /invite <nick> [channel]','error');break;}
        wsend({type:'send',conn_id,raw:`INVITE ${args[0]} ${args[1]||target}`}); break;
      }

      // ── Ignore (client-side) ────────────────────────────────────────
      case 'IGNORE': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /ignore <nick>','error');break;}
        addIgnore(args[0].toLowerCase());
        sysMsg(conn_id,target,`Ignoring ${args[0]}`,'system'); break;
      }
      case 'UNIGNORE': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /unignore <nick>','error');break;}
        removeIgnore(args[0].toLowerCase());
        sysMsg(conn_id,target,`Unignored ${args[0]}`,'system'); break;
      }
      case 'IGNORELIST': case 'IGNORES': {
        const list=[...ignoreList];
        sysMsg(conn_id,target,list.length?`Ignored: ${list.join(', ')}`:'Ignore list is empty','system'); break;
      }
      case 'PMALLOW': case 'PMADD': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /pmallow <nick>','error');break;}
        addPmAllow(args[0],conn_id);
        const _pn=loadPmNet();const _scope=(_pn[conn_id]&&_pn[conn_id].override)?'this network':'global';
        sysMsg(conn_id,target,`PMs from ${args[0]} will bypass protection (${_scope})`,'system'); break;
      }
      case 'PMREMOVE': case 'PMDEL': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /pmremove <nick>','error');break;}
        removePmAllow(args[0],conn_id);
        const _pn=loadPmNet();const _scope=(_pn[conn_id]&&_pn[conn_id].override)?'this network':'global';
        sysMsg(conn_id,target,`${args[0]} removed from PM allow list (${_scope})`,'system'); break;
      }
      case 'PMALLOWLIST': case 'PMLIST': {
        const _pn=loadPmNet();
        const _n=_pn[conn_id];
        const list=(_n&&_n.override&&Array.isArray(_n.allowList))?[..._n.allowList].sort():[...pmAllowList].sort();
        const scope=(_n&&_n.override)?'Network':'Global';
        sysMsg(conn_id,target,list.length?`${scope} PM allow list: ${list.join(', ')}`:`${scope} PM allow list is empty`,'system'); break;
      }
      case 'PMPROTECTION': case 'PMSETTINGS': {
        showPmProtectionPanel(); break;
      }

      // ── NickServ / Services shortcuts ────────────────────────────────
      case 'NS': case 'NICKSERV':
        wsend({type:'send',conn_id,raw:`PRIVMSG NickServ :${args.join(' ')}`}); break;
      case 'CS': case 'CHANSERV':
        wsend({type:'send',conn_id,raw:`PRIVMSG ChanServ :${args.join(' ')}`}); break;
      case 'IDENTIFY': case 'ID':
        wsend({type:'send',conn_id,raw:`PRIVMSG NickServ :IDENTIFY ${args.join(' ')}`}); break;
      case 'REGISTER':
        wsend({type:'send',conn_id,raw:`PRIVMSG NickServ :REGISTER ${args.join(' ')}`}); break;
      case 'GHOST':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /ghost <nick> [password]','error');break;}
        wsend({type:'send',conn_id,raw:`PRIVMSG NickServ :GHOST ${args.join(' ')}`}); break;
      case 'REGAIN': case 'RECOVER':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /regain <nick> [password]','error');break;}
        wsend({type:'send',conn_id,raw:`PRIVMSG NickServ :REGAIN ${args.join(' ')}`}); break;

      // ── UnrealIRCd / oper commands ───────────────────────────────────
      case 'SHUN':
        wsend({type:'send',conn_id,raw:`SHUN ${args.join(' ')}`}); break;
      case 'GLINE':
        wsend({type:'send',conn_id,raw:`GLINE ${args.join(' ')}`}); break;
      case 'ZLINE':
        wsend({type:'send',conn_id,raw:`ZLINE ${args.join(' ')}`}); break;
      case 'KLINE':
        wsend({type:'send',conn_id,raw:`KLINE ${args.join(' ')}`}); break;
      case 'KILL':
        if(!args[0]){sysMsg(conn_id,target,'Usage: /kill <nick> <reason>','error');break;}
        wsend({type:'send',conn_id,raw:`KILL ${args[0]} :${args.slice(1).join(' ')||'Killed'}`}); break;
      case 'OPER':
        wsend({type:'send',conn_id,raw:`OPER ${args.join(' ')}`}); break;
      case 'REHASH':
        wsend({type:'send',conn_id,raw:'REHASH'}); break;
      case 'RESTART':
        wsend({type:'send',conn_id,raw:'RESTART'}); break;
      case 'DIE':
        wsend({type:'send',conn_id,raw:'DIE'}); break;
      case 'SQUIT':
        wsend({type:'send',conn_id,raw:`SQUIT ${args.join(' ')}`}); break;
      case 'CONNECT':
        wsend({type:'connect',id:conn_id}); break;
      case 'DISCONNECT':
        wsend({type:'disconnect',id:conn_id}); break;

      // ── Utility ─────────────────────────────────────────────────────
      case 'QUOTE': case 'RAW':
        wsend({type:'send',conn_id,raw:args.join(' ')}); break;
      case 'CLOSE': case 'WC': {
        // Close a PM window or part a channel
        const closeTarget=args[0]||target;
        if(closeTarget.startsWith('#')||closeTarget.startsWith('&')||closeTarget.startsWith('+')||closeTarget.startsWith('!')){
          wsend({type:'part_channel',conn_id,channel:closeTarget});
        } else {
          // Close PM but keep buffer for history (closeQuery records the closed marker + syncs)
          closeQuery(conn_id, closeTarget.toLowerCase());
        }
        break;
      }
      case 'CLEAR':
        // Permanently deletes the on-disk log for this target so it can't
        // resurrect on the next sync. Server replies with target_cleared,
        // which wipes the local buffer + msg_id sync state.
        {wsend({type:'clear_target_logs',conn_id,target}); break;}
      case 'CLEARALL':
        {buffers={}; _historyView=null; renderChat(); break;}
      case 'UPLOAD':
      case 'UPLOADS':
        // Reopen the Uploads channel even after it's been hidden from the
        // sidebar. Convenient when you want to check status without
        // starting a new upload first.
        { setUploadsHidden(false); setActive(UPLOAD_CONN, UPLOAD_TARGET); break; }
      case 'PING': {
        const pnick=args[0]||target;
        const pts=Date.now();
        wsend({type:'send',conn_id,raw:`PRIVMSG ${pnick} :\x01PING ${pts}\x01`});
        sysMsg(conn_id,target,`CTCP PING → ${pnick}`,'system'); break;
      }
      case 'VERSION': {
        const vt=args[0]||target;
        wsend({type:'send',conn_id,raw:`PRIVMSG ${vt} :\x01VERSION\x01`});
        sysMsg(conn_id,target,`CTCP VERSION → ${vt}`,'system'); break;
      }
      case 'TIME': {
        const tt=args[0]||target;
        wsend({type:'send',conn_id,raw:`PRIVMSG ${tt} :\x01TIME\x01`});
        sysMsg(conn_id,target,`CTCP TIME → ${tt}`,'system'); break;
      }
      case 'SLAP': {
        const t=`slaps ${args[0]||'themselves'} around a bit with a large trout`;
        const slapWire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,`\x01ACTION ${t}\x01`):null;
        if(slapWire){wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${slapWire}`});}
        else{wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :\x01ACTION ${t}\x01`});}
        addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'action'}); break;
      }
      case 'MONITOR': case 'WATCH': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /monitor <nick>','error');break;}
        monitorAdd(args[0]);
        sysMsg(conn_id,target,`Now monitoring ${args[0]}`,'system'); break;
      }
      case 'UNMONITOR': case 'UNWATCH': {
        if(!args[0]){sysMsg(conn_id,target,'Usage: /unmonitor <nick>','error');break;}
        monitorRemove(args[0]);
        sysMsg(conn_id,target,`Stopped monitoring ${args[0]}`,'system'); break;
      }
      case 'HELP':
        showHelp(conn_id, target, args[0]); break;
      case 'SHRUG': { const t='¯\\_(ツ)_/¯'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'ADVERTISE': case 'AD': { const t='\x02✦ CryptIRC v0.3.0 ✦\x02 End-to-end encrypted IRC client — \x02AES-256-GCM\x02 encrypted logs • \x02Signal Protocol\x02 E2E DMs (X3DH + Double Ratchet) • Channel encryption • Zero-knowledge vault (Argon2id) • 121 themes • 135 fonts • 100+ commands • https://github.com/gh0st68/CryptIRC';wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'GIPHY': case 'GIF': {
        const sub=(args[0]||'').toLowerCase();
        // ── Key management: /giphy key [value|clear] ────────────────────
        if(sub==='key'){
          const v=args[1];
          if(!v){
            const cur=_giphyKey();
            if(cur) sysMsg(conn_id,target,`Giphy key set: ${_giphyMaskKey(cur)} — rating: ${_giphyRating()}. Use /giphy key clear to remove, /giphy key <newkey> to replace.`,'system');
            else sysMsg(conn_id,target,'No Giphy key set. Get one free at https://developers.giphy.com/ → Create App → API. Then: /giphy key YOUR_KEY_HERE','system');
            break;
          }
          if(v.toLowerCase()==='clear'){
            try{localStorage.removeItem('cryptirc_giphy_key');}catch(e){}
            flushPrefsToServer(); // push the clear to the server so other devices un-set too
            sysMsg(conn_id,target,'Giphy key cleared (synced to your account).','system');break;
          }
          try{localStorage.setItem('cryptirc_giphy_key',v);}catch(e){sysMsg(conn_id,target,'Failed to save key (localStorage unavailable).','error');break;}
          flushPrefsToServer(); // push to server so other devices pick it up on next unlock
          sysMsg(conn_id,target,`Giphy key saved: ${_giphyMaskKey(v)} (synced to your account — other devices will pick it up on unlock). Try /giphy dog — or type /giphy dog (with a space) to see the live picker.`,'system');
          break;
        }
        // ── Rating filter: /giphy rating <g|pg|pg-13|r> ─────────────────
        if(sub==='rating'){
          const r=(args[1]||'').toLowerCase();
          if(!['g','pg','pg-13','r'].includes(r)){
            sysMsg(conn_id,target,`Usage: /giphy rating <g|pg|pg-13|r>. Current: ${_giphyRating()}`,'error');break;
          }
          try{localStorage.setItem('cryptirc_giphy_rating',r);}catch(e){}
          flushPrefsToServer();
          sysMsg(conn_id,target,`Giphy rating filter set to ${r} (synced).`,'system');break;
        }
        // ── Bare /giphy (no args): show status + help ───────────────────
        if(!sub){
          const cur=_giphyKey();
          const status=cur?`Key: ${_giphyMaskKey(cur)}, rating: ${_giphyRating()}`:'No key set — run /giphy key YOUR_KEY (get one at developers.giphy.com)';
          sysMsg(conn_id,target,`Giphy — ${status}. Usage:\n• /giphy <query>  send top match\n• /giphy <query>  (with space, then keep typing) live picker\n• /giphy key <k>  save your API key\n• /giphy key clear  remove\n• /giphy rating <g|pg|pg-13|r>  content filter`,'system');
          break;
        }
        // ── Default: search and send top match ───────────────────────────
        const q=args.join(' ').trim();
        if(!_giphyKey()){
          sysMsg(conn_id,target,'No Giphy key set. Run /giphy key YOUR_KEY_HERE first. Get a free key at developers.giphy.com (Create App → API).','error');break;
        }
        const url=await giphyFetchTop(q);
        if(!url){ sysMsg(conn_id,target,'Giphy search failed — invalid key, no result, or rate-limited.','error'); break; }
        const gifWire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,url):null;
        if(gifWire)wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${gifWire}`});
        else wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${url}`});
        addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:url,kind:'privmsg',encrypted:!!gifWire});
        break;
      }
      case 'TABLEFLIP': { const t='(╯°□°)╯︵ ┻━┻'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'UNFLIP': case 'UNFLIPTABLE': { const t='┬─┬ノ( º _ ºノ)'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'LENNY': { const t='( ͡° ͜ʖ ͡°)'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'DISAPPROVE': case 'LOOK': { const t='ಠ_ಠ'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'RAGE': { const t='(ノಠ益ಠ)ノ彡┻━┻'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'BEAR': { const t='ʕ•ᴥ•ʔ'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'SPARKLE': case 'SPARKLES': { const t='✧･ﾟ: *✧･ﾟ:* '+(args.length?args.join(' '):'')+'*:･ﾟ✧*:･ﾟ✧';wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'FINGER': case 'MIDDLEFINGER': { const t='╭∩╮(︶︿︶)╭∩╮'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'DANCE': { const t='♪┏(・o・)┛♪┗(・o・)┓♪'+(args.length?' '+args.join(' '):'');wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'RIP': { const t='⚰️ R.I.P. '+(args.length?args.join(' '):'')+'⚰️';wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'HUG': { const n=args[0]||'everyone';const t=`(づ｡◕‿‿◕｡)づ ${n}`;wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${t}`});addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:t,kind:'privmsg'});break; }
      case 'PRISM': case 'RAINBOW': {
        const text=args.join(' ');
        if(!text){sysMsg(conn_id,target,'Usage: /prism <message>','error');break;}
        const rainbowColors=[4,7,8,3,12,2,6]; // red,orange,yellow,green,cyan,blue,purple
        let colored='';
        let ci=0;
        for(const ch of text){
          if(ch===' '){colored+=ch;}
          else{colored+='\x03'+String(rainbowColors[ci%rainbowColors.length]).padStart(2,'0')+ch;ci++;}
        }
        colored+='\x0F'; // reset at end
        const wire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,colored):null;
        wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${wire||colored}`});
        addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:colored,kind:'privmsg',encrypted:!!wire});
        break;
      }
      case 'ENCRYPT': case 'E2E':
        await handleEncryptCommand(args, conn_id, target); break;
      case 'ASCII': case 'FIGLET': {
        const text=args.join(' ');if(!text){sysMsg(conn_id,target,'Usage: /ascii <text>','error');break;}
        const art=makeAsciiArt(text);
        for(const line of art.split('\n')){
          if(!line.trim())continue;
          const wire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,line):null;
          wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${wire||line}`});
          addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:line,kind:'privmsg',encrypted:!!wire});
        }
        break;
      }
      case 'UD': case 'URBAN': {
        const term=args.join(' ');if(!term){sysMsg(conn_id,target,'Usage: /ud <word>','error');break;}
        sysMsg(conn_id,target,`Looking up "${term}" on Urban Dictionary...`,'system');
        try{
          const _ac=new AbortController();const _to=setTimeout(()=>_ac.abort(),10000);
          const r=await fetch(`https://api.urbandictionary.com/v0/define?term=${encodeURIComponent(term)}`,{signal:_ac.signal});
          clearTimeout(_to);
          const d=await r.json();
          if(d.list&&d.list.length>0){
            const def=d.list[0];const clean=def.definition.replace(/\[|\]/g,'').slice(0,300);
            const msg=`📖 ${term}: ${clean}${def.definition.length>300?'...':''} (👍${def.thumbs_up} 👎${def.thumbs_down})`;
            const wire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,msg):null;
            wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${wire||msg}`});
            addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:msg,kind:'privmsg',encrypted:!!wire});
          } else sysMsg(conn_id,target,`No definition found for "${term}"`,'error');
        }catch(e){sysMsg(conn_id,target,`UD lookup failed — https://www.urbandictionary.com/define.php?term=${encodeURIComponent(term)}`,'error');}
        break;
      }
      case 'SHORTEN': {
        const url=args[0];if(!url||(!url.startsWith('http://')&&!url.startsWith('https://'))){sysMsg(conn_id,target,'Usage: /shorten <url>','error');break;}
        try{
          const token=sessionToken;
          const r=await fetch(`${location.pathname}s`,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${token}`},body:JSON.stringify({url})});
          const d=await r.json();
          if(d.url){document.getElementById('msg-input').value=d.url;sysMsg(conn_id,target,`Short URL: ${d.url}`,'system');}
          else sysMsg(conn_id,target,'Failed to create short URL','error');
        }catch(e){sysMsg(conn_id,target,'URL shortener error','error');}
        break;
      }
      case 'STATS': {
        showChannelStats(conn_id,target);
        break;
      }
      case 'NOTE': {
        const nick=args[0];const noteText=args.slice(1).join(' ');
        if(!nick){sysMsg(conn_id,target,'Usage: /note <nick> [text] — set or view notes','error');break;}
        const notes=loadUserNotes();
        if(!noteText){
          const existing=notes[nick.toLowerCase()];
          sysMsg(conn_id,target,existing?`Note on ${nick}: ${existing}`:`No note on ${nick}`,'system');
        } else {
          notes[nick.toLowerCase()]=noteText;saveUserNotes(notes);
          sysMsg(conn_id,target,`Note saved for ${nick}`,'system');
        }
        break;
      }
      case 'DND': {
        const sub=args[0]?.toLowerCase();
        if(sub==='on'){localStorage.setItem('cryptirc_dnd','1');savePrefsToServer();sysMsg(conn_id,target,'🔕 Do Not Disturb ON — notifications suppressed','system');}
        else if(sub==='off'){const hadSched=!!(localStorage.getItem('cryptirc_dnd_start')||localStorage.getItem('cryptirc_dnd_end'));localStorage.removeItem('cryptirc_dnd');localStorage.removeItem('cryptirc_dnd_start');localStorage.removeItem('cryptirc_dnd_end');savePrefsToServer();sysMsg(conn_id,target,`🔔 Do Not Disturb OFF${hadSched?' — schedule cleared':''}`,'system');}
        else if(sub==='schedule'){
          const start=args[1],end=args[2];
          if(!start||!end){sysMsg(conn_id,target,'Usage: /dnd schedule <HH:MM> <HH:MM>  e.g. /dnd schedule 23:00 07:00','error');break;}
          localStorage.setItem('cryptirc_dnd_start',start);localStorage.setItem('cryptirc_dnd_end',end);savePrefsToServer();
          sysMsg(conn_id,target,`🔕 DND scheduled: ${start} — ${end}`,'system');
        }
        else if(sub==='unschedule'){localStorage.removeItem('cryptirc_dnd_start');localStorage.removeItem('cryptirc_dnd_end');savePrefsToServer();sysMsg(conn_id,target,'🔔 DND schedule cleared','system');}
        else{const on=localStorage.getItem('cryptirc_dnd')==='1';const hasSched=!!(localStorage.getItem('cryptirc_dnd_start')&&localStorage.getItem('cryptirc_dnd_end'));sysMsg(conn_id,target,`DND is ${on?'ON':'OFF'}${hasSched?' (schedule set)':''}. Usage: /dnd on|off|schedule <start> <end>|unschedule`,'system');}
        break;
      }
      case 'SPLIT': case 'SPLITVIEW': {
        toggleSplitView();
        break;
      }
      case 'SEEN': {
        const nick=args[0];if(!nick){sysMsg(conn_id,target,'Usage: /seen <nick>','error');break;}
        const s=getSeen(nick);
        if(s){
          const ago=Math.round(Date.now()/1000-s.ts);
          const agoStr=ago<60?ago+'s ago':ago<3600?Math.round(ago/60)+'m ago':ago<86400?Math.round(ago/3600)+'h ago':Math.round(ago/86400)+'d ago';
          sysMsg(conn_id,target,`${s.nick} was last seen ${agoStr} in ${s.channel}`,'system');
        } else {
          sysMsg(conn_id,target,`${nick} has not been seen this session.`,'system');
        }
        break;
      }
      case 'RATELIMIT': {
        const ms=parseInt(args[0]);
        if(!args[0]){sysMsg(conn_id,target,`Rate limit: ${getRateLimit()}ms between messages. Usage: /ratelimit <ms> (default 500)`,'system');break;}
        if(isNaN(ms)||ms<100||ms>10000){sysMsg(conn_id,target,'Rate limit must be 100-10000ms','error');break;}
        setRateLimit(ms);sysMsg(conn_id,target,`Rate limit set to ${ms}ms between messages`,'system');
        break;
      }
      case 'EXPIRE': case 'MSGEXPIRY': {
        const hours=parseInt(args[0]);
        if(!args[0]){sysMsg(conn_id,target,`Message expiry: ${getMessageExpiry()||'off'} hours. Usage: /expire <hours> (0 = off)`,'system');break;}
        if(isNaN(hours)||hours<0){sysMsg(conn_id,target,'Usage: /expire <hours> (0 = off)','error');break;}
        setMessageExpiry(hours);sysMsg(conn_id,target,hours?`Messages will auto-expire after ${hours} hour${hours>1?'s':''}`:'Message expiry disabled','system');
        break;
      }
      case 'AUTOLOCK': {
        const mins=parseInt(args[0]);
        if(!args[0]){sysMsg(conn_id,target,`Vault auto-lock: ${getVaultAutoLock()||'off'} minutes. Usage: /autolock <minutes> (0 = off)`,'system');break;}
        if(isNaN(mins)||mins<0){sysMsg(conn_id,target,'Usage: /autolock <minutes> (0 = off)','error');break;}
        setVaultAutoLock(mins);sysMsg(conn_id,target,mins?`Vault will auto-lock after ${mins} minute${mins>1?'s':''} of inactivity`:'Vault auto-lock disabled','system');
        break;
      }
      case 'KEEPNICK': {
        const desired=args[0]||getNick(conn_id);
        if(!desired){sysMsg(conn_id,target,'Usage: /keepnick [nick] — keep a nick (defaults to current)','error');break;}
        keepnickSet(conn_id,desired);
        const net=networks.find(n=>n.config.id===conn_id);
        sysMsg(conn_id,target,`KeepNick: keeping "${desired}" on ${net?.config?.label||'this network'}. Will reclaim if lost.`,'system');
        break;
      }
      case 'UNKEEPNICK': {
        const kn=loadKeepNicks();
        if(!kn[conn_id]){sysMsg(conn_id,target,'No keepnick set for this network.','error');break;}
        const was=kn[conn_id].nick;
        keepnickRemove(conn_id);
        sysMsg(conn_id,target,`KeepNick: stopped keeping "${was}".`,'system');
        break;
      }
      case 'LISTNICK': case 'LISTNICKS': case 'KEEPNICKS': {
        const kn=loadKeepNicks();
        const entries=Object.entries(kn);
        if(!entries.length){sysMsg(conn_id,target,'No keepnicks set.','system');break;}
        sysMsg(conn_id,target,'── KeepNick List ──','system');
        for(const[cid,v] of entries){
          const net=networks.find(n=>n.config.id===cid);
          const label=net?.config?.label||cid.slice(0,8);
          const cur=getNick(cid)||'?';
          const hasIt=cur.toLowerCase()===v.nick.toLowerCase();
          const status=hasIt?'✓ have it':v.active?'polling...':'inactive';
          sysMsg(conn_id,target,`  ${label}: ${v.nick} [${status}]`,'system');
        }
        break;
      }
      case 'CHANKEY': case 'KEY': {
        const ch=args[0],key=args[1];
        if(!ch){sysMsg(conn_id,target,'Usage: /key #channel [key] — save or clear a channel key','error');break;}
        const keys=loadChanKeys();
        if(key){keys[bk(conn_id,ch)]=key;saveChanKeys(keys);sysMsg(conn_id,target,`Key saved for ${ch}`,'system');}
        else{delete keys[bk(conn_id,ch)];saveChanKeys(keys);sysMsg(conn_id,target,`Key cleared for ${ch}`,'system');}
        break;
      }
      default:
        wsend({type:'send',conn_id,raw:raw.slice(1)});
    }
  } else {
    // Translate visible caret-notation formatting tokens (^B/^I/^U/^O/^R/^Cnn[,nn]) to real mIRC control chars
    const raw2=toMircChars(raw);
    // Attempt E2E encryption for outgoing plaintext
    // Handle reply — send quote line first, then the actual message
    const replyPrefix=getReplyPrefix();
    if(replyPrefix){
      const quoteLine=replyPrefix.trim();
      const quoteWire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,quoteLine):null;
      wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${quoteWire||quoteLine}`});
      addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:quoteLine,kind:'privmsg',encrypted:!!quoteWire});
    }
    const e2eWire = (window.E2E?.ready || window.E2E?.channelKeys?.[target])
      ? await e2eEncryptOutgoing(target, raw2)
      : null;
    if (e2eWire) {
      rateLimitedSend({type:'send',conn_id,raw:`PRIVMSG ${target} :${e2eWire}`});
      addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:raw2,kind:'privmsg',encrypted:true});
    } else {
      rateLimitedSend({type:'send',conn_id,raw:`PRIVMSG ${target} :${raw2}`});
      addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:raw2,kind:'privmsg'});
    }
  }
}
function insertAtCursor(inp,text){
  const pos=inp.selectionStart;
  inp.value=inp.value.slice(0,pos)+text+inp.value.slice(inp.selectionEnd);
  inp.selectionStart=inp.selectionEnd=pos+text.length;
  inp.focus();
}
function showMircColorPicker(inp){
  // Remove existing picker
  document.getElementById('mirc-color-picker')?.remove();
  const colors=['#fff','#000','#00007f','#009300','#ff0000','#7f0000','#9c009c','#fc7f00','#ffff00','#00fc00','#009393','#00ffff','#0000fc','#ff00ff','#7f7f7f','#d2d2d2'];
  const picker=document.createElement('div');
  picker.id='mirc-color-picker';
  picker.style.cssText='position:absolute;bottom:100%;left:0;right:0;background:var(--bg1);border:1px solid var(--border);border-radius:6px;padding:8px;z-index:102;';
  picker.innerHTML=`
    <div style="font-size:10px;color:var(--text3);margin-bottom:6px;display:flex;justify-content:space-between;align-items:center">
      <span>mIRC Colors — Ctrl+K</span>
      <span onclick="document.getElementById('mirc-color-picker').remove()" style="cursor:pointer;padding:2px 6px">✕</span>
    </div>
    <div style="display:flex;gap:2px;flex-wrap:wrap;margin-bottom:6px">
      <span style="font-size:9px;color:var(--text3);width:100%">Foreground:</span>
      ${colors.map((c,i)=>`<div onclick="pickMircColor(${i},'fg')" style="width:22px;height:22px;background:${c};border-radius:3px;cursor:pointer;border:1px solid var(--border)" title="${i}"></div>`).join('')}
    </div>
    <div style="display:flex;gap:2px;flex-wrap:wrap">
      <span style="font-size:9px;color:var(--text3);width:100%">Background (optional — click after a foreground):</span>
      ${colors.map((c,i)=>`<div onclick="pickMircColor(${i},'bg')" style="width:22px;height:22px;background:${c};border-radius:3px;cursor:pointer;border:1px solid var(--border)" title="${i}"></div>`).join('')}
    </div>
    <div style="display:flex;gap:4px;margin-top:8px;flex-wrap:wrap">
      <button onclick="insertAtCursor(document.getElementById('msg-input'),'^B');document.getElementById('mirc-color-picker').remove()" style="padding:3px 8px;background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px">B</button>
      <button onclick="insertAtCursor(document.getElementById('msg-input'),'^I');document.getElementById('mirc-color-picker').remove()" style="padding:3px 8px;background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;font-style:italic;font-size:12px">I</button>
      <button onclick="insertAtCursor(document.getElementById('msg-input'),'^U');document.getElementById('mirc-color-picker').remove()" style="padding:3px 8px;background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;text-decoration:underline;font-size:12px">U</button>
      <button onclick="insertAtCursor(document.getElementById('msg-input'),'^O');document.getElementById('mirc-color-picker').remove()" style="padding:3px 8px;background:var(--bg3);border:1px solid var(--border);color:var(--text3);border-radius:4px;cursor:pointer;font-size:10px">Reset</button>
    </div>`;
  inp.parentNode.appendChild(picker);
  // Close on outside click
  setTimeout(()=>document.addEventListener('click',function closer(e){
    if(!e.target.closest('#mirc-color-picker')){document.getElementById('mirc-color-picker')?.remove();document.removeEventListener('click',closer);}
  }),100);
}
function pickMircColor(num,type){
  const inp=document.getElementById('msg-input');
  // Foreground inserts a full ^Cnn code. Background inserts ,nn — it's expected
  // to be appended directly after a ^Cnn you just placed. Picker stays open either
  // way; user closes via the ✕ in the picker header or by clicking outside.
  if(type==='fg'){
    insertAtCursor(inp,'^C'+String(num).padStart(2,'0'));
  } else {
    insertAtCursor(inp,','+String(num).padStart(2,'0'));
  }
}
// Convert visible caret-notation tokens to real mIRC control chars
// ^B bold, ^I italic, ^U underline, ^O reset, ^R reverse, ^C<fg>[,<bg>] color
function toMircChars(s){
  if(!s||typeof s!=='string')return s;
  s=s.replace(/\^C(\d{1,2})(?:,(\d{1,2}))?/g,(_,fg,bg)=>'\x03'+fg+(bg?','+bg:''));
  s=s.replace(/\^B/g,'\x02');
  s=s.replace(/\^I/g,'\x1D');
  s=s.replace(/\^U/g,'\x1F');
  s=s.replace(/\^O/g,'\x0F');
  s=s.replace(/\^R/g,'\x16');
  return s;
}

// Track last-spoke timestamps per channel for smart tab completion
const _lastSpoke={};
function trackLastSpoke(conn_id,target,nick,ts){
  if(!nick||nick==='*')return;
  const k=bk(conn_id,target);
  if(!_lastSpoke[k])_lastSpoke[k]={};
  _lastSpoke[k][nick.toLowerCase()]=ts||Date.now()/1000;
  const nk=Object.keys(_lastSpoke[k]);if(nk.length>500){nk.sort((a,b)=>_lastSpoke[k][a]-_lastSpoke[k][b]);for(let i=0;i<100;i++)delete _lastSpoke[k][nk[i]];}
}
let _tabCycleState=null; // {partial, matches, index, stamp}
function tabComplete(inp){
  if(!active)return;
  const net=networks.find(n=>n.config.id===active.conn_id);
  const ch=net?.channels.find(c=>c.name===active.target);
  if(!ch)return;
  const val=inp.value,words=val.split(' ');
  const partial=words[words.length-1].toLowerCase();
  if(!partial)return;
  // Check if we're cycling through previous tab results
  const now=Date.now();
  if(_tabCycleState&&_tabCycleState.partial===partial&&now-_tabCycleState.stamp<3000){
    // Cycle to next match
    _tabCycleState.index=(_tabCycleState.index+1)%_tabCycleState.matches.length;
    _tabCycleState.stamp=now;
    words[words.length-1]=_tabCycleState.matches[_tabCycleState.index]+(words.length===1?': ':' ');
    inp.value=words.join(' ');
    return;
  }
  // Build match list sorted by most recent speaker
  const k=bk(active.conn_id,active.target);
  const spokeMap=_lastSpoke[k]||{};
  const nicks=(ch.names||[]).map(n=>stripPfx(n)).filter(n=>n.toLowerCase().startsWith(partial));
  if(!nicks.length)return;
  // Sort: most recent speaker first, then alphabetical
  nicks.sort((a,b)=>{
    const ta=spokeMap[a.toLowerCase()]||0, tb=spokeMap[b.toLowerCase()]||0;
    if(tb!==ta) return tb-ta;
    return a.toLowerCase().localeCompare(b.toLowerCase());
  });
  _tabCycleState={partial,matches:nicks,index:0,stamp:now};
  words[words.length-1]=nicks[0]+(words.length===1?': ':' ');
  inp.value=words.join(' ');
}
function insertNick(nick){const inp=document.getElementById('msg-input');if(!inp.disabled){inp.value+=nick+': ';inp.focus();}}

// ─── Upload ───────────────────────────────────────────────────────────────────
function triggerUpload(){if(!active){showToast('Select a channel first');return;}document.getElementById('file-input').click();}

// ─── Encrypted Notepad ───────────────────────────────────────────────────────
let _notepadSaveTimer=null;
function showNotepad(){
  wsend({type:'load_notepad'});
  const ov=document.createElement('div');ov.id='notepad-overlay';
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:flex;align-items:center;justify-content:center;padding:16px;';
  const box=document.createElement('div');
  box.style.cssText='background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:min(600px,94vw);max-height:min(85vh,85dvh);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6);';
  box.innerHTML=`
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <span style="font-weight:700;font-size:14px;color:var(--text)">📝 Encrypted Notepad</span>
      <div style="display:flex;align-items:center;gap:8px">
        <span id="notepad-status" style="font-size:10px;color:var(--text3)"></span>
        <span onclick="closeNotepad()" style="cursor:pointer;color:var(--text3);font-size:18px">✕</span>
      </div>
    </div>
    <textarea id="notepad-area" placeholder="Your private encrypted notes..." style="flex:1;min-height:300px;background:var(--bg2);color:var(--text);font-family:var(--mono);font-size:14px;padding:16px;border:none;outline:none;resize:none;-webkit-overflow-scrolling:touch"></textarea>`;
  ov.appendChild(box);
  ov.onclick=e=>{if(e.target===ov)closeNotepad();};
  document.body.appendChild(ov);
  const ta=document.getElementById('notepad-area');
  ta.addEventListener('input',()=>{
    clearTimeout(_notepadSaveTimer);
    document.getElementById('notepad-status').textContent='Saving...';
    _notepadSaveTimer=setTimeout(()=>{
      wsend({type:'save_notepad',content:ta.value});
      document.getElementById('notepad-status').textContent='Saved ✓';
      setTimeout(()=>{const s=document.getElementById('notepad-status');if(s)s.textContent='';},2000);
    },1000);
  });
}
function closeNotepad(){const ov=document.getElementById('notepad-overlay');if(ov){
  // Save before closing
  const ta=document.getElementById('notepad-area');
  if(ta&&ta.value)wsend({type:'save_notepad',content:ta.value});
  ov.remove();
}}
function showPasteModal(){
  if(!active){showToast('Select a channel first');return;}
  const ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:flex;align-items:center;justify-content:center;padding:16px;';
  const box=document.createElement('div');
  box.style.cssText='background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:min(500px,94vw);max-height:min(85vh,85dvh);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6);';
  box.innerHTML=`
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <span style="font-weight:700;font-size:14px;color:var(--text)">📋 New Paste</span>
      <span onclick="this.closest('[style*=fixed]').remove()" style="cursor:pointer;color:var(--text3);font-size:18px">✕</span>
    </div>
    <div style="padding:16px 20px;overflow-y:auto;flex:1;display:flex;flex-direction:column;gap:10px">
      <textarea id="paste-content" placeholder="Paste your text here..." style="width:100%;min-height:200px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:10px;resize:vertical;outline:none;box-sizing:border-box"></textarea>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <select id="paste-lang" style="flex:1;padding:6px;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:13px">
          <option value="text">Plain Text</option>
          <option value="javascript">JavaScript</option>
          <option value="python">Python</option>
          <option value="rust">Rust</option>
          <option value="html">HTML</option>
          <option value="css">CSS</option>
          <option value="bash">Bash</option>
          <option value="json">JSON</option>
          <option value="sql">SQL</option>
          <option value="c">C/C++</option>
          <option value="go">Go</option>
          <option value="php">PHP</option>
          <option value="ruby">Ruby</option>
          <option value="yaml">YAML</option>
          <option value="xml">XML</option>
          <option value="markdown">Markdown</option>
        </select>
        <select id="paste-expire" style="flex:1;padding:6px;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:13px">
          <option value="0">No Expiration</option>
          <option value="600">10 Minutes</option>
          <option value="3600">1 Hour</option>
          <option value="86400">1 Day</option>
          <option value="604800">1 Week</option>
          <option value="2592000">30 Days</option>
        </select>
      </div>
      <input id="paste-password" type="password" placeholder="Password (optional)" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:14px;outline:none">
      <button onclick="submitPaste(this)" style="padding:10px;background:var(--accent,#00d4aa);color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:700;font-size:14px">Create Paste</button>
    </div>`;
  ov.appendChild(box);
  document.body.appendChild(ov);
  ov.onclick=e=>{if(e.target===ov)ov.remove();};
  document.getElementById('paste-content')?.focus();
}
async function submitPaste(btn){
  const content=document.getElementById('paste-content')?.value;
  if(!content?.trim()){showToast('Paste cannot be empty');return;}
  const lang=document.getElementById('paste-lang')?.value||'text';
  const expire=parseInt(document.getElementById('paste-expire')?.value||'0');
  const pw=document.getElementById('paste-password')?.value||'';
  btn.disabled=true;btn.textContent='Creating...';
  try{
    const r=await fetch('/cryptirc/paste',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+sessionToken},body:JSON.stringify({content,language:lang,expires_in:expire||null,password:pw||null})});
    const d=await r.json();
    if(!r.ok){showToast(d.error||'Failed');return;}
    const inp=document.getElementById('msg-input');
    if(inp){inp.value=inp.value?(inp.value+' '+d.url):d.url;inp.focus();}
    btn.closest('[style*=fixed]').remove();
  }catch(e){showToast('Error: '+e.message);}finally{btn.disabled=false;btn.textContent='Create Paste';}
}
function handleFileSelect(files){if(!active)return;Array.from(files).forEach(uploadFile);}

// ─── Chunked / resumable upload system ───────────────────────────────────────
//
// State model:
//   _uploads[id]      — server-authoritative record (mirrored from upload_*
//                       WS events). Drives the Uploads pseudo-channel UI.
//   _uploadJobs[id]   — local-only handle for an upload originating on THIS
//                       device. Holds the cancel flag and chunk-loop state.
//                       Records present in _uploads but not in _uploadJobs
//                       are uploads from another device — we can observe
//                       them but not feed them bytes.
//   IndexedDB store   — the File blob for each in-flight upload originating
//                       here, so we can auto-resume after a tab close.
const _uploads={};
const _uploadJobs={};
let _lastIrcActive=null;
const UPLOAD_CHUNK_BYTES = 1024 * 1024;        // 1 MB
const UPLOAD_RETRY_MS    = 2500;
const UPLOAD_TARGET      = '__uploads';
const UPLOAD_CONN        = '__sys';
const UPLOAD_KEY         = UPLOAD_CONN + '/' + UPLOAD_TARGET;
function isUploadsActive(){return !!active && active.conn_id===UPLOAD_CONN && active.target===UPLOAD_TARGET;}
function isUploadsConn(c){return c===UPLOAD_CONN;}
let _uploadsHidden = (()=>{ try{ return localStorage.getItem('cryptirc_uploads_hidden')==='1'; }catch(e){ return false; } })();
function setUploadsHidden(v){
  v=!!v;
  if(v===_uploadsHidden) return;        // idempotent — avoid spurious renders
  _uploadsHidden=v;
  try{localStorage.setItem('cryptirc_uploads_hidden', v?'1':'0');}catch(e){}
  renderSidebar();
}
function uploadsAnyActive(){ for(const id in _uploads){ if(_uploads[id].status==='uploading') return true; } return false; }
function uploadsAnyExist(){ for(const _ in _uploads) return true; return false; }

// ─── IndexedDB blob cache ────────────────────────────────────────────────────
const _idbName='cryptirc-uploads',_idbStore='files';
let _idbReady=null;
function _idbOpen(){
  if(_idbReady) return _idbReady;
  _idbReady = new Promise((resolve,reject)=>{
    if(!self.indexedDB){ reject(new Error('IndexedDB unavailable')); return; }
    const req=self.indexedDB.open(_idbName,1);
    req.onupgradeneeded=()=>{ const db=req.result; if(!db.objectStoreNames.contains(_idbStore)) db.createObjectStore(_idbStore,{keyPath:'id'}); };
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
  return _idbReady;
}
async function idbPutFile(id,file){
  try{
    const db=await _idbOpen();
    return new Promise((resolve,reject)=>{
      const tx=db.transaction(_idbStore,'readwrite');
      tx.objectStore(_idbStore).put({id, file, name:file.name, type:file.type, size:file.size, ts:Date.now()});
      tx.oncomplete=()=>resolve();
      tx.onerror=()=>reject(tx.error);
    });
  }catch(e){ console.warn('idbPutFile failed',e); }
}
async function idbGetFile(id){
  try{
    const db=await _idbOpen();
    return new Promise((resolve)=>{
      const tx=db.transaction(_idbStore,'readonly');
      const req=tx.objectStore(_idbStore).get(id);
      req.onsuccess=()=>resolve(req.result?.file||null);
      req.onerror=()=>resolve(null);
    });
  }catch(e){ return null; }
}
async function idbDeleteFile(id){
  try{
    const db=await _idbOpen();
    return new Promise((resolve)=>{
      const tx=db.transaction(_idbStore,'readwrite');
      tx.objectStore(_idbStore).delete(id);
      tx.oncomplete=()=>resolve();
      tx.onerror=()=>resolve();
    });
  }catch(e){}
}
async function idbListIds(){
  try{
    const db=await _idbOpen();
    return new Promise((resolve)=>{
      const tx=db.transaction(_idbStore,'readonly');
      const req=tx.objectStore(_idbStore).getAllKeys();
      req.onsuccess=()=>resolve(req.result||[]);
      req.onerror=()=>resolve([]);
    });
  }catch(e){ return []; }
}

// ─── Upload helpers ──────────────────────────────────────────────────────────
function _newUploadId(){
  if(self.crypto && self.crypto.randomUUID) return self.crypto.randomUUID().replace(/-/g,'').slice(0,32);
  return (Date.now().toString(36) + Math.random().toString(36).slice(2,12));
}
function _uploadBase(){ return location.pathname.replace(/\/$/,''); }
function _uploadAuthHeader(){ return {'Authorization':'Bearer '+(sessionToken||'')}; }
function _fmtSpeed(bps){
  if(!isFinite(bps)||bps<=0) return '';
  if(bps>=1024*1024) return (bps/1024/1024).toFixed(1)+' MB/s';
  if(bps>=1024)      return (bps/1024).toFixed(1)+' KB/s';
  return Math.round(bps)+' B/s';
}
async function _postJson(url,body){
  const r=await fetch(url,{method:'POST',headers:{..._uploadAuthHeader(),'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  return {ok:r.ok, status:r.status, data:d};
}

// Kick off a brand-new upload for a File the user just picked or dropped.
async function uploadFile(file){
  if(!sessionToken){showToast('Not authenticated');return;}
  if(!file){return;}
  // Some environments hand us a File whose .size is 0 even though the file has
  // data — notably drag-and-drop on certain Linux/Chromium (Wayland, or sandboxed
  // Flatpak/Snap) setups, and cloud "online-only" placeholders. The chunk loop is
  // gated on `offset < file.size`, so a 0-size File uploads nothing and the server
  // reports "No data uploaded". Don't trust a 0 size: try hard to read the real
  // bytes (Blob.arrayBuffer, then a FileReader fallback — they use different code
  // paths) and rebuild a proper File. Logs the actual numbers for diagnosis.
  if(file.size===0){
    let buf=null;
    try{ buf=await file.arrayBuffer(); }catch(e){ console.warn('[upload] arrayBuffer failed:', e&&e.name); }
    if(!buf || buf.byteLength===0){
      try{
        buf=await new Promise((res,rej)=>{ const fr=new FileReader(); fr.onload=()=>res(fr.result); fr.onerror=()=>rej(fr.error); fr.readAsArrayBuffer(file); });
      }catch(e){ console.warn('[upload] FileReader failed:', e&&e.name); buf=null; }
    }
    const got=buf?buf.byteLength:0;
    console.log('[upload] '+(file.name||'file')+' reportedSize='+file.size+' readableBytes='+got+' type='+(file.type||'?'));
    if(got>0){
      file=new File([buf], file.name||'upload', {type:file.type||'application/octet-stream'});
    }else{
      showToast(`Upload failed: "${file.name||'file'}" came through as 0 bytes — the browser couldn't read it. Try the upload button (📎) instead of drag-and-drop. (A Flatpak/Snap browser may lack permission to read dragged files.)`);
      return;
    }
  }
  // Source = the chat the user was last on (so even files dropped while
  // viewing the Uploads channel get a sensible "Insert into chat" target).
  const src = (active && !isUploadsConn(active.conn_id)) ? active : _lastIrcActive;
  if(!src){showToast('Select a channel first');return;}
  const id=_newUploadId();
  await idbPutFile(id,file);
  _uploadJobs[id]={canceled:false, file, lastTickAt:Date.now(), lastTickBytes:0, speed:0};
  // Pre-seed local state so the row appears instantly (server broadcast
  // confirms / replaces this in milliseconds).
  _uploads[id]={
    id, original_name:file.name, size:file.size, content_type:'',
    url:'', filename:'', uploaded_at:0, status:'uploading', progress_bytes:0,
    started_at: Math.floor(Date.now()/1000), completed_at:0, error:'',
    source_conn_id: src.conn_id, source_target: src.target,
  };
  setUploadsHidden(false);
  // Jump straight to the Uploads view so the user sees the row appear with
  // its progress bar instantly. We do this only on the originating device —
  // other sessions get the sidebar update + tiny toast but aren't yanked
  // away from whatever they were doing.
  if(!isUploadsActive()) setActive(UPLOAD_CONN, UPLOAD_TARGET);
  else renderChat();
  renderSidebar();
  flashUploadPip(`📤 ${file.name}`);
  try{
    const init=await _postJson(`${_uploadBase()}/upload/init`, {
      id, original_name:file.name, size:file.size,
      source_conn_id: src.conn_id, source_target: src.target,
    });
    if(!init.ok){
      showToast(init.data.error||'Upload init failed');
      _uploads[id].status='error'; _uploads[id].error=init.data.error||'init failed';
      delete _uploadJobs[id]; await idbDeleteFile(id);
      if(isUploadsActive()) renderChat();
      renderSidebar();
      return;
    }
    runUploadLoop(id);
  }catch(e){
    showToast('Upload init failed: '+e.message);
    _uploads[id].status='error'; _uploads[id].error=e.message;
    delete _uploadJobs[id]; await idbDeleteFile(id);
    if(isUploadsActive()) renderChat();
    renderSidebar();
  }
}

// Main chunk-pump. Survives navigation between channels; the only thing
// that stops it is `canceled` or running out of bytes. On transient errors
// (network blip, server 503), retries forever with backoff — that's how
// "tab closes mid-upload then reopens to seamless resume" works.
async function runUploadLoop(id){
  if(_uploadJobs[id]?.running) return;
  let file=_uploadJobs[id]?.file;
  if(!file){
    file=await idbGetFile(id);
    if(!file){
      // No bytes available on this device. Another device may finish it,
      // or it'll sit paused until someone removes it.
      delete _uploadJobs[id];
      return;
    }
    _uploadJobs[id]={canceled:false, file, lastTickAt:Date.now(), lastTickBytes:0, speed:0};
  }
  _uploadJobs[id].running=true;
  try{
    // Ask the server how far it actually has, in case we just woke from
    // a tab close and our local offset is stale.
    let offset=0;
    try{
      const sr=await fetch(`${_uploadBase()}/upload/status/${encodeURIComponent(id)}`,{headers:_uploadAuthHeader()});
      if(sr.ok){ const sd=await sr.json(); offset=sd.progress_bytes||0; }
    }catch(_){}
    while(offset < file.size){
      if(!_uploadJobs[id] || _uploadJobs[id].canceled) return;
      const end=Math.min(offset+UPLOAD_CHUNK_BYTES, file.size);
      const chunk=file.slice(offset, end);
      let ok=false;
      try{
        const r=await fetch(`${_uploadBase()}/upload/chunk/${encodeURIComponent(id)}?offset=${offset}`, {
          method:'POST', headers:{..._uploadAuthHeader(),'Content-Type':'application/octet-stream'}, body:chunk,
        });
        if(r.ok){
          const d=await r.json();
          const before=offset, now=Date.now(), j=_uploadJobs[id];
          offset=d.progress_bytes||end;
          if(j){
            const dt=Math.max(1, now - j.lastTickAt);
            const db=offset - j.lastTickBytes;
            j.speed = j.speed ? (j.speed*0.6 + (db*1000/dt)*0.4) : (db*1000/dt);
            j.lastTickAt=now; j.lastTickBytes=offset;
          }
          ok=true;
        } else if(r.status===400){
          // Most likely an offset mismatch — re-sync from server.
          try{
            const sr=await fetch(`${_uploadBase()}/upload/status/${encodeURIComponent(id)}`,{headers:_uploadAuthHeader()});
            if(sr.ok){ const sd=await sr.json(); offset=sd.progress_bytes||0; continue; }
          }catch(_){}
        }
      }catch(e){ /* network blip — fall through to retry */ }
      if(!ok){
        // Optimistically reflect our intent locally so the UI doesn't look
        // frozen during retries; the server's next 200 will overwrite.
        if(_uploadJobs[id]?.canceled) return;
        await new Promise(r=>setTimeout(r, UPLOAD_RETRY_MS));
      }
    }
    // All bytes uploaded — ask server to finalize.
    if(!_uploadJobs[id] || _uploadJobs[id].canceled) return;
    let tries=0;
    while(tries++<5){
      try{
        const r=await fetch(`${_uploadBase()}/upload/finalize/${encodeURIComponent(id)}`,{method:'POST',headers:_uploadAuthHeader()});
        if(r.ok){
          const d=await r.json();
          // _uploads[id] will be updated via broadcast, but populate now so the
          // UI doesn't briefly flicker between "100%" and the Done state.
          Object.assign(_uploads[id]||{}, d);
          await idbDeleteFile(id);
          delete _uploadJobs[id];
          if(isUploadsActive()) renderChat();
          renderSidebar();
          return;
        }
        if(r.status===401){ showToast('Upload finalize: not authenticated'); break; }
      }catch(_){}
      await new Promise(r=>setTimeout(r, UPLOAD_RETRY_MS));
    }
  } finally {
    if(_uploadJobs[id]) _uploadJobs[id].running=false;
  }
}

async function cancelUpload(id){
  const j=_uploadJobs[id];
  if(j) j.canceled=true;
  try{ await fetch(`${_uploadBase()}/upload/cancel/${encodeURIComponent(id)}`,{method:'POST',headers:_uploadAuthHeader()}); }catch(_){}
  await idbDeleteFile(id);
  delete _uploadJobs[id];
  // Server broadcasts the cancellation; UI updates on receipt.
}
function removeUploadRow(id){
  wsend({type:'upload_remove', id});
  // Optimistic local removal so the row disappears immediately even if
  // the WS round-trip is slow.
  delete _uploads[id];
  delete _uploadJobs[id];
  idbDeleteFile(id);
  if(isUploadsActive()) renderChat();
  renderSidebar();
}
function copyUploadLink(id){
  const r=_uploads[id]; if(!r||!r.url) return;
  const pubUrl=r.url.replace('/files/','/pub/');
  const shareUrl=`${location.origin}${pubUrl}`;
  navigator.clipboard?.writeText(shareUrl).then(()=>showToast('Link copied!')).catch(()=>{
    const t=document.createElement('textarea');t.value=shareUrl;document.body.appendChild(t);t.select();
    try{document.execCommand('copy');}catch(_){} document.body.removeChild(t);showToast('Link copied!');
  });
}
function insertUploadLink(id){
  const r=_uploads[id]; if(!r||!r.url) return;
  const pubUrl=r.url.replace('/files/','/pub/');
  const shareUrl=`${location.origin}${pubUrl}`;
  const isImg=['jpg','jpeg','png','gif','webp','avif','ico'].includes((r.filename||'').split('.').pop().toLowerCase());
  const text=isImg?shareUrl:`${r.original_name}: ${shareUrl}`;
  // Switch to the chat this upload was started in (if still around), then
  // drop the link in the input there.
  if(r.source_conn_id && r.source_target){
    const haveNet = networks.find(n=>n.config.id===r.source_conn_id);
    if(haveNet) setActive(r.source_conn_id, r.source_target);
  }
  const inp=document.getElementById('msg-input');
  if(inp){ inp.value = inp.value ? (inp.value+' '+text) : text; inp.focus(); }
  showToast('Inserted into chat');
}

// Briefly flash the existing tiny strip so users see something happened
// even when the Uploads channel isn't focused. Click to jump to it.
function flashUploadPip(msg){
  const prog=document.getElementById('upload-progress');
  if(!prog) return;
  prog.textContent=msg; prog.classList.add('show');
  prog.style.cursor='pointer';
  prog.onclick=()=>{ setUploadsHidden(false); setActive(UPLOAD_CONN, UPLOAD_TARGET); };
  clearTimeout(prog._fadeTimer);
  prog._fadeTimer=setTimeout(()=>prog.classList.remove('show'), 2500);
}

// ─── WS event glue ───────────────────────────────────────────────────────────
function _onUploadState(records){
  for(const k of Object.keys(_uploads)) delete _uploads[k];
  for(const r of records) _uploads[r.id]=r;
  // For any in-flight record where THIS device has the bytes cached,
  // (re)start the upload loop. That's what makes resume-after-reload work.
  (async()=>{
    const ids=await idbListIds();
    const haveLocal=new Set(ids);
    for(const r of records){
      if(r.status==='uploading' && haveLocal.has(r.id) && !_uploadJobs[r.id]){
        runUploadLoop(r.id);
      }
    }
    // Stale IDB rows whose server record is gone — clean up.
    for(const id of ids){
      if(!_uploads[id]) idbDeleteFile(id);
    }
  })();
  if(records.length) setUploadsHidden(false);
  if(isUploadsActive()) renderChat();
  renderSidebar();
}
function _onUploadUpdate(rec){
  const prev=_uploads[rec.id];
  _uploads[rec.id]=rec;
  if(rec.status==='uploading') setUploadsHidden(false);  // idempotent now
  // If a record canceled / errored from another device, stop our loop.
  if((rec.status==='canceled'||rec.status==='error') && _uploadJobs[rec.id]){
    _uploadJobs[rec.id].canceled=true;
    idbDeleteFile(rec.id);
  }
  // Brand-new row, or status transition between buckets that affects sidebar
  // visibility (none → exists, or last-uploading-finishing) — fall back to
  // a full render. Pure progress updates hit the in-place fast paths and
  // don't churn the main sidebar (which kept eating click handlers on
  // network channels mid-tap).
  const isNew = !prev;
  if(isNew){
    renderSidebar();
    if(isUploadsActive()) renderChat();
    return;
  }
  _refreshUploadsPin();
  _updateUploadRowInPlace(rec);
}
function _onUploadRemoved(id){
  delete _uploads[id];
  if(_uploadJobs[id]) _uploadJobs[id].canceled=true;
  delete _uploadJobs[id];
  idbDeleteFile(id);
  if(isUploadsActive()) renderChat();
  renderSidebar();
}

// ─── Renderers ───────────────────────────────────────────────────────────────
function renderUploadsView(){
  const area=document.getElementById('chat-area');
  area.style.display='block';
  area.innerHTML='';
  const wrap=document.createElement('div');
  wrap.style.cssText='padding:14px 16px;display:flex;flex-direction:column;gap:10px;max-width:800px;margin:0 auto';
  const header=document.createElement('div');
  header.style.cssText='display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:4px';
  header.innerHTML=`<div style="font-weight:700;color:var(--text);font-size:14px">Upload Status</div>
    <div style="display:flex;gap:8px;align-items:center">
      <button id="upload-pick-btn" style="background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:6px;font-size:12px;cursor:pointer">+ Upload file</button>
      <button id="upload-close-view-btn" title="Close (keeps sidebar entry)" style="background:none;border:1px solid var(--border);color:var(--text3);padding:3px 9px;border-radius:6px;font-size:14px;cursor:pointer;line-height:1">✕</button>
    </div>`;
  wrap.appendChild(header);
  header.querySelector('#upload-pick-btn').onclick=()=>document.getElementById('file-input').click();
  // Close-view: return to the last real IRC chat (or status) — does NOT
  // hide the sidebar entry, so the user can jump back into the channel
  // any time. To truly dismiss the entry, ✕ on the sidebar entry itself.
  header.querySelector('#upload-close-view-btn').onclick=()=>{
    if(_lastIrcActive){
      setActive(_lastIrcActive.conn_id, _lastIrcActive.target);
    } else if(networks[0]){
      setActive(networks[0].config.id, 'status');
    } else {
      active=null; renderChat(); renderSidebar(); updateInputPlaceholder();
      try{localStorage.removeItem('cryptirc_active');}catch(e){}
    }
  };
  const rows=Object.values(_uploads).sort((a,b)=>(b.started_at||0)-(a.started_at||0));
  if(!rows.length){
    const empty=document.createElement('div');
    empty.style.cssText='padding:30px;text-align:center;color:var(--text3);font-size:12px';
    empty.textContent='No uploads yet. Drop a file or click "+ Upload file" above.';
    wrap.appendChild(empty);
  }
  for(const r of rows) wrap.appendChild(_renderUploadRow(r));
  area.appendChild(wrap);
}
function _uploadStatusColor(status){
  if(status==='done')     return 'var(--accent,#00d4aa)';
  if(status==='error')    return 'var(--error,#ff6b6b)';
  if(status==='canceled') return 'var(--text3)';
  return 'var(--accent,#00d4aa)';
}
function _uploadStatusLabel(r){
  const job=_uploadJobs[r.id];
  const speedTxt = (r.status==='uploading' && job && job.speed>0) ? _fmtSpeed(job.speed) : '';
  if(r.status==='done')     return 'Done';
  if(r.status==='error')    return 'Error'+(r.error?': '+r.error:'');
  if(r.status==='canceled') return 'Canceled';
  return job ? `Uploading${speedTxt?' · '+speedTxt:''}` : 'Uploading (other device)';
}
function _renderUploadRow(r){
  const row=document.createElement('div');
  row.dataset.uploadId=r.id;
  row.dataset.uploadStatus=r.status||'uploading';
  row.style.cssText='background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;display:flex;flex-direction:column;gap:6px';
  const pct=r.size?Math.min(100, Math.floor((r.progress_bytes||0) * 100 / r.size)):0;
  const status=r.status||'uploading';
  const statusColor=_uploadStatusColor(status);
  const statusLabel=_uploadStatusLabel(r);
  const sizeTxt=`${formatBytes(r.progress_bytes||0)} / ${formatBytes(r.size||0)}`;
  // Data-* hooks let _updateUploadRowInPlace() target just the changing
  // bits per progress event instead of nuking the whole row each chunk.
  row.innerHTML=`
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:13px">
      <div style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text)" title="${esc(r.original_name||'')}">${esc(r.original_name||'(unnamed)')}</div>
      <div data-pct style="font-size:11px;color:var(--text3);font-family:var(--mono);flex-shrink:0">${pct}%</div>
    </div>
    <div style="height:6px;background:var(--bg3);border-radius:3px;overflow:hidden">
      <div data-bar style="height:100%;width:${pct}%;background:${statusColor};transition:width .2s ease"></div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:10px;color:var(--text3);font-family:var(--mono)">
      <div><span data-size>${sizeTxt}</span> · <span data-status style="color:${statusColor}">${esc(statusLabel)}</span></div>
      <div data-actions style="display:flex;gap:6px;flex-wrap:wrap"></div>
    </div>`;
  _fillUploadRowActions(row, r);
  return row;
}
function _fillUploadRowActions(row, r){
  const actions=row.querySelector('[data-actions]');
  actions.innerHTML='';
  const status=r.status||'uploading';
  function btn(label,fn,color){
    const b=document.createElement('button');
    b.textContent=label;
    b.style.cssText=`background:none;border:1px solid var(--border);color:${color||'var(--text2)'};padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px;font-family:var(--mono)`;
    b.onclick=fn; actions.appendChild(b);
  }
  if(status==='uploading') btn('Cancel', ()=>cancelUpload(r.id), 'var(--error,#ff6b6b)');
  if(status==='done'){
    btn('Copy link', ()=>copyUploadLink(r.id), 'var(--accent,#00d4aa)');
    btn('Insert', ()=>insertUploadLink(r.id), 'var(--accent,#00d4aa)');
  }
  if(status!=='uploading') btn('Remove', ()=>removeUploadRow(r.id), 'var(--text3)');
}
// In-place row update: progress bar, %, size, status text. Falls back to
// a full re-render only when the row doesn't exist yet or the status
// transitions (different action buttons are needed).
function _updateUploadRowInPlace(r){
  if(!isUploadsActive()) return;                 // not visible — skip
  const area=document.getElementById('chat-area');
  const row=area && area.querySelector(`[data-upload-id="${CSS.escape(r.id)}"]`);
  if(!row){ renderUploadsView(); return; }
  const prevStatus=row.dataset.uploadStatus||'uploading';
  const status=r.status||'uploading';
  const pct=r.size?Math.min(100, Math.floor((r.progress_bytes||0) * 100 / r.size)):0;
  const color=_uploadStatusColor(status);
  const pctEl=row.querySelector('[data-pct]');
  const barEl=row.querySelector('[data-bar]');
  const sizeEl=row.querySelector('[data-size]');
  const statusEl=row.querySelector('[data-status]');
  if(pctEl)    pctEl.textContent = pct+'%';
  if(barEl){   barEl.style.width = pct+'%'; barEl.style.background = color; }
  if(sizeEl)   sizeEl.textContent = `${formatBytes(r.progress_bytes||0)} / ${formatBytes(r.size||0)}`;
  if(statusEl){ statusEl.textContent = _uploadStatusLabel(r); statusEl.style.color = color; }
  if(prevStatus !== status){
    row.dataset.uploadStatus = status;
    _fillUploadRowActions(row, r);
  }
}
// Surgical pin refresh: just the "Upload Status · 2 uploading" subtitle
// and the dot. Cheap enough to fire on every chunk. Falls back to a full
// renderSidebar only when the visibility of the pin itself changes
// (appear / disappear).
function _refreshUploadsPin(){
  const pin=document.getElementById('uploads-pin');
  if(!pin) return;
  const shouldShow = !_uploadsHidden && uploadsAnyExist();
  const isShowing  = !!pin.firstChild;
  if(shouldShow !== isShowing){
    renderSidebar();
    return;
  }
  if(!shouldShow) return;
  let active_n=0;
  for(const id in _uploads) if(_uploads[id].status==='uploading') active_n++;
  const dot=pin.querySelector('.net-dot');
  if(dot){
    if(active_n) dot.classList.add('online');
    else dot.classList.remove('online');
  }
  const sub=pin.querySelector('.net-name span');
  if(sub){
    let done_n=0;
    for(const id in _uploads) if(_uploads[id].status==='done') done_n++;
    sub.textContent='· '+(active_n?`${active_n} uploading`:(done_n?`${done_n} ready`:'idle'));
  }
  const lbl=pin.querySelector('.net-label');
  if(lbl){
    if(isUploadsActive()){ lbl.classList.add('active'); lbl.style.background='var(--bg4)'; }
    else                 { lbl.classList.remove('active'); lbl.style.background=''; }
  }
}

function _renderUploadsSidebarEntry(){
  // Hide entirely when manually closed, OR when there's nothing to show yet
  // (no prior uploads + no in-flight) — keeps the sidebar clean for new users.
  if(_uploadsHidden) return null;
  if(!uploadsAnyExist()) return null;
  const el=document.createElement('div');
  el.className='net-group';
  el.dataset.netId=UPLOAD_CONN;
  const isA=isUploadsActive();
  let active_n=0, done_n=0;
  for(const id in _uploads){
    if(_uploads[id].status==='uploading') active_n++;
    else if(_uploads[id].status==='done') done_n++;
  }
  const subtitle=active_n?`${active_n} uploading`:(done_n?`${done_n} ready`:'idle');
  el.innerHTML=`<div class="net-label${isA?' active':''}" style="${isA?'background:var(--bg4);':''}">
    <span class="net-dot ${active_n?'online':''}"></span>
    <span class="net-name">Upload Status <span style="opacity:.5;font-size:10px;font-weight:normal">· ${esc(subtitle)}</span></span>
    <span class="net-actions">
      <button class="net-btn" title="Hide Upload Status (new uploads will bring it back)" data-upload-close>✕</button>
    </span>
  </div>`;
  el.querySelector('.net-label').onclick=(e)=>{
    if(e.target.closest('[data-upload-close]')) return;
    setActive(UPLOAD_CONN, UPLOAD_TARGET); closeSidebar();
  };
  el.querySelector('[data-upload-close]').onclick=(e)=>{
    e.stopPropagation();
    setUploadsHidden(true);
    if(isUploadsActive()) setActive(networks[0]?.config.id||'', 'status');
  };
  return el;
}

// ─── User Count Update + Blink ───────────────────────────────────────────────
function refreshUserCount(connId,channel){
  if(!active||active.conn_id!==connId||typeof channel!=='string'||active.target.toLowerCase()!==channel.toLowerCase())return;
  const net=networks.find(n=>n.config.id===connId);
  const ch=net?.channels.find(c=>c.name===channel);
  document.getElementById('usercount').textContent=ch?`${ch.names.length} users`:'';
  renderNickPanel(ch?.names||[]);
}
function blinkUserCount(type){
  const el=document.getElementById('nick-panel-count');if(!el)return;
  const cls=type==='join'?'blink-join':'blink-part';
  el.classList.remove('blink-join','blink-part');
  void el.offsetWidth; // force reflow for re-trigger
  el.classList.add(cls);
  setTimeout(()=>el.classList.remove(cls),800);
}

// ─── Settings Menu ───────────────────────────────────────────────────────────
function toggleSettingsMenu(){document.getElementById('settings-menu').classList.toggle('open');}
function closeSettingsMenu(){document.getElementById('settings-menu').classList.remove('open');}
document.addEventListener('click',e=>{const m=document.getElementById('settings-menu');if(m&&m.classList.contains('open')&&!e.target.closest('#settings-menu')&&!e.target.closest('#settings-gear-btn'))closeSettingsMenu();});

// ─── Custom prompt (works in Electron where window.prompt is broken) ─────────
// NOTE: customPrompt is defined later (single canonical definition near the nick
// menu) and uses textContent for the message — safe against HTML/JS injection.
// A second, earlier definition used to live here that injected its `label` into
// innerHTML UNESCAPED; several call sites pass attacker-influenced nicks into that
// label (e.g. `Note for ${nick}:`), making it a latent stored-XSS foot-gun the
// moment a refactor reordered the definitions (audit #89). It was always shadowed
// (the later same-name function declaration wins) and is now removed entirely.

// ─── Vault ────────────────────────────────────────────────────────────────────
function doUnlock(){
  const p=document.getElementById('vault-pass').value;
  if(!p){document.getElementById('vault-err').textContent='Passphrase required';return;}
  document.getElementById('vault-err').textContent='';
  wsend({type:'unlock_vault',passphrase:p});
}
async function lockVault(){if(!(await customConfirm('Lock the vault? This will disconnect you from all IRC networks. You will need to enter your passphrase again to reconnect.','Lock')))return;flushPrefsToServer();wsend({type:'lock_vault'});for(const n of networks)wsend({type:'disconnect',id:n.config.id});document.getElementById('vault-overlay').classList.add('show');const vb=document.getElementById('vault-lock-btn');if(vb){vb.textContent='🔒';vb.title='Lock vault';}}
async function showChangePass(){
  const old=await customPrompt('Current vault passphrase:','',true);if(!old)return;
  const nw=await customPrompt('New vault passphrase:','',true);if(!nw)return;
  const confirm=await customPrompt('Confirm new vault passphrase:','',true);
  if(nw!==confirm){showToast('Passphrases do not match');return;}
  wsend({type:'change_passphrase',old,new:nw});
  showToast('Vault passphrase changed');
}
async function showChangeClientPassword(){
  const old=await customPrompt('Current login password:','',true);if(!old)return;
  const nw=await customPrompt('New login password (min 10 chars, upper+lower+number+special):','',true);if(!nw)return;
  const confirm=await customPrompt('Confirm new login password:','',true);
  if(nw!==confirm){showToast('Passwords do not match');return;}
  try{
    const r=await fetch('/cryptirc/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+sessionToken},body:JSON.stringify({old_password:old,new_password:nw})});
    const d=await r.json();
    if(r.ok){showToast('Login password changed successfully');}
    else{showToast(d.message||'Password change failed');}
  }catch(e){showToast('Network error — try again');}
}
// ─── Password Safe ───────────────────────────────────────────────────────────
let _pwSafe=[];  // [{id,name,username,password,notes}]
let _pwSafeLoaded=false;
let _pwSafeDirty=false;

function handlePasswordSafeData(data){
  if(!data){_pwSafeLoaded=true;return;}
  try{const d=JSON.parse(data);if(Array.isArray(d))_pwSafe=d;}catch(e){}
  _pwSafeLoaded=true;
  _pwSafeDirty=false;
  // Re-render if panel is open
  const ov=document.getElementById('pwsafe-overlay');
  if(ov&&ov.classList.contains('show')) renderPasswordSafe();
}
function savePasswordSafe(){
  if(!sessionToken)return;
  wsend({type:'save_passwords',data:JSON.stringify(_pwSafe)});
  _pwSafeDirty=false;
}
function showPasswordPanel(){
  if(!_pwSafeLoaded) wsend({type:'load_passwords'});
  let ov=document.getElementById('pwsafe-overlay');
  if(!ov){
    ov=document.createElement('div');ov.id='pwsafe-overlay';
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;display:none;align-items:center;justify-content:center;padding:16px;';
    ov.innerHTML=`<div id="pwsafe-box" style="background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:min(500px,94vw);max-height:min(88vh,88dvh);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6)">
      <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-shrink:0">
        <span style="font-weight:700;font-size:14px;color:var(--text)">🔐 Password Management</span>
        <span onclick="document.getElementById('pwsafe-overlay').classList.remove('show');document.getElementById('pwsafe-overlay').style.display='none'" style="cursor:pointer;color:var(--text3);font-size:18px">✕</span>
      </div>
      <div id="pwsafe-body" style="padding:14px 20px;overflow-y:auto;flex:1;-webkit-overflow-scrolling:touch"></div>
    </div>`;
    document.body.appendChild(ov);
  }
  ov.style.display='flex';ov.classList.add('show');
  renderPasswordPanel();
}
// SECURITY: delegated handler for the password-safe item controls. Reads the entry
// index / element id from data-* (no user data in a code/JS-string context, #10) and
// performs the copy-username / reveal-password / copy-password action. Bound lazily
// on first render (the #pwsafe-body element lives below this script tag); idempotent.
function _bindPwSafeDelegation(){
  const body=document.getElementById('pwsafe-body');
  if(!body||body._pwSafeDelegated)return;
  body._pwSafeDelegated=true;
  body.addEventListener('click',e=>{
    const el=e.target.closest('[data-pw-act]');
    if(!el||!body.contains(el))return;
    const act=el.dataset.pwAct;
    if(act==='copyuser'){
      const entry=_pwSafe[+el.dataset.pwIdx];
      if(entry){navigator.clipboard?.writeText(entry.username||'');showToast('Username copied');}
      return;
    }
    const s=document.getElementById(el.dataset.pwTarget);
    if(!s)return;
    if(act==='reveal'){
      if(s.textContent==='••••••••'){
        s.textContent=atob(s.dataset.v);s.style.color='var(--accent)';
        setTimeout(()=>{s.textContent='••••••••';s.style.color='var(--text)';},5000);
      } else {s.textContent='••••••••';s.style.color='var(--text)';}
    } else if(act==='copypass'){
      navigator.clipboard?.writeText(atob(s.dataset.v||''));showToast('Password copied');
    }
  });
}
function renderPasswordPanel(){
  const body=document.getElementById('pwsafe-body');
  if(!body)return;
  _bindPwSafeDelegation();   // idempotent; binds the delegated item-action listener once
  let html='';
  // ── Change Passwords section ──
  html+=`<div style="margin-bottom:18px">
    <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.08em;font-weight:600;margin-bottom:8px">Change Passwords</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button onclick="showChangePass()" style="flex:1;min-width:140px;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;cursor:pointer;color:var(--text);font-family:var(--mono);font-size:12px;text-align:left;display:flex;align-items:center;gap:8px">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
        <div><div style="font-weight:600">Vault Passphrase</div><div style="font-size:10px;color:var(--text3)">Encryption key for logs &amp; data</div></div>
      </button>
      <button onclick="showChangeClientPassword()" style="flex:1;min-width:140px;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;cursor:pointer;color:var(--text);font-family:var(--mono);font-size:12px;text-align:left;display:flex;align-items:center;gap:8px">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <div><div style="font-weight:600">Login Password</div><div style="font-size:10px;color:var(--text3)">Account sign-in password</div></div>
      </button>
    </div>
  </div>`;
  // ── Password Safe section ──
  html+=`<div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.08em;font-weight:600;margin-bottom:8px">Password Safe</div>
  <div style="font-size:10px;color:var(--text3);margin-bottom:10px">Encrypted with your vault key — only accessible when unlocked. Syncs across all devices.</div>`;
  html+=renderPasswordSafeHTML();
  body.innerHTML=html;
  // Set password data attributes after render
  for(let i=0;i<_pwSafe.length;i++){
    const el=document.getElementById('pw-'+i);
    if(el) el.dataset.v=btoa(_pwSafe[i].password||'');
  }
}
function renderPasswordSafe(){
  const ov=document.getElementById('pwsafe-overlay');
  if(ov&&ov.classList.contains('show')) renderPasswordPanel();
}
function renderPasswordSafeHTML(){
  let html=`<div style="display:flex;gap:6px;margin-bottom:10px">
    <button onclick="pwSafeAdd()" style="padding:8px 14px;background:var(--accent);color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:700;font-size:13px;font-family:var(--mono)">+ Add Entry</button>
  </div>`;
  if(!_pwSafe.length){
    html+=`<div style="color:var(--text3);text-align:center;padding:30px 0;font-size:13px;background:var(--bg2);border:1px dashed var(--border);border-radius:8px">
      No saved passwords yet.
    </div>`;
    return html;
  }
  for(let i=0;i<_pwSafe.length;i++){
    const e=_pwSafe[i];
    const safeId='pw-'+i;
    html+=`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <span style="font-weight:600;font-size:13px;color:var(--text)">${esc(e.name||'Untitled')}</span>
        <div style="display:flex;gap:4px">
          <button onclick="pwSafeEdit(${i})" style="padding:3px 8px;background:none;border:1px solid var(--border);color:var(--text2);border-radius:4px;cursor:pointer;font-size:10px">Edit</button>
          <button onclick="pwSafeDelete(${i})" style="padding:3px 8px;background:none;border:1px solid var(--error);color:var(--error);border-radius:4px;cursor:pointer;font-size:10px">Delete</button>
        </div>
      </div>`;
    // SECURITY: vault entry username is user-provided. It is no longer interpolated
    // into an inline-handler JS-string (old onclick="...writeText('${esc(...)}')",
    // #10); the copy control carries a data-pw-act/data-pw-idx and a delegated
    // listener reads _pwSafe[idx].username at click time. Reveal/copy-password use
    // the same delegated path (they already used the safe dataset.v mechanism).
    if(e.username) html+=`<div style="font-size:11px;color:var(--text3);margin-bottom:3px">User: <span style="color:var(--text);font-family:var(--mono)">${esc(e.username)}</span>
      <span data-pw-act="copyuser" data-pw-idx="${i}" style="cursor:pointer;margin-left:4px;opacity:.5">📋</span></div>`;
    html+=`<div style="font-size:11px;color:var(--text3);margin-bottom:3px">Pass: <span id="${safeId}" style="color:var(--text);font-family:var(--mono)">••••••••</span>
      <span data-pw-act="reveal" data-pw-target="${safeId}" style="cursor:pointer;margin-left:4px;opacity:.5">👁</span>
      <span data-pw-act="copypass" data-pw-target="${safeId}" style="cursor:pointer;margin-left:2px;opacity:.5">📋</span></div>`;
    if(e.notes) html+=`<div style="font-size:10px;color:var(--text3);margin-top:4px;line-height:1.3">${esc(e.notes)}</div>`;
    html+=`</div>`;
  }
  return html;
}
async function pwSafeAdd(){
  const name=await customPrompt('Entry name (e.g. "Gmail", "GitHub"):');if(!name)return;
  const username=await customPrompt('Username / email (optional):');
  const password=await customPrompt('Password:','',true);if(!password)return;
  const notes=await customPrompt('Notes (optional):');
  _pwSafe.push({id:Date.now(),name,username:username||'',password,notes:notes||''});
  savePasswordSafe();
  renderPasswordSafe();
}
async function pwSafeEdit(idx){
  const e=_pwSafe[idx];if(!e)return;
  const name=await customPrompt('Entry name:',e.name);if(name===null)return;
  const username=await customPrompt('Username / email:',e.username||'');if(username===null)return;
  const password=await customPrompt('Password:',e.password,true);if(password===null)return;
  const notes=await customPrompt('Notes:',e.notes||'');if(notes===null)return;
  e.name=name;e.username=username;e.password=password;e.notes=notes;
  savePasswordSafe();
  renderPasswordSafe();
}
async function pwSafeDelete(idx){
  const e=_pwSafe[idx];if(!e)return;
  if(!(await customConfirm(`Delete "${e.name}"?`,'Delete')))return;
  _pwSafe.splice(idx,1);
  savePasswordSafe();
  renderPasswordSafe();
}

async function clearAllLogs(){
  if(!(await customConfirm('Clear ALL data? This will delete:\n• Chat history & logs (server + local)\n• Your notepad\n• Your paste posts\n\nThis cannot be undone.','Clear all')))return;
  // Clear local buffers
  buffers={}; _historyView=null;
  unread.clear();
  renderChat();
  renderSidebar();
  // Tell server to clear logs, notepad, and pastes
  wsend({type:'clear_all_data'});
  showToast('All data cleared');
}
async function showDeleteAccount(){
  const pw=await customPrompt('To delete your account permanently, enter your password:');
  if(!pw)return;
  if(!(await customConfirm('This will permanently delete your account, all connections, logs, and settings. This cannot be undone. Are you sure?','Delete')))return;
  wsend({type:'delete_account',password:pw});
}

// ─── Network modal ────────────────────────────────────────────────────────────
let editingNetworkId=null;
function resetNetworkForm(){
  editingNetworkId=null;
  const pre=document.getElementById('f-preset'); if(pre)pre.value='';
  document.getElementById('f-label').value='';
  document.getElementById('f-server').value='';
  document.getElementById('f-port').value='6697';
  document.getElementById('f-tls').value='true';
  document.getElementById('f-nick').value='';
  document.getElementById('f-user').value='';
  document.getElementById('f-real').value='';
  document.getElementById('f-pass').value='';
  document.getElementById('f-autojoin').value='';
  {const fq=document.getElementById('f-quit'); if(fq) fq.value='';}
  document.getElementById('f-sasl-method').value='none';
  document.getElementById('f-sasl-account').value='';
  document.getElementById('f-sasl-password').value='';
  document.getElementById('f-reconnect').value='true';
  document.getElementById('f-tls-invalid').value='false';
  document.getElementById('f-oper-login').value='';
  document.getElementById('f-oper-pass').value='';
  document.getElementById('f-auto-identify').value='false';
  document.getElementById('f-nickserv-pass').value='';
  {const fp=document.getElementById('f-perform'); if(fp) fp.value='';}
  // Reset ZNC fields + mode
  const modeEl=document.getElementById('f-mode');
  if(modeEl) modeEl.value='direct';
  const zu=document.getElementById('f-znc-user'); if(zu) zu.value='';
  const zn=document.getElementById('f-znc-network'); if(zn) zn.value='';
  const zp=document.getElementById('f-znc-pass'); if(zp){ zp.value=''; zp.placeholder=''; }
  onSaslMethodChange();
  // UI-only — don't run the defaults block since we just set mode to 'direct'
  applyServerModeUi();
  _prevServerMode='direct';
  renderCapsGrid([]);
}
const _ALL_CAPS=[
  {id:'away-notify',label:'Away Notify',desc:'See when users go away/back'},
  {id:'account-notify',label:'Account Notify',desc:'Account login/logout events'},
  {id:'extended-join',label:'Extended Join',desc:'Show account+realname on join'},
  {id:'server-time',label:'Server Time',desc:'Accurate server-side timestamps'},
  {id:'multi-prefix',label:'Multi Prefix',desc:'Show all user prefixes (@+%)'},
  {id:'cap-notify',label:'Cap Notify',desc:'Server advertises new caps'},
  {id:'message-tags',label:'Message Tags',desc:'IRCv3 message metadata'},
  {id:'batch',label:'Batch',desc:'Group related messages'},
  {id:'echo-message',label:'Echo Message',desc:'Server echoes your messages back'},
  {id:'invite-notify',label:'Invite Notify',desc:'See channel invites'},
  {id:'setname',label:'Setname',desc:'Real-time realname changes'},
  {id:'account-tag',label:'Account Tag',desc:'Account name in message tags'},
  {id:'userhost-in-names',label:'Userhost in Names',desc:'Full user@host in NAMES'},
  {id:'chghost',label:'Chghost',desc:'Host/ident change notifications'},
  {id:'labeled-response',label:'Labeled Response',desc:'Match responses to commands'},
  {id:'draft/typing',label:'Typing Indicators',desc:'See when someone is typing'},
  {id:'standard-replies',label:'Standard Replies',desc:'Structured server replies'},
];
function renderCapsGrid(disabledCaps){
  const grid=document.getElementById('f-caps-grid');if(!grid)return;
  grid.innerHTML='';
  for(const cap of _ALL_CAPS){
    const on=!disabledCaps.includes(cap.id);
    const el=document.createElement('label');
    el.style.cssText='display:flex;align-items:center;gap:5px;cursor:pointer;padding:3px 0;color:var(--text2);';
    el.title=cap.desc;
    el.innerHTML=`<input type="checkbox" data-cap="${cap.id}" ${on?'checked':''} style="accent-color:var(--accent);margin:0;cursor:pointer"><span>${cap.label}</span>`;
    grid.appendChild(el);
  }
}
function showAddNetwork(){
  resetNetworkForm();
  document.getElementById('modal-title').textContent='Add Network';
  document.getElementById('modal-save-btn').textContent='Add & Connect';
  document.getElementById('modal-overlay').classList.add('open');
  _overlayOpen('networkModal', closeModal);
  // Safety: clear any stuck drag-suppression class, and focus the first field so the
  // user can type immediately (especially important on Electron where focus-on-open
  // isn't automatic).
  document.body.classList.remove('force-no-select');
  setTimeout(()=>{document.getElementById('f-label')?.focus();},50);
}
function editNetwork(id){
  const net=networks.find(n=>n.config.id===id);
  if(!net)return;
  const c=net.config;
  editingNetworkId=c.id;
  const pre=document.getElementById('f-preset'); if(pre)pre.value='';
  // Reset ZNC-specific fields before populating (editing a direct network after
  // previously editing a ZNC one should not carry over the ZNC mode)
  const modeEl=document.getElementById('f-mode'); if(modeEl) modeEl.value='direct';
  const zu=document.getElementById('f-znc-user'); if(zu) zu.value='';
  const zn=document.getElementById('f-znc-network'); if(zn) zn.value='';
  const zp=document.getElementById('f-znc-pass'); if(zp) zp.value='';
  // Detect ZNC config by the password format <user>/<network>:<password>.
  // Require SASL to be off as an additional signal — SASL-enabled networks with
  // exotic passwords should not be mis-detected as ZNC.
  const zncParsed=(!c.sasl_plain && !c.sasl_external) ? parseZncPass(c.password) : null;
  if(zncParsed){
    if(modeEl) modeEl.value='znc';
    if(zu) zu.value=zncParsed.user;
    if(zn) zn.value=zncParsed.network;
    // Password intentionally not re-populated for security. Hint the user that
    // leaving it blank preserves the saved value.
    if(zp){ zp.value=''; zp.placeholder='(leave blank to keep existing)'; }
  } else {
    if(zp) zp.placeholder='';
  }
  document.getElementById('f-label').value=c.label||'';
  document.getElementById('f-server').value=c.server||'';
  document.getElementById('f-port').value=c.port||6697;
  document.getElementById('f-tls').value=c.tls?'true':'false';
  document.getElementById('f-nick').value=c.nick||'';
  document.getElementById('f-user').value=c.username||'';
  document.getElementById('f-real').value=c.realname||'';
  document.getElementById('f-pass').value='';
  document.getElementById('f-autojoin').value=(c.auto_join||[]).join(' ');
  {const fq=document.getElementById('f-quit'); if(fq) fq.value=c.quit_message||'';}
  document.getElementById('f-reconnect').value=c.auto_reconnect?'true':'false';
  document.getElementById('f-tls-invalid').value=c.tls_accept_invalid_certs?'true':'false';
  document.getElementById('f-oper-login').value=c.oper_login||'';
  document.getElementById('f-oper-pass').value=c.oper_pass||'';
  document.getElementById('f-auto-identify').value=c.auto_identify?'true':'false';
  document.getElementById('f-nickserv-pass').value='';
  {const fp=document.getElementById('f-perform'); if(fp) fp.value=(c.perform_commands||[]).join('\n');}
  renderCapsGrid(c.disabled_caps||[]);
  if(c.sasl_plain){
    document.getElementById('f-sasl-method').value='plain';
    document.getElementById('f-sasl-account').value=c.sasl_plain.account||'';
    document.getElementById('f-sasl-password').value='';
  } else if(c.sasl_external){
    document.getElementById('f-sasl-method').value='external';
  } else {
    document.getElementById('f-sasl-method').value='none';
    document.getElementById('f-sasl-account').value='';
    document.getElementById('f-sasl-password').value='';
  }
  onSaslMethodChange();
  // Apply ZNC mode show/hide based on the mode we set earlier from parseZncPass.
  // Use the UI-only helper so we don't overwrite the saved TLS/port config.
  applyServerModeUi();
  _prevServerMode=document.getElementById('f-mode')?.value||'direct';
  document.getElementById('modal-title').textContent='Edit Network';
  document.getElementById('modal-save-btn').textContent='Save Changes';
  document.getElementById('modal-overlay').classList.add('open');
  _overlayOpen('networkModal', closeModal);
  document.body.classList.remove('force-no-select');
  setTimeout(()=>{document.getElementById('f-label')?.focus();},50);
}
function closeModal(){
  _overlayClose('networkModal');
  document.getElementById('modal-overlay').classList.remove('open');
  editingNetworkId=null;
}
function onSaslMethodChange(){const m=document.getElementById('f-sasl-method').value;document.getElementById('sasl-plain-fields').style.display=m==='plain'?'':'none';document.getElementById('sasl-external-info').style.display=m==='external'?'':'none';}
// Parse a ZNC-format PASS string back into its 3 components.
// Format: <user>/<network>:<password>. First colon separates network from password;
// password may contain further colons. Returns null if it doesn't match.
function parseZncPass(pass){
  if(!pass||typeof pass!=='string')return null;
  const m=pass.match(/^([^/\s]+)\/([^:\s]+):(.+)$/);
  if(!m)return null;
  return {user:m[1], network:m[2], password:m[3]};
}
// Pure UI: show/hide ZNC vs Direct fields and relabel the server input. Doesn't
// mutate any user-entered values — safe to call during editNetwork without
// clobbering a saved config.
function applyServerModeUi(){
  const mode=document.getElementById('f-mode')?.value||'direct';
  const isZnc=mode==='znc';
  const znc=document.getElementById('znc-fields'); if(znc) znc.style.display=isZnc?'':'none';
  const passRow=document.getElementById('f-pass-row'); if(passRow) passRow.style.display=isZnc?'none':'';
  const saslSec=document.getElementById('f-sasl-section'); if(saslSec) saslSec.style.display=isZnc?'none':'';
  const srvLbl=document.getElementById('f-server-label'); if(srvLbl) srvLbl.textContent=isZnc?'ZNC Host':'Server';
}
// Pre-filled server presets for common IRC networks. Selecting one fills
// Label, Server, Port, and TLS; other fields (nick, SASL, etc.) are left
// untouched so the user can customize.
// Ports verified from each network's official docs. Several networks use
// self-signed or non-standard certs, so Accept-Invalid-Cert defaults to true
// for every preset — users can turn it off per-network if they want strict verification.
const NET_PRESETS={
  twistednet: {label:'TwistedNET',   server:'irc.twistednet.org',  port:6697, tls:true},
  libera:     {label:'Libera.Chat',  server:'irc.libera.chat',     port:6697, tls:true},
  oftc:       {label:'OFTC',         server:'irc.oftc.net',        port:6697, tls:true},
  undernet:   {label:'Undernet',     server:'irc.undernet.org',    port:6697, tls:true},
  ircnet:     {label:'IRCnet',       server:'irc.ircnet.net',      port:6697, tls:true},
  efnet:      {label:'EFnet',        server:'irc.efnet.org',       port:9999, tls:true},
  quakenet:   {label:'QuakeNet',     server:'irc.quakenet.org',    port:6697, tls:true},
  rizon:      {label:'Rizon',        server:'irc.rizon.net',       port:6697, tls:true},
  dalnet:     {label:'DALnet',       server:'irc.dal.net',         port:6697, tls:true},
  irchighway: {label:'IRCHighWay',   server:'irc.irchighway.net',  port:6697, tls:true},
  snoonet:    {label:'Snoonet',      server:'irc.snoonet.org',     port:6697, tls:true},
  geekshed:   {label:'GeekShed',     server:'irc.geekshed.net',    port:6697, tls:true},
  gamesurge:  {label:'GameSurge',    server:'irc.gamesurge.net',   port:6697, tls:true},
  slashnet:   {label:'SlashNET',     server:'irc.slashnet.org',    port:6697, tls:true},
  n2600:      {label:'2600net',      server:'irc.2600.net',        port:6697, tls:true},
  hackint:    {label:'Hackint',      server:'irc.hackint.org',     port:6697, tls:true},
  anonops:    {label:'AnonOps',      server:'irc.anonops.com',     port:6697, tls:true},
  chat4all:   {label:'Chat4All',     server:'irc.chat4all.org',    port:6697, tls:true},
  tildechat:  {label:'Tilde.chat',   server:'irc.tilde.chat',      port:6697, tls:true},
  esper:      {label:'EsperNet',     server:'irc.esper.net',       port:6697, tls:true},
};
function applyNetPreset(id){
  if(!id) return;
  const p=NET_PRESETS[id]; if(!p) return;
  document.getElementById('f-label').value=p.label;
  document.getElementById('f-server').value=p.server;
  document.getElementById('f-port').value=String(p.port);
  document.getElementById('f-tls').value=p.tls?'true':'false';
  const inv=document.getElementById('f-tls-invalid'); if(inv) inv.value='true';
}
// User-initiated mode change: apply UI toggle + ZNC-friendly defaults on the
// direct→znc transition only. Avoids clobbering values when editNetwork flips
// the mode programmatically with a real saved config already loaded.
let _prevServerMode='direct';
function onServerModeChange(){
  const mode=document.getElementById('f-mode').value;
  const isZnc=mode==='znc';
  applyServerModeUi();
  if(isZnc && _prevServerMode!=='znc'){
    // Apply ZNC-friendly defaults on fresh transition from direct mode.
    // Don't overwrite values the user has already set on the form.
    const portEl=document.getElementById('f-port');
    if(!portEl.value||portEl.value==='6667') portEl.value='6697';
    const tlsEl=document.getElementById('f-tls');
    if(tlsEl.value==='false') tlsEl.value='true';
    // ZNC commonly uses self-signed TLS, so default that to Yes.
    document.getElementById('f-tls-invalid').value='true';
    // ZNC handles SASL to the real network itself — disable client-side SASL.
    document.getElementById('f-sasl-method').value='none';
    onSaslMethodChange();
  }
  _prevServerMode=mode;
}
function saveNetwork(){
  const mode=document.getElementById('f-mode')?.value||'direct';
  const isZnc=mode==='znc';
  let saslMethod=document.getElementById('f-sasl-method').value;
  const srv=document.getElementById('f-server').value||'irc.twistednet.org';
  const aj=document.getElementById('f-autojoin').value.trim()||(srv==='irc.twistednet.org'?'#dev #twisted':'');
  // ZNC mode: compose PASS as <user>/<network>:<password> and stuff into the
  // server password field. Force SASL off — ZNC handles auth to the real network.
  let passValue=document.getElementById('f-pass').value||null;
  if(isZnc){
    const zu=document.getElementById('f-znc-user').value.trim();
    const zn=document.getElementById('f-znc-network').value.trim();
    const zp=document.getElementById('f-znc-pass').value;
    if(!zu||!zn){showToast('ZNC mode needs a username and network');return;}
    if(zp){
      passValue=`${zu}/${zn}:${zp}`;
    } else if(editingNetworkId){
      // On edit, if password field is blank, keep the existing saved password
      // but rebuild with any changes to user/network.
      const existing=networks.find(n=>n.config.id===editingNetworkId);
      const oldParsed=existing?parseZncPass(existing.config.password):null;
      if(oldParsed){
        passValue=`${zu}/${zn}:${oldParsed.password}`;
      } else {
        showToast('Enter the ZNC password to save');return;
      }
    } else {
      showToast('ZNC password required');return;
    }
    saslMethod='none';
  }
  const cfg={id:editingNetworkId||'',label:document.getElementById('f-label').value||srv,
    server:srv,port:parseInt(document.getElementById('f-port').value)||6697,
    tls:document.getElementById('f-tls').value==='true',tls_accept_invalid_certs:document.getElementById('f-tls-invalid').value==='true',
    nick:document.getElementById('f-nick').value||'CryptIRC',username:document.getElementById('f-user').value||'cryptirc',
    realname:document.getElementById('f-real').value||'CryptIRC User',password:passValue,
    sasl_plain:saslMethod==='plain'&&document.getElementById('f-sasl-account').value?{account:document.getElementById('f-sasl-account').value,password:document.getElementById('f-sasl-password').value}:null,
    sasl_external:saslMethod==='external',client_cert_id:null,
    auto_join:aj.split(/\s+/).filter(Boolean),
    auto_reconnect:document.getElementById('f-reconnect').value==='true',
    oper_login:document.getElementById('f-oper-login').value||null,
    oper_pass:document.getElementById('f-oper-pass').value||null,
    auto_identify:document.getElementById('f-auto-identify').value==='true',
    nickserv_pass:document.getElementById('f-nickserv-pass').value||null,
    disabled_caps:[...document.querySelectorAll('#f-caps-grid input[data-cap]:not(:checked)')].map(el=>el.dataset.cap),
    perform_commands:(document.getElementById('f-perform')?.value||'').split('\n').map(l=>l.trim()).filter(Boolean),
    quit_message:((document.getElementById('f-quit')?.value||'').trim())||null};
  if(editingNetworkId){
    wsend({type:'update_network',network:cfg}); closeModal();
  } else {
    wsend({type:'add_network',network:cfg}); closeModal();
    setTimeout(()=>{const n=networks[networks.length-1];if(n)wsend({type:'connect',id:n.config.id});},600);
  }
}

// ─── Encryption panel ─────────────────────────────────────────────────────────
function showEncryptPanel(){
  if(!active){return;}
  _bindEncryptDelegation();   // idempotent; binds the delegated button listener once
  const target=active.target;
  const conn_id=active.conn_id;
  const isChan=target.startsWith('#')||target.startsWith('&');
  const body=document.getElementById('encrypt-panel-body');
  const title=document.getElementById('encrypt-panel-title');

  if(isChan){
    title.textContent=`Encryption — ${target}`;
    const hasKey=window.E2E?.channelKeys?.[target];
    if(hasKey){
      body.innerHTML=`
        <div class="encrypt-status on">
          <span class="encrypt-status-icon">🔐</span>
          <div><strong>Encrypted</strong><br><span style="font-size:11px;color:var(--text2)">Messages in this channel are encrypted with a shared key</span></div>
        </div>
        <div class="encrypt-actions">
          <button class="encrypt-btn" data-encrypt-cmd="share">
            <span class="encrypt-btn-icon">👁</span>
            <div class="encrypt-btn-text">Show Key<div class="encrypt-btn-sub">Display the 32-word key in chat</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-fn="copyKey">
            <span class="encrypt-btn-icon">📋</span>
            <div class="encrypt-btn-text">Copy Key<div class="encrypt-btn-sub">Copy the 32-word key to clipboard</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-cmd="rotate">
            <span class="encrypt-btn-icon">🔄</span>
            <div class="encrypt-btn-text">Rotate Key<div class="encrypt-btn-sub">Generate a new key — old key holders lose access</div></div>
          </button>
          <button class="encrypt-btn danger" data-encrypt-cmd="off">
            <span class="encrypt-btn-icon">🔓</span>
            <div class="encrypt-btn-text">Disable Encryption<div class="encrypt-btn-sub">Remove channel key and send messages in plaintext</div></div>
          </button>
        </div>`;
    } else {
      body.innerHTML=`
        <div class="encrypt-status off">
          <span class="encrypt-status-icon">🔓</span>
          <div><strong>Not Encrypted</strong><br><span style="font-size:11px;color:var(--text3)">Messages are sent in plaintext</span></div>
        </div>
        <div class="encrypt-actions">
          <button class="encrypt-btn" data-encrypt-cmd="keygen">
            <span class="encrypt-btn-icon">🔑</span>
            <div class="encrypt-btn-text">Generate Key<div class="encrypt-btn-sub">Create a new encryption key for this channel</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-fn="importKey">
            <span class="encrypt-btn-icon">📥</span>
            <div class="encrypt-btn-text">Import Key<div class="encrypt-btn-sub">Enter a 32-word key shared by someone else</div></div>
          </button>
        </div>
        <div class="encrypt-note">
          Everyone in the channel needs the same key to read encrypted messages.
          Share the 32-word key privately (e.g. via DM) with people who should have access.
        </div>`;
    }
  } else if(target!=='status') {
    // DM
    title.textContent=`Encryption — ${target}`;
    const hasPSK=window.E2E?.channelKeys?.[target];
    const hasSession=window.E2E?.dmSessions?.[target];
    if(hasPSK){
      body.innerHTML=`
        <div class="encrypt-status on">
          <span class="encrypt-status-icon">🔐</span>
          <div><strong>PSK Encrypted</strong><br><span style="font-size:11px;color:var(--text2)">Using a shared key — works with any IRC client</span></div>
        </div>
        <div class="encrypt-actions">
          <button class="encrypt-btn" data-encrypt-cmd="share">
            <span class="encrypt-btn-icon">👁</span>
            <div class="encrypt-btn-text">Show Key<div class="encrypt-btn-sub">Display the 32-word key</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-fn="copyKey">
            <span class="encrypt-btn-icon">📋</span>
            <div class="encrypt-btn-text">Copy Key<div class="encrypt-btn-sub">Copy the 32-word key to clipboard</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-cmd="rotate">
            <span class="encrypt-btn-icon">🔄</span>
            <div class="encrypt-btn-text">Rotate Key<div class="encrypt-btn-sub">Generate a new key</div></div>
          </button>
          <button class="encrypt-btn danger" data-encrypt-cmd="off">
            <span class="encrypt-btn-icon">🔓</span>
            <div class="encrypt-btn-text">Disable Encryption<div class="encrypt-btn-sub">Send messages in plaintext</div></div>
          </button>
        </div>`;
    } else if(hasSession){
      body.innerHTML=`
        <div class="encrypt-status on">
          <span class="encrypt-status-icon">🔐</span>
          <div><strong>E2E Encrypted</strong><br><span style="font-size:11px;color:var(--text2)">Using Signal protocol (X3DH + Double Ratchet)</span></div>
        </div>
        <div class="encrypt-actions">
          <button class="encrypt-btn" data-encrypt-cmd="verify" data-encrypt-target="1">
            <span class="encrypt-btn-icon">✓</span>
            <div class="encrypt-btn-text">Verify Identity<div class="encrypt-btn-sub">Compare safety phrases to verify this person</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-cmd="fingerprint">
            <span class="encrypt-btn-icon">🆔</span>
            <div class="encrypt-btn-text">Your Fingerprint<div class="encrypt-btn-sub">Show your identity key fingerprint</div></div>
          </button>
          <button class="encrypt-btn danger" data-encrypt-cmd="off" data-encrypt-target="1">
            <span class="encrypt-btn-icon">🔓</span>
            <div class="encrypt-btn-text">End E2E Session<div class="encrypt-btn-sub">Stop encrypting messages to this user</div></div>
          </button>
        </div>`;
    } else {
      body.innerHTML=`
        <div class="encrypt-status off">
          <span class="encrypt-status-icon">🔓</span>
          <div><strong>Not Encrypted</strong><br><span style="font-size:11px;color:var(--text3)">Messages are sent in plaintext</span></div>
        </div>
        <div class="encrypt-actions">
          <button class="encrypt-btn" data-encrypt-cmd="keygen">
            <span class="encrypt-btn-icon">🔑</span>
            <div class="encrypt-btn-text">Shared Key (PSK)<div class="encrypt-btn-sub">Generate a key — share it with ${esc(target)} to encrypt DMs</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-fn="importKey">
            <span class="encrypt-btn-icon">📥</span>
            <div class="encrypt-btn-text">Import Key<div class="encrypt-btn-sub">Enter a 32-word key from ${esc(target)}</div></div>
          </button>
          <button class="encrypt-btn" data-encrypt-cmd="on" data-encrypt-target="1">
            <span class="encrypt-btn-icon">🔐</span>
            <div class="encrypt-btn-text">Signal E2E<div class="encrypt-btn-sub">Auto key exchange — requires ${esc(target)} on this CryptIRC server</div></div>
          </button>
        </div>`;
    }
  } else {
    title.textContent='Encryption';
    body.innerHTML='<div class="encrypt-note" style="text-align:center;padding:20px 0;">Select a channel or DM to manage encryption.</div>';
  }
  document.getElementById('encrypt-overlay').classList.add('show');
  _overlayOpen('encryptPanel', closeEncryptPanel);
}
function closeEncryptPanel(){_overlayClose('encryptPanel');document.getElementById('encrypt-overlay').classList.remove('show');}
// SECURITY: delegated handler for the encryption-panel buttons. The buttons carry
// a fixed data-encrypt-cmd (share/rotate/off/keygen/verify/fingerprint/on) plus an
// optional data-encrypt-target flag — never the PM nick interpolated into an inline
// handler JS-string (the old onclick="encryptAction('verify','…')" sinks, #9/#10).
// When the action needs the peer nick it uses active.target at click time (the panel
// only ever targets the active DM, so this is identical behavior). Bound lazily on
// first panel render (the body element lives below this script tag); idempotent.
function _bindEncryptDelegation(){
  const body=document.getElementById('encrypt-panel-body');
  if(!body||body._encryptDelegated)return;
  body._encryptDelegated=true;
  body.addEventListener('click',function(e){
    const btn=e.target.closest('[data-encrypt-cmd],[data-encrypt-fn]');
    if(!btn||!body.contains(btn))return;
    const fn=btn.dataset.encryptFn;
    if(fn==='copyKey'){copyChannelKey();return;}
    if(fn==='importKey'){showImportKeyUI();return;}
    const cmd=btn.dataset.encryptCmd;
    if(!cmd)return;
    encryptAction(cmd, btn.dataset.encryptTarget&&active?active.target:undefined);
  });
}
async function encryptAction(cmd,arg){
  if(!active)return;
  const args=arg?[cmd,arg]:[cmd];
  await handleEncryptCommand(args,active.conn_id,active.target);
  // Refresh panel after command completes
  for(const delay of [500,2000]){
    setTimeout(()=>{
      if(document.getElementById('encrypt-overlay').classList.contains('show'))showEncryptPanel();
    },delay);
  }
}
function showImportKeyUI(){
  const body=document.getElementById('encrypt-panel-body');
  body.innerHTML=`
    <div style="margin-bottom:12px;font-size:13px;color:var(--text2);">Enter the 32-word encryption key:</div>
    <div class="encrypt-input-wrap">
      <textarea class="encrypt-input" id="encrypt-import-words" rows="3" placeholder="word1 word2 word3 ... word32" style="resize:vertical;"></textarea>
    </div>
    <div class="encrypt-actions" style="flex-direction:row;gap:8px;">
      <button class="encrypt-btn" style="flex:1;justify-content:center;" onclick="showEncryptPanel()">
        <span class="encrypt-btn-text" style="text-align:center">Cancel</span>
      </button>
      <button class="encrypt-btn" style="flex:2;justify-content:center;background:var(--accent);color:#000;border-color:var(--accent);" onclick="doImportKey()">
        <span class="encrypt-btn-icon">🔑</span>
        <span class="encrypt-btn-text" style="text-align:center;font-weight:700;">Import Key</span>
      </button>
    </div>
    <div class="encrypt-note">Get this key from someone who already has encryption enabled on this channel. Share it only through a secure channel (e.g. encrypted DM).</div>`;
  document.getElementById('encrypt-import-words').focus();
}
async function doImportKey(){
  const raw=document.getElementById('encrypt-import-words').value.trim();
  if(!raw){return;}
  if(!active)return;
  // Extract only valid mnemonic words from pasted text (handles extra text, emojis, channel names, etc.)
  const tokens=raw.toLowerCase().split(/\s+/).filter(w=>w.length>1&&/^[a-z]+$/.test(w));
  const wl=window.WORDLIST||null;
  const filtered=wl?tokens.filter(w=>wl.includes(w)):tokens;
  const words=filtered.length===32?filtered:tokens;
  if(words.length!==32){
    e2eSysMsg(active.target,`❌ Expected 32 mnemonic words but found ${words.length}. Please paste only the 32-word key.`);
    return;
  }
  await handleEncryptCommand(['add',...words],active.conn_id,active.target);
  showEncryptPanel();
}

async function copyChannelKey(){
  if(!active)return;
  const key=window.E2E?.channelKeys?.[active.target];
  if(!key){showToast('No key set for this channel');return;}
  const raw=await crypto.subtle.exportKey('raw',key);
  const words=bytesToMnemonic(new Uint8Array(raw));
  try{await navigator.clipboard.writeText(words.join(' '));showToast('Key copied to clipboard!');}
  catch(e){await customPrompt('Copy this key:',words.join(' '));}
  closeEncryptPanel();
}

// ─── Appearance ───────────────────────────────────────────────────────────────
const THEMES={
  midnight: {label:'Midnight',bg0:'#0b0d0f',bg1:'#111418',bg2:'#181d24',bg3:'#1e242e',bg4:'#252c38',border:'#2a3444',border2:'#3a4a60',text:'#c8d8e8',text2:'#7a9ab8',text3:'#4a6278'},
  dracula:  {label:'Dracula', bg0:'#282a36',bg1:'#2d303e',bg2:'#343746',bg3:'#3b3f51',bg4:'#44495e',border:'#44475a',border2:'#6272a4',text:'#f8f8f2',text2:'#bd93f9',text3:'#6272a4'},
  monokai:  {label:'Monokai', bg0:'#272822',bg1:'#2d2e27',bg2:'#383830',bg3:'#3e3d32',bg4:'#49483e',border:'#49483e',border2:'#75715e',text:'#f8f8f2',text2:'#a6e22e',text3:'#75715e'},
  nord:     {label:'Nord',    bg0:'#2e3440',bg1:'#3b4252',bg2:'#434c5e',bg3:'#4c566a',bg4:'#576279',border:'#4c566a',border2:'#5e6779',text:'#eceff4',text2:'#88c0d0',text3:'#616e88'},
  solarize: {label:'Solar',   bg0:'#002b36',bg1:'#073642',bg2:'#0a3f4e',bg3:'#0d4a5a',bg4:'#1a5c6e',border:'#2aa198',border2:'#586e75',text:'#93a1a1',text2:'#839496',text3:'#586e75'},
  gruvbox:  {label:'Gruvbox', bg0:'#282828',bg1:'#3c3836',bg2:'#504945',bg3:'#665c54',bg4:'#7c6f64',border:'#504945',border2:'#665c54',text:'#ebdbb2',text2:'#b8bb26',text3:'#928374'},
  abyss:    {label:'Abyss',   bg0:'#000000',bg1:'#080808',bg2:'#101010',bg3:'#181818',bg4:'#222222',border:'#1a1a1a',border2:'#333333',text:'#cccccc',text2:'#888888',text3:'#555555'},
  light:    {label:'Light',   bg0:'#f5f5f5',bg1:'#ebebeb',bg2:'#e0e0e0',bg3:'#d5d5d5',bg4:'#cacaca',border:'#c0c0c0',border2:'#aaaaaa',text:'#1a1a1a',text2:'#444444',text3:'#888888'},
  cobalt:   {label:'Cobalt',  bg0:'#002240',bg1:'#002b50',bg2:'#003460',bg3:'#003d70',bg4:'#004880',border:'#0050a0',border2:'#1a6ab5',text:'#ffffff',text2:'#80d4ff',text3:'#4488aa'},
  onedark:  {label:'One Dark',bg0:'#21252b',bg1:'#282c34',bg2:'#2c313c',bg3:'#333842',bg4:'#3b4048',border:'#3e4451',border2:'#5c6370',text:'#abb2bf',text2:'#61afef',text3:'#5c6370'},
  catppuccin:{label:'Catppuccin',bg0:'#1e1e2e',bg1:'#181825',bg2:'#313244',bg3:'#45475a',bg4:'#585b70',border:'#45475a',border2:'#585b70',text:'#cdd6f4',text2:'#cba6f7',text3:'#6c7086'},
  rosepine: {label:'Rosé Pine',bg0:'#191724',bg1:'#1f1d2e',bg2:'#26233a',bg3:'#2a273f',bg4:'#393552',border:'#393552',border2:'#524f67',text:'#e0def4',text2:'#c4a7e7',text3:'#6e6a86'},
  tokyonight:{label:'Tokyo Night',bg0:'#1a1b26',bg1:'#16161e',bg2:'#1f2335',bg3:'#24283b',bg4:'#292e42',border:'#292e42',border2:'#3b4261',text:'#c0caf5',text2:'#7aa2f7',text3:'#565f89'},
  cyberpunk:{label:'Cyberpunk',bg0:'#0a0a0f',bg1:'#0f0f18',bg2:'#161622',bg3:'#1e1e2e',bg4:'#28283a',border:'#ff00ff33',border2:'#ff00ff55',text:'#e0e0ff',text2:'#ff00ff',text3:'#8888aa'},
  matrix:   {label:'Matrix',  bg0:'#000000',bg1:'#001100',bg2:'#002200',bg3:'#003300',bg4:'#004400',border:'#005500',border2:'#008800',text:'#00ff00',text2:'#00cc00',text3:'#006600'},
  ocean:    {label:'Ocean',   bg0:'#0d1926',bg1:'#132636',bg2:'#1a3346',bg3:'#214056',bg4:'#284d66',border:'#1e4060',border2:'#2a5a80',text:'#d4e8f8',text2:'#5cacee',text3:'#4a7090'},
  sunset:   {label:'Sunset',  bg0:'#1a0f1e',bg1:'#241528',bg2:'#2e1b32',bg3:'#38213c',bg4:'#422746',border:'#3d2640',border2:'#5a3860',text:'#e8d0e8',text2:'#ff8866',text3:'#8a6080'},
  blumhouse:{label:'Blumhouse',bg0:'#0a0000',bg1:'#120000',bg2:'#1a0505',bg3:'#220808',bg4:'#2d0b0b',border:'#3a0a0a',border2:'#551111',text:'#d4b8b8',text2:'#cc0000',text3:'#663333'},
  scream:   {label:'Scream',  bg0:'#000000',bg1:'#08080a',bg2:'#0e0e12',bg3:'#14141a',bg4:'#1c1c24',border:'#222233',border2:'#333355',text:'#e8e8f0',text2:'#f0f0f0',text3:'#555566'},
  forest:   {label:'🌧 Forest',bg0:'#0a120a',bg1:'#0d170d',bg2:'#111e11',bg3:'#162516',bg4:'#1b2d1b',border:'#1e3a1e',border2:'#2a4a2a',text:'#c8dcc8',text2:'#6abf6a',text3:'#4a7a4a',animation:'rain'},
  deepspace:    {label:'✦ Deep Space',bg0:'#050510',bg1:'#080818',bg2:'#0c0c22',bg3:'#10102c',bg4:'#161638',border:'#1a1a44',border2:'#2a2a66',text:'#c8d0e8',text2:'#6688cc',text3:'#3a4a70',animation:'deepspace'},
  snowfall:     {label:'❄ Snowfall',bg0:'#0a1018',bg1:'#0e1520',bg2:'#131c2a',bg3:'#182434',bg4:'#1e2c3e',border:'#243448',border2:'#344860',text:'#e0e8f4',text2:'#88a8cc',text3:'#506880',animation:'snowfall'},
  fireflies:    {label:'✧ Fireflies',bg0:'#080c06',bg1:'#0c1208',bg2:'#10180c',bg3:'#141e10',bg4:'#1a2616',border:'#1e3018',border2:'#2a4428',text:'#c8d8b8',text2:'#b8cc44',text3:'#5a6a3a',animation:'fireflies'},
  aurora:       {label:'◌ Aurora',bg0:'#060812',bg1:'#0a0e18',bg2:'#0e1420',bg3:'#121a2a',bg4:'#182234',border:'#1a2844',border2:'#2a3a5a',text:'#d0e0e8',text2:'#44ccaa',text3:'#3a6060',animation:'aurora'},
  digitalrain:  {label:'⟩ Digital Rain',bg0:'#020604',bg1:'#040a06',bg2:'#061008',bg3:'#08160a',bg4:'#0a1c0e',border:'#0e2812',border2:'#143818',text:'#44dd44',text2:'#22aa22',text3:'#116611',animation:'digitalrain'},
  neongrid:     {label:'⊞ Neon Grid',bg0:'#08060e',bg1:'#0c0a16',bg2:'#120e1e',bg3:'#181228',bg4:'#1e1832',border:'#281e44',border2:'#382866',text:'#e0d8f0',text2:'#00ccff',text3:'#6644aa',animation:'neongrid'},
  underwater:   {label:'◎ Underwater',bg0:'#04101a',bg1:'#061620',bg2:'#081c28',bg3:'#0a2430',bg4:'#0e2c3a',border:'#103848',border2:'#1a4c60',text:'#b8d8e8',text2:'#44aabb',text3:'#2a6678',animation:'underwater'},
  cherryblossom:{label:'✿ Blossom',bg0:'#100a0e',bg1:'#161012',bg2:'#1c1618',bg3:'#241c20',bg4:'#2c2228',border:'#382a30',border2:'#4a3a44',text:'#e8d8dc',text2:'#e888a0',text3:'#886068',animation:'cherryblossom'},
  starwarp:     {label:'⋆ Starfield',bg0:'#000004',bg1:'#04040c',bg2:'#080814',bg3:'#0c0c1e',bg4:'#121228',border:'#1a1a38',border2:'#2a2a50',text:'#d0d0e8',text2:'#8888cc',text3:'#4a4a78',animation:'starwarp'},
  ember:        {label:'⊙ Ember',bg0:'#100804',bg1:'#180e06',bg2:'#201408',bg3:'#281a0c',bg4:'#322010',border:'#3a2814',border2:'#503820',text:'#e8d0b8',text2:'#ee8833',text3:'#886030',animation:'ember'},
  nebula:       {label:'☁ Nebula',bg0:'#0a0610',bg1:'#0e0a18',bg2:'#140e22',bg3:'#1a122c',bg4:'#201838',border:'#281e48',border2:'#382a60',text:'#d8c8e8',text2:'#aa66ee',text3:'#6644aa',animation:'nebula'},
  confetti:     {label:'◈ Confetti',bg0:'#0e0e12',bg1:'#14141a',bg2:'#1a1a22',bg3:'#20202c',bg4:'#282836',border:'#303044',border2:'#404060',text:'#e8e8f0',text2:'#ff8844',text3:'#666680',animation:'confetti'},
  campfire:     {label:'♨ Campfire',bg0:'#0e0804',bg1:'#140c06',bg2:'#1a1208',bg3:'#22180c',bg4:'#2a1e10',border:'#342816',border2:'#483820',text:'#e0d0b0',text2:'#ee9944',text3:'#806830',animation:'campfire'},
  oceanwaves:   {label:'≈ Ocean Waves',bg0:'#04101c',bg1:'#061624',bg2:'#081e2e',bg3:'#0c2638',bg4:'#102e42',border:'#163a50',border2:'#204c66',text:'#c0d8e8',text2:'#3399cc',text3:'#2a6688',animation:'oceanwaves'},
  plasma:       {label:'◉ Plasma',bg0:'#0a0810',bg1:'#100c18',bg2:'#161020',bg3:'#1c142a',bg4:'#241a34',border:'#2c2040',border2:'#3c2c58',text:'#d8d0e8',text2:'#cc66ff',text3:'#7744aa',animation:'plasma'},
  oceandeep:    {label:'Ocean Deep',bg0:'#040e16',bg1:'#061420',bg2:'#081a2a',bg3:'#0c2234',bg4:'#102a3e',border:'#143650',border2:'#1e4a68',text:'#b0d0e4',text2:'#2288bb',text3:'#1a5a7a'},
  neontokyo:    {label:'Neon Tokyo',bg0:'#0c0814',bg1:'#120c1c',bg2:'#181024',bg3:'#1e142e',bg4:'#261a38',border:'#302044',border2:'#442e60',text:'#e0d0f0',text2:'#ff3388',text3:'#8844aa'},
  vaporwave:    {label:'Vaporwave',bg0:'#1a0e24',bg1:'#221434',bg2:'#2a1a40',bg3:'#32204c',bg4:'#3a2658',border:'#442e66',border2:'#5a3e80',text:'#e8d0ff',text2:'#ff71ce',text3:'#8a58aa'},
  bloodmoon:    {label:'Blood Moon',bg0:'#100404',bg1:'#180606',bg2:'#200a0a',bg3:'#2a0e0e',bg4:'#341212',border:'#401818',border2:'#582424',text:'#e0b8b8',text2:'#dd2222',text3:'#883030'},
  arctic:       {label:'Arctic',bg0:'#0c1218',bg1:'#101820',bg2:'#141e28',bg3:'#1a2632',bg4:'#202e3c',border:'#283a4c',border2:'#384e64',text:'#e4eef4',text2:'#66bbdd',text3:'#4a7a90'},
  goldenhour:   {label:'Golden Hour',bg0:'#141008',bg1:'#1a1610',bg2:'#221c14',bg3:'#2a2218',bg4:'#342a1e',border:'#3e3424',border2:'#584a34',text:'#e8dcc0',text2:'#ddaa44',text3:'#887040'},
  midnightpurple:{label:'Midnight Purple',bg0:'#0a0612',bg1:'#0e0a1a',bg2:'#140e24',bg3:'#1a1230',bg4:'#20183c',border:'#281e4c',border2:'#382a66',text:'#d0c0e8',text2:'#9966ff',text3:'#5a3aaa'},
  termgreen:    {label:'Terminal Green',bg0:'#040804',bg1:'#060c06',bg2:'#081208',bg3:'#0c180c',bg4:'#0e1e0e',border:'#142814',border2:'#1e381e',text:'#88ee88',text2:'#44bb44',text3:'#227722'},
  neonmint:     {label:'Neon Mint',bg0:'#060e0e',bg1:'#0a1414',bg2:'#0e1a1a',bg3:'#122222',bg4:'#182a2a',border:'#1e3636',border2:'#2a4a4a',text:'#c8f0e8',text2:'#00eebb',text3:'#337766'},
  stealth:      {label:'Stealth',bg0:'#0e0e0e',bg1:'#141414',bg2:'#1a1a1a',bg3:'#222222',bg4:'#2a2a2a',border:'#333333',border2:'#444444',text:'#aaaaaa',text2:'#777777',text3:'#505050'},
  lava:         {label:'Lava',bg0:'#120400',bg1:'#1a0800',bg2:'#220c00',bg3:'#2c1000',bg4:'#361400',border:'#441a00',border2:'#602800',text:'#e8c8a0',text2:'#ff6600',text3:'#884400'},
  frost:        {label:'Frost',bg0:'#0a1020',bg1:'#0e1628',bg2:'#121c32',bg3:'#18243c',bg4:'#1e2c48',border:'#243658',border2:'#304870',text:'#d8e8f8',text2:'#88ccff',text3:'#4a7aaa'},
  cyberdeck:    {label:'Cyberdeck',bg0:'#0a0a10',bg1:'#0e0e18',bg2:'#141420',bg3:'#1a1a2a',bg4:'#222234',border:'#2a2a44',border2:'#3a3a5c',text:'#c8c8e0',text2:'#00ff88',text3:'#4a4a6a'},
  phantom:      {label:'Phantom',bg0:'#08080c',bg1:'#0e0e14',bg2:'#14141c',bg3:'#1a1a26',bg4:'#222230',border:'#2a2a3c',border2:'#3c3c52',text:'#c0c0d0',text2:'#8888aa',text3:'#505068'},
  hacker:       {label:'Hacker',bg0:'#000000',bg1:'#060606',bg2:'#0c0c0c',bg3:'#141414',bg4:'#1c1c1c',border:'#262626',border2:'#383838',text:'#33ff33',text2:'#22cc22',text3:'#0f7a0f'},
  coffee:       {label:'Coffee',bg0:'#120e08',bg1:'#181410',bg2:'#1e1a14',bg3:'#262018',bg4:'#2e281e',border:'#383026',border2:'#4a4234',text:'#d8ccb0',text2:'#b8884a',text3:'#7a6040'},
  emerald:      {label:'Emerald',bg0:'#040e08',bg1:'#061410',bg2:'#081a14',bg3:'#0c221a',bg4:'#102a20',border:'#143628',border2:'#1e4a3a',text:'#b8e8cc',text2:'#22cc66',text3:'#1a7a44'},
  ruby:         {label:'Ruby',bg0:'#100408',bg1:'#18060c',bg2:'#200a12',bg3:'#280e18',bg4:'#32121e',border:'#3e1a28',border2:'#582438',text:'#e8c0cc',text2:'#dd2255',text3:'#883050'},
  sapphire:     {label:'Sapphire',bg0:'#040810',bg1:'#060e18',bg2:'#081420',bg3:'#0c1a2a',bg4:'#102034',border:'#142a44',border2:'#1e3a5c',text:'#c0d0e8',text2:'#2266ee',text3:'#1a4a8a'},
  amethyst:     {label:'Amethyst',bg0:'#0c0610',bg1:'#120a18',bg2:'#180e22',bg3:'#1e122c',bg4:'#261838',border:'#301e48',border2:'#442a60',text:'#d8c0e8',text2:'#8833dd',text3:'#5a2a88'},
  coral:        {label:'Coral',bg0:'#120808',bg1:'#1a0e0e',bg2:'#221414',bg3:'#2a1a1a',bg4:'#342222',border:'#3e2a2a',border2:'#543c3c',text:'#e8d0c8',text2:'#ff6655',text3:'#885050'},
  obsidian:     {label:'Obsidian',bg0:'#080808',bg1:'#0e0e10',bg2:'#141418',bg3:'#1a1a20',bg4:'#22222a',border:'#2a2a34',border2:'#3a3a48',text:'#b8b8c8',text2:'#6666aa',text3:'#444466'},
  rosegold:     {label:'Rose Gold',bg0:'#120c0c',bg1:'#1a1212',bg2:'#221818',bg3:'#2a1e1e',bg4:'#342626',border:'#3e2e2e',border2:'#544040',text:'#e8d4cc',text2:'#dd8877',text3:'#886058'},
  retroterminal:{label:'Retro Terminal',bg0:'#001000',bg1:'#001800',bg2:'#002200',bg3:'#002c00',bg4:'#003600',border:'#004400',border2:'#005e00',text:'#33ff00',text2:'#28cc00',text3:'#167700'},
  bladerunner:  {label:'Blade Runner',bg0:'#0a0810',bg1:'#100c18',bg2:'#161020',bg3:'#1c1428',bg4:'#241a32',border:'#2c2040',border2:'#3c2c58',text:'#d8c8d4',text2:'#ee6644',text3:'#7a5060'},
  outrun:       {label:'Outrun',bg0:'#0c0418',bg1:'#120620',bg2:'#1a082c',bg3:'#220a38',bg4:'#2a0e44',border:'#341258',border2:'#441a70',text:'#e0c0ff',text2:'#ff2299',text3:'#8844aa'},
  hotlinemiami: {label:'Hotline Miami',bg0:'#1a0c14',bg1:'#22101c',bg2:'#2a1424',bg3:'#34182e',bg4:'#3e1c38',border:'#4a2444',border2:'#603060',text:'#f0d0e0',text2:'#ff4488',text3:'#aa4480'},
  lofi:         {label:'Lo-fi',bg0:'#14120e',bg1:'#1c1a14',bg2:'#24221a',bg3:'#2c2a22',bg4:'#363228',border:'#403a30',border2:'#584e44',text:'#d8d0c0',text2:'#aaaa66',text3:'#706a50'},
  darkwave:     {label:'Darkwave',bg0:'#06060e',bg1:'#0a0a16',bg2:'#0e0e1e',bg3:'#141428',bg4:'#1a1a32',border:'#222240',border2:'#303058',text:'#c0c0e0',text2:'#6666dd',text3:'#3a3a88'},
  copper:       {label:'Copper',bg0:'#100a06',bg1:'#180e08',bg2:'#20140c',bg3:'#281a10',bg4:'#302014',border:'#3a281a',border2:'#503824',text:'#e0ccb0',text2:'#cc8844',text3:'#886038'},
  slate:        {label:'Slate',bg0:'#0e1014',bg1:'#14181c',bg2:'#1a1e24',bg3:'#20262e',bg4:'#282e38',border:'#303844',border2:'#404c5c',text:'#c8d0d8',text2:'#7088a0',text3:'#4a5a6c'},
  charcoal:     {label:'Charcoal',bg0:'#101010',bg1:'#161616',bg2:'#1c1c1c',bg3:'#242424',bg4:'#2c2c2c',border:'#363636',border2:'#484848',text:'#c8c8c8',text2:'#888888',text3:'#585858'},
  graphite:     {label:'Graphite',bg0:'#0c0e10',bg1:'#121416',bg2:'#181a1e',bg3:'#1e2226',bg4:'#262a2e',border:'#2e3438',border2:'#3e4448',text:'#c0c8cc',text2:'#6a7a84',text3:'#4a5660'},
  indigonight:  {label:'Indigo Night',bg0:'#080614',bg1:'#0c0a1c',bg2:'#120e26',bg3:'#181230',bg4:'#1e183c',border:'#261e4c',border2:'#342a64',text:'#c8c0e0',text2:'#5544ee',text3:'#3a2aaa'},
  twilight:     {label:'Twilight',bg0:'#0e0a14',bg1:'#14101c',bg2:'#1a1624',bg3:'#221c2e',bg4:'#2a2238',border:'#322a44',border2:'#44385c',text:'#d8cce0',text2:'#cc7788',text3:'#7a5068'},
  alien:        {label:'👽 Alien',bg0:'#020808',bg1:'#041010',bg2:'#061818',bg3:'#082020',bg4:'#0c2c2c',border:'#0e3a2a',border2:'#145038',text:'#88ffcc',text2:'#44ee88',text3:'#227744',animation:'alien'},
  lightning:    {label:'⚡ Lightning',bg0:'#0a0a14',bg1:'#0e0e1c',bg2:'#141424',bg3:'#1a1a2e',bg4:'#202038',border:'#282844',border2:'#383866',text:'#d0d0e0',text2:'#aaaaff',text3:'#5555aa',animation:'lightning'},
  sandstorm:    {label:'🏜 Sandstorm',bg0:'#141008',bg1:'#1c1610',bg2:'#241e16',bg3:'#2c261e',bg4:'#362e24',border:'#40382c',border2:'#584c3c',text:'#e0d8c4',text2:'#ccaa66',text3:'#887044',animation:'sandstorm'},
  hologram:     {label:'◇ Hologram',bg0:'#040810',bg1:'#061018',bg2:'#081820',bg3:'#0c202a',bg4:'#102834',border:'#143444',border2:'#1e4860',text:'#c0e8f0',text2:'#00eeff',text3:'#2a7788',animation:'hologram'},
  meteorshower: {label:'☄ Meteors',bg0:'#06040e',bg1:'#0a0816',bg2:'#0e0c1e',bg3:'#141028',bg4:'#1a1432',border:'#221a40',border2:'#302660',text:'#d4c8e8',text2:'#ff8844',text3:'#6644aa',animation:'meteorshower'},
  pixelrain:    {label:'▦ Pixel Rain',bg0:'#040604',bg1:'#080c08',bg2:'#0c120c',bg3:'#101810',bg4:'#141e14',border:'#1a281a',border2:'#223822',text:'#b0e0b0',text2:'#44dd88',text3:'#226640',animation:'pixelrain'},
  synthsun:     {label:'▽ Synthwave',bg0:'#0e041a',bg1:'#140822',bg2:'#1c0c2c',bg3:'#241038',bg4:'#2c1444',border:'#381c58',border2:'#4a2870',text:'#e0c0f0',text2:'#ff44aa',text3:'#8844aa',animation:'synthsun'},
  toxicrain:    {label:'☢ Toxic Rain',bg0:'#040804',bg1:'#080e08',bg2:'#0c140c',bg3:'#101c10',bg4:'#142414',border:'#1a3018',border2:'#244420',text:'#c0e8b0',text2:'#66ff22',text3:'#338822',animation:'toxicrain'},
  fairydust:    {label:'✦ Fairy Dust',bg0:'#0c0a12',bg1:'#12101a',bg2:'#181622',bg3:'#1e1c2c',bg4:'#262236',border:'#302a44',border2:'#403a5c',text:'#d8d0e8',text2:'#eebb44',text3:'#7a6888',animation:'fairydust'},
  comettrail:   {label:'☆ Comets',bg0:'#040610',bg1:'#060a18',bg2:'#0a0e22',bg3:'#0e142c',bg4:'#141a38',border:'#1a2248',border2:'#243260',text:'#c8d4f0',text2:'#88bbff',text3:'#4466aa',animation:'comettrail'},
  lavalamp:     {label:'● Lava Lamp',bg0:'#100804',bg1:'#180c06',bg2:'#201208',bg3:'#28180c',bg4:'#301e10',border:'#3c2816',border2:'#503820',text:'#e8d0b0',text2:'#ff6622',text3:'#884422',animation:'lavalamp'},
  electricarc:  {label:'϶ Electric',bg0:'#04060e',bg1:'#060a16',bg2:'#080e20',bg3:'#0c122a',bg4:'#101834',border:'#142044',border2:'#1c2e5c',text:'#c0d0f0',text2:'#44aaff',text3:'#2266aa',animation:'electricarc'},
  galaxy:       {label:'☊ Galaxy',bg0:'#080410',bg1:'#0c0818',bg2:'#120c22',bg3:'#18102e',bg4:'#1e163a',border:'#281e4c',border2:'#342a66',text:'#d0c4e8',text2:'#bb66ff',text3:'#6644aa',animation:'galaxy'},
  glitch:       {label:'▣ Glitch',bg0:'#0a0a0e',bg1:'#101016',bg2:'#16161e',bg3:'#1c1c28',bg4:'#242432',border:'#2c2c40',border2:'#3c3c58',text:'#d0d0e0',text2:'#ff4466',text3:'#5555aa',animation:'glitch'},
  firewall:     {label:'⧫ Firewall',bg0:'#0c0804',bg1:'#120e08',bg2:'#18140c',bg3:'#201a10',bg4:'#282016',border:'#342a1c',border2:'#483c2c',text:'#e0d4b8',text2:'#ff8800',text3:'#886622',animation:'firewall'},
  northern:     {label:'❂ Northern',bg0:'#040810',bg1:'#060e18',bg2:'#0a1420',bg3:'#0e1a2a',bg4:'#142234',border:'#1a2c44',border2:'#243e5c',text:'#c8e0f0',text2:'#44ddaa',text3:'#2a7060',animation:'northern'},
  pumpkin:      {label:'Pumpkin Spice',bg0:'#141006',bg1:'#1c160a',bg2:'#241e0e',bg3:'#2e2614',bg4:'#382e1a',border:'#443822',border2:'#5c4c30',text:'#e8d8b8',text2:'#ee8822',text3:'#886620'},
  deepsea:      {label:'Deep Sea',bg0:'#020c14',bg1:'#04121c',bg2:'#061a26',bg3:'#0a2230',bg4:'#0e2a3c',border:'#123650',border2:'#1a4a68',text:'#a8d0e8',text2:'#1188cc',text3:'#0a5a88'},
  neonblue:     {label:'Neon Blue',bg0:'#04040e',bg1:'#080816',bg2:'#0c0c20',bg3:'#10102a',bg4:'#161636',border:'#1c1c48',border2:'#2a2a66',text:'#c8c8f0',text2:'#4488ff',text3:'#2244bb'},
  bubblegum:    {label:'Bubblegum',bg0:'#120810',bg1:'#1a0e18',bg2:'#221420',bg3:'#2c1a2a',bg4:'#362234',border:'#422a40',border2:'#5a3c58',text:'#f0d0e8',text2:'#ff66aa',text3:'#aa4488'},
  volcanic:     {label:'Volcanic',bg0:'#100400',bg1:'#1a0800',bg2:'#240e00',bg3:'#301400',bg4:'#3c1a00',border:'#4c2200',border2:'#663400',text:'#e8c8a0',text2:'#ff4400',text3:'#aa3300'},
  pineforest:   {label:'Pine Forest',bg0:'#060c08',bg1:'#0a1410',bg2:'#0e1c16',bg3:'#12241c',bg4:'#182c22',border:'#1e382c',border2:'#2a4c3c',text:'#c0dcc8',text2:'#44aa66',text3:'#2a6a40'},
  burgundy:     {label:'Burgundy',bg0:'#100408',bg1:'#18080e',bg2:'#220c14',bg3:'#2c101a',bg4:'#361420',border:'#441a28',border2:'#5c2438',text:'#e8c8d0',text2:'#cc2244',text3:'#882244'},
  teal:         {label:'Teal',bg0:'#040c0c',bg1:'#081414',bg2:'#0c1c1c',bg3:'#102424',bg4:'#142e2e',border:'#1a3a3a',border2:'#244e4e',text:'#c0e8e4',text2:'#22bbaa',text3:'#1a7a70'},
  solarflare:   {label:'Solar Flare',bg0:'#120804',bg1:'#1c0e08',bg2:'#28140c',bg3:'#341a10',bg4:'#402014',border:'#4e2a1a',border2:'#663c24',text:'#e8d4b8',text2:'#ffaa22',text3:'#aa6a22'},
  winterfell:   {label:'Winterfell',bg0:'#0a0e14',bg1:'#10161e',bg2:'#141e28',bg3:'#1a2632',bg4:'#202e3c',border:'#283a4c',border2:'#384e64',text:'#dce8f4',text2:'#88aacc',text3:'#4a6a88'},
  sakura:       {label:'Sakura',bg0:'#120a0c',bg1:'#1a1014',bg2:'#22161c',bg3:'#2a1c24',bg4:'#34222c',border:'#402a34',border2:'#583c48',text:'#f0d8dc',text2:'#ee6688',text3:'#aa5068'},
  cybernetic:   {label:'Cybernetic',bg0:'#060808',bg1:'#0c1010',bg2:'#121818',bg3:'#182020',bg4:'#1e2a2a',border:'#263636',border2:'#344a4a',text:'#c8e0dc',text2:'#00ddcc',text3:'#228878'},
  desert:       {label:'Desert',bg0:'#14100a',bg1:'#1c1810',bg2:'#261e16',bg3:'#30261c',bg4:'#3a2e22',border:'#463828',border2:'#5e4c38',text:'#e4d8c0',text2:'#cc9944',text3:'#887040'},
  ivory:        {label:'Ivory Tower',bg0:'#f0ece4',bg1:'#e8e4dc',bg2:'#dedad0',bg3:'#d4d0c6',bg4:'#c8c4b8',border:'#b8b4a8',border2:'#a0a090',text:'#2a2820',text2:'#605848',text3:'#908878'},
  noir:         {label:'Noir',bg0:'#050505',bg1:'#0a0a0a',bg2:'#111111',bg3:'#181818',bg4:'#202020',border:'#2a2a2a',border2:'#3a3a3a',text:'#c0c0c0',text2:'#808080',text3:'#484848'},
  spearmint:    {label:'Spearmint',bg0:'#06100c',bg1:'#0a1812',bg2:'#0e2018',bg3:'#12281e',bg4:'#183226',border:'#1e3e30',border2:'#2a5444',text:'#c4e8d8',text2:'#44cc88',text3:'#2a8858'},
  ultraviolet:  {label:'Ultraviolet',bg0:'#0a0414',bg1:'#10081c',bg2:'#180c28',bg3:'#201034',bg4:'#281640',border:'#321e54',border2:'#442a70',text:'#d4c0f0',text2:'#aa44ff',text3:'#6a2aaa'},
  warmgray:     {label:'Warm Gray',bg0:'#121010',bg1:'#1a1616',bg2:'#221e1e',bg3:'#2a2626',bg4:'#342e2e',border:'#3e3838',border2:'#524c4c',text:'#d0c8c8',text2:'#a09090',text3:'#686060'},
  wine:         {label:'Wine',bg0:'#100608',bg1:'#180a0e',bg2:'#200e14',bg3:'#28121a',bg4:'#321620',border:'#3e1c28',border2:'#562838',text:'#e4c8cc',text2:'#bb3355',text3:'#883344'},
  zinc:         {label:'Zinc',bg0:'#0c0e10',bg1:'#121416',bg2:'#181c1e',bg3:'#202426',bg4:'#282c2e',border:'#323638',border2:'#444a4c',text:'#c8ccce',text2:'#7a8488',text3:'#505860'},
  petrol:       {label:'Petrol',bg0:'#060a0e',bg1:'#0a1014',bg2:'#0e161c',bg3:'#141e26',bg4:'#1a2630',border:'#203040',border2:'#2c4258',text:'#b8d0dc',text2:'#3388aa',text3:'#1a5a78'},
  oxide:        {label:'Oxide',bg0:'#0e0808',bg1:'#160e0c',bg2:'#1e1410',bg3:'#281a14',bg4:'#32201a',border:'#3e2a22',border2:'#543a30',text:'#dcc8b8',text2:'#cc6633',text3:'#884830'},
  candy:        {label:'Candy',bg0:'#100810',bg1:'#180e18',bg2:'#201420',bg3:'#2a1a2a',bg4:'#342234',border:'#402a40',border2:'#583c58',text:'#f0d0f0',text2:'#ee44cc',text3:'#aa3388'},
  dusk:         {label:'Dusk',bg0:'#0c0810',bg1:'#140e18',bg2:'#1c1420',bg3:'#241a2a',bg4:'#2e2234',border:'#382a40',border2:'#4c3c58',text:'#dcd0e4',text2:'#aa88cc',text3:'#6a5088'},
  sepia:        {label:'Sepia',bg0:'#12100a',bg1:'#1a1610',bg2:'#221e16',bg3:'#2c261e',bg4:'#362e24',border:'#40382c',border2:'#584e3c',text:'#dcd4c0',text2:'#aa8844',text3:'#786038'},
  mango:        {label:'Mango',bg0:'#140e04',bg1:'#1c1408',bg2:'#261c0c',bg3:'#302410',bg4:'#3c2c16',border:'#48361c',border2:'#604a28',text:'#e8dcc0',text2:'#ffaa00',text3:'#aa7400'},
  wasabi:       {label:'Wasabi',bg0:'#080c04',bg1:'#0e1408',bg2:'#141c0c',bg3:'#1a2410',bg4:'#202e16',border:'#283a1e',border2:'#364e2a',text:'#d0e0b8',text2:'#88cc22',text3:'#5a8820'},
  ash:          {label:'Ash',bg0:'#0e0e0c',bg1:'#141412',bg2:'#1c1c18',bg3:'#24241e',bg4:'#2c2c26',border:'#363630',border2:'#4a4a40',text:'#c8c8c0',text2:'#8a8a78',text3:'#5c5c50'},
  mauve:        {label:'Mauve',bg0:'#0e0a10',bg1:'#141018',bg2:'#1c1620',bg3:'#241e2a',bg4:'#2c2634',border:'#342e40',border2:'#48405a',text:'#dcd0e0',text2:'#bb88cc',text3:'#7a5a88'},
  tundra:       {label:'Tundra',bg0:'#0a0c10',bg1:'#101418',bg2:'#161c22',bg3:'#1e242c',bg4:'#262e36',border:'#303a46',border2:'#404e5e',text:'#d0d8e0',text2:'#7898b0',text3:'#4a6478'},
  verdant:      {label:'Verdant',bg0:'#040a06',bg1:'#081208',bg2:'#0c1a0e',bg3:'#102214',bg4:'#162a1a',border:'#1c3622',border2:'#284a30',text:'#c0dcc4',text2:'#22bb44',text3:'#1a7a30'},
  salmon:       {label:'Salmon',bg0:'#120a08',bg1:'#1a100e',bg2:'#221614',bg3:'#2a1c1a',bg4:'#342422',border:'#3e2c2a',border2:'#543e3a',text:'#e8d4cc',text2:'#ee7766',text3:'#aa5a50'},
  storm:        {label:'Storm',bg0:'#08080e',bg1:'#0e0e16',bg2:'#14141e',bg3:'#1a1a28',bg4:'#222232',border:'#2a2a3e',border2:'#3a3a56',text:'#c8c8d8',text2:'#6688bb',text3:'#445880'},
  glacier:      {label:'Glacier',bg0:'#081014',bg1:'#0e181e',bg2:'#142028',bg3:'#1a2832',bg4:'#22323e',border:'#2a3e4e',border2:'#385266',text:'#d4e4f0',text2:'#66aadd',text3:'#3a7098'},
  sunflower:    {label:'Sunflower',bg0:'#121004',bg1:'#1a1808',bg2:'#24200c',bg3:'#2e2810',bg4:'#383016',border:'#443a1e',border2:'#5c4e2a',text:'#e8e0c0',text2:'#eecc00',text3:'#aa8c00'},
  // ── SCENE PACK: Nature (10) ─────────────────────────────────────────────────
  tokyo_sunset: {label:'🗼 Tokyo Sunset',bg0:'#140818',bg1:'#1c0a1e',bg2:'#240c22',bg3:'#2e1028',bg4:'#3a1630',border:'#4a1c3a',border2:'#66264c',text:'#f4d8e4',text2:'#ff7a9a',text3:'#a06680',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='g' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23301040'/><stop offset='.45' stop-color='%23c8447a'/><stop offset='.75' stop-color='%23ff8a4a'/><stop offset='1' stop-color='%23ffc070'/></linearGradient></defs><rect width='800' height='400' fill='url(%23g)'/><circle cx='560' cy='260' r='50' fill='%23ffdc88' opacity='.7'/><polygon points='0,400 0,300 40,300 50,270 70,270 80,300 120,300 120,260 160,260 170,220 175,160 180,220 190,260 240,260 250,240 280,240 290,260 340,260 360,230 380,230 390,260 440,260 460,240 500,240 510,260 560,260 580,210 610,210 620,260 680,260 700,240 740,240 750,270 800,270 800,400' fill='%23080410'/></svg>\")",animation:'tokyoSunsetGlow'},
  misty_mountain: {label:'⛰ Misty Mountain',bg0:'#0a1218',bg1:'#0e1820',bg2:'#121e28',bg3:'#182632',bg4:'#1e2e3c',border:'#243648',border2:'#34485e',text:'#d8e2ec',text2:'#88a4b8',text3:'#526a80',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='s' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23182838'/><stop offset='1' stop-color='%23506878'/></linearGradient></defs><rect width='800' height='400' fill='url(%23s)'/><polygon points='0,260 120,180 220,230 340,160 460,220 580,150 720,210 800,190 800,400 0,400' fill='%23304858' opacity='.55'/><polygon points='0,300 140,230 260,270 400,210 520,260 660,200 800,240 800,400 0,400' fill='%23203848' opacity='.7'/><polygon points='0,340 160,280 300,320 440,270 580,310 720,270 800,300 800,400 0,400' fill='%23101e2a'/></svg>\")",animation:'mistDrift'},
  bamboo_forest: {label:'🎋 Bamboo Forest',bg0:'#060e08',bg1:'#0a140c',bg2:'#0e1a10',bg3:'#142216',bg4:'#1a2c1c',border:'#223824',border2:'#305038',text:'#d0e4c8',text2:'#88c888',text3:'#4a7a52',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400'><rect width='800' height='400' fill='%23081408'/><g fill='%232a5030' opacity='.7'><rect x='60' y='0' width='14' height='400'/><rect x='180' y='0' width='18' height='400'/><rect x='320' y='0' width='12' height='400'/><rect x='440' y='0' width='16' height='400'/><rect x='580' y='0' width='14' height='400'/><rect x='700' y='0' width='18' height='400'/></g><g stroke='%23143820' stroke-width='2' opacity='.8'><line x1='55' y1='80' x2='79' y2='80'/><line x1='55' y1='200' x2='79' y2='200'/><line x1='55' y1='320' x2='79' y2='320'/><line x1='175' y1='120' x2='203' y2='120'/><line x1='315' y1='60' x2='337' y2='60'/><line x1='435' y1='160' x2='461' y2='160'/><line x1='575' y1='100' x2='599' y2='100'/></g></svg>\")"},
  tropical_beach: {label:'🌴 Tropical Beach',bg0:'#120a10',bg1:'#1a0e14',bg2:'#221218',bg3:'#2c161e',bg4:'#361c24',border:'#442430',border2:'#5c3442',text:'#f0d4c0',text2:'#ff9966',text3:'#a06858',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='sk' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23241030'/><stop offset='.55' stop-color='%23d85a44'/><stop offset='1' stop-color='%23ffb060'/></linearGradient></defs><rect width='800' height='400' fill='url(%23sk)'/><circle cx='600' cy='240' r='40' fill='%23ffe0a0' opacity='.85'/><path d='M0 280 Q200 270 400 282 T800 278 L800 400 L0 400Z' fill='%23180a14'/><g fill='%23050208'><rect x='140' y='120' width='6' height='200'/><path d='M143 120 Q100 100 60 120 Q100 110 143 130'/><path d='M143 120 Q180 95 220 115 Q180 105 143 128'/><path d='M143 120 Q170 80 200 60 Q165 90 145 125'/></g></svg>\")",animation:'beachShimmer'},
  desert_dunes: {label:'🏜 Desert Dunes',bg0:'#14100a',bg1:'#1a1410',bg2:'#221a14',bg3:'#2a201a',bg4:'#342820',border:'#403026',border2:'#584436',text:'#ecdcc0',text2:'#e0a868',text3:'#8a6a48',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='ng' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23100820'/><stop offset='1' stop-color='%23301838'/></linearGradient><linearGradient id='sg' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%238a5030'/><stop offset='1' stop-color='%23301810'/></linearGradient></defs><rect width='800' height='400' fill='url(%23ng)'/><g fill='%23ffffff'><circle cx='80' cy='60' r='1'/><circle cx='200' cy='40' r='1.2'/><circle cx='340' cy='80' r='1'/><circle cx='480' cy='50' r='1.4'/><circle cx='620' cy='70' r='1'/><circle cx='720' cy='30' r='1.2'/></g><path d='M0 260 Q200 220 400 250 T800 240 L800 400 L0 400Z' fill='url(%23sg)'/><path d='M0 320 Q150 290 320 310 T640 305 T800 315 L800 400 L0 400Z' fill='%231a0e08'/></svg>\")"},
  arctic_glacier: {label:'🧊 Arctic Glacier',bg0:'#081418',bg1:'#0c1c22',bg2:'#10242c',bg3:'#162e38',bg4:'#1c3844',border:'#244658',border2:'#346078',text:'#d8eef4',text2:'#88d4e0',text3:'#4a8898',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='au' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23061420'/><stop offset='.5' stop-color='%2322586a' stop-opacity='.7'/><stop offset='.7' stop-color='%2344aa88' stop-opacity='.5'/><stop offset='1' stop-color='%23081620'/></linearGradient></defs><rect width='800' height='400' fill='%23061018'/><rect width='800' height='260' fill='url(%23au)'/><polygon points='0,300 120,220 200,270 300,210 420,280 520,230 640,290 760,240 800,270 800,400 0,400' fill='%23aadde8' opacity='.9'/><polygon points='0,340 100,300 220,330 340,290 460,330 580,300 700,330 800,310 800,400 0,400' fill='%23e0f4f8'/></svg>\")",animation:'auroraFlow'},
  volcanic_vent: {label:'🌋 Volcanic Vent',bg0:'#0c0604',bg1:'#140804',bg2:'#1a0a06',bg3:'#220c08',bg4:'#2a100a',border:'#381810',border2:'#502818',text:'#f0c8a0',text2:'#ff5a1e',text3:'#a04020',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400'><rect width='800' height='400' fill='%23080402'/><polygon points='0,400 0,280 80,240 160,300 240,220 320,280 400,200 480,280 560,240 640,300 720,260 800,290 800,400' fill='%23180808'/><g stroke='%23ff4818' stroke-width='2' fill='none' opacity='.85'><path d='M40 400 Q80 340 60 300 Q90 260 70 220'/><path d='M280 400 Q320 360 300 320 Q340 280 310 240'/><path d='M520 400 Q500 350 540 320 Q510 280 550 240'/></g></svg>\")",animation:'volcanicPulse'},
  waterfall: {label:'💧 Waterfall',bg0:'#061218',bg1:'#081820',bg2:'#0c2028',bg3:'#102834',bg4:'#163040',border:'#1e4258',border2:'#2c5c78',text:'#d4ecf4',text2:'#88cce0',text3:'#4a8898',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='w' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23102838'/><stop offset='.4' stop-color='%2344a0c0'/><stop offset='.9' stop-color='%23d0e8f0'/><stop offset='1' stop-color='%23506878'/></linearGradient></defs><rect width='800' height='400' fill='%23081420'/><rect x='160' y='0' width='480' height='400' fill='url(%23w)' opacity='.85'/><g fill='%23081018'><polygon points='0,0 160,0 160,400 100,400 80,340 60,400 0,400'/><polygon points='640,0 800,0 800,400 740,400 720,360 700,400 640,400'/></g></svg>\")",animation:'waterfallMist'},
  savannah_dawn: {label:'🦒 Savannah Dawn',bg0:'#10080a',bg1:'#180c0e',bg2:'#1e1010',bg3:'#261414',bg4:'#2e1a18',border:'#3a221e',border2:'#523028',text:'#f0d4bc',text2:'#ee9040',text3:'#966048',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400' preserveAspectRatio='xMidYMax slice'><defs><linearGradient id='sv' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%231a1240'/><stop offset='.5' stop-color='%23aa3c44'/><stop offset='.85' stop-color='%23ff9840'/><stop offset='1' stop-color='%23ffc880'/></linearGradient></defs><rect width='800' height='400' fill='url(%23sv)'/><circle cx='580' cy='260' r='42' fill='%23ffd890' opacity='.9'/><path d='M0 310 Q200 290 400 305 T800 300 L800 400 L0 400Z' fill='%23100808'/><g fill='%23050204'><rect x='200' y='180' width='7' height='140'/><path d='M140 175 Q180 140 204 170 Q230 140 270 172 Q250 180 204 178 Q170 182 140 175Z'/></g></svg>\")"},
  rainy_window: {label:'🌧 Rainy Window',bg0:'#0a0c10',bg1:'#0e1218',bg2:'#12161e',bg3:'#181c26',bg4:'#1e242e',border:'#262c3a',border2:'#363e52',text:'#d0d8e4',text2:'#8898b0',text3:'#4a5668',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 400'><defs><linearGradient id='wn' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%230c1420'/><stop offset='1' stop-color='%23182838'/></linearGradient></defs><rect width='800' height='400' fill='%23060810'/><rect x='60' y='40' width='320' height='320' fill='url(%23wn)'/><rect x='420' y='40' width='320' height='320' fill='url(%23wn)'/><rect x='40' y='20' width='360' height='20' fill='%23181e28'/><rect x='400' y='20' width='360' height='20' fill='%23181e28'/><rect x='40' y='360' width='720' height='24' fill='%23181e28'/></svg>\")",animation:'rainyWindowDrops'},
  // ── SCENE PACK: Urban / Tech (10) ───────────────────────────────────────────
  crt_terminal: {label:'▸ CRT Terminal',bg0:'#020802',bg1:'#041004',bg2:'#061806',bg3:'#0a220a',bg4:'#0e2c0e',border:'#144014',border2:'#1e5c1e',text:'#9dff9d',text2:'#33dd33',text3:'#1a7a1a',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%23020802'/><defs><radialGradient id='g' cx='50%25' cy='50%25' r='70%25'><stop offset='0%25' stop-color='%231a6a1a' stop-opacity='.35'/><stop offset='100%25' stop-color='%23020802' stop-opacity='0'/></radialGradient></defs><rect width='400' height='300' fill='url(%23g)'/><g fill='%2333ff33' font-family='monospace' font-size='11' opacity='.12'><text x='10' y='24'>&gt; LOGIN: root_</text><text x='10' y='48'>&gt; ACCESS GRANTED</text><text x='10' y='72'>&gt; SYS READY</text></g></svg>\")",animation:'crtScanlines'},
  cyberdeck_hud: {label:'◈ Cyberdeck HUD',bg0:'#020608',bg1:'#040c10',bg2:'#081418',bg3:'#0c1c22',bg4:'#12262e',border:'#16343e',border2:'#204e5c',text:'#c0ecf4',text2:'#00e6ff',text3:'#3a8090',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%23020608'/><g stroke='%2300e6ff' stroke-width='.6' fill='none' opacity='.22'><circle cx='200' cy='150' r='100'/><circle cx='200' cy='150' r='60'/><circle cx='200' cy='150' r='20'/><path d='M200 10v280M10 150h380'/></g></svg>\")"},
  subway_tunnel: {label:'◧ Subway Tunnel',bg0:'#0c0a08',bg1:'#14110d',bg2:'#1c1812',bg3:'#241f18',bg4:'#2c261e',border:'#3a3226',border2:'#524a3a',text:'#e4dcc8',text2:'#ffcc33',text3:'#8a7e5a',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%230c0a08'/><g stroke='%234a3f30' stroke-width='.5' fill='none' opacity='.5'><path d='M0 0L200 150M400 0L200 150M0 300L200 150M400 300L200 150'/></g><rect x='198' y='148' width='4' height='4' fill='%23ffd766' opacity='.6'/></svg>\")"},
  nyc_rooftop: {label:'◨ NYC Rooftop',bg0:'#050810',bg1:'#080c18',bg2:'#0c1220',bg3:'#121828',bg4:'#181e34',border:'#202848',border2:'#303a60',text:'#d8dcec',text2:'#ffcc66',text3:'#5868a0',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300' preserveAspectRatio='xMidYMax slice'><rect width='400' height='300' fill='%23080c18'/><g fill='%23070a14'><rect x='0' y='160' width='40' height='140'/><rect x='40' y='100' width='50' height='200'/><rect x='120' y='80' width='60' height='220'/><rect x='220' y='60' width='55' height='240'/><rect x='310' y='150' width='45' height='150'/><rect x='355' y='120' width='45' height='180'/></g><g fill='%23ffcc66'><rect x='8' y='180' width='4' height='4'/><rect x='48' y='120' width='3' height='3'/><rect x='148' y='140' width='4' height='4'/><rect x='232' y='80' width='4' height='4'/><rect x='320' y='170' width='4' height='4'/></g></svg>\")",animation:'nycWindows'},
  server_room: {label:'▤ Server Room',bg0:'#060608',bg1:'#0a0a10',bg2:'#101018',bg3:'#161620',bg4:'#1e1e2a',border:'#262634',border2:'#36364a',text:'#c8c8d4',text2:'#00ff88',text3:'#4a4a60',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%23060608'/><g fill='%230e0e16' stroke='%231a1a26' stroke-width='.5'><rect x='20' y='20' width='100' height='260'/><rect x='150' y='20' width='100' height='260'/><rect x='280' y='20' width='100' height='260'/></g></svg>\")",animation:'serverLeds'},
  highway_night: {label:'═ Highway Night',bg0:'#04060a',bg1:'#080a12',bg2:'#0c101a',bg3:'#121624',bg4:'#181e30',border:'#222a42',border2:'#32385a',text:'#d0d4e4',text2:'#ff5533',text3:'#4a5a7a',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%2304060a'/><g stroke='%231a2038' stroke-width='.6' opacity='.6'><path d='M0 170L400 170M0 200L400 200M0 230L400 230'/></g></svg>\")",animation:'highwayLights'},
  arcade_cabinet: {label:'▦ Arcade',bg0:'#0a0414',bg1:'#12061e',bg2:'#1a0a28',bg3:'#220e34',bg4:'#2c1240',border:'#3a1a58',border2:'#522880',text:'#f0c8f8',text2:'#ff44cc',text3:'#8a48aa',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%230a0414'/><g fill='%2318082a'><path d='M130 50h140l-10 160h-120z'/><rect x='120' y='210' width='160' height='60'/></g><rect x='142' y='62' width='116' height='80' fill='%23080410' stroke='%23ff44cc' stroke-width='1' opacity='.7'/></svg>\")"},
  hacker_basement: {label:'▣ Hacker Basement',bg0:'#050604',bg1:'#080a06',bg2:'#0c0e0a',bg3:'#10140e',bg4:'#161a14',border:'#1e2418',border2:'#2a3224',text:'#bcc8b0',text2:'#66dd44',text3:'#50604a',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%23050604'/><g fill='%230a0c08' stroke='%23161c12' stroke-width='.5'><rect x='40' y='80' width='110' height='70' rx='3'/><rect x='160' y='70' width='110' height='80' rx='3'/><rect x='280' y='85' width='100' height='65' rx='3'/></g></svg>\")"},
  neon_alley: {label:'▓ Neon Alley',bg0:'#0a0812',bg1:'#10081e',bg2:'#180a28',bg3:'#200c34',bg4:'#2a0e40',border:'#381450',border2:'#4e2470',text:'#e8d0ec',text2:'#ff3388',text3:'#8a5ab0',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%230a0812'/><g fill='%2308040e'><path d='M0 0h120v300H0z'/><path d='M280 0h120v300H280z'/></g><g font-family='serif' font-size='22' font-style='italic'><text x='16' y='60' fill='%23ff3388' opacity='.85'>酒</text><text x='72' y='110' fill='%2300eeff' opacity='.75'>麺</text><text x='22' y='170' fill='%23ffdd33' opacity='.8'>夜</text><text x='296' y='80' fill='%2300ffaa' opacity='.8'>茶</text></g></svg>\")"},
  datacenter_pulse: {label:'⟁ Datacenter',bg0:'#02060a',bg1:'#040a12',bg2:'#081018',bg3:'#0c1824',bg4:'#122032',border:'#1a2c44',border2:'#264464',text:'#c4d8ec',text2:'#44ccff',text3:'#3a6088',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'><rect width='400' height='300' fill='%2302060a'/><g fill='%23081420' stroke='%231a2c44' stroke-width='.6'><rect x='30' y='30' width='60' height='90' rx='2'/><rect x='110' y='30' width='60' height='90' rx='2'/><rect x='190' y='30' width='60' height='90' rx='2'/><rect x='270' y='30' width='60' height='90' rx='2'/></g></svg>\")",animation:'dataStream'},
  // ── SCENE PACK: Cosmic (8) ─────────────────────────────────────────────────
  iss_earth: {label:'🌍 ISS View',bg0:'#02040a',bg1:'#040812',bg2:'#06101e',bg3:'#0a182c',bg4:'#0e243c',border:'#12304a',border2:'#1e5478',text:'#d6e6f4',text2:'#6cb4e4',text3:'#3a6a92',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600' preserveAspectRatio='xMidYMid slice'><defs><radialGradient id='e' cx='30%25' cy='55%25' r='55%25'><stop offset='0' stop-color='%231a6fb8'/><stop offset='.55' stop-color='%230a3d6e'/><stop offset='.9' stop-color='%23051a34'/><stop offset='1' stop-color='%23020610'/></radialGradient></defs><rect width='800' height='600' fill='%23010208'/><g fill='%23ffffff' opacity='.55'><circle cx='640' cy='80' r='.8'/><circle cx='720' cy='160' r='.6'/><circle cx='560' cy='40' r='.5'/><circle cx='780' cy='320' r='.7'/></g><circle cx='240' cy='330' r='280' fill='url(%23e)'/></svg>\")",animation:'issEarth'},
  mars_surface: {label:'🔴 Mars Surface',bg0:'#140804',bg1:'#1c0c06',bg2:'#241208',bg3:'#2c180a',bg4:'#3a200e',border:'#4a2a12',border2:'#6a3a1c',text:'#f0d8c0',text2:'#e08a4a',text3:'#8a5838',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600' preserveAspectRatio='xMidYMid slice'><defs><linearGradient id='s' x1='0' y1='0' x2='0' y2='1'><stop offset='0' stop-color='%23c86038'/><stop offset='.5' stop-color='%238c3a1e'/><stop offset='1' stop-color='%23421808'/></linearGradient></defs><rect width='800' height='600' fill='url(%23s)'/><circle cx='640' cy='120' r='34' fill='%23f4c090' opacity='.55'/><path d='M0 380 L90 340 L170 360 L260 300 L340 340 L430 290 L520 330 L620 280 L720 320 L800 300 L800 600 L0 600 Z' fill='%235a2814'/></svg>\")"},
  nebula_wide: {label:'☁ Nebula Wide',bg0:'#08040e',bg1:'#0c0616',bg2:'#120820',bg3:'#180c2c',bg4:'#20103a',border:'#2a1850',border2:'#3e2670',text:'#e0c8f4',text2:'#d680d8',text3:'#7a4aa0',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600'><defs><filter id='t'><feTurbulence baseFrequency='.012' numOctaves='3' seed='7'/><feColorMatrix values='0 0 0 0 .95  0 0 0 0 .35  0 0 0 0 .75  0 0 0 .55 0'/></filter></defs><rect width='800' height='600' fill='%23060410'/><rect width='800' height='600' filter='url(%23t)' opacity='.8'/></svg>\")"},
  moon_crater: {label:'🌑 Moon Crater',bg0:'#050507',bg1:'#0c0c10',bg2:'#121218',bg3:'#1a1a22',bg4:'#22222c',border:'#2c2c38',border2:'#444452',text:'#d4d4dc',text2:'#9898a8',text3:'#5a5a68',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600' preserveAspectRatio='xMidYMid slice'><defs><linearGradient id='m' x1='0' y1='0' x2='0' y2='1'><stop offset='0' stop-color='%2390909c'/><stop offset='.55' stop-color='%235a5a66'/><stop offset='1' stop-color='%2320202a'/></linearGradient></defs><rect width='800' height='600' fill='%23020206'/><circle cx='620' cy='110' r='28' fill='%23ffffcc' opacity='.9'/><path d='M0 350 Q200 290 400 340 T800 320 L800 600 L0 600 Z' fill='url(%23m)'/></svg>\")"},
  wormhole: {label:'⊙ Wormhole',bg0:'#040010',bg1:'#08021a',bg2:'#0e0624',bg3:'#160a30',bg4:'#20103c',border:'#2a1850',border2:'#3e2870',text:'#d8c8f0',text2:'#aa88ff',text3:'#6848aa',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600'><rect width='800' height='600' fill='%23040010'/><g fill='none' stroke='%23a060ff' stroke-width='1'><ellipse cx='400' cy='300' rx='360' ry='260' opacity='.15'/><ellipse cx='400' cy='300' rx='240' ry='165' opacity='.28' stroke='%23c488ff'/><ellipse cx='400' cy='300' rx='135' ry='90' opacity='.5' stroke='%2366ccff'/><ellipse cx='400' cy='300' rx='50' ry='32' opacity='.85' stroke='%2388f0ff'/></g></svg>\")",animation:'wormholeTunnel'},
  galactic_core: {label:'✦ Galactic Core',bg0:'#050208',bg1:'#0a0612',bg2:'#100a1c',bg3:'#181028',bg4:'#201636',border:'#2c1e48',border2:'#44306a',text:'#f0e4d4',text2:'#f0c878',text3:'#8a7048',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600'><defs><radialGradient id='c' cx='50%25' cy='50%25' r='22%25'><stop offset='0' stop-color='%23fff6d0'/><stop offset='.3' stop-color='%23f4c060'/><stop offset='.7' stop-color='%23884420'/><stop offset='1' stop-color='%230a0408' stop-opacity='0'/></radialGradient></defs><rect width='800' height='600' fill='%23040208'/><circle cx='400' cy='300' r='160' fill='url(%23c)'/></svg>\")"},
  ship_porthole: {label:'⊚ Ship Porthole',bg0:'#040608',bg1:'#080c10',bg2:'#0c1218',bg3:'#121820',bg4:'#1a2028',border:'#2a3440',border2:'#445468',text:'#c8d4e0',text2:'#7a9cc0',text3:'#4a6078',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600'><defs><radialGradient id='s' cx='50%25' cy='50%25' r='50%25'><stop offset='0' stop-color='%23080c18'/><stop offset='1' stop-color='%23000004'/></radialGradient></defs><rect width='800' height='600' fill='%230a0e14'/><circle cx='400' cy='300' r='240' fill='url(%23s)'/><circle cx='400' cy='300' r='240' fill='none' stroke='%23505868' stroke-width='28'/></svg>\")"},
  black_hole: {label:'● Black Hole',bg0:'#020004',bg1:'#06020a',bg2:'#0a0414',bg3:'#12081e',bg4:'#1a0c2a',border:'#241238',border2:'#3a1e58',text:'#e8d8f0',text2:'#ffaa44',text3:'#7a5088',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600'><defs><radialGradient id='d' cx='50%25' cy='50%25' r='50%25'><stop offset='.18' stop-color='%23000' stop-opacity='0'/><stop offset='.22' stop-color='%23ffd88a'/><stop offset='.35' stop-color='%23ff8020'/><stop offset='.55' stop-color='%23882040'/><stop offset='.85' stop-color='%231a0620' stop-opacity='.3'/><stop offset='1' stop-color='%23000' stop-opacity='0'/></radialGradient></defs><rect width='800' height='600' fill='%23010006'/><ellipse cx='400' cy='300' rx='280' ry='90' fill='url(%23d)'/><circle cx='400' cy='300' r='62' fill='%23000'/></svg>\")",animation:'blackHoleDisk'},
  // ── SCENE PACK: Abstract / Retro (12) ──────────────────────────────────────
  bauhaus: {label:'◼ Bauhaus',bg0:'#1a1a1a',bg1:'#222222',bg2:'#2a2a2a',bg3:'#343434',bg4:'#3f3f3f',border:'#4a4a4a',border2:'#666666',text:'#f2ead3',text2:'#f4c91a',text3:'#a0a0a0',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><rect width='240' height='240' fill='%23f2ead3'/><circle cx='60' cy='60' r='34' fill='%23d7263d'/><rect x='130' y='30' width='70' height='70' fill='%23f4c91a'/><polygon points='40,220 100,120 160,220' fill='%230a4fa0'/><circle cx='190' cy='180' r='18' fill='%231a1a1a'/></svg>\")"},
  art_deco: {label:'◆ Art Deco',bg0:'#0b1a2e',bg1:'#122443',bg2:'#1a2f58',bg3:'#243d6e',bg4:'#2e4880',border:'#c9a646',border2:'#8a6f28',text:'#f4e6b8',text2:'#e9c96b',text3:'#a89152',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='300' height='300'><rect width='300' height='300' fill='%230b1a2e'/><g stroke='%23c9a646' stroke-width='1' fill='none' opacity='0.55'><path d='M150 300 L150 60 M150 300 L60 90 M150 300 L240 90 M150 300 L20 160 M150 300 L280 160'/><path d='M150 300 A180 180 0 0 1 330 300 M150 300 A140 140 0 0 1 290 300 M150 300 A100 100 0 0 1 250 300 M150 300 A60 60 0 0 1 210 300'/></g><circle cx='150' cy='300' r='10' fill='%23e9c96b'/></svg>\")"},
  memphis: {label:'◈ Memphis',bg0:'#1a1a2e',bg1:'#22243f',bg2:'#2c2e4d',bg3:'#3a3c60',bg4:'#44466e',border:'#ff3ea5',border2:'#1cd3c9',text:'#fef9e7',text2:'#ffde59',text3:'#b8b5c8',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='260' height='260'><rect width='260' height='260' fill='%231a1a2e'/><path d='M10 40 Q30 20 50 40 T90 40 T130 40' stroke='%23ff3ea5' stroke-width='4' fill='none'/><path d='M140 200 l20 -20 l20 20 l20 -20 l20 20' stroke='%23ffde59' stroke-width='4' fill='none'/><circle cx='60' cy='180' r='4' fill='%231cd3c9'/><circle cx='200' cy='60' r='4' fill='%23ff3ea5'/><rect x='180' y='100' width='14' height='14' fill='%231cd3c9' transform='rotate(20 187 107)'/></svg>\")"},
  brutalist: {label:'▣ Brutalist',bg0:'#2a2a2a',bg1:'#333333',bg2:'#3d3d3d',bg3:'#4a4a4a',bg4:'#555555',border:'#606060',border2:'#787878',text:'#e8e5e0',text2:'#b5b2ac',text3:'#7a7770',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><rect width='200' height='200' fill='%232a2a2a'/><g fill='%23000' opacity='.2'><circle cx='20' cy='30' r='1'/><circle cx='70' cy='15' r='1.2'/><circle cx='130' cy='45' r='1'/><circle cx='180' cy='80' r='1.5'/><circle cx='40' cy='120' r='1'/><circle cx='100' cy='170' r='1.2'/></g><rect x='0' y='100' width='200' height='1' fill='%23000' opacity='.3'/><rect x='100' y='0' width='1' height='200' fill='%23000' opacity='.3'/></svg>\")"},
  watercolor: {label:'❀ Watercolor',bg0:'#1a1614',bg1:'#221e1a',bg2:'#2a2622',bg3:'#332e2a',bg4:'#3c3732',border:'#504a44',border2:'#6a625a',text:'#f5ede0',text2:'#d4a5b8',text3:'#8fb5c4',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='400'><defs><radialGradient id='a' cx='20%25' cy='30%25'><stop offset='0' stop-color='%23d4a5b8' stop-opacity='0.55'/><stop offset='1' stop-color='%23d4a5b8' stop-opacity='0'/></radialGradient><radialGradient id='b' cx='80%25' cy='70%25'><stop offset='0' stop-color='%238fb5c4' stop-opacity='0.55'/><stop offset='1' stop-color='%238fb5c4' stop-opacity='0'/></radialGradient></defs><rect width='400' height='400' fill='%23f5ede0'/><rect width='400' height='400' fill='url(%23a)'/><rect width='400' height='400' fill='url(%23b)'/></svg>\")"},
  stained_glass: {label:'✦ Stained Glass',bg0:'#0f1220',bg1:'#171a2e',bg2:'#20243c',bg3:'#2b304c',bg4:'#363c5e',border:'#1a1a1a',border2:'#000000',text:'#f2e8d0',text2:'#e6cf9a',text3:'#a8936a',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='300' height='300'><rect width='300' height='300' fill='%230f1220'/><g stroke='%23000' stroke-width='3'><polygon points='0,0 120,0 90,90 0,110' fill='%239c2b3a'/><polygon points='120,0 240,0 210,100 90,90' fill='%23d8a23a'/><polygon points='240,0 300,0 300,110 210,100' fill='%232d6a8f'/><polygon points='0,110 90,90 130,200 0,220' fill='%233f7a5e'/><polygon points='90,90 210,100 220,190 130,200' fill='%23c8563a'/><polygon points='210,100 300,110 300,210 220,190' fill='%236b3d8a'/></g></svg>\")"},
  origami: {label:'▲ Origami',bg0:'#1f1c15',bg1:'#28251d',bg2:'#332f25',bg3:'#3d392e',bg4:'#474237',border:'#575042',border2:'#766c5a',text:'#e8e0d2',text2:'#c8b890',text3:'#8a7a60',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='220' height='220'><rect width='220' height='220' fill='%23e8e0d2'/><polygon points='0,0 110,0 0,110' fill='%23f0e8d8'/><polygon points='110,0 220,0 220,110' fill='%23dcd0b8'/><polygon points='0,110 110,220 0,220' fill='%23d0c2a8'/><polygon points='220,110 220,220 110,220' fill='%23e4dcc8'/><polygon points='110,0 220,110 110,220 0,110' fill='none' stroke='%238a7a60' stroke-width='0.8' opacity='0.5'/></svg>\")"},
  low_poly: {label:'△ Low Poly',bg0:'#0e2a30',bg1:'#133a42',bg2:'#184c56',bg3:'#1f6270',bg4:'#267584',border:'#2a8598',border2:'#3a9aa8',text:'#e0f4f1',text2:'#a8d8d0',text3:'#6a9a95',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='300' height='300'><rect width='300' height='300' fill='%230e2a30'/><g stroke='%230e2a30' stroke-width='0.5'><polygon points='0,0 80,20 0,90' fill='%23133a42'/><polygon points='80,20 160,0 170,70' fill='%23184c56'/><polygon points='160,0 300,0 300,60 170,70' fill='%23143840'/><polygon points='0,90 80,20 170,70 90,150' fill='%231c5560'/><polygon points='170,70 300,60 300,140 220,160' fill='%23216a78'/><polygon points='90,150 170,70 220,160 130,220' fill='%23184c56'/></g></svg>\")"},
  pixel_8bit: {label:'▪ 8-Bit',bg0:'#0a0a1f',bg1:'#121232',bg2:'#1c1c4a',bg3:'#2a2a66',bg4:'#38389a',border:'#5454fc',border2:'#a8a8fc',text:'#fcfcfc',text2:'#fc5454',text3:'#7c7c7c',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='128' height='128' shape-rendering='crispEdges'><rect width='128' height='128' fill='%230a0a1f'/><rect x='8' y='8' width='8' height='8' fill='%235454fc'/><rect x='16' y='16' width='8' height='8' fill='%23a8a8fc'/><rect x='48' y='24' width='8' height='8' fill='%23fc5454'/><rect x='56' y='32' width='8' height='8' fill='%23fcbc54'/><rect x='88' y='40' width='8' height='8' fill='%2354fc54'/><rect x='24' y='72' width='8' height='8' fill='%23fc54a8'/><rect x='96' y='88' width='8' height='8' fill='%235454fc'/><rect x='72' y='104' width='8' height='8' fill='%23a8a8fc'/></svg>\")"},
  synthwave_sun: {label:'☼ Synthwave',bg0:'#14052a',bg1:'#1e0a3e',bg2:'#2a1155',bg3:'#3a1a6e',bg4:'#4c2090',border:'#ff2e93',border2:'#00e5ff',text:'#ffe9fa',text2:'#ffb1e2',text3:'#9a6aa8',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='400'><defs><linearGradient id='sky' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%2314052a'/><stop offset='1' stop-color='%23ff2e93' stop-opacity='0.3'/></linearGradient><linearGradient id='sun' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23ffe14a'/><stop offset='0.5' stop-color='%23ff6a3d'/><stop offset='1' stop-color='%23ff2e93'/></linearGradient></defs><rect width='400' height='400' fill='url(%23sky)'/><circle cx='200' cy='200' r='110' fill='url(%23sun)'/><rect x='90' y='178' width='220' height='5' fill='%2314052a'/><rect x='90' y='195' width='220' height='4' fill='%2314052a'/><rect x='90' y='210' width='220' height='3' fill='%2314052a'/><g stroke='%2300e5ff' stroke-width='1' fill='none'><path d='M0 260 L400 260 M0 290 L400 290 M0 330 L400 330 M0 380 L400 380'/><path d='M50 400 L200 230 M100 400 L200 230 M150 400 L200 230 M250 400 L200 230 M300 400 L200 230 M350 400 L200 230'/></g></svg>\")"},
  vaporwave_mall: {label:'░ Vaporwave',bg0:'#2a1b4e',bg1:'#3a2466',bg2:'#4d2f80',bg3:'#6240a0',bg4:'#7450b0',border:'#01cdfe',border2:'#ff71ce',text:'#fff8ff',text2:'#b9f6ff',text3:'#a89ad0',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='360' height='360'><defs><linearGradient id='vs' x1='0' x2='0' y1='0' y2='1'><stop offset='0' stop-color='%23ff71ce'/><stop offset='0.5' stop-color='%2301cdfe'/><stop offset='1' stop-color='%232a1b4e'/></linearGradient></defs><rect width='360' height='360' fill='url(%23vs)'/><circle cx='180' cy='110' r='42' fill='%23fff8ff' opacity='0.18'/><g fill='%23fff8ff' opacity='0.95'><ellipse cx='180' cy='220' rx='28' ry='14'/><path d='M152 220 Q160 170 180 168 Q200 170 208 220 Q195 210 180 212 Q165 210 152 220 Z'/></g></svg>\")"},
  nes_palette: {label:'■ NES',bg0:'#0f0f2c',bg1:'#1a1a44',bg2:'#252560',bg3:'#30307c',bg4:'#3e3e94',border:'#6888fc',border2:'#f8b8f8',text:'#fcfcfc',text2:'#e40058',text3:'#7c7c7c',bgImage:"url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='128' height='128' shape-rendering='crispEdges'><rect width='128' height='128' fill='%230f0f2c'/><rect x='0' y='112' width='128' height='16' fill='%23503000'/><rect x='0' y='104' width='128' height='8' fill='%23886800'/><rect x='16' y='40' width='8' height='8' fill='%23fcfcfc'/><rect x='24' y='48' width='16' height='8' fill='%23fcfcfc'/><rect x='72' y='24' width='24' height='8' fill='%23fcfcfc'/><rect x='56' y='80' width='8' height='16' fill='%23e40058'/><rect x='48' y='88' width='24' height='8' fill='%23e40058'/><rect x='96' y='72' width='8' height='24' fill='%2300a800'/><rect x='88' y='80' width='24' height='8' fill='%2300a800'/></svg>\")"},
  // ── SCENE PACK: Motion (10) ─────────────────────────────────────────────────
  meteor_shower: {label:'☄ Meteor Rain',bg0:'#05060a',bg1:'#0a0c14',bg2:'#12151f',bg3:'#1a1e2b',bg4:'#252a3a',border:'#2e3446',border2:'#4a5268',text:'#e8ecf5',text2:'#a8b0c4',text3:'#6c7489',animation:'meteorShower'},
  lightning_storm: {label:'⚡ Storm',bg0:'#060810',bg1:'#0c1018',bg2:'#141822',bg3:'#1c2130',bg4:'#272d40',border:'#343a4e',border2:'#505878',text:'#e4e8f2',text2:'#9aa2b8',text3:'#5e6680',animation:'lightningStorm'},
  rain_glass: {label:'💦 Rain Glass',bg0:'#0a1419',bg1:'#101a22',bg2:'#18242e',bg3:'#22303c',bg4:'#2e3e4c',border:'#3a4a5a',border2:'#566878',text:'#d8e4ec',text2:'#98a8b4',text3:'#60707c',animation:'rainGlass'},
  drifting_clouds: {label:'☁ Drifting Clouds',bg0:'#151a24',bg1:'#1c2230',bg2:'#252c3c',bg3:'#2f3748',bg4:'#3a4358',border:'#485168',border2:'#646e88',text:'#e0e4ec',text2:'#a8b0c0',text3:'#6c7488',animation:'driftingClouds'},
  data_stream: {label:'⌬ Data Stream',bg0:'#030806',bg1:'#071410',bg2:'#0c1e18',bg3:'#112a22',bg4:'#1a3a2e',border:'#1e4236',border2:'#2e6854',text:'#c4e8d8',text2:'#7eb89a',text3:'#4a8268',animation:'dataStreamFall'},
  heartbeat_pulse: {label:'♥ Heartbeat',bg0:'#0c0608',bg1:'#160a0e',bg2:'#221014',bg3:'#2e161c',bg4:'#3a1e26',border:'#4a2630',border2:'#6e3a48',text:'#f0dde2',text2:'#c89ea8',text3:'#8a6872',animation:'heartbeatPulse'},
  glitch_flicker: {label:'▓ Glitch',bg0:'#08060c',bg1:'#100c18',bg2:'#181224',bg3:'#221a32',bg4:'#2e2442',border:'#3a2e52',border2:'#584478',text:'#e8e2f4',text2:'#a898c4',text3:'#6a5e88',animation:'glitchFlicker'},
  scanlines: {label:'⎯ Scanlines',bg0:'#060a08',bg1:'#0a120e',bg2:'#101c16',bg3:'#16261e',bg4:'#1e3228',border:'#263c30',border2:'#3c5c48',text:'#d4e8dc',text2:'#94b49e',text3:'#5e7a68',animation:'scanlinesRoll'},
  falling_leaves: {label:'🍂 Autumn Leaves',bg0:'#120906',bg1:'#1c120a',bg2:'#281c10',bg3:'#342618',bg4:'#423222',border:'#4e3c2a',border2:'#785a40',text:'#f0e0cc',text2:'#c8a888',text3:'#8a7458',animation:'fallingLeaves'},
  firefly_meadow: {label:'✨ Firefly Meadow',bg0:'#050a06',bg1:'#0a120c',bg2:'#101a12',bg3:'#16241a',bg4:'#1e3022',border:'#263a2c',border2:'#3e5a44',text:'#e4efd8',text2:'#a4b898',text3:'#687c5c',animation:'fireflyMeadow'},
  // ── mIRC: classic 1998 white-chrome look. Pairs with the html[data-theme='mirc']
  //    CSS block in index.html (square corners, navy switchbar, Fixedsys font). ──
  mirc:         {label:'mIRC',bg0:'#ffffff',bg1:'#ffffff',bg2:'#f0f0f0',bg3:'#e4e4e4',bg4:'#000080',border:'#c0c0c0',border2:'#808080',text:'#000000',text2:'#00007f',text3:'#555555',accent:'#000080',accent2:'#00007f',link:'#0000ff',warn:'#7f0000',error:'#ff0000',join:'#009300',part:'#7f0000',notice:'#7f0000',action:'#9c009c'},
  // ── ESHEEP: classic desktop pet, wanders the screen ────────────────────────
};
// Default semantic message colors (mirror :root in index.html). Used to RESET
// these vars when switching away from a custom theme that overrode them.
const SEMANTIC_DEFAULTS={warn:'#ffaa00',error:'#ff4466',join:'#44cc88',part:'#cc6644',notice:'#9988cc',action:'#ffcc44'};
// Every editable color in a custom theme, in display order, grouped for the editor UI.
const CT_COLOR_GROUPS=[
  {title:'Backgrounds', keys:[['bg0','Base'],['bg1','Layer 1'],['bg2','Layer 2'],['bg3','Layer 3'],['bg4','Layer 4']]},
  {title:'Borders',     keys:[['border','Border'],['border2','Border 2']]},
  {title:'Text',        keys:[['text','Primary'],['text2','Secondary'],['text3','Muted']]},
  {title:'Accents',     keys:[['accent','Accent'],['accent2','Accent 2'],['link','Links']]},
  {title:'Status colors',keys:[['warn','Warning'],['error','Error'],['join','Join'],['part','Part/Quit'],['notice','Notice'],['action','Action']]},
];
// Flat list of every color key a custom theme stores.
const CT_COLOR_KEYS=CT_COLOR_GROUPS.flatMap(g=>g.keys.map(k=>k[0]));
// Resolve a theme name to its color object. Custom themes (id "custom:<id>") come
// from cfg.customThemes; everything else is a built-in from THEMES.
function resolveThemeObj(name,cfg){
  if(typeof name==='string' && name.indexOf('custom:')===0){
    const ct=(cfg&&cfg.customThemes)?cfg.customThemes[name.slice(7)]:null;
    if(ct) return {t:ct, custom:true};
  }
  return {t:THEMES[name]||THEMES.midnight, custom:false};
}
// Background image for a custom theme: syncable bgUrl wins, else the device-local
// data URL (stored outside the 4KB-capped appearance config). Returns null/none.
function _customThemeBgValue(themeName,t){
  if(!t||!t.bgKind) return null;
  if(t.bgUrl) return t.bgUrl;
  if(typeof themeName==='string' && themeName.indexOf('custom:')===0){
    try{ return localStorage.getItem('cryptirc_cbg_'+themeName.slice(7)); }catch(e){ return null; }
  }
  return null;
}
// Sanitize a background image value for safe use inside CSS url("..."). Allows only
// https: URLs and data:image/* URLs (matches the CSP img-src directive). Strips any
// quote/backslash that could break out of the url("...") wrapper.
function _safeBgCss(v){
  if(!v||typeof v!=='string') return 'none';
  const s=v.trim();
  if(!/^https:\/\//i.test(s) && !/^data:image\//i.test(s)) return 'none';
  return 'url("'+s.replace(/["\\\n\r]/g,'')+'")';
}
const APPEAR_DEFAULTS={
  theme:'starwarp', chatSize:13, sidebarFont:12, nickFont:12,
  sidebarW:220, nickW:100, nickPanelW:180, lineHeight:1.55,
  timestamps:true, joinpart:true, statusMsg:'condense', compact:false, coloredNicks:true,
  accent:'#00d4aa', accent2:'#0099ff', brightness:100, nickList:true, spellcheck:true, soundPM:true, soundMention:true, desktopNotif:true, notifSound:'water-drop', msgGap:4, inputH:36,
  font:"'Spooky Magic',cursive", linkPreviews:true,
  mobileChatSize:15, mobileNickW:60, mobileTimestamps:false,
  mobileTheme:'', mobileAccent:'', mobileAccent2:'',
  // Hyperlink color. '' = follow Accent 2 (default). mobileLink '' = inherit desktop link.
  linkColor:'', mobileLink:'',
  // User-created themes, keyed by id. Selected via theme:'custom:<id>'.
  customThemes:{},
  // Desktop pet (eSheep) — a little sheep wanders the client window. Off by default.
  esheep:'off',
  crab:'off',
  ghost:'off',
  fish:'off',
  alien:'off',
  // Media & previews: shape/size/border/radius controls for images, videos,
  // YouTube thumbs, and link-preview cards. Defaults preserve the old look.
  mediaShape:'rounded',    // rounded | square | pronounced | circle | custom
  mediaSize:'medium',      // small | medium | large | xlarge
  mediaBorder:'none',      // none | subtle | accent | glow
  mediaRadius:10,          // custom-shape slider 0–40px
  mediaAspect:'natural',   // natural | sixteen_nine | square
  mediaMaxHeight:280,      // slider 150–600px
  ytPlayOverlay:true,      // show ▶ overlay on YouTube thumbs
};
function isMobileView(){return window.innerWidth<=768;}
// eSheep enablement mode: 'off' | 'desktop' | 'mobile' | 'both' (legacy boolean true => 'both').
function _esheepMode(v){ if(v===true) return 'both'; return (v==='desktop'||v==='mobile'||v==='both') ? v : 'off'; }
function _esheepOn(v){ var m=_esheepMode(v), mob=isMobileView(); return m==='both' || (m==='desktop'&&!mob) || (m==='mobile'&&mob); }
function _crabMode(v){ if(v===true) return 'both'; return (v==='desktop'||v==='mobile'||v==='both') ? v : 'off'; }
function _crabOn(v){ var m=_crabMode(v), mob=isMobileView(); return m==='both' || (m==='desktop'&&!mob) || (m==='mobile'&&mob); }
function _ghostMode(v){ if(v===true) return 'both'; return (v==='desktop'||v==='mobile'||v==='both') ? v : 'off'; }
function _ghostOn(v){ var m=_ghostMode(v), mob=isMobileView(); return m==='both' || (m==='desktop'&&!mob) || (m==='mobile'&&mob); }
function _fishMode(v){ if(v===true) return 'both'; return (v==='desktop'||v==='mobile'||v==='both') ? v : 'off'; }
function _fishOn(v){ var m=_fishMode(v), mob=isMobileView(); return m==='both' || (m==='desktop'&&!mob) || (m==='mobile'&&mob); }
function _alienMode(v){ if(v===true) return 'both'; return (v==='desktop'||v==='mobile'||v==='both') ? v : 'off'; }
function _alienOn(v){ var m=_alienMode(v), mob=isMobileView(); return m==='both' || (m==='desktop'&&!mob) || (m==='mobile'&&mob); }
let _appearCache=null,_appearCacheTs=0;
function loadAppearance(){
  const now=Date.now();
  if(_appearCache&&now-_appearCacheTs<2000)return _appearCache;
  try{_appearCache={...APPEAR_DEFAULTS,...JSON.parse(localStorage.getItem('cryptirc_appear')||'{}')};}
  catch{_appearCache={...APPEAR_DEFAULTS};}
  _appearCacheTs=now;
  return _appearCache;
}
function invalidateAppearCache(){_appearCache=null;_appearCacheTs=0;}
let _appearOversizeWarned=false;
function saveAppearance(cfg){
  invalidateAppearCache();
  const json=JSON.stringify(cfg);
  try{localStorage.setItem('cryptirc_appear',json);}catch(e){}
  // The server silently drops appearance payloads over 4KB (main.rs). Sending one
  // anyway is worse than not sending: it gets dropped, then a later sync from the
  // server's last-good copy can overwrite what we just changed. So when oversized,
  // keep the full config in localStorage (works on THIS device) but DON'T sync it,
  // and warn the user once. The custom-theme editor pre-checks at APPEAR_SYNC_BUDGET
  // (3900) so this is only a backstop for pathological configs.
  if(json.length>4096){
    try{console.warn('[appearance] config '+json.length+'B exceeds 4KB server cap — not syncing across devices');}catch(_){}
    if(!_appearOversizeWarned){ _appearOversizeWarned=true; try{showToast('Settings too large to sync across devices — saved on this device only');}catch(_){} }
    return;
  }
  _appearOversizeWarned=false;
  wsend({type:'save_appearance',settings:json});
}
function applyAppearance(){
  const el=id=>document.getElementById(id);
  // Only save if theme modal is populated (prevent saving corrupt zeros)
  if(!el('a-chat-size')||!el('a-chat-size').value||+el('a-chat-size').value<8){return;}
  const prev=loadAppearance();
  const cfg={
    theme:      document.querySelector('.theme-card.active')?.dataset?.theme||prev.theme||'midnight',
    chatSize:   +el('a-chat-size').value||prev.chatSize||13,
    sidebarFont:+el('a-sidebar-font').value||prev.sidebarFont||12,
    nickFont:   +el('a-nick-font').value||prev.nickFont||12,
    sidebarW:   +el('a-sidebar-w').value||prev.sidebarW||220,
    nickW:      +el('a-nick-w').value||prev.nickW||100,
    nickPanelW: +el('a-nickpanel-w').value||prev.nickPanelW||160,
    lineHeight: +el('a-line-height').value||prev.lineHeight||1.55,
    timestamps: el('a-timestamps').classList.contains('on'),
    joinpart:   true,
    statusMsg:  el('a-statusmsg').value||'condense',
    compact:    el('a-compact').classList.contains('on'),
    coloredNicks: el('a-colorednicks').classList.contains('on'),
    nickList:   el('a-nicklist').classList.contains('on'),
    spellcheck: prev.spellcheck!==undefined?prev.spellcheck:true,
    linkPreviews: prev.linkPreviews!==undefined?prev.linkPreviews:true,
    msgGap:     +el('a-msg-gap').value||prev.msgGap||4,
    inputH:     +el('a-input-h').value||prev.inputH||36,
    accent:     el('a-accent-color').value||prev.accent||'#00d4aa',
    accent2:    el('a-accent2-color').value||prev.accent2||'#0099ff',
    // '' means "follow accent2" (the Match toggle is on).
    linkColor:  el('a-link-match')?.classList.contains('on') ? '' : (el('a-link-color')?.value||''),
    // Custom themes are not represented by DOM inputs here — carry them through
    // untouched so a slider tweak never drops the user's saved themes.
    customThemes: prev.customThemes||{},
    brightness: +el('a-brightness').value,
    mobileChatSize: +el('a-mobile-chat-size').value,
    mobileNickW:    +el('a-mobile-nick-w').value,
    mobileTimestamps: el('a-mobile-timestamps').classList.contains('on'),
    mobileTheme:    el('a-mobile-theme').value||'',
    mobileAccent:   el('a-mobile-accent-color').value||'',
    mobileAccent2:  el('a-mobile-accent2-color').value||'',
    // '' means "inherit the desktop link color" (the Inherit toggle is on).
    mobileLink:     el('a-mobile-link-inherit')?.classList.contains('on') ? '' : (el('a-mobile-link-color')?.value||''),
    font:           el('a-font').value||prev.font||"'Spooky Magic',cursive",
    mediaShape:     el('a-media-shape')?.value || prev.mediaShape || 'rounded',
    mediaSize:      el('a-media-size')?.value || prev.mediaSize || 'medium',
    mediaBorder:    el('a-media-border')?.value || prev.mediaBorder || 'none',
    // Use nullish-coalescing for numeric sliders so a legitimate 0 isn't overwritten
    // by the default (previous `+value || prev || 10` turned 0 into 10).
    mediaRadius:    (()=>{const v=el('a-media-radius')?.value; const n=v==null||v===''?NaN:+v; return Number.isFinite(n)?n:(prev.mediaRadius??10);})(),
    mediaAspect:    el('a-media-aspect')?.value || prev.mediaAspect || 'natural',
    mediaMaxHeight: (()=>{const v=el('a-media-max-h')?.value; const n=v==null||v===''?NaN:+v; return Number.isFinite(n)?n:(prev.mediaMaxHeight??280);})(),
    ytPlayOverlay:  el('a-yt-play')?.classList.contains('on') ?? true,
    // Desktop pet toggle. Carry the previous value through if the row is absent.
    esheep:     el('a-esheep') ? el('a-esheep').value : _esheepMode(prev.esheep),
    crab:       el('a-crab') ? el('a-crab').value : _crabMode(prev.crab),
    ghost:      el('a-ghost') ? el('a-ghost').value : _ghostMode(prev.ghost),
    fish:       el('a-fish') ? el('a-fish').value : _fishMode(prev.fish),
    alien:      el('a-alien') ? el('a-alien').value : _alienMode(prev.alien),
  };
  // Show/hide the custom radius slider based on shape
  const _radiusRow = el('a-media-radius-row');
  if (_radiusRow) _radiusRow.style.display = cfg.mediaShape === 'custom' ? '' : 'none';
  if (el('a-media-radius-val')) el('a-media-radius-val').textContent = (cfg.mediaRadius|0) + 'px';
  if (el('a-media-max-h-val')) el('a-media-max-h-val').textContent = (cfg.mediaMaxHeight|0) + 'px';
  applyThemeCSS(cfg);
  saveAppearance(cfg);
  // Update value labels
  el('a-chat-size-val').textContent=cfg.chatSize+'px';
  el('a-sidebar-font-val').textContent=cfg.sidebarFont+'px';
  el('a-nick-font-val').textContent=cfg.nickFont+'px';
  el('a-sidebar-w-val').textContent=cfg.sidebarW+'px';
  el('a-nick-w-val').textContent=cfg.nickW+'px';
  el('a-nickpanel-w-val').textContent=cfg.nickPanelW+'px';
  el('a-line-height-val').textContent=cfg.lineHeight.toFixed(1);
  el('a-brightness-val').textContent=(cfg.brightness||100)+'%';
  el('a-msg-gap-val').textContent=(cfg.msgGap!=null?cfg.msgGap:4)+'px';
  if(el('a-input-h-val')) el('a-input-h-val').textContent=(cfg.inputH!=null?cfg.inputH:36)+'px';
  el('a-mobile-chat-size-val').textContent=(cfg.mobileChatSize||15)+'px';
  el('a-mobile-nick-w-val').textContent=(cfg.mobileNickW||60)+'px';
  el('a-mobile-accent-swatch').style.background=cfg.mobileAccent||cfg.accent;
  el('a-mobile-accent2-swatch').style.background=cfg.mobileAccent2||cfg.accent2;
  // Keep link swatches/pickers tracking the effective color (accent2 while matched).
  const _lEff=cfg.linkColor||cfg.accent2||'#0099ff';
  if(el('a-link-swatch')) el('a-link-swatch').style.background=_lEff;
  if(el('a-link-color')) el('a-link-color').value=_lEff;
  if(el('a-link-match-hint')) el('a-link-match-hint').textContent=cfg.linkColor?'':'(using accent 2)';
  const _mlEff=cfg.mobileLink||cfg.linkColor||cfg.accent2||'#0099ff';
  if(el('a-mobile-link-swatch')) el('a-mobile-link-swatch').style.background=_mlEff;
}
function applyThemeCSS(cfg){
  const r=document.documentElement.style;
  const mob=isMobileView();
  // Pick theme: use mobile override if set
  const themeName=(mob&&cfg.mobileTheme)?cfg.mobileTheme:cfg.theme;
  const _rt=resolveThemeObj(themeName,cfg);
  const t=_rt.t, isCustom=_rt.custom;
  // Expose the active theme name so theme-specific CSS (e.g. the mIRC look) can
  // target html[data-theme='...']. Harmless for every other theme.
  document.documentElement.setAttribute('data-theme', typeof themeName==='string'?themeName:'');
  // Keep the iOS PWA status-bar tint in sync with the active theme background,
  // otherwise a light theme shows a black status-bar seam above the app.
  const _tc=document.querySelector('meta[name="theme-color"]'); if(_tc&&t.bg0) _tc.setAttribute('content',t.bg0);
  r.setProperty('--bg0',t.bg0); r.setProperty('--bg1',t.bg1); r.setProperty('--bg2',t.bg2);
  r.setProperty('--bg3',t.bg3); r.setProperty('--bg4',t.bg4);
  r.setProperty('--border',t.border); r.setProperty('--border2',t.border2);
  r.setProperty('--text',t.text); r.setProperty('--text2',t.text2); r.setProperty('--text3',t.text3);
  // Pick accents: mobile override wins; otherwise a theme that carries its OWN
  // accent (custom themes, plus the built-in mIRC) uses it, else the global pref.
  // (Only the mIRC built-in defines accent keys, so this is a no-op for the rest.)
  const accent=(mob&&cfg.mobileAccent)?cfg.mobileAccent:(t.accent||cfg.accent);
  const accent2=(mob&&cfg.mobileAccent2)?cfg.mobileAccent2:(t.accent2||cfg.accent2);
  r.setProperty('--accent',accent); r.setProperty('--accent2',accent2);
  // Hyperlink color: mobile override → theme link → custom accent2 / global linkColor → accent2.
  const link=(mob&&cfg.mobileLink)?cfg.mobileLink:(t.link||(isCustom?(t.accent2||accent2):(cfg.linkColor||accent2)));
  r.setProperty('--link',link||accent2);
  // Semantic message colors: custom themes may override them; built-ins keep the
  // :root defaults, so always reset to default first then apply any custom value.
  ['warn','error','join','part','notice','action'].forEach(k=>{
    if(isCustom && t[k]) r.setProperty('--'+k,t[k]);
    else r.setProperty('--'+k,SEMANTIC_DEFAULTS[k]);
  });
  r.setProperty('--sidebar-w',cfg.sidebarW+'px');
  r.setProperty('--nicks-w',cfg.nickPanelW+'px');
  r.setProperty('--input-h',(cfg.inputH!=null?cfg.inputH:36)+'px');
  // Picture-backdrop layer — themes with bgImage render an SVG scene at low
  // opacity behind the chat. Themes without bgImage clear the var so solid color wins.
  if(isCustom){
    const _cbg=_customThemeBgValue(themeName,t);
    r.setProperty('--theme-bg-image', _cbg ? _safeBgCss(_cbg) : 'none');
    r.setProperty('--theme-bg-opacity', t.bgOpacity!=null ? (Math.max(0,Math.min(100,t.bgOpacity))/100) : .25);
    const _bgl=document.getElementById('theme-bg-layer');
    if(_bgl) _bgl.classList.toggle('repeat', !!t.bgRepeat);
  }else{
    r.setProperty('--theme-bg-image', t.bgImage || 'none');
    r.setProperty('--theme-bg-opacity', .25);
    const _bgl=document.getElementById('theme-bg-layer');
    if(_bgl) _bgl.classList.remove('repeat');
  }
  // Media & preview variables — shape/size/border/aspect/max-height/YT play overlay
  const _sizeMap = { small: 200, medium: 320, large: 400, xlarge: 480 };
  const _mMaxW = _sizeMap[cfg.mediaSize] || _sizeMap.medium;
  let _mRadius;
  switch (cfg.mediaShape) {
    case 'square':     _mRadius = '0'; break;
    case 'pronounced': _mRadius = '18px'; break;
    case 'circle':     _mRadius = '50%'; break;
    case 'custom':     _mRadius = Math.max(0, Math.min(40, cfg.mediaRadius|0)) + 'px'; break;
    default:           _mRadius = '10px'; // 'rounded'
  }
  // Circle forces 1:1 aspect so we get an actual circle, not an oval
  let _mAspect;
  if (cfg.mediaShape === 'circle') {
    _mAspect = '1/1';
  } else if (cfg.mediaAspect === 'sixteen_nine') {
    _mAspect = '16/9';
  } else if (cfg.mediaAspect === 'square') {
    _mAspect = '1/1';
  } else {
    _mAspect = 'auto'; // natural
  }
  // object-fit: when aspect is forced, cover crops so image fills the frame
  const _mFit = _mAspect === 'auto' ? 'contain' : 'cover';
  // Border / glow presets
  let _mBorder, _mBorderYt, _mShadow;
  switch (cfg.mediaBorder) {
    case 'accent':
      _mBorder = '2px solid var(--accent)';
      _mBorderYt = '2px solid var(--accent)';
      _mShadow = 'none';
      break;
    case 'glow':
      _mBorder = '1px solid var(--accent)';
      _mBorderYt = '1px solid var(--accent)';
      _mShadow = '0 0 14px rgba(0,212,170,.35)';
      break;
    case 'subtle':
      _mBorder = '1px solid var(--border)';
      _mBorderYt = '1px solid var(--border)';
      _mShadow = 'none';
      break;
    default: // 'none'
      _mBorder = 'none';
      _mBorderYt = '1px solid var(--border)'; // YT card keeps its border by default so the text info area reads
      _mShadow = 'none';
  }
  const _mMaxH = Math.max(100, Math.min(800, (cfg.mediaMaxHeight|0) || 280));
  r.setProperty('--media-max-w', _mMaxW + 'px');
  r.setProperty('--media-max-h', _mMaxH + 'px');
  r.setProperty('--media-radius', _mRadius);
  r.setProperty('--media-radius-sm', cfg.mediaShape === 'square' ? '0' : (cfg.mediaShape === 'circle' ? '50%' : '6px'));
  r.setProperty('--media-aspect', _mAspect);
  r.setProperty('--media-fit', _mFit);
  r.setProperty('--media-border', _mBorder);
  r.setProperty('--media-border-yt', _mBorderYt);
  r.setProperty('--media-shadow', _mShadow);
  // YT-specific: honor user's aspect choice on the YT thumb too so "square" affects YT thumbs
  r.setProperty('--yt-aspect', cfg.mediaAspect === 'square' || cfg.mediaShape === 'circle' ? '1/1' : '16/9');
  r.setProperty('--yt-play-display', cfg.ytPlayOverlay === false ? 'none' : 'flex');
  // Dynamic styles via a stylesheet
  let ss=document.getElementById('appear-styles');
  if(!ss){ss=document.createElement('style');ss.id='appear-styles';document.head.appendChild(ss);}
  const fontSize=mob&&cfg.mobileChatSize?cfg.mobileChatSize:cfg.chatSize;
  const nickW=mob&&cfg.mobileNickW?cfg.mobileNickW:cfg.nickW;
  const showTs=mob?(cfg.mobileTimestamps!==undefined?cfg.mobileTimestamps:false):cfg.timestamps;
  ss.textContent=`
    body { font-size:${fontSize}px; ${cfg.brightness&&cfg.brightness!==100?`filter:brightness(${cfg.brightness/100});`:''} }
    :root { --mono:${cfg.font||"'Spooky Magic',cursive"}; }
    .msg-row { line-height:${cfg.lineHeight}; ${cfg.compact?'padding:1px 12px;':''} gap:${cfg.msgGap||4}px; }
    .msg-ts, .sc-ts { ${showTs?'':'display:none;'} font-size:${Math.max(fontSize-3,8)}px; }
    .msg-nick { width:${nickW}px; font-size:${fontSize}px; }
    .msg-body { font-size:${fontSize}px; }
    .chan-item { font-size:${cfg.sidebarFont}px; }
    .net-label { font-size:${Math.max(cfg.sidebarFont-1,9)}px; }
    .nick-entry { font-size:${cfg.nickFont}px; }
    ${cfg.statusMsg==='hide'?'.row-join,.row-part,.row-quit,.row-nick,.row-mode,.row-kick,.row-away,.row-back,.status-condensed{display:none!important;}':''}
    ${cfg.compact?'.msg-row:hover{background:none;}':''}
    ${cfg.coloredNicks===false?'.nc0,.nc1,.nc2,.nc3,.nc4,.nc5,.nc6,.nc7,.nc8,.nc9{color:var(--text2)!important;}.nc-self{color:var(--accent)!important;}':''}
    ${cfg.nickList===false?'#nick-panel{display:none!important;}':''}
  `;
  // Apply spellcheck setting to input
  const inp=document.getElementById('msg-input');
  if(inp){
    const sc=cfg.spellcheck!==false;
    inp.setAttribute('spellcheck',sc?'true':'false');
    inp.setAttribute('autocorrect',sc?'on':'off');
  }
  // Toggle animation overlay
  const animEl=document.getElementById('anim-overlay');
  if(animEl){
    if(t.animation){
      animEl.classList.add('active');
      _desiredAnimType=t.animation;
      // Only actually run the 60fps loop while the window is visible+focused;
      // the visibility watcher (see _syncAnimToVisibility) starts/stops it as
      // focus changes. Same visible result when in use — no canvas churn when
      // the window is hidden or in the background.
      if(_appActive())startAnimation(t.animation);else stopAnimation();
    }else{
      animEl.classList.remove('active');
      _desiredAnimType=null;
      stopAnimation();
    }
  }
  // Desktop pet (eSheep): mirror the toggle through the one universal apply
  // funnel (initial load + sync + every change). enable()/disable() are
  // idempotent. Guarded: esheep.js is a deferred script, so on the first
  // app.js apply it may not be defined yet — the window 'load' handler below
  // re-applies the saved state once it is.
  if(window.CryptIRCSheep){ _esheepOn(cfg.esheep) ? window.CryptIRCSheep.enable() : window.CryptIRCSheep.disable(); }
  if(window.CryptIRCCrab){ _crabOn(cfg.crab) ? window.CryptIRCCrab.enable() : window.CryptIRCCrab.disable(); }
  if(window.CryptIRCGhost){ _ghostOn(cfg.ghost) ? window.CryptIRCGhost.enable() : window.CryptIRCGhost.disable(); }
  if(window.CryptIRCFish){ _fishOn(cfg.fish) ? window.CryptIRCFish.enable() : window.CryptIRCFish.disable(); }
  if(window.CryptIRCAlien){ _alienOn(cfg.alien) ? window.CryptIRCAlien.enable() : window.CryptIRCAlien.disable(); }
}

// Apply the saved eSheep state once everything (including the deferred
// esheep.js) has loaded — covers returning users who left the pet enabled,
// regardless of the app.js-runs-before-deferred-scripts execution order.
window.addEventListener('load', function(){
  try{ if(window.CryptIRCSheep){ var _c=loadAppearance(); _esheepOn(_c.esheep) ? window.CryptIRCSheep.enable() : window.CryptIRCSheep.disable(); } }catch(_){}
  try{ if(window.CryptIRCCrab){ var _cc=loadAppearance(); _crabOn(_cc.crab) ? window.CryptIRCCrab.enable() : window.CryptIRCCrab.disable(); } }catch(_){}
  try{ if(window.CryptIRCGhost){ var _cg=loadAppearance(); _ghostOn(_cg.ghost) ? window.CryptIRCGhost.enable() : window.CryptIRCGhost.disable(); } }catch(_){}
  try{ if(window.CryptIRCFish){ var _cf=loadAppearance(); _fishOn(_cf.fish) ? window.CryptIRCFish.enable() : window.CryptIRCFish.disable(); } }catch(_){}
  try{ if(window.CryptIRCAlien){ var _ca=loadAppearance(); _alienOn(_ca.alien) ? window.CryptIRCAlien.enable() : window.CryptIRCAlien.disable(); } }catch(_){}
});

// ─── Animation System ─────────────────────────────────────────────────────────
let _animId=null,_animTimers=[],_animResizeFn=null,_animCurType=null,_desiredAnimType=null;
function stopAnimation(){
  if(_animId){cancelAnimationFrame(_animId);_animId=null;}
  // Timers can be either setInterval handles or {cancel} objects (for mouse listeners etc.)
  _animTimers.forEach(t=>{
    if(t && typeof t==='object' && typeof t.cancel==='function') t.cancel();
    else clearInterval(t);
  });
  _animTimers=[];
  if(_animResizeFn){window.removeEventListener('resize',_animResizeFn);_animResizeFn=null;}
  if(_animResizeRaf){cancelAnimationFrame(_animResizeRaf);_animResizeRaf=0;}
  const cv=document.getElementById('anim-canvas');
  if(cv){const c=cv.getContext('2d');if(c)c.clearRect(0,0,cv.width,cv.height);}
  document.querySelectorAll('.anim-flash').forEach(e=>e.remove());
  _animCurType=null;
}
let _animResizeRaf=0;
function startAnimation(type){
  if(_animCurType===type)return;
  // Honor the OS Reduce Motion setting — skip the decorative background entirely.
  if(window.matchMedia&&window.matchMedia('(prefers-reduced-motion:reduce)').matches)return;
  stopAnimation();_animCurType=type;
  const cv=document.getElementById('anim-canvas');if(!cv)return;
  const ctx=cv.getContext('2d');
  // rAF-coalesce resizes and skip no-ops: iOS fires resize repeatedly on URL-bar
  // show/hide and keyboard open/close, and each cv.width= reallocates+clears the
  // whole backing store. Size to the visual viewport so it tracks the visible area.
  function resize(){
    if(_animResizeRaf)return;
    _animResizeRaf=requestAnimationFrame(()=>{
      _animResizeRaf=0;
      const vv=window.visualViewport;
      const w=Math.round(vv?vv.width:window.innerWidth);
      const h=Math.round(vv?vv.height:window.innerHeight);
      if(cv.width!==w||cv.height!==h){cv.width=w;cv.height=h;}
    });
  }
  cv.width=Math.round(window.visualViewport?window.visualViewport.width:window.innerWidth);
  cv.height=Math.round(window.visualViewport?window.visualViewport.height:window.innerHeight);
  _animResizeFn=resize;window.addEventListener('resize',resize,{passive:true});
  const fn=_ANIM[type];if(fn)fn(cv,ctx);
}
// Pause the decorative background animation whenever the window is hidden or
// unfocused — there's no reason to burn 60fps of GPU/CPU on a starfield nobody
// is looking at. Biggest idle-cost reduction, and invisible in normal use: when
// the window is focused the animation runs exactly as before; when you switch
// away it stops and resumes on return. _desiredAnimType (set in applyThemeCSS)
// is the single source of truth for what should run, so theme changes stay in
// sync. Registered as dedicated listeners so existing visibility/focus handlers
// are untouched.
function _appActive(){return !document.hidden && document.hasFocus();}
function _syncAnimToVisibility(){
  if(_appActive()){
    if(_desiredAnimType && _animCurType!==_desiredAnimType) startAnimation(_desiredAnimType);
  }else if(_animCurType){
    stopAnimation();
  }
}
document.addEventListener('visibilitychange',_syncAnimToVisibility);
window.addEventListener('blur',_syncAnimToVisibility);
window.addEventListener('focus',_syncAnimToVisibility);
const _ANIM={
rain(cv,ctx){
  const drops=[];
  for(let i=0;i<150;i++)drops.push({x:Math.random()*cv.width,y:Math.random()*cv.height,len:Math.random()*15+8,speed:Math.random()*4+6,opacity:Math.random()*0.15+0.05});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const d of drops){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(d.x+1,d.y+d.len);ctx.strokeStyle=`rgba(180,200,220,${d.opacity})`;ctx.lineWidth=0.8;ctx.stroke();d.y+=d.speed;d.x+=0.3;if(d.y>cv.height){d.y=-d.len;d.x=Math.random()*cv.width;}}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(Math.random()<0.3){const flash=document.createElement('div');flash.className='anim-flash';flash.style.cssText='position:fixed;inset:0;background:rgba(200,220,255,0.06);z-index:0;pointer-events:none;transition:opacity 0.15s;';document.body.appendChild(flash);setTimeout(()=>{flash.style.opacity='0';},80);setTimeout(()=>{flash.remove();if(Math.random()<0.5){const f2=document.createElement('div');f2.className='anim-flash';f2.style.cssText='position:fixed;inset:0;background:rgba(200,220,255,0.04);z-index:0;pointer-events:none;transition:opacity 0.2s;';document.body.appendChild(f2);setTimeout(()=>{f2.style.opacity='0';},60);setTimeout(()=>f2.remove(),300);}},150);}},8000));
},
deepspace(cv,ctx){
  const stars=[];for(let i=0;i<200;i++)stars.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*1.5+0.3,speed:Math.random()*0.2+0.05,tw:Math.random()*Math.PI*2});
  let shooters=[];
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of stars){s.tw+=0.02;const a=0.3+Math.sin(s.tw)*0.2;ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(200,210,240,${a})`;ctx.fill();s.x-=s.speed;if(s.x<0){s.x=cv.width;s.y=Math.random()*cv.height;}}for(let i=shooters.length-1;i>=0;i--){const sh=shooters[i];ctx.beginPath();ctx.moveTo(sh.x,sh.y);ctx.lineTo(sh.x-sh.len,sh.y-sh.len*0.3);ctx.strokeStyle=`rgba(255,255,255,${sh.a})`;ctx.lineWidth=1.2;ctx.stroke();sh.x+=sh.speed;sh.y+=sh.speed*0.3;sh.a-=0.01;if(sh.a<=0)shooters.splice(i,1);}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(Math.random()<0.4)shooters.push({x:Math.random()*cv.width*0.5,y:Math.random()*cv.height*0.3,len:40+Math.random()*40,speed:6+Math.random()*4,a:0.7});},3000));
},
snowfall(cv,ctx){
  const flakes=[];for(let i=0;i<120;i++)flakes.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*2.5+0.8,speed:Math.random()*1+0.5,w:Math.random()*Math.PI*2,ws:Math.random()*0.02+0.01,opacity:Math.random()*0.4+0.1});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const f of flakes){f.w+=f.ws;f.x+=Math.sin(f.w)*0.5;f.y+=f.speed;if(f.y>cv.height+5){f.y=-5;f.x=Math.random()*cv.width;}ctx.beginPath();ctx.arc(f.x,f.y,f.r,0,Math.PI*2);ctx.fillStyle=`rgba(220,230,255,${f.opacity})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
fireflies(cv,ctx){
  const flies=[];for(let i=0;i<50;i++)flies.push({x:Math.random()*cv.width,y:Math.random()*cv.height,vx:(Math.random()-0.5)*0.5,vy:(Math.random()-0.5)*0.5,phase:Math.random()*Math.PI*2,r:Math.random()*2+1});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const f of flies){f.phase+=0.03;const a=0.1+Math.sin(f.phase)*0.15;f.x+=f.vx;f.y+=f.vy;if(f.x<0||f.x>cv.width)f.vx*=-1;if(f.y<0||f.y>cv.height)f.vy*=-1;const g=ctx.createRadialGradient(f.x,f.y,0,f.x,f.y,f.r*4);g.addColorStop(0,`rgba(180,220,60,${a+0.15})`);g.addColorStop(1,'rgba(180,220,60,0)');ctx.beginPath();ctx.arc(f.x,f.y,f.r*4,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();ctx.beginPath();ctx.arc(f.x,f.y,f.r,0,Math.PI*2);ctx.fillStyle=`rgba(200,240,80,${a+0.2})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
aurora(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.005;for(let b=0;b<3;b++){ctx.beginPath();const yB=cv.height*0.15+b*50;ctx.moveTo(0,yB);for(let x=0;x<=cv.width;x+=4){const y=yB+Math.sin(x*0.003+t+b*2)*40+Math.sin(x*0.007+t*1.5)*20;ctx.lineTo(x,y);}ctx.lineTo(cv.width,cv.height);ctx.lineTo(0,cv.height);ctx.closePath();const colors=['rgba(40,220,160,0.03)','rgba(80,120,220,0.03)','rgba(160,60,200,0.025)'];ctx.fillStyle=colors[b];ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
digitalrain(cv,ctx){
  const cols=Math.floor(cv.width/14);const ypos=Array(cols).fill(0).map(()=>Math.random()*cv.height);
  const chars='01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
  const buf=document.createElement('canvas');buf.width=cv.width;buf.height=cv.height;const bctx=buf.getContext('2d');
  (function draw(){bctx.fillStyle='rgba(0,0,0,0.05)';bctx.fillRect(0,0,buf.width,buf.height);bctx.font='13px monospace';for(let i=0;i<cols;i++){const ch=chars[Math.floor(Math.random()*chars.length)];bctx.fillStyle=`rgba(0,${180+Math.random()*75},0,0.8)`;bctx.fillText(ch,i*14,ypos[i]);ypos[i]+=14;if(ypos[i]>buf.height&&Math.random()>0.98)ypos[i]=0;}ctx.clearRect(0,0,cv.width,cv.height);ctx.globalAlpha=0.3;ctx.drawImage(buf,0,0);ctx.globalAlpha=1;_animId=requestAnimationFrame(draw);})();
},
neongrid(cv,ctx){
  let offset=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);offset=(offset+0.5)%50;const horizon=cv.height*0.4;const cx=cv.width/2;for(let i=0;i<15;i++){const t=(i*50+offset)/750;const y=horizon+Math.pow(t,1.5)*(cv.height-horizon)*1.2;if(y>cv.height)continue;const a=Math.min(0.15,t*0.3);ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(cv.width,y);ctx.strokeStyle=`rgba(0,200,255,${a})`;ctx.lineWidth=0.8;ctx.stroke();}for(let i=-10;i<=10;i++){const x=cx+i*cv.width*0.15;ctx.beginPath();ctx.moveTo(cx,horizon);ctx.lineTo(x,cv.height);ctx.strokeStyle=`rgba(0,200,255,${Math.min(0.08+Math.abs(i)*0.005,0.15)})`;ctx.lineWidth=0.6;ctx.stroke();}_animId=requestAnimationFrame(draw);})();
},
underwater(cv,ctx){
  const bubbles=[];for(let i=0;i<60;i++)bubbles.push({x:Math.random()*cv.width,y:cv.height+Math.random()*cv.height,r:Math.random()*4+1,speed:Math.random()*1.5+0.3,w:Math.random()*Math.PI*2});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const b of bubbles){b.w+=0.02;b.x+=Math.sin(b.w)*0.3;b.y-=b.speed;if(b.y<-10){b.y=cv.height+10;b.x=Math.random()*cv.width;}ctx.beginPath();ctx.arc(b.x,b.y,b.r,0,Math.PI*2);ctx.strokeStyle=`rgba(100,200,230,${0.15+b.r*0.03})`;ctx.lineWidth=0.8;ctx.stroke();ctx.beginPath();ctx.arc(b.x-b.r*0.3,b.y-b.r*0.3,b.r*0.2,0,Math.PI*2);ctx.fillStyle=`rgba(150,220,240,${0.1+b.r*0.02})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
cherryblossom(cv,ctx){
  const petals=[];for(let i=0;i<80;i++)petals.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*4+2,speed:Math.random()*1+0.3,drift:Math.random()*0.5+0.2,rot:Math.random()*Math.PI*2,rs:Math.random()*0.03+0.01,opacity:Math.random()*0.2+0.05});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const p of petals){p.y+=p.speed;p.x+=p.drift+Math.sin(p.rot)*0.3;p.rot+=p.rs;if(p.y>cv.height+10){p.y=-10;p.x=Math.random()*cv.width;}ctx.save();ctx.translate(p.x,p.y);ctx.rotate(p.rot);ctx.beginPath();ctx.ellipse(0,0,p.r,p.r*0.6,0,0,Math.PI*2);ctx.fillStyle=`rgba(255,180,200,${p.opacity})`;ctx.fill();ctx.restore();}_animId=requestAnimationFrame(draw);})();
},
starwarp(cv,ctx){
  const stars=[];for(let i=0;i<200;i++)stars.push({x:(Math.random()-0.5)*cv.width,y:(Math.random()-0.5)*cv.height,z:Math.random()*1000+1});
  const buf=document.createElement('canvas');buf.width=cv.width;buf.height=cv.height;const bctx=buf.getContext('2d');
  (function draw(){bctx.fillStyle='rgba(0,0,4,0.15)';bctx.fillRect(0,0,buf.width,buf.height);const cx=cv.width/2,cy=cv.height/2;for(const s of stars){s.z-=3;if(s.z<=0){s.x=(Math.random()-0.5)*cv.width;s.y=(Math.random()-0.5)*cv.height;s.z=1000;}const sx=cx+s.x*(500/s.z),sy=cy+s.y*(500/s.z);const r=Math.max(0.3,(1-s.z/1000)*2);bctx.beginPath();bctx.arc(sx,sy,r,0,Math.PI*2);bctx.fillStyle=`rgba(200,210,255,${Math.min(0.8,1-s.z/1000)})`;bctx.fill();}ctx.clearRect(0,0,cv.width,cv.height);ctx.globalAlpha=0.5;ctx.drawImage(buf,0,0);ctx.globalAlpha=1;_animId=requestAnimationFrame(draw);})();
},
ember(cv,ctx){
  const sparks=[];for(let i=0;i<70;i++)sparks.push({x:Math.random()*cv.width,y:cv.height+Math.random()*100,vx:(Math.random()-0.5)*0.5,vy:-(Math.random()*1.5+0.5),life:Math.random(),r:Math.random()*2+0.5});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of sparks){s.x+=s.vx+Math.sin(s.life*10)*0.2;s.y+=s.vy;s.life-=0.003;if(s.life<=0||s.y<-10){s.x=Math.random()*cv.width;s.y=cv.height+10;s.life=1;s.vx=(Math.random()-0.5)*0.5;s.vy=-(Math.random()*1.5+0.5);}const g=ctx.createRadialGradient(s.x,s.y,0,s.x,s.y,s.r*3);g.addColorStop(0,`rgba(255,${120+Math.random()*40},20,${s.life*0.3})`);g.addColorStop(1,'rgba(255,100,0,0)');ctx.beginPath();ctx.arc(s.x,s.y,s.r*3,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
nebula(cv,ctx){
  const clouds=[];for(let i=0;i<40;i++){const hue=Math.random()*360;clouds.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*60+20,vx:(Math.random()-0.5)*0.3,vy:(Math.random()-0.5)*0.3,hue,phase:Math.random()*Math.PI*2});}
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const c of clouds){c.phase+=0.008;c.x+=c.vx;c.y+=c.vy;if(c.x<-c.r)c.x=cv.width+c.r;if(c.x>cv.width+c.r)c.x=-c.r;if(c.y<-c.r)c.y=cv.height+c.r;if(c.y>cv.height+c.r)c.y=-c.r;const a=0.02+Math.sin(c.phase)*0.01;const g=ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,c.r);g.addColorStop(0,`hsla(${c.hue},60%,50%,${a+0.02})`);g.addColorStop(1,`hsla(${c.hue},60%,50%,0)`);ctx.beginPath();ctx.arc(c.x,c.y,c.r,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
confetti(cv,ctx){
  const pieces=[];const colors=['#ff4466','#44ff66','#4488ff','#ffaa00','#ff44ff','#44ffff','#ffff44'];
  for(let i=0;i<80;i++)pieces.push({x:Math.random()*cv.width,y:Math.random()*cv.height,w:Math.random()*6+3,h:Math.random()*4+2,rot:Math.random()*Math.PI*2,rs:(Math.random()-0.5)*0.08,speed:Math.random()*1.5+0.5,drift:Math.random()*0.5-0.25,color:colors[Math.floor(Math.random()*colors.length)],opacity:Math.random()*0.25+0.05});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const p of pieces){p.y+=p.speed;p.x+=p.drift;p.rot+=p.rs;if(p.y>cv.height+10){p.y=-10;p.x=Math.random()*cv.width;}ctx.save();ctx.translate(p.x,p.y);ctx.rotate(p.rot);ctx.globalAlpha=p.opacity;ctx.fillStyle=p.color;ctx.fillRect(-p.w/2,-p.h/2,p.w,p.h);ctx.globalAlpha=1;ctx.restore();}_animId=requestAnimationFrame(draw);})();
},
campfire(cv,ctx){
  const embers=[];for(let i=0;i<90;i++){const x=cv.width*0.3+Math.random()*cv.width*0.4;embers.push({x,ox:x,y:cv.height+Math.random()*50,vy:-(Math.random()*1.2+0.3),life:Math.random(),r:Math.random()*2+0.5,w:Math.random()*Math.PI*2});}
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);const glow=ctx.createRadialGradient(cv.width/2,cv.height,0,cv.width/2,cv.height,cv.height*0.4);glow.addColorStop(0,'rgba(255,100,20,0.03)');glow.addColorStop(1,'rgba(255,60,0,0)');ctx.fillStyle=glow;ctx.fillRect(0,0,cv.width,cv.height);for(const e of embers){e.w+=0.03;e.x=e.ox+Math.sin(e.w)*20;e.y+=e.vy;e.life-=0.002;if(e.life<=0||e.y<-10){e.ox=cv.width*0.3+Math.random()*cv.width*0.4;e.x=e.ox;e.y=cv.height+10;e.life=1;}const r=e.r*e.life;ctx.beginPath();ctx.arc(e.x,e.y,r,0,Math.PI*2);ctx.fillStyle=`rgba(255,${80+e.life*100},${e.life*30},${e.life*0.25})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
oceanwaves(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.02;for(let w=0;w<4;w++){ctx.beginPath();const yB=cv.height*0.65+w*30;ctx.moveTo(0,cv.height);for(let x=0;x<=cv.width;x+=3){const y=yB+Math.sin(x*0.005+t+w*1.5)*15+Math.sin(x*0.01+t*0.7)*8;ctx.lineTo(x,y);}ctx.lineTo(cv.width,cv.height);ctx.closePath();ctx.fillStyle=`rgba(20,80,140,${0.02+w*0.005})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
plasma(cv,ctx){
  let t=0;const bw=Math.ceil(cv.width/4),bh=Math.ceil(cv.height/4);
  const buf=document.createElement('canvas');buf.width=bw;buf.height=bh;const bctx=buf.getContext('2d');const img=bctx.createImageData(bw,bh);
  (function draw(){t+=0.02;for(let y=0;y<bh;y++){for(let x=0;x<bw;x++){const v=Math.sin(x*0.05+t)+Math.sin(y*0.05+t*0.7)+Math.sin((x+y)*0.03+t*0.5)+Math.sin(Math.sqrt(x*x+y*y)*0.04);const idx=(y*bw+x)*4;img.data[idx]=(Math.sin(v*Math.PI)*0.5+0.5)*40;img.data[idx+1]=(Math.sin(v*Math.PI+2)*0.5+0.5)*30;img.data[idx+2]=(Math.sin(v*Math.PI+4)*0.5+0.5)*50;img.data[idx+3]=20;}}bctx.putImageData(img,0,0);ctx.clearRect(0,0,cv.width,cv.height);ctx.drawImage(buf,0,0,cv.width,cv.height);_animId=requestAnimationFrame(draw);})();
},
alien(cv,ctx){
  // Stars background
  const stars=[];for(let i=0;i<100;i++)stars.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*1.2+0.3,tw:Math.random()*Math.PI*2});
  // UFOs that drift across the screen
  const ufos=[];for(let i=0;i<3;i++)ufos.push({x:Math.random()*cv.width,y:40+Math.random()*cv.height*0.25,vx:(Math.random()-0.5)*1.2,vy:0,w:40+Math.random()*20,bob:Math.random()*Math.PI*2,beamOn:false,beamTimer:0});
  // Sheep on the ground that walk around
  const sheep=[];for(let i=0;i<5;i++)sheep.push({x:Math.random()*cv.width,y:cv.height-30-Math.random()*20,vx:(Math.random()-0.5)*0.6,abducted:false,abY:0,abUfo:null,phase:Math.random()*Math.PI*2,dir:Math.random()>0.5?1:-1});
  let t=0;
  (function draw(){
    ctx.clearRect(0,0,cv.width,cv.height);t+=0.02;
    // Stars
    for(const s of stars){s.tw+=0.015;const a=0.2+Math.sin(s.tw)*0.15;ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(150,220,180,${a})`;ctx.fill();}
    // Sheep on ground
    for(const sh of sheep){
      if(!sh.abducted){
        sh.phase+=0.04;sh.x+=sh.vx;
        if(sh.x<20||sh.x>cv.width-20){sh.vx*=-1;sh.dir*=-1;}
        const bx=sh.x,by=sh.y+Math.sin(sh.phase)*1;
        // Body (fluffy cloud shape)
        ctx.fillStyle='rgba(220,220,210,0.15)';
        ctx.beginPath();ctx.ellipse(bx,by,8,6,0,0,Math.PI*2);ctx.fill();
        ctx.beginPath();ctx.ellipse(bx-4,by-3,4,4,0,0,Math.PI*2);ctx.fill();
        ctx.beginPath();ctx.ellipse(bx+4,by-3,4,4,0,0,Math.PI*2);ctx.fill();
        // Head
        ctx.fillStyle='rgba(180,180,170,0.18)';
        ctx.beginPath();ctx.arc(bx+(sh.dir*8),by-1,3.5,0,Math.PI*2);ctx.fill();
        // Legs
        ctx.strokeStyle='rgba(200,200,190,0.12)';ctx.lineWidth=1;
        ctx.beginPath();ctx.moveTo(bx-4,by+5);ctx.lineTo(bx-4,by+10);ctx.moveTo(bx+4,by+5);ctx.lineTo(bx+4,by+10);ctx.stroke();
      } else {
        // Being abducted - float upward
        sh.abY-=0.8;
        const bx=sh.x,by=sh.y+sh.abY;
        if(by<-20){sh.abducted=false;sh.abY=0;sh.x=Math.random()*cv.width;sh.y=cv.height-30-Math.random()*20;}
        ctx.fillStyle=`rgba(100,255,150,${0.15+Math.sin(t*5)*0.05})`;
        ctx.beginPath();ctx.ellipse(bx,by,8,6,Math.sin(t*3)*0.3,0,Math.PI*2);ctx.fill();
        ctx.beginPath();ctx.ellipse(bx-4,by-3,4,4,0,0,Math.PI*2);ctx.fill();
        ctx.beginPath();ctx.ellipse(bx+4,by-3,4,4,0,0,Math.PI*2);ctx.fill();
      }
    }
    // UFOs
    for(const u of ufos){
      u.bob+=0.03;u.x+=u.vx;u.y+=Math.sin(u.bob)*0.3;
      if(u.x<-60)u.x=cv.width+60;if(u.x>cv.width+60)u.x=-60;
      // Tractor beam timer
      u.beamTimer--;
      if(u.beamTimer<=0){u.beamOn=Math.random()<0.02;if(u.beamOn)u.beamTimer=200+Math.random()*150;}
      // UFO body - saucer shape
      const ux=u.x,uy=u.y;
      // Glow under UFO
      const gl=ctx.createRadialGradient(ux,uy+6,0,ux,uy+6,u.w*0.6);
      gl.addColorStop(0,'rgba(80,255,120,0.06)');gl.addColorStop(1,'rgba(80,255,120,0)');
      ctx.fillStyle=gl;ctx.beginPath();ctx.arc(ux,uy+6,u.w*0.6,0,Math.PI*2);ctx.fill();
      // Dome (top bubble)
      ctx.fillStyle='rgba(120,255,180,0.12)';
      ctx.beginPath();ctx.ellipse(ux,uy-5,u.w*0.25,8,0,Math.PI,0);ctx.fill();
      // Main saucer body
      ctx.fillStyle='rgba(60,180,100,0.15)';
      ctx.beginPath();ctx.ellipse(ux,uy,u.w*0.5,6,0,0,Math.PI*2);ctx.fill();
      // Lights on rim
      for(let li=0;li<5;li++){
        const la=li/5*Math.PI*2+t*2;
        const lx=ux+Math.cos(la)*u.w*0.4,ly=uy+Math.sin(la)*3;
        ctx.beginPath();ctx.arc(lx,ly,1.5,0,Math.PI*2);
        ctx.fillStyle=`rgba(${li%2?'255,100,100':'100,255,100'},${0.2+Math.sin(t*4+li)*0.1})`;ctx.fill();
      }
      // Tractor beam
      if(u.beamOn){
        const beamW=u.w*0.3;
        const grd=ctx.createLinearGradient(ux,uy+8,ux,cv.height);
        grd.addColorStop(0,'rgba(80,255,120,0.08)');grd.addColorStop(0.5,'rgba(80,255,120,0.04)');grd.addColorStop(1,'rgba(80,255,120,0)');
        ctx.fillStyle=grd;
        ctx.beginPath();ctx.moveTo(ux-beamW*0.5,uy+8);ctx.lineTo(ux-beamW*1.5,cv.height);ctx.lineTo(ux+beamW*1.5,cv.height);ctx.lineTo(ux+beamW*0.5,uy+8);ctx.closePath();ctx.fill();
        // Check if any sheep is under the beam — abduct it!
        for(const sh of sheep){
          if(!sh.abducted && Math.abs(sh.x-ux)<beamW*2 && sh.y>uy){sh.abducted=true;sh.abY=0;}
        }
      }
    }
    _animId=requestAnimationFrame(draw);
  })();
},
lightning(cv,ctx){
  const bolts=[];const drops=[];for(let i=0;i<80;i++)drops.push({x:Math.random()*cv.width,y:Math.random()*cv.height,len:Math.random()*10+5,speed:Math.random()*3+4});
  function mkBolt(){const segs=[];let cx=Math.random()*cv.width,cy=0;for(let i=0;i<10;i++){cx+=(Math.random()-0.5)*60;cy+=cv.height/10;segs.push({x:cx,y:cy});}return{segs,a:0.7};}
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const d of drops){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(d.x+0.5,d.y+d.len);ctx.strokeStyle='rgba(160,170,200,0.06)';ctx.lineWidth=0.6;ctx.stroke();d.y+=d.speed;if(d.y>cv.height){d.y=-d.len;d.x=Math.random()*cv.width;}}for(let i=bolts.length-1;i>=0;i--){const b=bolts[i];ctx.beginPath();ctx.moveTo(b.segs[0].x,0);for(const s of b.segs)ctx.lineTo(s.x,s.y);ctx.strokeStyle=`rgba(180,180,255,${b.a})`;ctx.lineWidth=2;ctx.stroke();ctx.strokeStyle=`rgba(220,220,255,${b.a*0.4})`;ctx.lineWidth=6;ctx.stroke();b.a-=0.025;if(b.a<=0)bolts.splice(i,1);}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(Math.random()<0.3){bolts.push(mkBolt());const fl=document.createElement('div');fl.className='anim-flash';fl.style.cssText='position:fixed;inset:0;background:rgba(180,180,255,0.05);z-index:0;pointer-events:none;transition:opacity 0.15s;';document.body.appendChild(fl);setTimeout(()=>{fl.style.opacity='0';},80);setTimeout(()=>fl.remove(),300);}},5000));
},
sandstorm(cv,ctx){
  const grains=[];for(let i=0;i<200;i++)grains.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*1.5+0.3,speed:Math.random()*3+1,vy:(Math.random()-0.5)*0.5,o:Math.random()*0.15+0.03});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const g of grains){g.x+=g.speed;g.y+=g.vy+Math.sin(g.x*0.01)*0.3;if(g.x>cv.width+5){g.x=-5;g.y=Math.random()*cv.height;}if(g.y<0)g.y=cv.height;if(g.y>cv.height)g.y=0;ctx.beginPath();ctx.arc(g.x,g.y,g.r,0,Math.PI*2);ctx.fillStyle=`rgba(200,180,140,${g.o})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
hologram(cv,ctx){
  let offset=0;const lines=[];for(let i=0;i<30;i++)lines.push({y:Math.random()*cv.height,speed:Math.random()*1+0.5,h:Math.random()*2+1,o:Math.random()*0.06+0.02});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);offset+=0.5;for(const l of lines){l.y+=l.speed;if(l.y>cv.height)l.y=-l.h;ctx.fillStyle=`rgba(0,238,255,${l.o})`;ctx.fillRect(0,l.y,cv.width,l.h);}for(let y=0;y<cv.height;y+=3){ctx.fillStyle=`rgba(0,238,255,${0.008+Math.sin((y+offset)*0.1)*0.004})`;ctx.fillRect(0,y,cv.width,1);}_animId=requestAnimationFrame(draw);})();
},
meteorshower(cv,ctx){
  const stars=[];for(let i=0;i<100;i++)stars.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()+0.3,tw:Math.random()*Math.PI*2});
  const meteors=[];function mk(){return{x:Math.random()*cv.width*1.5,y:-20-Math.random()*100,speed:Math.random()*6+4,len:Math.random()*60+30,angle:Math.PI*0.7+Math.random()*0.2,a:Math.random()*0.4+0.3};}
  for(let i=0;i<4;i++)meteors.push(mk());
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of stars){s.tw+=0.01;ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(200,200,240,${0.15+Math.sin(s.tw)*0.1})`;ctx.fill();}for(let i=meteors.length-1;i>=0;i--){const m=meteors[i];m.x+=Math.cos(m.angle)*m.speed;m.y+=Math.sin(m.angle)*m.speed;const tx=m.x-Math.cos(m.angle)*m.len,ty=m.y-Math.sin(m.angle)*m.len;const g=ctx.createLinearGradient(m.x,m.y,tx,ty);g.addColorStop(0,`rgba(255,200,100,${m.a})`);g.addColorStop(1,'rgba(255,200,100,0)');ctx.beginPath();ctx.moveTo(m.x,m.y);ctx.lineTo(tx,ty);ctx.strokeStyle=g;ctx.lineWidth=1.5;ctx.stroke();if(m.y>cv.height+50||m.x<-100)meteors[i]=mk();}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(meteors.length<8&&Math.random()<0.4)meteors.push(mk());},2000));
},
pixelrain(cv,ctx){
  const pixels=[];const colors=['#44dd88','#22cc66','#66eebb','#33bb77','#55ffaa'];
  for(let i=0;i<100;i++)pixels.push({x:Math.floor(Math.random()*cv.width/8)*8,y:Math.random()*cv.height,s:Math.floor(Math.random()*3+2)*2,speed:Math.random()*2+0.5,color:colors[Math.floor(Math.random()*colors.length)],o:Math.random()*0.2+0.05});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const p of pixels){p.y+=p.speed;if(p.y>cv.height){p.y=-p.s;p.x=Math.floor(Math.random()*cv.width/8)*8;}ctx.globalAlpha=p.o;ctx.fillStyle=p.color;ctx.fillRect(p.x,p.y,p.s,p.s);}ctx.globalAlpha=1;_animId=requestAnimationFrame(draw);})();
},
synthsun(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.01;const cx=cv.width/2,sunY=cv.height*0.65,sunR=80;const sg=ctx.createRadialGradient(cx,sunY,0,cx,sunY,sunR);sg.addColorStop(0,'rgba(255,60,120,0.08)');sg.addColorStop(0.5,'rgba(255,120,50,0.04)');sg.addColorStop(1,'rgba(255,60,120,0)');ctx.beginPath();ctx.arc(cx,sunY,sunR,0,Math.PI*2);ctx.fillStyle=sg;ctx.fill();for(let i=0;i<8;i++){const y=sunY-sunR+i*(sunR*2/8)+((t*20)%(sunR*2/8));if(y>sunY-sunR&&y<sunY+sunR){ctx.fillStyle='rgba(14,4,26,0.4)';ctx.fillRect(cx-sunR,y,sunR*2,2);}}const hz=cv.height*0.65;for(let i=0;i<12;i++){const ft=(i*40+(t*40)%40)/500;const y=hz+Math.pow(ft,1.3)*(cv.height-hz)*1.5;if(y>cv.height)continue;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(cv.width,y);ctx.strokeStyle=`rgba(255,60,180,${Math.min(0.08,ft*0.2)})`;ctx.lineWidth=0.6;ctx.stroke();}for(let i=-8;i<=8;i++){ctx.beginPath();ctx.moveTo(cx,hz);ctx.lineTo(cx+i*cv.width*0.15,cv.height);ctx.strokeStyle='rgba(255,60,180,0.06)';ctx.lineWidth=0.5;ctx.stroke();}_animId=requestAnimationFrame(draw);})();
},
toxicrain(cv,ctx){
  const drops=[];for(let i=0;i<120;i++)drops.push({x:Math.random()*cv.width,y:Math.random()*cv.height,len:Math.random()*12+6,speed:Math.random()*4+3,o:Math.random()*0.12+0.04});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const d of drops){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(d.x+0.5,d.y+d.len);ctx.strokeStyle=`rgba(100,255,40,${d.o})`;ctx.lineWidth=0.8;ctx.stroke();d.y+=d.speed;if(d.y>cv.height){d.y=-d.len;d.x=Math.random()*cv.width;}}_animId=requestAnimationFrame(draw);})();
},
fairydust(cv,ctx){
  const sparks=[];const colors=['rgba(255,220,100,','rgba(220,180,255,','rgba(180,220,255,','rgba(255,180,220,'];
  for(let i=0;i<60;i++)sparks.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*2+0.5,ph:Math.random()*Math.PI*2,vx:(Math.random()-0.5)*0.3,vy:-(Math.random()*0.3+0.1)});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of sparks){s.ph+=0.04;s.x+=s.vx+Math.sin(s.ph)*0.3;s.y+=s.vy;if(s.y<-10){s.y=cv.height+10;s.x=Math.random()*cv.width;}const a=0.1+Math.sin(s.ph)*0.12;const c=colors[Math.floor(Math.abs(s.ph))%colors.length];const g=ctx.createRadialGradient(s.x,s.y,0,s.x,s.y,s.r*3);g.addColorStop(0,c+(a+0.1)+')');g.addColorStop(1,c+'0)');ctx.beginPath();ctx.arc(s.x,s.y,s.r*3,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();ctx.beginPath();ctx.arc(s.x,s.y,s.r*0.5,0,Math.PI*2);ctx.fillStyle=c+(a+0.15)+')';ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
comettrail(cv,ctx){
  const stars=[];for(let i=0;i<80;i++)stars.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()+0.2,tw:Math.random()*Math.PI*2});
  const comets=[];function mk(){return{x:-50-Math.random()*100,y:Math.random()*cv.height*0.6,speed:Math.random()*2+1.5,a:Math.random()*0.3+0.2,trail:[]};}
  for(let i=0;i<4;i++)comets.push(mk());
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of stars){s.tw+=0.01;ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(180,200,240,${0.15+Math.sin(s.tw)*0.1})`;ctx.fill();}for(const c of comets){c.x+=c.speed;c.trail.push({x:c.x,y:c.y});if(c.trail.length>30)c.trail.shift();for(let i=0;i<c.trail.length;i++){const t=c.trail[i],a=c.a*(i/c.trail.length);ctx.beginPath();ctx.arc(t.x,t.y,1.5*(i/c.trail.length),0,Math.PI*2);ctx.fillStyle=`rgba(140,180,255,${a})`;ctx.fill();}ctx.beginPath();ctx.arc(c.x,c.y,2,0,Math.PI*2);ctx.fillStyle=`rgba(220,230,255,${c.a})`;ctx.fill();if(c.x>cv.width+100)Object.assign(c,mk());}_animId=requestAnimationFrame(draw);})();
},
lavalamp(cv,ctx){
  const blobs=[];for(let i=0;i<6;i++)blobs.push({x:cv.width*0.2+Math.random()*cv.width*0.6,y:cv.height*0.3+Math.random()*cv.height*0.4,r:Math.random()*60+30,vx:(Math.random()-0.5)*0.3,vy:(Math.random()-0.5)*0.3,ph:Math.random()*Math.PI*2,hue:Math.random()*40+10});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const b of blobs){b.ph+=0.008;b.x+=b.vx+Math.sin(b.ph)*0.5;b.y+=b.vy+Math.cos(b.ph*0.7)*0.3;if(b.x<b.r||b.x>cv.width-b.r)b.vx*=-1;if(b.y<b.r||b.y>cv.height-b.r)b.vy*=-1;const r=b.r+Math.sin(b.ph*2)*10;const g=ctx.createRadialGradient(b.x,b.y,0,b.x,b.y,r);g.addColorStop(0,`hsla(${b.hue},80%,50%,0.04)`);g.addColorStop(0.6,`hsla(${b.hue},80%,40%,0.02)`);g.addColorStop(1,`hsla(${b.hue},80%,30%,0)`);ctx.beginPath();ctx.arc(b.x,b.y,r,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
electricarc(cv,ctx){
  const nodes=[];for(let i=0;i<8;i++)nodes.push({x:Math.random()*cv.width,y:Math.random()*cv.height,vx:(Math.random()-0.5)*0.8,vy:(Math.random()-0.5)*0.8});
  let arcs=[];
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const n of nodes){n.x+=n.vx;n.y+=n.vy;if(n.x<0||n.x>cv.width)n.vx*=-1;if(n.y<0||n.y>cv.height)n.vy*=-1;ctx.beginPath();ctx.arc(n.x,n.y,2,0,Math.PI*2);ctx.fillStyle='rgba(68,170,255,0.15)';ctx.fill();}for(let i=arcs.length-1;i>=0;i--){const a=arcs[i];ctx.beginPath();ctx.moveTo(a.p[0].x,a.p[0].y);for(let j=1;j<a.p.length;j++)ctx.lineTo(a.p[j].x,a.p[j].y);ctx.strokeStyle=`rgba(100,180,255,${a.a})`;ctx.lineWidth=1.5;ctx.stroke();ctx.strokeStyle=`rgba(150,200,255,${a.a*0.3})`;ctx.lineWidth=4;ctx.stroke();a.a-=0.02;if(a.a<=0)arcs.splice(i,1);}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(arcs.length<3&&nodes.length>=2){const a=nodes[Math.floor(Math.random()*nodes.length)],b=nodes[Math.floor(Math.random()*nodes.length)];if(a!==b){const p=[{x:a.x,y:a.y}];let cx=a.x,cy=a.y;for(let i=1;i<=8;i++){cx+=(b.x-a.x)/8+(Math.random()-0.5)*40;cy+=(b.y-a.y)/8+(Math.random()-0.5)*40;p.push({x:cx,y:cy});}arcs.push({p,a:0.5});}}},500));
},
galaxy(cv,ctx){
  const stars=[];const arms=3;for(let i=0;i<250;i++){const arm=i%arms;const dist=Math.random()*Math.min(cv.width,cv.height)*0.4;const angle=arm*(Math.PI*2/arms)+dist*0.003+Math.random()*0.5;stars.push({dist,angle,r:Math.random()*1.2+0.3,speed:0.0008+Math.random()*0.0004,hue:200+Math.random()*60});}
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);const cx=cv.width/2,cy=cv.height/2;for(const s of stars){s.angle+=s.speed;const x=cx+Math.cos(s.angle)*s.dist,y=cy+Math.sin(s.angle)*s.dist*0.6;ctx.beginPath();ctx.arc(x,y,s.r,0,Math.PI*2);ctx.fillStyle=`hsla(${s.hue},60%,70%,${0.15+0.1*(1-s.dist/(Math.min(cv.width,cv.height)*0.4))})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
glitch(cv,ctx){
  let f=0;const colors=['rgba(255,68,102,0.06)','rgba(68,136,255,0.06)','rgba(68,255,136,0.06)','rgba(255,255,68,0.04)'];
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);f++;if(f%3===0){for(let i=0;i<Math.floor(Math.random()*4)+1;i++){ctx.fillStyle=colors[Math.floor(Math.random()*colors.length)];ctx.fillRect(Math.random()*cv.width,Math.random()*cv.height,Math.random()*100+20,Math.random()*4+1);}if(Math.random()<0.03){const sy=Math.random()*cv.height,sh=Math.random()*15+3;try{const strip=ctx.getImageData(0,sy,cv.width,sh);ctx.putImageData(strip,Math.random()*20-10,sy);}catch(e){}}}_animId=requestAnimationFrame(draw);})();
},
firewall(cv,ctx){
  const cols=Math.floor(cv.width/10);const ypos=Array(cols).fill(0).map(()=>Math.random()*cv.height);const chars='0123456789ABCDEF<>/{}[]|';
  const buf=document.createElement('canvas');buf.width=cv.width;buf.height=cv.height;const bctx=buf.getContext('2d');
  (function draw(){bctx.fillStyle='rgba(0,0,0,0.06)';bctx.fillRect(0,0,buf.width,buf.height);bctx.font='9px monospace';for(let i=0;i<cols;i++){if(Math.random()>0.3)continue;bctx.fillStyle=`rgba(255,${120+Math.random()*60},0,0.7)`;bctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*10,ypos[i]);ypos[i]+=10;if(ypos[i]>buf.height&&Math.random()>0.97)ypos[i]=0;}ctx.clearRect(0,0,cv.width,cv.height);ctx.globalAlpha=0.25;ctx.drawImage(buf,0,0);ctx.globalAlpha=1;_animId=requestAnimationFrame(draw);})();
},
northern(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.006;const bands=[{h:140,y:0.12,a:50},{h:180,y:0.18,a:40},{h:280,y:0.25,a:35},{h:160,y:0.10,a:55},{h:220,y:0.22,a:30}];for(const b of bands){ctx.beginPath();const yB=cv.height*b.y;ctx.moveTo(0,yB);for(let x=0;x<=cv.width;x+=3){ctx.lineTo(x,yB+Math.sin(x*0.003+t+b.h*0.01)*b.a+Math.sin(x*0.008+t*1.3)*b.a*0.5);}ctx.lineTo(cv.width,cv.height);ctx.lineTo(0,cv.height);ctx.closePath();ctx.fillStyle=`hsla(${b.h},60%,50%,${0.025+Math.sin(t+b.h)*0.01})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
// ── Scene-pack animations ──────────────────────────────────────────────────
tokyoSunsetGlow(cv,ctx){
  const lights=[];for(let i=0;i<60;i++)lights.push({x:Math.random()*cv.width,y:cv.height*0.55+Math.random()*cv.height*0.4,r:Math.random()*1.5+0.6,phase:Math.random()*Math.PI*2,hue:Math.random()<0.5?40:320});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const l of lights){l.phase+=0.04;const a=0.15+Math.sin(l.phase)*0.12;ctx.beginPath();ctx.arc(l.x,l.y,l.r,0,Math.PI*2);ctx.fillStyle=`hsla(${l.hue},90%,70%,${a})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
mistDrift(cv,ctx){
  const bands=[];for(let i=0;i<5;i++)bands.push({y:cv.height*(0.35+i*0.1),off:Math.random()*1000,speed:0.2+Math.random()*0.3});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const b of bands){b.off+=b.speed;ctx.beginPath();ctx.moveTo(0,b.y);for(let x=0;x<=cv.width;x+=8){const y=b.y+Math.sin((x+b.off)*0.006)*12;ctx.lineTo(x,y);}ctx.lineTo(cv.width,b.y+40);ctx.lineTo(0,b.y+40);ctx.closePath();ctx.fillStyle='rgba(180,200,220,0.025)';ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
beachShimmer(cv,ctx){
  const sparks=[];for(let i=0;i<80;i++)sparks.push({x:Math.random()*cv.width,y:cv.height*0.7+Math.random()*cv.height*0.3,phase:Math.random()*Math.PI*2,r:Math.random()*1.2+0.3});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of sparks){s.phase+=0.05;const a=Math.max(0,Math.sin(s.phase))*0.35;ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(255,220,160,${a})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
auroraFlow(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.006;for(let b=0;b<3;b++){ctx.beginPath();const yB=cv.height*0.2+b*40;ctx.moveTo(0,yB);for(let x=0;x<=cv.width;x+=4){const y=yB+Math.sin(x*0.004+t+b*1.8)*35+Math.sin(x*0.009+t*1.3)*15;ctx.lineTo(x,y);}ctx.lineTo(cv.width,yB+60);ctx.lineTo(0,yB+60);ctx.closePath();const cols=['rgba(80,230,190,0.04)','rgba(120,200,240,0.035)','rgba(180,140,230,0.03)'];ctx.fillStyle=cols[b];ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
volcanicPulse(cv,ctx){
  const cracks=[];for(let i=0;i<14;i++)cracks.push({x:Math.random()*cv.width,y:cv.height*0.5+Math.random()*cv.height*0.5,r:30+Math.random()*40,phase:Math.random()*Math.PI*2,speed:0.02+Math.random()*0.03});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const c of cracks){c.phase+=c.speed;const a=0.12+Math.sin(c.phase)*0.1;const g=ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,c.r);g.addColorStop(0,`rgba(255,120,30,${a})`);g.addColorStop(0.5,`rgba(200,40,10,${a*0.4})`);g.addColorStop(1,'rgba(100,10,0,0)');ctx.beginPath();ctx.arc(c.x,c.y,c.r,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
waterfallMist(cv,ctx){
  const drops=[];for(let i=0;i<120;i++)drops.push({x:cv.width*0.2+Math.random()*cv.width*0.6,y:Math.random()*cv.height,len:8+Math.random()*14,speed:8+Math.random()*6,o:0.08+Math.random()*0.12});
  const mist=[];for(let i=0;i<25;i++)mist.push({x:Math.random()*cv.width,y:cv.height*0.7+Math.random()*cv.height*0.3,r:20+Math.random()*30,vx:(Math.random()-0.5)*0.4,phase:Math.random()*Math.PI*2});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const d of drops){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(d.x,d.y+d.len);ctx.strokeStyle=`rgba(200,230,240,${d.o})`;ctx.lineWidth=1;ctx.stroke();d.y+=d.speed;if(d.y>cv.height){d.y=-d.len;d.x=cv.width*0.2+Math.random()*cv.width*0.6;}}for(const m of mist){m.phase+=0.01;m.x+=m.vx;if(m.x<-50)m.x=cv.width+50;if(m.x>cv.width+50)m.x=-50;const a=0.04+Math.sin(m.phase)*0.02;const g=ctx.createRadialGradient(m.x,m.y,0,m.x,m.y,m.r);g.addColorStop(0,`rgba(220,235,245,${a})`);g.addColorStop(1,'rgba(220,235,245,0)');ctx.beginPath();ctx.arc(m.x,m.y,m.r,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
rainyWindowDrops(cv,ctx){
  const drops=[];for(let i=0;i<45;i++)drops.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:2+Math.random()*3,trail:0,speed:0,falling:false});
  (function draw(){ctx.fillStyle='rgba(0,0,0,0.02)';ctx.fillRect(0,0,cv.width,cv.height);for(const d of drops){if(!d.falling&&Math.random()<0.003){d.falling=true;d.speed=1+Math.random()*3;}if(d.falling){d.y+=d.speed;d.trail+=d.speed;if(d.y>cv.height){d.y=-5;d.x=Math.random()*cv.width;d.falling=false;d.trail=0;}ctx.beginPath();ctx.moveTo(d.x,d.y-d.trail);ctx.lineTo(d.x,d.y);ctx.strokeStyle='rgba(180,200,220,0.12)';ctx.lineWidth=d.r*0.6;ctx.stroke();}ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(200,220,240,0.25)';ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
crtScanlines(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);ctx.fillStyle='rgba(0,0,0,0.12)';for(let y=0;y<cv.height;y+=3)ctx.fillRect(0,y,cv.width,1);const y=((t*0.6)%(cv.height+80))-40;const g=ctx.createLinearGradient(0,y,0,y+60);g.addColorStop(0,'rgba(80,255,120,0)');g.addColorStop(0.5,'rgba(80,255,120,0.06)');g.addColorStop(1,'rgba(80,255,120,0)');ctx.fillStyle=g;ctx.fillRect(0,y,cv.width,60);if(Math.random()<0.015){ctx.fillStyle='rgba(80,255,120,0.025)';ctx.fillRect(0,0,cv.width,cv.height);}t++;_animId=requestAnimationFrame(draw);})();
},
nycWindows(cv,ctx){
  const wins=[];for(let i=0;i<80;i++)wins.push({x:Math.random()*cv.width,y:cv.height*(0.3+Math.random()*0.65),on:Math.random()<0.6,next:Math.random()*200,w:3+Math.random()*2});
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const w of wins){if(t>w.next){if(Math.random()<0.1){w.on=!w.on;w.next=t+50+Math.random()*400;}}ctx.fillStyle=w.on?'rgba(255,204,102,0.25)':'rgba(40,30,15,0.1)';ctx.fillRect(w.x,w.y,w.w,w.w);}t++;_animId=requestAnimationFrame(draw);})();
},
serverLeds(cv,ctx){
  const leds=[];for(let i=0;i<40;i++)leds.push({x:Math.random()*cv.width,y:Math.random()*cv.height,color:['#00ff88','#ffaa00','#ff3344','#44ccff'][Math.floor(Math.random()*4)],rate:0.02+Math.random()*0.08,phase:Math.random()*Math.PI*2});
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const l of leds){const b=0.5+0.5*Math.sin(t*l.rate+l.phase);ctx.globalAlpha=(0.15+0.25*b);ctx.fillStyle=l.color;ctx.beginPath();ctx.arc(l.x,l.y,2+b*1.5,0,Math.PI*2);ctx.fill();}ctx.globalAlpha=1;t++;_animId=requestAnimationFrame(draw);})();
},
highwayLights(cv,ctx){
  const cars=[];for(let i=0;i<16;i++)cars.push({x:Math.random()*cv.width,y:cv.height*(0.5+(i%4)*0.1),v:(i%2?-1:1)*(2+Math.random()*5),len:40+Math.random()*80,col:i%2?'rgba(255,60,40,':'rgba(255,230,120,'});
  (function draw(){ctx.fillStyle='rgba(4,6,10,0.12)';ctx.fillRect(0,0,cv.width,cv.height);for(const c of cars){c.x+=c.v;if(c.v>0&&c.x>cv.width+c.len)c.x=-c.len;if(c.v<0&&c.x<-c.len)c.x=cv.width+c.len;const g=ctx.createLinearGradient(c.x-c.len*Math.sign(c.v),c.y,c.x,c.y);g.addColorStop(0,c.col+'0)');g.addColorStop(1,c.col+'0.5)');ctx.strokeStyle=g;ctx.lineWidth=1.5;ctx.beginPath();ctx.moveTo(c.x-c.len*Math.sign(c.v),c.y);ctx.lineTo(c.x,c.y);ctx.stroke();}_animId=requestAnimationFrame(draw);})();
},
dataStream(cv,ctx){
  const lanes=[cv.height*0.25,cv.height*0.45,cv.height*0.55,cv.height*0.75];
  const pkts=[];for(let i=0;i<40;i++)pkts.push({lane:lanes[i%4],x:Math.random()*cv.width,v:(i%2?1:-1)*(1.5+Math.random()*2.5),hue:180+Math.random()*40});
  (function draw(){ctx.fillStyle='rgba(2,6,10,0.15)';ctx.fillRect(0,0,cv.width,cv.height);ctx.strokeStyle='rgba(68,204,255,0.08)';ctx.lineWidth=1;for(const y of lanes){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(cv.width,y);ctx.stroke();}for(const p of pkts){p.x+=p.v;if(p.x>cv.width+20)p.x=-20;if(p.x<-20)p.x=cv.width+20;const g=ctx.createLinearGradient(p.x-20*Math.sign(p.v),p.lane,p.x,p.lane);g.addColorStop(0,`hsla(${p.hue},100%,60%,0)`);g.addColorStop(1,`hsla(${p.hue},100%,70%,0.6)`);ctx.strokeStyle=g;ctx.lineWidth=1.5;ctx.beginPath();ctx.moveTo(p.x-20*Math.sign(p.v),p.lane);ctx.lineTo(p.x,p.lane);ctx.stroke();}_animId=requestAnimationFrame(draw);})();
},
issEarth(cv,ctx){
  const clouds=[];for(let i=0;i<12;i++)clouds.push({x:Math.random()*cv.width,y:cv.height*0.3+Math.random()*cv.height*0.45,r:60+Math.random()*70,v:0.1+Math.random()*0.15,a:0.02+Math.random()*0.03});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const c of clouds){c.x+=c.v;if(c.x-c.r>cv.width)c.x=-c.r;const g=ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,c.r);g.addColorStop(0,`rgba(230,240,250,${c.a})`);g.addColorStop(1,'rgba(230,240,250,0)');ctx.fillStyle=g;ctx.beginPath();ctx.arc(c.x,c.y,c.r,0,Math.PI*2);ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
wormholeTunnel(cv,ctx){
  let t=0;const rings=[];for(let i=0;i<18;i++)rings.push({p:i/18});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.012;const cx=cv.width/2,cy=cv.height/2;for(const r of rings){r.p-=0.004;if(r.p<=0)r.p=1;const rx=r.p*cv.width*0.6,ry=r.p*cv.height*0.55;const a=Math.sin(r.p*Math.PI)*0.3;const hue=220+Math.sin(t+r.p*6)*60;ctx.beginPath();ctx.ellipse(cx,cy,rx,ry,0,0,Math.PI*2);ctx.strokeStyle=`hsla(${hue},90%,65%,${a})`;ctx.lineWidth=1+(1-r.p)*1.5;ctx.stroke();}_animId=requestAnimationFrame(draw);})();
},
blackHoleDisk(cv,ctx){
  const stars=[];for(let i=0;i<140;i++)stars.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()*1.2+0.2,tw:Math.random()*Math.PI*2});
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.008;const cx=cv.width/2,cy=cv.height/2;for(const s of stars){s.tw+=0.02;const dx=s.x-cx,dy=s.y-cy,d=Math.sqrt(dx*dx+dy*dy)+1,warp=Math.max(0,1-80/d)*0.9+0.1,sx=cx+dx*warp,sy=cy+dy*warp;const a=(0.2+Math.sin(s.tw)*0.1)*(d<80?0:1);ctx.beginPath();ctx.arc(sx,sy,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(220,225,255,${a})`;ctx.fill();}for(let i=0;i<48;i++){const ang=(i/48)*Math.PI*2+t;const rx=180+Math.sin(ang*2)*10,ry=56+Math.sin(ang*3)*6;const x=cx+Math.cos(ang)*rx,y=cy+Math.sin(ang)*ry;const hot=(Math.sin(ang-t*2)+1)*0.5;ctx.beginPath();ctx.arc(x,y,2.4,0,Math.PI*2);ctx.fillStyle=`rgba(255,${(120+hot*130)|0},${(40+hot*60)|0},${0.25+hot*0.25})`;ctx.fill();}ctx.beginPath();ctx.arc(cx,cy,50,0,Math.PI*2);ctx.fillStyle='#000';ctx.fill();_animId=requestAnimationFrame(draw);})();
},
// ── Motion pack (canvas-based) ──────────────────────────────────────────────
meteorShower(cv,ctx){
  const stars=[];for(let i=0;i<80;i++)stars.push({x:Math.random()*cv.width,y:Math.random()*cv.height,r:Math.random()+0.3,tw:Math.random()*Math.PI*2});
  const meteors=[];function mk(){return{x:-50-Math.random()*cv.width*0.3,y:-20+Math.random()*cv.height*0.4,vx:6+Math.random()*6,vy:3+Math.random()*2,len:60+Math.random()*80,a:0.6+Math.random()*0.4};}
  for(let i=0;i<3;i++)meteors.push(mk());
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const s of stars){s.tw+=0.02;ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle=`rgba(220,230,240,${0.2+Math.sin(s.tw)*0.15})`;ctx.fill();}for(let i=meteors.length-1;i>=0;i--){const m=meteors[i];m.x+=m.vx;m.y+=m.vy;const tx=m.x-m.vx*8,ty=m.y-m.vy*8;const g=ctx.createLinearGradient(m.x,m.y,tx,ty);g.addColorStop(0,`rgba(255,255,255,${m.a})`);g.addColorStop(1,'rgba(255,255,255,0)');ctx.beginPath();ctx.moveTo(m.x,m.y);ctx.lineTo(tx,ty);ctx.strokeStyle=g;ctx.lineWidth=1.5;ctx.stroke();if(m.x>cv.width+50||m.y>cv.height+50)meteors[i]=mk();}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(meteors.length<6&&Math.random()<0.4)meteors.push(mk());},1500));
},
lightningStorm(cv,ctx){
  (function draw(){ctx.fillStyle='rgba(8,12,24,0.02)';ctx.fillRect(0,0,cv.width,cv.height);_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(Math.random()<0.35){const x=cv.width*0.2+Math.random()*cv.width*0.6;ctx.save();ctx.strokeStyle=`rgba(200,220,255,${0.5+Math.random()*0.4})`;ctx.lineWidth=2;ctx.shadowColor='#c8d4ff';ctx.shadowBlur=20;ctx.beginPath();let cx=x,cy=0;ctx.moveTo(cx,cy);while(cy<cv.height*0.7){cx+=(Math.random()-0.5)*40;cy+=20+Math.random()*30;ctx.lineTo(cx,cy);}ctx.stroke();ctx.restore();const flash=document.createElement('div');flash.className='anim-flash';flash.style.cssText='position:fixed;inset:0;background:rgba(200,220,255,0.12);z-index:0;pointer-events:none;transition:opacity 0.3s;';document.body.appendChild(flash);setTimeout(()=>flash.style.opacity='0',100);setTimeout(()=>flash.remove(),400);}},3000));
},
rainGlass(cv,ctx){
  const drops=[];for(let i=0;i<50;i++)drops.push({x:Math.random()*cv.width,y:Math.random()*cv.height*0.5,speed:1+Math.random()*3,trail:0,h:10+Math.random()*20});
  (function draw(){ctx.fillStyle='rgba(10,18,24,0.04)';ctx.fillRect(0,0,cv.width,cv.height);for(const d of drops){d.y+=d.speed;d.trail=Math.min(d.trail+d.speed,d.h*3);if(d.y>cv.height){d.y=-10;d.x=Math.random()*cv.width;d.trail=0;}ctx.beginPath();ctx.moveTo(d.x,d.y-d.trail);ctx.lineTo(d.x,d.y);ctx.strokeStyle='rgba(216,228,236,0.2)';ctx.lineWidth=1.5;ctx.stroke();ctx.beginPath();ctx.arc(d.x,d.y,2,0,Math.PI*2);ctx.fillStyle='rgba(200,220,240,0.35)';ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
driftingClouds(cv,ctx){
  const clouds=[];for(let i=0;i<6;i++)clouds.push({x:Math.random()*cv.width,y:cv.height*(0.1+Math.random()*0.7),r:120+Math.random()*100,v:0.15+Math.random()*0.25,a:0.04+Math.random()*0.05});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const c of clouds){c.x+=c.v;if(c.x-c.r>cv.width)c.x=-c.r;const g=ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,c.r);g.addColorStop(0,`rgba(180,195,225,${c.a})`);g.addColorStop(1,'rgba(180,195,225,0)');ctx.fillStyle=g;ctx.beginPath();ctx.arc(c.x,c.y,c.r,0,Math.PI*2);ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
dataStreamFall(cv,ctx){
  const cols=Math.floor(cv.width/14);const chars='01{}[]<>#@$%&*+=/\\|アイウエオカキクケコ';
  const trails=Array(cols).fill(0).map(()=>({y:Math.random()*cv.height*-1,speed:1+Math.random()*2,len:8+Math.floor(Math.random()*14)}));
  (function draw(){ctx.fillStyle='rgba(3,8,6,0.08)';ctx.fillRect(0,0,cv.width,cv.height);ctx.font='14px monospace';for(let i=0;i<cols;i++){const t=trails[i];t.y+=t.speed;for(let j=0;j<t.len;j++){const y=t.y-j*16;if(y<0||y>cv.height)continue;const a=(1-j/t.len)*0.6;ctx.fillStyle=j===0?`rgba(200,255,230,${a})`:`rgba(126,184,154,${a*0.5})`;ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*14,y);}if(t.y-t.len*16>cv.height){t.y=Math.random()*-200;t.speed=1+Math.random()*2;t.len=8+Math.floor(Math.random()*14);}}_animId=requestAnimationFrame(draw);})();
},
heartbeatPulse(cv,ctx){
  let t=0;const pulses=[];
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);t+=0.02;const cx=cv.width/2,cy=cv.height/2;for(let i=pulses.length-1;i>=0;i--){const p=pulses[i];p.r+=p.speed;p.a-=0.008;ctx.beginPath();ctx.arc(cx,cy,p.r,0,Math.PI*2);ctx.strokeStyle=`rgba(200,60,80,${p.a})`;ctx.lineWidth=2;ctx.stroke();if(p.a<=0)pulses.splice(i,1);}_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{pulses.push({r:30,speed:3,a:0.6});setTimeout(()=>pulses.push({r:30,speed:3,a:0.5}),220);},1100));
},
glitchFlicker(cv,ctx){
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);_animId=requestAnimationFrame(draw);})();
  _animTimers.push(setInterval(()=>{if(Math.random()<0.3){const type=Math.random();if(type<0.5){ctx.fillStyle='rgba(255,0,170,0.08)';ctx.fillRect(0,Math.random()*cv.height,cv.width,4+Math.random()*15);}else{try{const sy=Math.random()*cv.height,sh=Math.random()*25+5;const strip=ctx.getImageData(0,sy,cv.width,sh);ctx.putImageData(strip,Math.random()*30-15,sy);}catch(e){}}setTimeout(()=>ctx.clearRect(0,0,cv.width,cv.height),80+Math.random()*150);}},300));
},
scanlinesRoll(cv,ctx){
  let t=0;
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);ctx.fillStyle='rgba(20,50,40,0.1)';for(let y=0;y<cv.height;y+=4)ctx.fillRect(0,y,cv.width,2);const rolly=(t*0.8)%(cv.height+40)-20;const g=ctx.createLinearGradient(0,rolly,0,rolly+60);g.addColorStop(0,'rgba(148,180,158,0)');g.addColorStop(0.5,'rgba(148,180,158,0.1)');g.addColorStop(1,'rgba(148,180,158,0)');ctx.fillStyle=g;ctx.fillRect(0,rolly,cv.width,60);t++;_animId=requestAnimationFrame(draw);})();
},
fallingLeaves(cv,ctx){
  const colors=['#c8651e','#a8441a','#d8862e','#8a3612','#b8581a'];
  const leaves=[];for(let i=0;i<25;i++)leaves.push({x:Math.random()*cv.width,y:Math.random()*cv.height,size:6+Math.random()*8,phase:Math.random()*Math.PI*2,speed:0.5+Math.random()*1,sway:0.01+Math.random()*0.02,rot:Math.random()*Math.PI,rotSpeed:(Math.random()-0.5)*0.04,color:colors[Math.floor(Math.random()*colors.length)]});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const l of leaves){l.phase+=l.sway;l.x+=Math.sin(l.phase)*1.5;l.y+=l.speed;l.rot+=l.rotSpeed;if(l.y>cv.height+20){l.y=-20;l.x=Math.random()*cv.width;}ctx.save();ctx.translate(l.x,l.y);ctx.rotate(l.rot);ctx.fillStyle=l.color;ctx.beginPath();ctx.ellipse(0,0,l.size,l.size*0.6,0,0,Math.PI*2);ctx.fill();ctx.restore();}_animId=requestAnimationFrame(draw);})();
},
fireflyMeadow(cv,ctx){
  const flies=[];for(let i=0;i<50;i++)flies.push({x:Math.random()*cv.width,y:Math.random()*cv.height,vx:0,vy:0,phase:Math.random()*Math.PI*2});
  let mx=cv.width/2,my=cv.height/2;
  const onMove=(e)=>{mx=e.clientX;my=e.clientY;};
  window.addEventListener('mousemove',onMove);
  _animResizeFn=(()=>{const old=_animResizeFn;return function(){if(old)old();};})();
  _animTimers.push({isListener:true,cancel:()=>window.removeEventListener('mousemove',onMove)});
  (function draw(){ctx.clearRect(0,0,cv.width,cv.height);for(const f of flies){const dx=mx-f.x,dy=my-f.y,d=Math.sqrt(dx*dx+dy*dy)+0.1;const pull=Math.min(0.04,30/d);f.vx+=dx/d*pull+(Math.random()-0.5)*0.2;f.vy+=dy/d*pull+(Math.random()-0.5)*0.2;f.vx*=0.94;f.vy*=0.94;f.x+=f.vx;f.y+=f.vy;f.phase+=0.06;const a=0.3+0.7*Math.abs(Math.sin(f.phase));const g=ctx.createRadialGradient(f.x,f.y,0,f.x,f.y,10);g.addColorStop(0,`rgba(228,239,136,${a})`);g.addColorStop(1,'rgba(228,239,136,0)');ctx.beginPath();ctx.arc(f.x,f.y,10,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();ctx.beginPath();ctx.arc(f.x,f.y,2,0,Math.PI*2);ctx.fillStyle=`rgba(255,255,200,${a})`;ctx.fill();}_animId=requestAnimationFrame(draw);})();
},
};

function populateAppearanceModal(cfg){
  const el=id=>document.getElementById(id);
  el('a-font').value=cfg.font||"'Spooky Magic',cursive";
  el('a-chat-size').value=cfg.chatSize;
  el('a-sidebar-font').value=cfg.sidebarFont;
  el('a-nick-font').value=cfg.nickFont;
  el('a-sidebar-w').value=cfg.sidebarW;
  el('a-nick-w').value=cfg.nickW;
  el('a-nickpanel-w').value=cfg.nickPanelW;
  el('a-line-height').value=cfg.lineHeight;
  el('a-msg-gap').value=cfg.msgGap!=null?cfg.msgGap:4;
  el('a-input-h').value=cfg.inputH!=null?cfg.inputH:36;
  el('a-input-h-val').textContent=(cfg.inputH!=null?cfg.inputH:36)+'px';
  cfg.timestamps ? el('a-timestamps').classList.add('on') : el('a-timestamps').classList.remove('on');
  el('a-statusmsg').value=cfg.statusMsg||'condense';
  cfg.compact ? el('a-compact').classList.add('on') : el('a-compact').classList.remove('on');
  cfg.coloredNicks!==false ? el('a-colorednicks').classList.add('on') : el('a-colorednicks').classList.remove('on');
  cfg.nickList!==false ? el('a-nicklist').classList.add('on') : el('a-nicklist').classList.remove('on');
  { const _es=el('a-esheep'); if(_es){ _es.value=_esheepMode(cfg.esheep); } }
  { const _cr=el('a-crab'); if(_cr){ _cr.value=_crabMode(cfg.crab); } }
  { const _gh=el('a-ghost'); if(_gh){ _gh.value=_ghostMode(cfg.ghost); } }
  { const _fh=el('a-fish'); if(_fh){ _fh.value=_fishMode(cfg.fish); } }
  { const _al=el('a-alien'); if(_al){ _al.value=_alienMode(cfg.alien); } }
  // spellcheck and linkPreviews toggles are now in the Security panel
  el('a-accent-color').value=cfg.accent;
  el('a-accent2-color').value=cfg.accent2;
  el('a-accent-swatch').style.background=cfg.accent;
  el('a-accent2-swatch').style.background=cfg.accent2;
  // Link color: empty linkColor => "Match accent 2" toggle on, swatch previews accent2.
  const _linkEff=cfg.linkColor||cfg.accent2||'#0099ff';
  el('a-link-match').classList.toggle('on', !cfg.linkColor);
  el('a-link-color').value=_linkEff;
  el('a-link-swatch').style.background=_linkEff;
  el('a-chat-size-val').textContent=cfg.chatSize+'px';
  el('a-sidebar-font-val').textContent=cfg.sidebarFont+'px';
  el('a-nick-font-val').textContent=cfg.nickFont+'px';
  el('a-sidebar-w-val').textContent=cfg.sidebarW+'px';
  el('a-nick-w-val').textContent=cfg.nickW+'px';
  el('a-nickpanel-w-val').textContent=cfg.nickPanelW+'px';
  el('a-line-height-val').textContent=cfg.lineHeight.toFixed(1);
  el('a-brightness').value=cfg.brightness||100;
  el('a-brightness-val').textContent=(cfg.brightness||100)+'%';
  // Mobile settings
  el('a-mobile-chat-size').value=cfg.mobileChatSize||15;
  el('a-mobile-chat-size-val').textContent=(cfg.mobileChatSize||15)+'px';
  el('a-mobile-nick-w').value=cfg.mobileNickW||60;
  el('a-mobile-nick-w-val').textContent=(cfg.mobileNickW||60)+'px';
  cfg.mobileTimestamps ? el('a-mobile-timestamps').classList.add('on') : el('a-mobile-timestamps').classList.remove('on');
  // Mobile theme dropdown — custom themes first, then built-ins.
  const mts=el('a-mobile-theme');
  mts.innerHTML='<option value="">Same as desktop</option>';
  const _custom=cfg.customThemes||{};
  for(const cid of Object.keys(_custom)){
    const ct=_custom[cid]; if(!ct) continue;
    const opt=document.createElement('option');opt.value='custom:'+cid;opt.textContent='★ '+(ct.label||'Custom');
    if(cfg.mobileTheme==='custom:'+cid)opt.selected=true;
    mts.appendChild(opt);
  }
  for(const[key,t] of Object.entries(THEMES)){
    const opt=document.createElement('option');opt.value=key;opt.textContent=t.label;
    if(cfg.mobileTheme===key)opt.selected=true;
    mts.appendChild(opt);
  }
  el('a-mobile-accent-color').value=cfg.mobileAccent||cfg.accent;
  el('a-mobile-accent-swatch').style.background=cfg.mobileAccent||cfg.accent;
  el('a-mobile-accent2-color').value=cfg.mobileAccent2||cfg.accent2;
  el('a-mobile-accent2-swatch').style.background=cfg.mobileAccent2||cfg.accent2;
  // Mobile link: empty => "Inherit" toggle on, swatch previews the desktop link color.
  const _mlEff=cfg.mobileLink||cfg.linkColor||cfg.accent2||'#0099ff';
  el('a-mobile-link-inherit').classList.toggle('on', !cfg.mobileLink);
  el('a-mobile-link-color').value=_mlEff;
  el('a-mobile-link-swatch').style.background=_mlEff;
  // Media & previews
  if (el('a-media-shape'))  el('a-media-shape').value  = cfg.mediaShape  || 'rounded';
  if (el('a-media-size'))   el('a-media-size').value   = cfg.mediaSize   || 'medium';
  if (el('a-media-border')) el('a-media-border').value = cfg.mediaBorder || 'none';
  if (el('a-media-aspect')) el('a-media-aspect').value = cfg.mediaAspect || 'natural';
  if (el('a-media-radius')) el('a-media-radius').value = cfg.mediaRadius ?? 10;
  if (el('a-media-max-h'))  el('a-media-max-h').value  = cfg.mediaMaxHeight ?? 280;
  if (el('a-media-radius-val')) el('a-media-radius-val').textContent = (cfg.mediaRadius ?? 10) + 'px';
  if (el('a-media-max-h-val'))  el('a-media-max-h-val').textContent  = (cfg.mediaMaxHeight ?? 280) + 'px';
  if (el('a-media-radius-row')) el('a-media-radius-row').style.display = cfg.mediaShape === 'custom' ? '' : 'none';
  const _ytp = el('a-yt-play');
  if (_ytp) (cfg.ytPlayOverlay !== false) ? _ytp.classList.add('on') : _ytp.classList.remove('on');
  // Privacy/Security/Behavior settings are now in the standalone Security panel
  // Theme cards
  const grid=el('theme-grid'); grid.innerHTML='';
  const selectCard=(card)=>{grid.querySelectorAll('.theme-card').forEach(c=>c.classList.remove('active'));card.classList.add('active');applyAppearance();};
  // 1) User-created custom themes first (with an edit pencil). Labels are user
  //    input, so build them with textContent — never innerHTML — to avoid XSS.
  const custom=cfg.customThemes||{};
  for(const id of Object.keys(custom)){
    const t=custom[id]; if(!t) continue;
    const themeKey='custom:'+id;
    const card=document.createElement('div');
    card.className='theme-card'+(cfg.theme===themeKey?' active':'');
    card.dataset.theme=themeKey;
    const prev=document.createElement('div'); prev.className='theme-preview';
    for(const c of [t.bg0,t.accent||t.bg2,t.text||t.bg4]){const s=document.createElement('span');s.style.background=c||'#000';prev.appendChild(s);}
    const name=document.createElement('div'); name.className='theme-name'; name.textContent=t.label||'Custom';
    const edit=document.createElement('button'); edit.className='tc-edit'; edit.title='Edit theme'; edit.textContent='✎';
    edit.onclick=(e)=>{e.stopPropagation();openThemeEditor(id);};
    card.appendChild(prev); card.appendChild(name); card.appendChild(edit);
    card.onclick=()=>selectCard(card);
    grid.appendChild(card);
  }
  // 2) "Create custom theme" card.
  const create=document.createElement('div');
  create.className='theme-card theme-card-create';
  create.innerHTML='<div class="tc-plus">+</div><div class="theme-name">Create theme</div>';
  create.onclick=()=>openThemeEditor(null);
  grid.appendChild(create);
  // 3) Built-in themes (labels are static/trusted).
  for(const[key,t] of Object.entries(THEMES)){
    const card=document.createElement('div');
    card.className='theme-card'+(cfg.theme===key?' active':'');
    card.dataset.theme=key;
    card.innerHTML=`<div class="theme-preview"><span style="background:${t.bg0}"></span><span style="background:${t.bg2}"></span><span style="background:${t.bg4}"></span></div><div class="theme-name">${t.label}</div>`;
    card.onclick=()=>selectCard(card);
    grid.appendChild(card);
  }
  // While a custom theme is active, the global accent/link pickers are inert
  // (the theme owns those colors) — surface a hint so the controls don't look broken.
  const _ch=el('a-colors-customhint');
  if(_ch) _ch.style.display=(typeof cfg.theme==='string'&&cfg.theme.indexOf('custom:')===0)?'':'none';
}
function showAppearanceModal(){
  const cfg=loadAppearance();
  populateAppearanceModal(cfg);
  document.getElementById('appearance-overlay').classList.add('show');
  _overlayOpen('appearance', closeAppearanceModal);
}
function closeAppearanceModal(){
  _overlayClose('appearance');
  document.getElementById('appearance-overlay').classList.remove('show');
}
function resetAppearance(){
  // Preserve the user's hand-built custom themes across a defaults reset — they're
  // creations, not settings. (Their device-local background blobs stay in place too.)
  const prev=loadAppearance();
  const cfg={...APPEAR_DEFAULTS, customThemes: prev.customThemes||{}};
  saveAppearance(cfg);
  populateAppearanceModal(cfg);
  applyThemeCSS(cfg);
}

// ─── Custom theme editor ────────────────────────────────────────────────────
let _teId=null;        // id of the custom theme being edited (always assigned)
let _teState=null;     // working copy of the theme object
let _teBgData=null;    // device-local uploaded background data URL (held until save)
let _teIsNew=false;    // true when creating (vs editing an existing theme)
const TE_MAX_BG_DIM=1600;   // downscale uploads so the localStorage blob stays small
const APPEAR_SYNC_BUDGET=3900; // keep synced config under the server's 4KB cap

function _teNewId(){
  if(self.crypto&&self.crypto.randomUUID) return self.crypto.randomUUID().replace(/-/g,'').slice(0,10);
  return (Date.now().toString(36)+Math.floor((performance.now()*1000)%1e6).toString(36)).slice(0,10);
}
// Build a complete theme object, filling any missing color from the current
// effective theme / global prefs so a custom theme is always fully specified.
function _teSeedFrom(t,isCustom,cfg){
  const out={};
  for(const k of ['bg0','bg1','bg2','bg3','bg4','border','border2','text','text2','text3']) out[k]=t[k]||THEMES.midnight[k];
  out.accent = isCustom?(t.accent||cfg.accent||'#00d4aa'):(cfg.accent||'#00d4aa');
  out.accent2= isCustom?(t.accent2||cfg.accent2||'#0099ff'):(cfg.accent2||'#0099ff');
  out.link   = isCustom?(t.link||t.accent2||out.accent2):(cfg.linkColor||out.accent2);
  for(const k of ['warn','error','join','part','notice','action']) out[k]=(isCustom&&t[k])?t[k]:SEMANTIC_DEFAULTS[k];
  out.animation = t.animation||'';
  out.bgUrl = isCustom?(t.bgUrl||''):'';
  out.bgKind = isCustom?(t.bgKind||''):'';
  out.bgRepeat = isCustom?!!t.bgRepeat:false;
  out.bgOpacity = isCustom&&t.bgOpacity!=null?t.bgOpacity:25;
  return out;
}
function openThemeEditor(id){
  const cfg=loadAppearance();
  _teIsNew=!id;
  if(id && cfg.customThemes && cfg.customThemes[id]){
    _teId=id;
    // _teSeedFrom returns a fresh object, so edits never mutate the stored theme.
    _teState=_teSeedFrom(cfg.customThemes[id],true,cfg);
    _teState.label=cfg.customThemes[id].label||'Custom';
    try{_teBgData=localStorage.getItem('cryptirc_cbg_'+id);}catch(e){_teBgData=null;}
  }else{
    _teId=_teNewId();
    // Seed from whatever theme is currently active so "create" starts from a sane palette.
    const rt=resolveThemeObj(cfg.theme,cfg);
    _teState=_teSeedFrom(rt.t,rt.custom,cfg);
    _teState.label='My Theme';
    _teBgData=null;
  }
  _renderThemeEditor();
  document.getElementById('theme-editor-overlay').classList.add('show');
  if(typeof _overlayOpen==='function') _overlayOpen('theme-editor', closeThemeEditor);
}
function closeThemeEditor(){
  if(typeof _overlayClose==='function') _overlayClose('theme-editor');
  document.getElementById('theme-editor-overlay').classList.remove('show');
  _teState=null; _teBgData=null;
}
function _renderThemeEditor(){
  const el=id=>document.getElementById(id);
  el('te-title').textContent=_teIsNew?'New Custom Theme':'Edit Custom Theme';
  el('te-name').value=_teState.label||'';
  el('te-delete').style.display=_teIsNew?'none':'';
  // Base dropdown (clone source): current + built-ins
  const base=el('te-base');
  base.innerHTML='<option value="">— current colors —</option>';
  for(const[key,t] of Object.entries(THEMES)){
    const o=document.createElement('option'); o.value=key; o.textContent=t.label; base.appendChild(o);
  }
  base.value='';
  // Animation dropdown — built live from the real animation registry.
  const anim=el('te-anim');
  anim.innerHTML='<option value="">None</option>';
  try{
    Object.keys(_ANIM).sort().forEach(k=>{const o=document.createElement('option');o.value=k;o.textContent=k;anim.appendChild(o);});
  }catch(e){}
  anim.value=_teState.animation||'';
  // Color rows
  const wrap=el('te-colors'); wrap.innerHTML='';
  for(const grp of CT_COLOR_GROUPS){
    const sec=document.createElement('div'); sec.className='appear-section';
    const title=document.createElement('div'); title.className='appear-section-title'; title.textContent=grp.title;
    sec.appendChild(title);
    const gridEl=document.createElement('div'); gridEl.className='te-color-grid';
    for(const[key,label] of grp.keys){
      const row=document.createElement('div'); row.className='te-color-row';
      const lab=document.createElement('span'); lab.className='appear-label'; lab.textContent=label;
      const w=document.createElement('div'); w.className='color-input-wrap';
      const sw=document.createElement('div'); sw.className='color-swatch'; sw.id='te-sw-'+key; sw.style.background=_teState[key]||'#000';
      const inp=document.createElement('input'); inp.type='color'; inp.value=_normHex(_teState[key]); inp.id='te-col-'+key;
      inp.oninput=()=>teSetColor(key,inp.value);
      sw.appendChild(inp); w.appendChild(sw); row.appendChild(lab); row.appendChild(w);
      gridEl.appendChild(row);
    }
    sec.appendChild(gridEl); wrap.appendChild(sec);
  }
  // Background fields
  el('te-bg-url').value=_teState.bgUrl||'';
  el('te-bg-repeat').classList.toggle('on', !!_teState.bgRepeat);
  el('te-bg-opacity').value=_teState.bgOpacity!=null?_teState.bgOpacity:25;
  el('te-bg-opacity-val').textContent=(_teState.bgOpacity!=null?_teState.bgOpacity:25)+'%';
  _teUpdateBgStatus();
  _teApplyPreview();
}
// Color inputs require #rrggbb; coerce shorthand/invalid to a safe value.
function _normHex(v){
  if(typeof v==='string'){
    const s=v.trim();
    if(/^#[0-9a-fA-F]{6}$/.test(s)) return s;
    if(/^#[0-9a-fA-F]{3}$/.test(s)) return '#'+s[1]+s[1]+s[2]+s[2]+s[3]+s[3];
  }
  return '#000000';
}
// Storage-time validation: keep any valid hex (incl. 4/8-digit alpha from cloned
// built-ins like cyberpunk's border), otherwise fall back to a safe 6-digit value.
function _storeColor(v){
  if(typeof v==='string'){
    const s=v.trim();
    if(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(s)) return s;
  }
  return _normHex(v);
}
// All te* handlers below guard on _teState: they're wired to live DOM controls,
// and an in-flight async upload (teUploadBg) can resolve AFTER closeThemeEditor()
// has nulled _teState — without the guard that callback would throw.
function teSetColor(key,val){
  if(!_teState) return;
  _teState[key]=val;
  const sw=document.getElementById('te-sw-'+key); if(sw) sw.style.background=val;
  _teApplyPreview();
}
function teSetAnim(v){ if(!_teState) return; _teState.animation=v||''; }
function teSetBgUrl(v){
  if(!_teState) return;
  v=(v||'').trim();
  // A pasted data: URL is too large to sync — route it to device-local storage instead.
  if(/^data:image\//i.test(v)){
    _teBgData=v; _teState.bgUrl=''; _teState.bgKind='image';
    document.getElementById('te-bg-url').value='';
    _teUpdateBgStatus(); _teApplyPreview(); return;
  }
  _teState.bgUrl=v;
  _teState.bgKind=(v||_teBgData)?'image':'';
  _teUpdateBgStatus(); _teApplyPreview();
}
function teSetRepeat(){ if(!_teState) return; _teState.bgRepeat=document.getElementById('te-bg-repeat').classList.contains('on'); _teApplyPreview(); }
function teSetOpacity(v){ if(!_teState) return; _teState.bgOpacity=Math.max(0,Math.min(100,+v||0)); document.getElementById('te-bg-opacity-val').textContent=_teState.bgOpacity+'%'; _teApplyPreview(); }
function teClearBg(){
  if(!_teState) return;
  _teBgData=null; _teState.bgUrl=''; _teState.bgKind='';
  document.getElementById('te-bg-url').value='';
  _teUpdateBgStatus(); _teApplyPreview();
}
function _teUpdateBgStatus(){
  const s=document.getElementById('te-bg-status');
  if(!s||!_teState) return;
  if(_teBgData) s.textContent='✓ Uploaded image (this device only, ~'+Math.round((_teBgData.length*0.75)/1024)+' KB)';
  else if(_teState.bgUrl) s.textContent='✓ Using image URL (syncs across devices)';
  else s.textContent='No background image.';
}
async function teUploadBg(file){
  if(!file||!_teState) return;
  if(!/^image\//.test(file.type)){ showToast('Please choose an image file'); return; }
  const s=document.getElementById('te-bg-status'); if(s) s.textContent='Processing image…';
  const editId=_teId; // bail if the editor closed or switched themes while decoding
  try{
    const dataUrl=await _downscaleImage(file,TE_MAX_BG_DIM);
    if(!_teState||_teId!==editId) return;
    _teBgData=dataUrl; _teState.bgUrl=''; _teState.bgKind='image';
    document.getElementById('te-bg-url').value='';
    _teUpdateBgStatus(); _teApplyPreview();
  }catch(e){ if(s&&_teState&&_teId===editId) s.textContent='Could not read image.'; showToast('Image processing failed'); }
}
// Read an image File, downscale to maxDim, re-encode as JPEG to keep the
// localStorage data URL small. Falls back to PNG for images with transparency.
function _downscaleImage(file,maxDim){
  return new Promise((resolve,reject)=>{
    const fr=new FileReader();
    fr.onerror=()=>reject(new Error('read'));
    fr.onload=()=>{
      const img=new Image();
      img.onerror=()=>reject(new Error('decode'));
      img.onload=()=>{
        try{
          let w=img.naturalWidth||img.width, h=img.naturalHeight||img.height;
          if(!w||!h){reject(new Error('dim'));return;}
          const scale=Math.min(1, maxDim/Math.max(w,h));
          w=Math.round(w*scale); h=Math.round(h*scale);
          const cv=document.createElement('canvas'); cv.width=w; cv.height=h;
          const ctx=cv.getContext('2d'); ctx.drawImage(img,0,0,w,h);
          // GIF/PNG may rely on transparency; everything else → JPEG (much smaller).
          const useJpeg=!/image\/(png|gif|webp)/i.test(file.type);
          resolve(cv.toDataURL(useJpeg?'image/jpeg':'image/png', useJpeg?0.82:undefined));
        }catch(e){reject(e);}
      };
      img.src=fr.result;
    };
    fr.readAsDataURL(file);
  });
}
// Apply the working theme to the scoped preview pane (sets CSS vars locally so it
// never touches the live document).
function _teApplyPreview(){
  const pv=document.getElementById('te-preview'); if(!pv||!_teState) return;
  const st=pv.style;
  for(const k of CT_COLOR_KEYS) st.setProperty('--'+k, _teState[k]||'#000');
  const bg=_teBgData||_teState.bgUrl||'';
  st.setProperty('--te-bg', bg?_safeBgCss(bg):'none');
  st.setProperty('--te-bg-op', (_teState.bgOpacity!=null?_teState.bgOpacity:25)/100);
  pv.classList.toggle('bg-repeat', !!_teState.bgRepeat);
}
function _teNameInput(){ if(!_teState) return; _teState.label=document.getElementById('te-name').value; }
// "Start from" — replace the working palette (and animation) with a base theme's,
// while preserving the user's name and background choices. Empty = no-op.
function teStartFrom(name){
  if(!name||!_teState) return;
  const cfg=loadAppearance();
  const rt=resolveThemeObj(name,cfg);
  const seeded=_teSeedFrom(rt.t,rt.custom,cfg);
  const keep={label:_teState.label, bgUrl:_teState.bgUrl, bgKind:_teState.bgKind, bgRepeat:_teState.bgRepeat, bgOpacity:_teState.bgOpacity};
  _teState=Object.assign(seeded, keep);
  _renderThemeEditor(); // re-renders color rows + resets the dropdown to "current"
}
function _appearByteSize(cfg){ try{return JSON.stringify(cfg).length;}catch(e){return 0;} }
function saveCustomTheme(){
  if(!_teState) return;
  let label=(_teState.label||'').trim();
  if(!label) label='My Theme';
  if(label.length>32) label=label.slice(0,32);
  _teState.label=label;
  // Keep every color a valid hex (preserving alpha from cloned built-ins).
  for(const k of CT_COLOR_KEYS) _teState[k]=_storeColor(_teState[k]);
  // Drop an animation key that no longer exists in the registry (e.g. after a
  // refactor, or hand-edited storage) so it degrades to "None" rather than an
  // empty animation overlay.
  if(_teState.animation && (typeof _ANIM==='undefined' || !_ANIM[_teState.animation])) _teState.animation='';
  // Validate/limit the syncable bgUrl (https only, length-capped). data:/http: rejected.
  let bgUrl=(_teState.bgUrl||'').trim();
  if(bgUrl && !/^https:\/\//i.test(bgUrl)){
    if(/^data:image\//i.test(bgUrl)){ _teBgData=bgUrl; bgUrl=''; }
    else { showToast('Background URL must start with https://'); return; }
  }
  if(bgUrl.length>1024){ showToast('Background URL too long'); return; }
  _teState.bgUrl=bgUrl;
  _teState.bgKind=(bgUrl||_teBgData)?'image':'';
  // Build the prospective config and enforce the 4KB server cap BEFORE committing.
  const cfg=loadAppearance();
  const customThemes={...(cfg.customThemes||{})};
  customThemes[_teId]={...(_teState)};
  const next={...cfg, customThemes, theme:'custom:'+_teId};
  if(_appearByteSize(next)>APPEAR_SYNC_BUDGET){
    const warn=document.getElementById('te-size-warn');
    if(warn){warn.style.display='';warn.textContent='⚠ Your themes exceed the 4 KB sync limit, so this can\'t be saved across devices. Delete a custom theme or use shorter image URLs (uploaded images don\'t count — they stay on this device).';}
    return;
  }
  // Persist the device-local uploaded background (if any) keyed by theme id.
  if(_teBgData){
    try{ localStorage.setItem('cryptirc_cbg_'+_teId, _teBgData); }
    catch(e){ showToast('Image too large for this device\'s storage'); return; }
  }else{
    try{ localStorage.removeItem('cryptirc_cbg_'+_teId); }catch(e){}
  }
  saveAppearance(next);
  applyThemeCSS(next);
  populateAppearanceModal(next);
  closeThemeEditor();
  showToast('Theme saved');
}
function deleteCustomTheme(){
  if(_teIsNew||!_teId){ closeThemeEditor(); return; }
  const id=_teId;
  customConfirm('Delete this custom theme?').then(ok=>{
    if(!ok) return;
    const cfg=loadAppearance();
    const customThemes={...(cfg.customThemes||{})};
    delete customThemes[id];
    const next={...cfg, customThemes};
    // If the deleted theme was active (desktop or mobile), fall back to a built-in.
    if(next.theme==='custom:'+id) next.theme='starwarp';
    if(next.mobileTheme==='custom:'+id) next.mobileTheme='';
    try{ localStorage.removeItem('cryptirc_cbg_'+id); }catch(e){}
    saveAppearance(next);
    applyThemeCSS(next);
    populateAppearanceModal(next);
    closeThemeEditor();
    showToast('Theme deleted');
  });
}
// Apply saved appearance on load and on resize (mobile/desktop switch)
(function(){
  const cfg=loadAppearance();applyThemeCSS(cfg);
  let _resizeTimer;
  window.addEventListener('resize',()=>{
    clearTimeout(_resizeTimer);
    _resizeTimer=setTimeout(()=>applyThemeCSS(loadAppearance()),200);
  });
})();

// ─── Emoji picker ─────────────────────────────────────────────────────────────
const EMOJIS=[
  {e:'😀',n:'grinning'},{e:'😂',n:'joy'},{e:'😅',n:'sweat_smile'},{e:'🤣',n:'rofl'},{e:'😊',n:'blush'},
  {e:'😍',n:'heart_eyes'},{e:'🥰',n:'smiling_hearts'},{e:'😘',n:'kissing_heart'},{e:'😜',n:'winking_tongue'},
  {e:'🤔',n:'thinking'},{e:'🤨',n:'raised_eyebrow'},{e:'😐',n:'neutral'},{e:'😑',n:'expressionless'},
  {e:'😶',n:'no_mouth'},{e:'🙄',n:'rolling_eyes'},{e:'😏',n:'smirk'},{e:'😬',n:'grimacing'},
  {e:'😢',n:'cry'},{e:'😭',n:'sob'},{e:'😤',n:'triumph'},{e:'😡',n:'angry'},{e:'🤬',n:'cursing'},
  {e:'😱',n:'scream'},{e:'😰',n:'cold_sweat'},{e:'😴',n:'sleeping'},{e:'🤮',n:'vomiting'},
  {e:'🤡',n:'clown'},{e:'💀',n:'skull'},{e:'👻',n:'ghost'},{e:'👽',n:'alien'},{e:'🤖',n:'robot'},
  {e:'💩',n:'poop'},{e:'😈',n:'smiling_imp'},{e:'👿',n:'imp'},
  {e:'👍',n:'thumbsup'},{e:'👎',n:'thumbsdown'},{e:'👏',n:'clap'},{e:'🤝',n:'handshake'},
  {e:'🙏',n:'pray'},{e:'💪',n:'muscle'},{e:'🖕',n:'middle_finger'},{e:'✌️',n:'peace'},
  {e:'🤙',n:'call_me'},{e:'👋',n:'wave'},{e:'✍️',n:'writing'},{e:'🤦',n:'facepalm'},
  {e:'🤷',n:'shrug'},{e:'👀',n:'eyes'},{e:'🧠',n:'brain'},
  {e:'❤️',n:'heart'},{e:'🧡',n:'orange_heart'},{e:'💛',n:'yellow_heart'},{e:'💚',n:'green_heart'},
  {e:'💙',n:'blue_heart'},{e:'💜',n:'purple_heart'},{e:'🖤',n:'black_heart'},{e:'💔',n:'broken_heart'},
  {e:'💯',n:'100'},{e:'💥',n:'boom'},{e:'🔥',n:'fire'},{e:'⭐',n:'star'},{e:'✨',n:'sparkles'},
  {e:'⚡',n:'zap'},{e:'🎉',n:'tada'},{e:'🎊',n:'confetti'},{e:'🏆',n:'trophy'},
  {e:'🎮',n:'video_game'},{e:'🎧',n:'headphones'},{e:'🎵',n:'musical_note'},{e:'🎶',n:'notes'},
  {e:'💻',n:'computer'},{e:'🖥️',n:'desktop'},{e:'📱',n:'phone'},{e:'🔒',n:'lock'},{e:'🔓',n:'unlock'},
  {e:'🔑',n:'key'},{e:'🛡️',n:'shield'},{e:'⚙️',n:'gear'},{e:'🔧',n:'wrench'},{e:'🔨',n:'hammer'},
  {e:'💡',n:'bulb'},{e:'📁',n:'folder'},{e:'📂',n:'open_folder'},{e:'📝',n:'memo'},
  {e:'✅',n:'check'},{e:'❌',n:'x'},{e:'⚠️',n:'warning'},{e:'🚫',n:'no_entry'},{e:'❓',n:'question'},
  {e:'❗',n:'exclamation'},{e:'🔴',n:'red_circle'},{e:'🟢',n:'green_circle'},{e:'🔵',n:'blue_circle'},
  {e:'⬆️',n:'up'},{e:'⬇️',n:'down'},{e:'➡️',n:'right'},{e:'⬅️',n:'left'},
  {e:'🍺',n:'beer'},{e:'🍻',n:'beers'},{e:'☕',n:'coffee'},{e:'🍕',n:'pizza'},
  {e:'🐛',n:'bug'},{e:'🐍',n:'snake'},{e:'🦀',n:'crab'},{e:'🐧',n:'penguin'},{e:'🐳',n:'whale'},
];
function toggleEmojiPicker(){
  const p=document.getElementById('emoji-picker');
  if(p.style.display==='none'){
    p.style.display='flex';
    renderEmojiGrid('');
    document.getElementById('emoji-search').value='';
    document.getElementById('emoji-search').focus();
  } else p.style.display='none';
}
function renderEmojiGrid(filter){
  const grid=document.getElementById('emoji-grid');
  grid.innerHTML='';
  const f=filter.toLowerCase();
  for(const em of EMOJIS){
    if(f&&!em.n.includes(f)&&!em.e.includes(f))continue;
    const d=document.createElement('span');
    d.className='emoji-item'; d.textContent=em.e; d.title=`:${em.n}:`;
    d.onclick=()=>{insertEmoji(em.e);};
    grid.appendChild(d);
  }
}
function insertEmoji(e){
  const inp=document.getElementById('msg-input');
  if(inp.disabled)return;
  const pos=inp.selectionStart||inp.value.length;
  inp.value=inp.value.slice(0,pos)+e+inp.value.slice(pos);
  inp.focus();
  document.getElementById('emoji-picker').style.display='none';
}
document.getElementById('emoji-search')?.addEventListener('input',e=>renderEmojiGrid(e.target.value));
// Close emoji picker on outside click
document.addEventListener('click',e=>{
  const p=document.getElementById('emoji-picker');
  if(p&&p.style.display!=='none'&&!e.target.closest('#emoji-picker')&&!e.target.closest('#emoji-btn'))
    p.style.display='none';
});
// Colon autocomplete
(function(){
  const inp=document.getElementById('msg-input');
  if(!inp)return;
  let acEl=document.createElement('div');
  acEl.id='emoji-autocomplete';
  inp.parentNode.style.position='relative';
  inp.parentNode.appendChild(acEl);
  let acIdx=-1;
  inp.addEventListener('input',()=>{
    const v=inp.value, pos=inp.selectionStart;
    const before=v.slice(0,pos);
    const m=before.match(/:([a-z0-9_]{2,})$/);
    if(!m){acEl.style.display='none';acIdx=-1;return;}
    const q=m[1];
    const matches=EMOJIS.filter(em=>em.n.includes(q)).slice(0,8);
    if(!matches.length){acEl.style.display='none';acIdx=-1;return;}
    acEl.style.display='block'; acIdx=0;
    acEl.innerHTML=matches.map((em,i)=>`<div class="emoji-ac-item${i===0?' active':''}" data-i="${i}">${em.e} :${em.n}:</div>`).join('');
    acEl.querySelectorAll('.emoji-ac-item').forEach(el=>{
      // pointerdown + preventDefault — same iOS-blur-cascade fix as nick picker.
      el.addEventListener('pointerdown',e=>{
        if(e.button!==undefined && e.button!==0) return;
        e.preventDefault();
        completeEmoji(matches[+el.dataset.i]);
      });
    });
  });
  function completeEmoji(em){
    const v=inp.value, pos=inp.selectionStart;
    const before=v.slice(0,pos);
    const idx=before.lastIndexOf(':');
    inp.value=before.slice(0,idx)+em.e+v.slice(pos);
    inp.focus();
    acEl.style.display='none';acIdx=-1;
  }
  inp.addEventListener('keydown',e=>{
    if(acEl.style.display==='none')return;
    const items=acEl.querySelectorAll('.emoji-ac-item');
    if(!items.length)return;
    // stopImmediatePropagation — see slash-picker comment for the why.
    if(e.key==='ArrowDown'){e.preventDefault();e.stopImmediatePropagation();acIdx=Math.min(acIdx+1,items.length-1);items.forEach((el,i)=>el.classList.toggle('active',i===acIdx));}
    else if(e.key==='ArrowUp'){e.preventDefault();e.stopImmediatePropagation();acIdx=Math.max(acIdx-1,0);items.forEach((el,i)=>el.classList.toggle('active',i===acIdx));}
    else if(e.key==='Tab'||e.key==='Enter'){
      if(acIdx>=0&&acIdx<items.length){
        e.preventDefault();
        e.stopImmediatePropagation();
        const q=inp.value.slice(0,inp.selectionStart).match(/:([a-z0-9_]{2,})$/)?.[1]||'';
        const matches=EMOJIS.filter(em=>em.n.includes(q)).slice(0,8);
        if(matches[acIdx])completeEmoji(matches[acIdx]);
      }
    }
  });
})();

// ─── @ Nick autocomplete ─────────────────────────────────────────────────────
(function(){
  const inp=document.getElementById('msg-input');
  if(!inp)return;
  let nacEl=document.createElement('div');
  nacEl.id='nick-autocomplete';
  nacEl.style.cssText='position:absolute;bottom:100%;left:0;right:0;background:var(--bg1);border:1px solid var(--border);border-radius:6px;max-height:200px;overflow-y:auto;display:none;z-index:102;';
  inp.parentNode.appendChild(nacEl);
  let nacIdx=-1;
  function getChannelNicks(){
    if(!active)return [];
    const net=networks.find(n=>n.config.id===active.conn_id);
    const ch=net?.channels?.find(c=>c.name===active.target);
    return (ch?.names||[]).map(n=>stripPfx(n));
  }
  inp.addEventListener('input',()=>{
    const v=inp.value, pos=inp.selectionStart;
    const before=v.slice(0,pos);
    const m=before.match(/@([a-zA-Z0-9_\-\[\]\\`^]{0,20})$/);
    if(!m){nacEl.style.display='none';nacIdx=-1;return;}
    const q=m[1].toLowerCase();
    const nicks=getChannelNicks().filter(n=>n.toLowerCase().startsWith(q)).slice(0,10);
    if(!nicks.length){nacEl.style.display='none';nacIdx=-1;return;}
    nacEl.style.display='block'; nacIdx=0;
    nacEl.innerHTML=nicks.map((n,i)=>`<div class="emoji-ac-item${i===0?' active':''}" data-i="${i}" style="font-size:13px"><span class="nc${nickHash(n)}">${esc(n)}</span></div>`).join('');
    nacEl.querySelectorAll('.emoji-ac-item').forEach(el=>{
      // pointerdown + preventDefault to dodge the iOS input-blur cascade:
      // a plain click handler gets eaten because the tap blurs the input,
      // dismisses the keyboard, slides the overlay down out of the original
      // tap coordinates, and the synthetic click lands on empty space →
      // user has to tap twice. This is the same fix slash uses below.
      el.addEventListener('pointerdown',e=>{
        if(e.button!==undefined && e.button!==0) return;
        e.preventDefault();
        completeNick(nicks[+el.dataset.i]);
      });
    });
  });
  function completeNick(nick){
    const v=inp.value, pos=inp.selectionStart;
    const before=v.slice(0,pos);
    const idx=before.lastIndexOf('@');
    inp.value=before.slice(0,idx)+nick+' '+v.slice(pos);
    inp.focus();
    nacEl.style.display='none';nacIdx=-1;
  }
  inp.addEventListener('keydown',e=>{
    if(nacEl.style.display==='none')return;
    const items=nacEl.querySelectorAll('.emoji-ac-item');
    if(!items.length)return;
    // stopImmediatePropagation — see slash-picker comment for the why.
    if(e.key==='ArrowDown'){e.preventDefault();e.stopImmediatePropagation();nacIdx=Math.min(nacIdx+1,items.length-1);items.forEach((el,i)=>el.classList.toggle('active',i===nacIdx));}
    else if(e.key==='ArrowUp'){e.preventDefault();e.stopImmediatePropagation();nacIdx=Math.max(nacIdx-1,0);items.forEach((el,i)=>el.classList.toggle('active',i===nacIdx));}
    else if(e.key==='Tab'||e.key==='Enter'){
      if(nacIdx>=0&&nacIdx<items.length){
        e.preventDefault();
        e.stopImmediatePropagation();
        const nicks=getChannelNicks().filter(n=>n.toLowerCase().startsWith(
          (inp.value.slice(0,inp.selectionStart).match(/@([a-zA-Z0-9_\-\[\]\\`^]{0,20})$/)||[])[1]?.toLowerCase()||''
        )).slice(0,10);
        if(nicks[nacIdx])completeNick(nicks[nacIdx]);
      }
    }
    else if(e.key==='Escape'){e.stopImmediatePropagation();nacEl.style.display='none';nacIdx=-1;}
  });
})();

// ─── Slash command autocomplete ───────────────────────────────────────────────
(function(){
  const inp=document.getElementById('msg-input');
  if(!inp)return;
  const CMDS=[
    // ── Channel ──
    {cmd:'join',desc:'Join a channel',usage:'/join #channel [key]'},
    {cmd:'part',desc:'Leave channel',usage:'/part [#channel] [reason]'},
    {cmd:'cycle',desc:'Part and rejoin',usage:'/cycle [#channel]'},
    {cmd:'topic',desc:'View/set topic',usage:'/topic [text]'},
    {cmd:'list',desc:'List all channels',usage:'/list'},
    {cmd:'links',desc:'Show server links',usage:'/links'},
    {cmd:'invite',desc:'Invite user to channel',usage:'/invite nick [#channel]'},
    {cmd:'names',desc:'Refresh nick list',usage:'/names'},
    {cmd:'key',desc:'Save/clear a channel key (+k)',usage:'/key #channel [key]'},
    // ── Messaging ──
    {cmd:'msg',desc:'Send private message',usage:'/msg nick text'},
    {cmd:'query',desc:'Open DM window',usage:'/query nick [text]'},
    {cmd:'me',desc:'Send action',usage:'/me does something'},
    {cmd:'say',desc:'Send raw text',usage:'/say text'},
    {cmd:'notice',desc:'Send notice',usage:'/notice nick text'},
    {cmd:'ctcp',desc:'Send CTCP command',usage:'/ctcp nick command'},
    {cmd:'slap',desc:'Slap with a trout',usage:'/slap nick'},
    // ── Identity ──
    {cmd:'nick',desc:'Change nickname',usage:'/nick newnick'},
    {cmd:'away',desc:'Set away status',usage:'/away [message]'},
    {cmd:'back',desc:'Remove away',usage:'/back'},
    {cmd:'whois',desc:'Look up user info',usage:'/whois nick'},
    {cmd:'whowas',desc:'Look up offline user',usage:'/whowas nick'},
    {cmd:'who',desc:'List channel users',usage:'/who #channel'},
    // ── User Modes ──
    {cmd:'mode',desc:'Set channel/user mode',usage:'/mode +o nick'},
    {cmd:'op',desc:'Give operator',usage:'/op nick'},
    {cmd:'deop',desc:'Remove operator',usage:'/deop nick'},
    {cmd:'voice',desc:'Give voice',usage:'/voice nick'},
    {cmd:'devoice',desc:'Remove voice',usage:'/devoice nick'},
    {cmd:'halfop',desc:'Give half-op',usage:'/halfop nick'},
    {cmd:'dehalfop',desc:'Remove half-op',usage:'/dehalfop nick'},
    {cmd:'owner',desc:'Give owner (+q)',usage:'/owner nick'},
    {cmd:'deowner',desc:'Remove owner (-q)',usage:'/deowner nick'},
    {cmd:'admin',desc:'Give admin/protect (+a)',usage:'/admin nick'},
    {cmd:'deadmin',desc:'Remove admin (-a)',usage:'/deadmin nick'},
    // ── Mass Operations ──
    {cmd:'opall',desc:'Op everyone in channel',usage:'/opall'},
    {cmd:'deopall',desc:'Deop everyone',usage:'/deopall'},
    {cmd:'mdop',desc:'Mass deop all but yourself',usage:'/mdop'},
    {cmd:'drop',desc:'Strip all status from everyone',usage:'/drop'},
    {cmd:'voiceall',desc:'Voice everyone',usage:'/voiceall'},
    {cmd:'devoiceall',desc:'Devoice everyone',usage:'/devoiceall'},
    {cmd:'kickall',desc:'Kick everyone (except you)',usage:'/kickall'},
    // ── Moderation ──
    {cmd:'kick',desc:'Kick user',usage:'/kick nick [reason]'},
    {cmd:'ban',desc:'Ban user',usage:'/ban nick'},
    {cmd:'unban',desc:'Remove ban',usage:'/unban mask'},
    {cmd:'kickban',desc:'Kick and ban',usage:'/kickban nick [reason]'},
    {cmd:'tban',desc:'Temporary ban',usage:'/tban nick seconds [reason]'},
    {cmd:'banlist',desc:'View ban list',usage:'/banlist'},
    {cmd:'unbanall',desc:'Remove all bans',usage:'/unbanall'},
    {cmd:'unexemptall',desc:'Remove all ban exempts (+e)',usage:'/unexemptall'},
    {cmd:'ignore',desc:'Ignore user or mask',usage:'/ignore nick|mask'},
    {cmd:'unignore',desc:'Remove ignore',usage:'/unignore nick|mask'},
    {cmd:'ignorelist',desc:'Show ignored users',usage:'/ignorelist'},
    {cmd:'pmallow',desc:'Allow PMs from user (bypass protection)',usage:'/pmallow nick'},
    {cmd:'pmremove',desc:'Remove from PM allow list',usage:'/pmremove nick'},
    {cmd:'pmallowlist',desc:'Show PM allow list',usage:'/pmallowlist'},
    {cmd:'pmprotection',desc:'Open PM protection settings',usage:'/pmprotection'},
    // ── Giphy ──
    {cmd:'giphy',desc:'Search Giphy (live picker — arrow keys + Enter)',usage:'/giphy query'},
    {cmd:'gif',desc:'Alias for /giphy',usage:'/gif query'},
    // ── Services ──
    {cmd:'ns',desc:'NickServ command',usage:'/ns identify password'},
    {cmd:'cs',desc:'ChanServ command',usage:'/cs op #chan nick'},
    {cmd:'identify',desc:'Identify to NickServ',usage:'/identify password'},
    {cmd:'register',desc:'Register with NickServ',usage:'/register password email'},
    {cmd:'ghost',desc:'Ghost a nick',usage:'/ghost nick [password]'},
    {cmd:'regain',desc:'Recover a nick',usage:'/regain nick [password]'},
    // ── IRCOp ──
    {cmd:'oper',desc:'Authenticate as IRCOp',usage:'/oper login password'},
    {cmd:'kill',desc:'Kill a user',usage:'/kill nick reason'},
    {cmd:'shun',desc:'Shun a user',usage:'/shun mask duration reason'},
    {cmd:'gline',desc:'G-line (network ban)',usage:'/gline mask duration reason'},
    {cmd:'zline',desc:'Z-line (IP ban)',usage:'/zline mask duration reason'},
    {cmd:'kline',desc:'K-line (server ban)',usage:'/kline mask duration reason'},
    {cmd:'rehash',desc:'Reload server config',usage:'/rehash'},
    {cmd:'squit',desc:'Disconnect a server',usage:'/squit server reason'},
    // ── Connection ──
    {cmd:'connect',desc:'Connect to server',usage:'/connect'},
    {cmd:'disconnect',desc:'Disconnect from server',usage:'/disconnect'},
    {cmd:'quote',desc:'Send raw IRC command',usage:'/quote RAW LINE'},
    // ── Encryption ──
    {cmd:'encrypt',desc:'Manage E2E encryption',usage:'/encrypt on|off|keygen|add|rotate'},
    // ── Client ──
    {cmd:'close',desc:'Close current DM/channel',usage:'/close'},
    {cmd:'clear',desc:'Clear current chat',usage:'/clear'},
    {cmd:'clearall',desc:'Clear all chat buffers',usage:'/clearall'},
    {cmd:'uploads',desc:'Open Upload Status',usage:'/uploads'},
    {cmd:'help',desc:'Show help panel',usage:'/help'},
    {cmd:'ping',desc:'CTCP ping user',usage:'/ping nick'},
    {cmd:'version',desc:'CTCP version user',usage:'/version nick'},
    {cmd:'time',desc:'CTCP time user',usage:'/time nick'},
    {cmd:'monitor',desc:'Monitor nick online/offline',usage:'/monitor nick'},
    {cmd:'unmonitor',desc:'Stop monitoring',usage:'/unmonitor nick'},
    // ── Tools ──
    {cmd:'ascii',desc:'Generate ASCII art text',usage:'/ascii <text>'},
    {cmd:'ud',desc:'Urban Dictionary lookup',usage:'/ud <word>'},
    {cmd:'shorten',desc:'Shorten a URL',usage:'/shorten <url>'},
    {cmd:'stats',desc:'Channel statistics dashboard',usage:'/stats'},
    {cmd:'note',desc:'Set/view notes on a nick',usage:'/note <nick> [text]'},
    {cmd:'dnd',desc:'Do Not Disturb mode',usage:'/dnd on|off|schedule HH:MM HH:MM'},
    {cmd:'split',desc:'Toggle split view (two channels)',usage:'/split'},
    {cmd:'seen',desc:'When was a nick last seen?',usage:'/seen <nick>'},
    {cmd:'ratelimit',desc:'Set message rate limit (ms)',usage:'/ratelimit <ms>'},
    {cmd:'expire',desc:'Auto-delete old messages (hours)',usage:'/expire <hours>'},
    {cmd:'autolock',desc:'Vault auto-lock timer (minutes)',usage:'/autolock <minutes>'},
    {cmd:'keepnick',desc:'Keep a nick (reclaim if lost)',usage:'/keepnick [nick]'},
    {cmd:'unkeepnick',desc:'Stop keeping a nick',usage:'/unkeepnick'},
    {cmd:'listnick',desc:'List all kept nicks',usage:'/listnick'},
    // ── Fun ──
    {cmd:'prism',desc:'Rainbow colored text',usage:'/prism message'},
    {cmd:'advertise',desc:'Tell the channel about CryptIRC',usage:'/advertise'},
    {cmd:'shrug',desc:'¯\\_(ツ)_/¯',usage:'/shrug [text]'},
    {cmd:'tableflip',desc:'(╯°□°)╯︵ ┻━┻',usage:'/tableflip [text]'},
    {cmd:'unflip',desc:'┬─┬ノ( º _ ºノ)',usage:'/unflip [text]'},
    {cmd:'lenny',desc:'( ͡° ͜ʖ ͡°)',usage:'/lenny [text]'},
    {cmd:'disapprove',desc:'ಠ_ಠ',usage:'/disapprove [text]'},
    {cmd:'rage',desc:'(ノಠ益ಠ)ノ彡┻━┻',usage:'/rage [text]'},
    {cmd:'bear',desc:'ʕ•ᴥ•ʔ',usage:'/bear [text]'},
    {cmd:'sparkle',desc:'✧･ﾟ sparkle text ･ﾟ✧',usage:'/sparkle text'},
    {cmd:'finger',desc:'╭∩╮(︶︿︶)╭∩╮',usage:'/finger [text]'},
    {cmd:'dance',desc:'♪┏(・o・)┛♪',usage:'/dance [text]'},
    {cmd:'rip',desc:'⚰️ R.I.P. ⚰️',usage:'/rip name'},
    {cmd:'hug',desc:'(づ｡◕‿‿◕｡)づ',usage:'/hug nick'},
  ];
  let slashEl=document.createElement('div');
  slashEl.id='slash-autocomplete';
  const wrap=inp.closest('#input-wrap');
  wrap.style.position='relative';
  wrap.appendChild(slashEl);
  let slashIdx=-1;

  function updateSlash(){
    const v=inp.value;
    if(!v.startsWith('/')||v.includes(' ')){slashEl.style.display='none';slashIdx=-1;return;}
    const q=v.slice(1).toLowerCase();
    const matches=q?CMDS.filter(c=>c.cmd.startsWith(q)):CMDS;
    const show=matches.slice(0,80);
    if(!show.length){slashEl.style.display='none';slashIdx=-1;return;}
    slashEl.style.display='block'; slashIdx=0;
    slashEl.innerHTML=show.map((c,i)=>`<div class="slash-ac-item${i===0?' active':''}" data-i="${i}"><span class="slash-ac-cmd">/${c.cmd}</span><span class="slash-ac-desc">${c.desc}</span></div>`).join('');
    slashEl.querySelectorAll('.slash-ac-item').forEach(el=>{
      el.addEventListener('pointerdown',e=>{e.preventDefault();completeSlash(show[+el.dataset.i]);});
    });
  }
  function completeSlash(c){
    inp.value='/'+c.cmd+' ';
    inp.focus();
    slashEl.style.display='none';slashIdx=-1;
  }
  inp.addEventListener('input',updateSlash);
  inp.addEventListener('keydown',e=>{
    if(slashEl.style.display==='none'||slashEl.style.display==='')return;
    const items=slashEl.querySelectorAll('.slash-ac-item');
    if(!items.length)return;
    // CRITICAL: stopImmediatePropagation on every key we handle. This IIFE's
    // keydown is registered during HTML parse — the main inp.keydown handler
    // registers later inside DOMContentLoaded. JS dispatches in registration
    // order, so without this stop, completeSlash() closes the picker FIRST,
    // then the main handler runs against a now-closed picker, fails its
    // defer check, and pipes the half-typed value into handleInput (causing
    // a double-execute for argless commands and a stale partial submit for
    // arg-taking ones). The earlier _acOpen defer was insufficient.
    if(e.key==='ArrowDown'){e.preventDefault();e.stopImmediatePropagation();slashIdx=Math.min(slashIdx+1,items.length-1);items.forEach((el,i)=>el.classList.toggle('active',i===slashIdx));items[slashIdx]?.scrollIntoView({block:'nearest'});}
    else if(e.key==='ArrowUp'){e.preventDefault();e.stopImmediatePropagation();slashIdx=Math.max(slashIdx-1,0);items.forEach((el,i)=>el.classList.toggle('active',i===slashIdx));items[slashIdx]?.scrollIntoView({block:'nearest'});}
    else if(e.key==='Tab'||e.key==='Enter'){
      // Tab: complete only (leave cursor parked for arg typing).
      // Enter: complete AND submit. For argless commands we run them. For
      // arg-taking commands we still complete and park the cursor — the user
      // is expected to type args and press Enter again.
      e.preventDefault();
      e.stopImmediatePropagation();
      const v=inp.value;
      const q=v.slice(1).toLowerCase();
      const matches=q?CMDS.filter(c=>c.cmd.startsWith(q)):CMDS;
      const show=matches.slice(0,80);
      const picked=show[slashIdx];
      if(picked){
        completeSlash(picked);
        const argless = (picked.usage||'').trim() === '/'+picked.cmd;
        if(e.key==='Enter' && argless){
          // Belt-and-suspenders against any other handler firing on this same
          // keydown event: synchronously clear inp.value FIRST so any
          // downstream `handleInput(inp.value)` call (main keydown, etc.) sees
          // an empty input and bails. Capture the command separately, then
          // dispatch via setTimeout(0) so the rest of the current event
          // finishes before we actually fire the command.
          const cmdToRun = inp.value.replace(/\s+$/, '');
          inp.value = '';
          setTimeout(()=>{
            if(typeof handleInput === 'function') handleInput(cmdToRun);
          }, 0);
        }
      }
    }
    else if(e.key==='Escape'){e.stopImmediatePropagation();slashEl.style.display='none';slashIdx=-1;}
  });
  // Close on click outside
  document.addEventListener('click',e=>{if(!e.target.closest('#slash-autocomplete')&&!e.target.closest('#msg-input'))slashEl.style.display='none';});
})();

// ─── Giphy live picker ──────────────────────────────────────────────────────
// No shared key — each user stores their own free key via `/giphy key <k>`.
// Key lives in localStorage (per-device); rating filter too.
function _giphyKey(){try{return localStorage.getItem('cryptirc_giphy_key')||null;}catch{return null;}}
function _giphyRating(){return localStorage.getItem('cryptirc_giphy_rating')||'pg-13';}
function _giphyMaskKey(k){if(!k)return '(none)';if(k.length<8)return k[0]+'…';return k.slice(0,4)+'…'+k.slice(-2);}
async function giphyFetchTop(query){
  const key=_giphyKey(); if(!key)return null;
  try{
    const r=await fetch(`https://api.giphy.com/v1/gifs/search?api_key=${encodeURIComponent(key)}&q=${encodeURIComponent(query)}&limit=1&rating=${encodeURIComponent(_giphyRating())}`);
    if(!r.ok)return null;
    const d=await r.json();
    const g=d?.data?.[0];
    return g?.images?.original?.url||null;
  }catch(e){return null;}
}
async function giphyFetchList(query, n){
  const key=_giphyKey(); if(!key)return [];
  try{
    const r=await fetch(`https://api.giphy.com/v1/gifs/search?api_key=${encodeURIComponent(key)}&q=${encodeURIComponent(query)}&limit=${n|0}&rating=${encodeURIComponent(_giphyRating())}`);
    if(!r.ok)return [];
    const d=await r.json();
    return (d?.data||[]).map(g=>({
      preview:g?.images?.fixed_height_small?.url||g?.images?.preview_gif?.url,
      url:g?.images?.original?.url,
      title:g?.title||'',
    })).filter(x=>x.url);
  }catch(e){return [];}
}
(function(){
  const inp=document.getElementById('msg-input');if(!inp)return;
  // Picker element — floats above the input like the slash-autocomplete does.
  // Append to #input-wrap (which slash-autocomplete sets to position:relative)
  // so our `bottom:100%` anchors against the input bar, not against whatever
  // position:relative ancestor the inner flex child lives inside.
  let picker=document.createElement('div');
  picker.id='giphy-picker';
  // Edge fade masks the left+right edges to hint at horizontal overflow.
  // `touch-action:pan-x` limits gesture interpretation to horizontal pan so
  // vertical scrolls don't get captured. Height is responsive via media query.
  picker.style.cssText='position:absolute;bottom:calc(100% + 6px);left:0;right:0;background:linear-gradient(to bottom,var(--bg1) 0%,var(--bg2) 100%);border:1px solid var(--border2);border-radius:12px;display:none;z-index:102;box-shadow:0 -8px 28px rgba(0,0,0,.55),0 -2px 8px rgba(0,0,0,.3);padding:14px 12px;overflow-x:auto;overflow-y:hidden;white-space:nowrap;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;touch-action:pan-x;';
  const wrap=inp.closest('#input-wrap')||inp.parentNode;
  wrap.style.position='relative';
  wrap.appendChild(picker);
  let items=[]; // [{preview,url,title,el}]
  let idx=-1;
  let debounceTimer=null;
  let lastQuery='';
  // Timestamp of the most recent thumb pick. Used to suppress the stray
  // synthetic click that iOS fires AFTER layout shift from the on-tap keyboard
  // dismissal — that click can land on body/etc and would otherwise trigger
  // the outside-click close() below.
  let _giphyJustPicked=0;

  function close(){picker.style.display='none';items=[];idx=-1;picker.innerHTML='';lastQuery='';}
  function setActive(i){
    idx=Math.max(0,Math.min(i,items.length-1));
    items.forEach((it,j)=>{
      if(j===idx) it.el.classList.add('giphy-thumb-active');
      else it.el.classList.remove('giphy-thumb-active');
    });
    items[idx]?.el.scrollIntoView({block:'nearest',inline:'nearest',behavior:'smooth'});
  }
  // Add a close (X) button in the top-right corner of the picker. Clicking
  // it clears the input's "/giphy ..." prefix so the picker doesn't
  // immediately reopen on the next input event.
  function addCloseBtn(){
    const btn=document.createElement('button');
    btn.textContent='✕';
    btn.title='Close';
    btn.setAttribute('aria-label','Close Giphy picker');
    btn.type='button';
    btn.className='giphy-close-btn';
    btn.style.touchAction='manipulation';
    const doClose=e=>{
      e.preventDefault();e.stopPropagation();
      if(_extractQuery(inp.value)!=null) inp.value='';
      close();
    };
    // Same iOS fix as thumbs: handle on touchend to avoid the blur cascade
    // misfiring the outside-click handler in the layout-shift window.
    let tstart=null;
    btn.addEventListener('touchstart',ev=>{
      const t=ev.touches[0];tstart={x:t.clientX,y:t.clientY};
    },{passive:true});
    btn.addEventListener('touchend',ev=>{
      if(!tstart)return;tstart=null;
      _giphyJustPicked=Date.now();
      doClose(ev);
    },{passive:false});
    btn.addEventListener('click',ev=>{
      if(Date.now()-_giphyJustPicked<600)return;
      doClose(ev);
    });
    picker.appendChild(btn);
  }
  function renderLoading(q){
    picker.innerHTML='';
    picker.style.position='relative';
    const msg=document.createElement('div');
    msg.style.cssText='color:var(--text3);font-size:11px;padding:8px 28px 8px 10px;font-family:var(--mono)';
    msg.textContent=`Searching Giphy for "${q}"…`;
    picker.appendChild(msg);
    addCloseBtn();
    picker.style.display='block';
  }
  function renderNoKey(){
    picker.innerHTML='';
    picker.style.position='relative';
    const msg=document.createElement('div');
    msg.style.cssText='color:var(--text2);font-size:12px;padding:10px 28px 10px 12px;font-family:var(--mono);line-height:1.5';
    msg.innerHTML='⚠ No Giphy API key set. Get a free key at <strong>developers.giphy.com</strong> → Create App → API. Then run: <code style="color:var(--accent)">/giphy key YOUR_KEY</code>';
    picker.appendChild(msg);
    addCloseBtn();
    picker.style.display='block';
    items=[];idx=-1;
  }
  function renderResults(list,q){
    picker.innerHTML='';
    picker.style.position='relative';
    items=[];idx=-1;
    if(!list.length){
      const msg=document.createElement('div');
      msg.style.cssText='color:var(--text3);font-size:11px;padding:8px 28px 8px 10px;font-family:var(--mono)';
      msg.textContent=`No Giphy results for "${q}"`;
      picker.appendChild(msg);
      addCloseBtn();
      return;
    }
    for(const g of list){
      const el=document.createElement('img');
      el.src=g.preview;
      el.alt=g.title||'gif';
      el.title=g.title||'';
      el.loading='lazy';
      el.draggable=false;
      el.className='giphy-thumb';
      // `touch-action:manipulation` disables the 300ms double-tap delay on iOS
      // and avoids the parent picker's `pan-x` gesture being inherited for the
      // thumb itself — the thumb is tap-only; horizontal scroll happens on the
      // picker background between thumbs.
      el.style.cssText='display:inline-block;width:auto;margin:0 3px;border-radius:10px;cursor:pointer;outline:2px solid transparent;outline-offset:-2px;transition:outline .12s ease,transform .12s ease,box-shadow .12s ease;vertical-align:top;-webkit-touch-callout:none;-webkit-user-select:none;user-select:none;background:var(--bg3);touch-action:manipulation;';
      // iOS tap handling: on a tap, touchend → synthetic click sequence causes
      // input blur → keyboard dismiss → visualViewport resize → #input-wrap
      // slides down → picker slides with it → synthetic click lands on empty
      // space → document-level outside-click handler closes the picker. Net
      // effect: tap does nothing, picker "just goes away". Fix: handle the
      // tap on touchend with preventDefault to suppress the synthetic click
      // and its blur cascade. Guard scroll-vs-tap with a small move threshold.
      let tstart=null;
      el.addEventListener('touchstart',ev=>{
        const t=ev.touches[0];
        tstart={x:t.clientX,y:t.clientY};
      },{passive:true});
      el.addEventListener('touchmove',ev=>{
        if(!tstart)return;
        const t=ev.touches[0];
        if(Math.hypot(t.clientX-tstart.x,t.clientY-tstart.y)>10)tstart=null;
      },{passive:true});
      el.addEventListener('touchend',ev=>{
        if(!tstart)return;
        tstart=null;
        ev.preventDefault(); // suppress synthetic click + blur on iOS
        _giphyJustPicked=Date.now();
        pick({...g,el});
      },{passive:false});
      // Mouse fallback for non-touch devices. Will not double-fire because
      // touchend's preventDefault cancels the synthetic click on iOS.
      el.addEventListener('click',ev=>{
        if(Date.now()-_giphyJustPicked<600)return;
        ev.preventDefault();pick({...g,el});
      });
      picker.appendChild(el);
      items.push({...g,el});
    }
    addCloseBtn();
    setActive(0);
  }
  async function search(q){
    if(q===lastQuery)return;
    lastQuery=q;
    if(!_giphyKey()){ renderNoKey(); return; }
    renderLoading(q);
    const list=await giphyFetchList(q,10);
    const now=_extractQuery(inp.value);
    if(now!==q)return;
    renderResults(list,q);
  }
  function _extractQuery(v){
    const m=v.match(/^\/(giphy|gif)\s+(.+)$/i);
    if(!m)return null;
    const rest=m[2].trim();
    // Don't trigger the live picker when the input is actually a subcommand
    // like `/giphy key <secret>` or `/giphy rating pg`. Otherwise the picker
    // would search Giphy with your API KEY as the query — leaking it in the
    // GET URL to Giphy's servers.
    const firstWord=rest.split(/\s+/)[0].toLowerCase();
    if(firstWord==='key'||firstWord==='rating')return null;
    return rest;
  }
  inp.addEventListener('input',()=>{
    // Cancel any pending search when input changes — even if we're about to
    // call search() again, this prevents a stale fetch from landing after the
    // user has started typing `/giphy key` or otherwise moved on.
    clearTimeout(debounceTimer);
    const q=_extractQuery(inp.value);
    if(!q){close();return;}
    debounceTimer=setTimeout(()=>search(q),300);
  });
  // Register at document CAPTURE phase so we intercept Enter BEFORE the
  // msg-input's own bubble-phase handler (which would send "/giphy query" as
  // a literal command). stopImmediatePropagation ensures nothing downstream
  // sees the Enter once we've committed to a pick.
  document.addEventListener('keydown',async e=>{
    if(picker.style.display==='none')return;
    if(document.activeElement!==inp)return;
    if(!items.length){
      // Even with an empty picker, Escape should close it
      if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();close();}
      return;
    }
    if(e.key==='ArrowRight'||e.key==='Tab'){e.preventDefault();e.stopImmediatePropagation();setActive(idx+1);}
    else if(e.key==='ArrowLeft'){e.preventDefault();e.stopImmediatePropagation();setActive(idx-1);}
    else if(e.key==='Enter'){
      const sel=items[idx];
      if(sel){e.preventDefault();e.stopImmediatePropagation();pick(sel);}
    }
    else if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();close();}
  },true);
  async function pick(sel){
    if(!active)return;
    const{conn_id,target}=active;
    const url=sel.url;
    // Clear the input and close the picker first
    inp.value=''; close();
    const gifWire=(window.E2E?.ready||window.E2E?.channelKeys?.[target])?await e2eEncryptOutgoing(target,url):null;
    if(gifWire) wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${gifWire}`});
    else wsend({type:'send',conn_id,raw:`PRIVMSG ${target} :${url}`});
    addMessage(conn_id,target,{ts:Date.now()/1000|0,from:getNick(conn_id),text:url,kind:'privmsg',encrypted:!!gifWire});
  }
  // Close on click outside. The <600ms guard suppresses the stray synthetic
  // click iOS fires after a thumb tap — at that point the picker has shifted
  // due to keyboard dismissal layout, so the click target is likely body/html,
  // which would otherwise incorrectly close an already-handled pick.
  document.addEventListener('click',e=>{
    if(Date.now()-_giphyJustPicked<600)return;
    if(!e.target.closest('#giphy-picker')&&!e.target.closest('#msg-input'))close();
  });
})();

// ─── Security panel ──────────────────────────────────────────────────────────
function showSecurityPanel(){
  const el=id=>document.getElementById(id);
  el('sec-vault-autolock').value=String(getVaultAutoLock());
  el('sec-msg-expiry').value=String(getMessageExpiry());
  el('sec-ratelimit').value=String(getRateLimit());
  const cfg=loadAppearance();
  localStorage.getItem('cryptirc_autorejoin')!=='false'?el('sec-autorejoin').classList.add('on'):el('sec-autorejoin').classList.remove('on');
  localStorage.getItem('cryptirc_block_pms')==='true'?el('sec-block-pms').classList.add('on'):el('sec-block-pms').classList.remove('on');
  cfg.linkPreviews!==false?el('sec-linkpreviews').classList.add('on'):el('sec-linkpreviews').classList.remove('on');
  cfg.spellcheck!==false?el('sec-spellcheck').classList.add('on'):el('sec-spellcheck').classList.remove('on');
  document.getElementById('security-overlay').classList.add('show');
  _overlayOpen('securityPanel', closeSecurityPanel);
}
function closeSecurityPanel(){_overlayClose('securityPanel');document.getElementById('security-overlay').classList.remove('show');}
function secSaveToggle(key,val){
  invalidateAppearCache();
  const cfg=loadAppearance();
  cfg[key]=val;
  saveAppearance(cfg);
  applyThemeCSS(cfg);
}

// ─── IRC Oper Panel ──────────────────────────────────────────────────────────
let _operIRCd='unrealircd';
let _operConnId=null;
function showOperPanel(){
  document.getElementById('oper-overlay').classList.add('show');
  _overlayOpen('operPanel', closeOperPanel);
  renderOperMain();
}
function closeOperPanel(){_overlayClose('operPanel');document.getElementById('oper-overlay').classList.remove('show');}
function operSend(raw){
  if(!_operConnId){showToast('Select a network first');return;}
  wsend({type:'send',conn_id:_operConnId,raw});
}
function operPrompt(title,fields,onSubmit){
  const body=document.getElementById('oper-body');
  let html='<button class="oper-back" onclick="renderOperMain()">&larr; Back</button>';
  html+=`<div style="font-size:14px;font-weight:700;color:var(--text);margin-bottom:12px">${title}</div>`;
  html+='<div class="oper-form">';
  for(const f of fields){
    html+=`<label>${esc(f.label)}</label>`;
    if(f.type==='select'){
      html+=`<select id="oper-f-${f.id}">`;
      for(const o of f.options) html+=`<option value="${esc(o.value)}">${esc(o.label)}</option>`;
      html+=`</select>`;
    } else if(f.type==='textarea'){
      html+=`<textarea id="oper-f-${f.id}" placeholder="${esc(f.placeholder||'')}" rows="2"></textarea>`;
    } else {
      html+=`<input id="oper-f-${f.id}" type="${f.type||'text'}" placeholder="${esc(f.placeholder||'')}" value="${esc(f.default||'')}">`;
    }
  }
  html+='<div class="oper-form-actions"><button class="oper-form-btn cancel" onclick="renderOperMain()">Cancel</button>';
  html+=`<button class="oper-form-btn" id="oper-submit">Execute</button></div></div>`;
  body.innerHTML=html;
  document.getElementById('oper-submit').onclick=()=>{
    const vals={};for(const f of fields)vals[f.id]=document.getElementById('oper-f-'+f.id)?.value||'';
    onSubmit(vals);
    showToast('Command sent');
    renderOperMain();
  };
  const first=body.querySelector('input,select,textarea');if(first)first.focus();
}
function operConfirm(title,msg,onYes){
  const body=document.getElementById('oper-body');
  let html='<button class="oper-back" onclick="renderOperMain()">&larr; Back</button>';
  html+=`<div style="font-size:14px;font-weight:700;color:var(--text);margin-bottom:8px">${title}</div>`;
  html+=`<div style="font-size:12px;color:var(--text3);margin-bottom:16px">${msg}</div>`;
  html+='<div class="oper-form-actions"><button class="oper-form-btn cancel" onclick="renderOperMain()">Cancel</button>';
  html+=`<button class="oper-form-btn danger" id="oper-yes">Confirm</button></div>`;
  body.innerHTML=html;
  document.getElementById('oper-yes').onclick=()=>{onYes();showToast('Command sent');renderOperMain();};
}

const OPER_IRCDS={
  unrealircd:{label:'UnrealIRCd',commands:{
    bans:[
      {label:'List G-Lines',icon:'📋',action:()=>operSend('STATS G')},
      {label:'List K-Lines',icon:'📋',action:()=>operSend('STATS k')},
      {label:'List Z-Lines',icon:'📋',action:()=>operSend('STATS Z')},
      {label:'List Shuns',icon:'📋',action:()=>operSend('STATS s')},
      {label:'List Spamfilters',icon:'📋',action:()=>operSend('STATS S')},
      {label:'List Excepts (E-Lines)',icon:'📋',action:()=>operSend('STATS e')},
      {label:'Add G-Line',icon:'🔨',action:()=>operPrompt('Add G-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host.com'},{id:'duration',label:'Duration',placeholder:'1d / 7d / 0 (permanent)'},{id:'reason',label:'Reason',placeholder:'Reason for ban'}],v=>operSend(`GLINE ${v.mask} ${v.duration} :${v.reason}`))},
      {label:'Remove G-Line',icon:'✖',action:()=>operPrompt('Remove G-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host.com'}],v=>operSend(`GLINE -${v.mask}`))},
      {label:'Add K-Line',icon:'🔨',action:()=>operPrompt('Add K-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host.com'},{id:'duration',label:'Duration',placeholder:'1d / 7d / 0'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`KLINE ${v.mask} ${v.duration} :${v.reason}`))},
      {label:'Remove K-Line',icon:'✖',action:()=>operPrompt('Remove K-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host.com'}],v=>operSend(`KLINE -${v.mask}`))},
      {label:'Add Z-Line',icon:'🔨',action:()=>operPrompt('Add Z-Line (IP ban)',[{id:'ip',label:'IP / CIDR',placeholder:'192.168.1.0/24'},{id:'duration',label:'Duration',placeholder:'1d / 7d / 0'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`ZLINE ${v.ip} ${v.duration} :${v.reason}`))},
      {label:'Remove Z-Line',icon:'✖',action:()=>operPrompt('Remove Z-Line',[{id:'ip',label:'IP / CIDR',placeholder:'192.168.1.0/24'}],v=>operSend(`ZLINE -${v.ip}`))},
      {label:'Add Shun',icon:'🔇',action:()=>operPrompt('Add Shun',[{id:'mask',label:'Host mask',placeholder:'*@annoying.host'},{id:'duration',label:'Duration',placeholder:'1d / 7d / 0'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`SHUN ${v.mask} ${v.duration} :${v.reason}`))},
      {label:'Remove Shun',icon:'✖',action:()=>operPrompt('Remove Shun',[{id:'mask',label:'Host mask',placeholder:'*@annoying.host'}],v=>operSend(`SHUN -${v.mask}`))},
      {label:'Add Spamfilter',icon:'🛡',action:()=>operPrompt('Add Spamfilter',[{id:'target',label:'Target',placeholder:'cpn',default:'cpn'},{id:'action',label:'Action',type:'select',options:[{value:'kill',label:'Kill'},{value:'gzline',label:'GZ-Line'},{value:'gline',label:'G-Line'},{value:'shun',label:'Shun'},{value:'block',label:'Block'},{value:'warn',label:'Warn'}]},{id:'duration',label:'Ban duration',placeholder:'1d / 0',default:'0'},{id:'reason',label:'Reason',placeholder:'No spamming'},{id:'regex',label:'Regex pattern',placeholder:'/badword/i'}],v=>operSend(`SPAMFILTER add ${v.target} ${v.action} ${v.duration} ${v.reason} ${v.regex}`))},
      {label:'Add E-Line (Exempt)',icon:'✅',action:()=>operPrompt('Add Exception',[{id:'mask',label:'Host mask',placeholder:'*@trusted.host'},{id:'duration',label:'Duration',placeholder:'0'},{id:'reason',label:'Reason',placeholder:'Trusted'}],v=>operSend(`ELINE ${v.mask} ${v.duration} :${v.reason}`))},
      {label:'Remove E-Line',icon:'✖',action:()=>operPrompt('Remove E-Line',[{id:'mask',label:'Host mask',placeholder:'*@trusted.host'}],v=>operSend(`ELINE -${v.mask}`))},
    ],
    users:[
      {label:'Kill User',icon:'💀',danger:true,action:()=>operPrompt('Kill User',[{id:'nick',label:'Nickname',placeholder:'baduser'},{id:'reason',label:'Reason',placeholder:'Violation of rules'}],v=>operSend(`KILL ${v.nick} :${v.reason}`))},
      {label:'SAJOIN',icon:'➡️',action:()=>operPrompt('Force Join',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAJOIN ${v.nick} ${v.chan}`))},
      {label:'SAPART',icon:'⬅️',action:()=>operPrompt('Force Part',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'chan',label:'Channel',placeholder:'#channel'},{id:'reason',label:'Reason',placeholder:''}],v=>operSend(`SAPART ${v.nick} ${v.chan}${v.reason?` :${v.reason}`:''}`))},
      {label:'SANICK',icon:'✏️',action:()=>operPrompt('Force Nick Change',[{id:'nick',label:'Current nick',placeholder:'oldnick'},{id:'newnick',label:'New nick',placeholder:'newnick'}],v=>operSend(`SANICK ${v.nick} ${v.newnick}`))},
      {label:'SAMODE',icon:'🔧',action:()=>operPrompt('Force Mode',[{id:'target',label:'Target',placeholder:'#channel or nick'},{id:'modes',label:'Modes',placeholder:'+o user'}],v=>operSend(`SAMODE ${v.target} ${v.modes}`))},
      {label:'SAUMODE',icon:'🔧',action:()=>operPrompt('Force User Mode',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'modes',label:'Modes',placeholder:'+x / -i'}],v=>operSend(`SAUMODE ${v.nick} ${v.modes}`))},
      {label:'Check Clones',icon:'🔍',action:()=>operPrompt('Check Clones',[{id:'ip',label:'IP address',placeholder:'192.168.1.1'}],v=>operSend(`WHO ${v.ip}`))},
      {label:'GLOBOPS',icon:'📢',action:()=>operPrompt('GLOBOPS Notice',[{id:'msg',label:'Message',type:'textarea',placeholder:'Announcement...'}],v=>operSend(`GLOBOPS :${v.msg}`))},
      {label:'Wallops',icon:'📢',action:()=>operPrompt('Wallops',[{id:'msg',label:'Message',type:'textarea',placeholder:'Message...'}],v=>operSend(`WALLOPS :${v.msg}`))},
      {label:'CHGHOST',icon:'🏷',action:()=>operPrompt('Change Host',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'vhost',label:'Virtual host',placeholder:'cool.vhost.net'}],v=>operSend(`CHGHOST ${v.nick} ${v.vhost}`))},
      {label:'CHGIDENT',icon:'🏷',action:()=>operPrompt('Change Ident',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'ident',label:'Ident',placeholder:'newident'}],v=>operSend(`CHGIDENT ${v.nick} ${v.ident}`))},
      {label:'CHGNAME',icon:'🏷',action:()=>operPrompt('Change Realname',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'name',label:'Realname',placeholder:'New Name'}],v=>operSend(`CHGNAME ${v.nick} :${v.name}`))},
    ],
    channels:[
      {label:'SAJOIN Self',icon:'➡️',action:()=>operPrompt('Join as Oper',[{id:'chan',label:'Channel',placeholder:'#secret'}],v=>{const net=networks.find(n=>n.config.id===_operConnId);operSend(`SAJOIN ${net?.nick||'me'} ${v.chan}`);})},
      {label:'Force Topic',icon:'📝',action:()=>operPrompt('Set Topic',[{id:'chan',label:'Channel',placeholder:'#channel'},{id:'topic',label:'Topic',type:'textarea',placeholder:'New topic'}],v=>{operSend(`SAMODE ${v.chan} +t`);setTimeout(()=>operSend(`TOPIC ${v.chan} :${v.topic}`),500);})
},
      {label:'Clear All Bans',icon:'🧹',action:()=>operPrompt('Clear Bans',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAMODE ${v.chan} -b *!*@*`))},
      {label:'Clear Invex (+I)',icon:'🧹',action:()=>operPrompt('Clear Invite Exceptions',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAMODE ${v.chan} -I *!*@*`))},
      {label:'Clear Excepts (+e)',icon:'🧹',action:()=>operPrompt('Clear Ban Exceptions',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAMODE ${v.chan} -e *!*@*`))},
    ],
    server:[
      {label:'REHASH',icon:'🔄',action:()=>operConfirm('Rehash Server','Reload config?',()=>operSend('REHASH'))},
      {label:'REHASH -tls',icon:'🔐',action:()=>operConfirm('Rehash TLS','Reload TLS certs?',()=>operSend('REHASH -tls'))},
      {label:'Server Map',icon:'🗺',action:()=>operSend('MAP')},
      {label:'Server Links',icon:'🔗',action:()=>operSend('LINKS')},
      {label:'LUSERS',icon:'📊',action:()=>operSend('LUSERS')},
      {label:'Uptime',icon:'⏱',action:()=>operSend('STATS u')},
      {label:'Traffic Stats',icon:'📈',action:()=>operSend('STATS T')},
      {label:'MOTD',icon:'📜',action:()=>operSend('MOTD')},
      {label:'Opers Online',icon:'👑',action:()=>operSend('STATS p')},
      {label:'Module List',icon:'📦',action:()=>operSend('STATS l')},
      {label:'Connect Server',icon:'🔗',action:()=>operPrompt('Connect Server',[{id:'server',label:'Server',placeholder:'hub.irc.net'}],v=>operSend(`CONNECT ${v.server}`))},
      {label:'Squit',icon:'✂️',danger:true,action:()=>operPrompt('Squit',[{id:'server',label:'Server',placeholder:'leaf.irc.net'},{id:'reason',label:'Reason',placeholder:'Maintenance'}],v=>operSend(`SQUIT ${v.server} :${v.reason}`))},
      {label:'DIE',icon:'☠️',danger:true,action:()=>operConfirm('⚠ Shutdown','SHUT DOWN the IRC server?',()=>operSend('DIE'))},
      {label:'RESTART',icon:'🔁',danger:true,action:()=>operConfirm('⚠ Restart','RESTART the IRC server?',()=>operSend('RESTART'))},
    ],
  }},
  inspircd:{label:'InspIRCd',commands:{
    bans:[
      {label:'List G-Lines',icon:'📋',action:()=>operSend('STATS G')},
      {label:'List K-Lines',icon:'📋',action:()=>operSend('STATS k')},
      {label:'List Z-Lines',icon:'📋',action:()=>operSend('STATS Z')},
      {label:'List Q-Lines',icon:'📋',action:()=>operSend('STATS Q')},
      {label:'List E-Lines',icon:'📋',action:()=>operSend('STATS e')},
      {label:'List Shuns',icon:'📋',action:()=>operSend('STATS H')},
      {label:'Add G-Line',icon:'🔨',action:()=>operPrompt('Add G-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host'},{id:'duration',label:'Duration (secs)',placeholder:'86400'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`GLINE ${v.mask} ${v.duration} :${v.reason}`))},
      {label:'Remove G-Line',icon:'✖',action:()=>operPrompt('Remove G-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host'}],v=>operSend(`GLINE ${v.mask}`))},
      {label:'Add K-Line',icon:'🔨',action:()=>operPrompt('Add K-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host'},{id:'duration',label:'Duration (secs)',placeholder:'86400'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`KLINE ${v.mask} ${v.duration} :${v.reason}`))},
      {label:'Remove K-Line',icon:'✖',action:()=>operPrompt('Remove K-Line',[{id:'mask',label:'Host mask',placeholder:'*@bad.host'}],v=>operSend(`KLINE ${v.mask}`))},
      {label:'Add Z-Line',icon:'🔨',action:()=>operPrompt('Add Z-Line',[{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'},{id:'duration',label:'Duration (secs)',placeholder:'86400'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`ZLINE ${v.ip} ${v.duration} :${v.reason}`))},
      {label:'Remove Z-Line',icon:'✖',action:()=>operPrompt('Remove Z-Line',[{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'}],v=>operSend(`ZLINE ${v.ip}`))},
      {label:'Add Q-Line (nick)',icon:'🚫',action:()=>operPrompt('Add Q-Line',[{id:'nick',label:'Nick mask',placeholder:'badnick*'},{id:'duration',label:'Duration (secs)',placeholder:'86400'},{id:'reason',label:'Reason',placeholder:'Reserved'}],v=>operSend(`QLINE ${v.nick} ${v.duration} :${v.reason}`))},
      {label:'Remove Q-Line',icon:'✖',action:()=>operPrompt('Remove Q-Line',[{id:'nick',label:'Nick mask',placeholder:'badnick*'}],v=>operSend(`QLINE ${v.nick}`))},
    ],
    users:[
      {label:'Kill User',icon:'💀',danger:true,action:()=>operPrompt('Kill User',[{id:'nick',label:'Nickname',placeholder:'baduser'},{id:'reason',label:'Reason',placeholder:'Violation'}],v=>operSend(`KILL ${v.nick} :${v.reason}`))},
      {label:'SAJOIN',icon:'➡️',action:()=>operPrompt('Force Join',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAJOIN ${v.nick} ${v.chan}`))},
      {label:'SAPART',icon:'⬅️',action:()=>operPrompt('Force Part',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAPART ${v.nick} ${v.chan}`))},
      {label:'SANICK',icon:'✏️',action:()=>operPrompt('Force Nick',[{id:'nick',label:'Current nick',placeholder:'oldnick'},{id:'newnick',label:'New nick',placeholder:'newnick'}],v=>operSend(`SANICK ${v.nick} ${v.newnick}`))},
      {label:'SAMODE',icon:'🔧',action:()=>operPrompt('Force Mode',[{id:'target',label:'Target',placeholder:'#channel or nick'},{id:'modes',label:'Modes',placeholder:'+o user'}],v=>operSend(`SAMODE ${v.target} ${v.modes}`))},
      {label:'SAQUIT',icon:'💀',danger:true,action:()=>operPrompt('Force Quit',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'reason',label:'Reason',placeholder:'Forced quit'}],v=>operSend(`SAQUIT ${v.nick} :${v.reason}`))},
      {label:'CHGHOST',icon:'🏷',action:()=>operPrompt('Change Host',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'vhost',label:'vHost',placeholder:'cool.vhost'}],v=>operSend(`CHGHOST ${v.nick} ${v.vhost}`))},
      {label:'CHGIDENT',icon:'🏷',action:()=>operPrompt('Change Ident',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'ident',label:'Ident',placeholder:'newident'}],v=>operSend(`CHGIDENT ${v.nick} ${v.ident}`))},
      {label:'CHGNAME',icon:'🏷',action:()=>operPrompt('Change Realname',[{id:'nick',label:'Nickname',placeholder:'user'},{id:'name',label:'Realname',placeholder:'New Name'}],v=>operSend(`CHGNAME ${v.nick} :${v.name}`))},
      {label:'Clones Check',icon:'🔍',action:()=>operPrompt('Check Clones',[{id:'ip',label:'IP',placeholder:'192.168.1.1'}],v=>operSend(`CLONES ${v.ip}`))},
      {label:'Wallops',icon:'📢',action:()=>operPrompt('Wallops',[{id:'msg',label:'Message',type:'textarea',placeholder:'Message...'}],v=>operSend(`WALLOPS :${v.msg}`))},
    ],
    channels:[
      {label:'SAJOIN Self',icon:'➡️',action:()=>operPrompt('Join as Oper',[{id:'chan',label:'Channel',placeholder:'#secret'}],v=>{const net=networks.find(n=>n.config.id===_operConnId);operSend(`SAJOIN ${net?.nick||'me'} ${v.chan}`);})},
      {label:'Force Topic',icon:'📝',action:()=>operPrompt('Set Topic',[{id:'chan',label:'Channel',placeholder:'#channel'},{id:'topic',label:'Topic',type:'textarea',placeholder:'New topic'}],v=>{operSend(`SAMODE ${v.chan} +t`);setTimeout(()=>operSend(`TOPIC ${v.chan} :${v.topic}`),500);})
},
      {label:'Clear All Bans',icon:'🧹',action:()=>operPrompt('Clear Bans',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`SAMODE ${v.chan} -b *!*@*`))},
    ],
    server:[
      {label:'REHASH',icon:'🔄',action:()=>operConfirm('Rehash','Reload config?',()=>operSend('REHASH'))},
      {label:'Server Map',icon:'🗺',action:()=>operSend('MAP')},
      {label:'Links',icon:'🔗',action:()=>operSend('LINKS')},
      {label:'LUSERS',icon:'📊',action:()=>operSend('LUSERS')},
      {label:'Uptime',icon:'⏱',action:()=>operSend('STATS u')},
      {label:'MOTD',icon:'📜',action:()=>operSend('MOTD')},
      {label:'Opers Online',icon:'👑',action:()=>operSend('STATS p')},
      {label:'Connect Server',icon:'🔗',action:()=>operPrompt('Connect Server',[{id:'server',label:'Server',placeholder:'hub.irc.net'}],v=>operSend(`CONNECT ${v.server}`))},
      {label:'Squit',icon:'✂️',danger:true,action:()=>operPrompt('Squit',[{id:'server',label:'Server',placeholder:'leaf.irc.net'},{id:'reason',label:'Reason',placeholder:'Maintenance'}],v=>operSend(`SQUIT ${v.server} :${v.reason}`))},
      {label:'DIE',icon:'☠️',danger:true,action:()=>operConfirm('⚠ Shutdown','Shut down?',()=>operSend('DIE'))},
      {label:'RESTART',icon:'🔁',danger:true,action:()=>operConfirm('⚠ Restart','Restart?',()=>operSend('RESTART'))},
    ],
  }},
  charybdis:{label:'charybdis / Solanum',commands:{
    bans:[
      {label:'List K-Lines',icon:'📋',action:()=>operSend('STATS K')},
      {label:'List D-Lines',icon:'📋',action:()=>operSend('STATS d')},
      {label:'List X-Lines',icon:'📋',action:()=>operSend('STATS x')},
      {label:'List RESVs',icon:'📋',action:()=>operSend('STATS q')},
      {label:'Add K-Line',icon:'🔨',action:()=>operPrompt('Add K-Line',[{id:'duration',label:'Duration (mins, 0=perm)',placeholder:'1440'},{id:'mask',label:'user@host',placeholder:'*@bad.host'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`KLINE ${v.duration} ${v.mask} :${v.reason}`))},
      {label:'Remove K-Line',icon:'✖',action:()=>operPrompt('Remove K-Line',[{id:'mask',label:'user@host',placeholder:'*@bad.host'}],v=>operSend(`UNKLINE ${v.mask}`))},
      {label:'Add D-Line',icon:'🔨',action:()=>operPrompt('Add D-Line',[{id:'duration',label:'Duration (mins)',placeholder:'1440'},{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`DLINE ${v.duration} ${v.ip} :${v.reason}`))},
      {label:'Remove D-Line',icon:'✖',action:()=>operPrompt('Remove D-Line',[{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'}],v=>operSend(`UNDLINE ${v.ip}`))},
      {label:'Add RESV',icon:'🚫',action:()=>operPrompt('Add RESV',[{id:'duration',label:'Duration (mins)',placeholder:'0'},{id:'target',label:'Nick or #chan',placeholder:'badnick'},{id:'reason',label:'Reason',placeholder:'Reserved'}],v=>operSend(`RESV ${v.duration} ${v.target} :${v.reason}`))},
      {label:'Remove RESV',icon:'✖',action:()=>operPrompt('Remove RESV',[{id:'target',label:'Nick or #chan',placeholder:'badnick'}],v=>operSend(`UNRESV ${v.target}`))},
    ],
    users:[
      {label:'Kill User',icon:'💀',danger:true,action:()=>operPrompt('Kill',[{id:'nick',label:'Nickname',placeholder:'baduser'},{id:'reason',label:'Reason',placeholder:'Violation'}],v=>operSend(`KILL ${v.nick} :${v.reason}`))},
      {label:'Wallops',icon:'📢',action:()=>operPrompt('Wallops',[{id:'msg',label:'Message',type:'textarea',placeholder:'Message...'}],v=>operSend(`WALLOPS :${v.msg}`))},
      {label:'Force Nick',icon:'✏️',action:()=>operPrompt('Force Nick',[{id:'nick',label:'Current nick',placeholder:'oldnick'},{id:'newnick',label:'New nick',placeholder:'newnick'}],v=>operSend(`FNICK ${v.nick} ${v.newnick}`))},
    ],
    channels:[
      {label:'Join (override)',icon:'➡️',action:()=>operPrompt('Join (override +p/+i/+k)',[{id:'chan',label:'Channel',placeholder:'#secret'}],v=>operSend(`JOIN ${v.chan} override`))},
      {label:'Clear Bans',icon:'🧹',action:()=>operPrompt('Clear Bans',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`MODE ${v.chan} -b *!*@*`))},
    ],
    server:[
      {label:'REHASH',icon:'🔄',action:()=>operConfirm('Rehash','Reload config?',()=>operSend('REHASH'))},
      {label:'Map',icon:'🗺',action:()=>operSend('MAP')},
      {label:'Links',icon:'🔗',action:()=>operSend('LINKS')},
      {label:'LUSERS',icon:'📊',action:()=>operSend('LUSERS')},
      {label:'Uptime',icon:'⏱',action:()=>operSend('STATS u')},
      {label:'MOTD',icon:'📜',action:()=>operSend('MOTD')},
      {label:'Opers',icon:'👑',action:()=>operSend('STATS p')},
      {label:'Connect',icon:'🔗',action:()=>operPrompt('Connect',[{id:'server',label:'Server',placeholder:'hub.irc.net'}],v=>operSend(`CONNECT ${v.server}`))},
      {label:'Squit',icon:'✂️',danger:true,action:()=>operPrompt('Squit',[{id:'server',label:'Server',placeholder:'leaf.irc.net'},{id:'reason',label:'Reason',placeholder:''}],v=>operSend(`SQUIT ${v.server} :${v.reason}`))},
      {label:'DIE',icon:'☠️',danger:true,action:()=>operConfirm('⚠ Shutdown','Shut down?',()=>operSend('DIE'))},
      {label:'RESTART',icon:'🔁',danger:true,action:()=>operConfirm('⚠ Restart','Restart?',()=>operSend('RESTART'))},
    ],
  }},
  ratbox:{label:'ircd-ratbox',commands:{
    bans:[
      {label:'List K-Lines',icon:'📋',action:()=>operSend('STATS K')},
      {label:'List D-Lines',icon:'📋',action:()=>operSend('STATS d')},
      {label:'List RESVs',icon:'📋',action:()=>operSend('STATS q')},
      {label:'Add K-Line',icon:'🔨',action:()=>operPrompt('Add K-Line',[{id:'duration',label:'Duration (mins)',placeholder:'1440'},{id:'mask',label:'user@host',placeholder:'*@bad.host'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`KLINE ${v.duration} ${v.mask} :${v.reason}`))},
      {label:'Remove K-Line',icon:'✖',action:()=>operPrompt('Remove K-Line',[{id:'mask',label:'user@host',placeholder:'*@bad.host'}],v=>operSend(`UNKLINE ${v.mask}`))},
      {label:'Add D-Line',icon:'🔨',action:()=>operPrompt('Add D-Line',[{id:'duration',label:'Duration (mins)',placeholder:'1440'},{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`DLINE ${v.duration} ${v.ip} :${v.reason}`))},
      {label:'Remove D-Line',icon:'✖',action:()=>operPrompt('Remove D-Line',[{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'}],v=>operSend(`UNDLINE ${v.ip}`))},
      {label:'Add RESV',icon:'🚫',action:()=>operPrompt('Add RESV',[{id:'duration',label:'Duration (mins)',placeholder:'0'},{id:'target',label:'Nick or #chan',placeholder:'badnick'},{id:'reason',label:'Reason',placeholder:'Reserved'}],v=>operSend(`RESV ${v.duration} ${v.target} :${v.reason}`))},
      {label:'Remove RESV',icon:'✖',action:()=>operPrompt('Remove RESV',[{id:'target',label:'Nick or #chan',placeholder:'badnick'}],v=>operSend(`UNRESV ${v.target}`))},
    ],
    users:[
      {label:'Kill',icon:'💀',danger:true,action:()=>operPrompt('Kill',[{id:'nick',label:'Nickname',placeholder:'baduser'},{id:'reason',label:'Reason',placeholder:'Violation'}],v=>operSend(`KILL ${v.nick} :${v.reason}`))},
      {label:'Wallops',icon:'📢',action:()=>operPrompt('Wallops',[{id:'msg',label:'Message',type:'textarea',placeholder:'Message...'}],v=>operSend(`WALLOPS :${v.msg}`))},
    ],
    channels:[
      {label:'Clear Bans',icon:'🧹',action:()=>operPrompt('Clear Bans',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`MODE ${v.chan} -b *!*@*`))},
    ],
    server:[
      {label:'REHASH',icon:'🔄',action:()=>operConfirm('Rehash','Reload?',()=>operSend('REHASH'))},
      {label:'Map',icon:'🗺',action:()=>operSend('MAP')},
      {label:'Links',icon:'🔗',action:()=>operSend('LINKS')},
      {label:'LUSERS',icon:'📊',action:()=>operSend('LUSERS')},
      {label:'Uptime',icon:'⏱',action:()=>operSend('STATS u')},
      {label:'MOTD',icon:'📜',action:()=>operSend('MOTD')},
      {label:'Opers',icon:'👑',action:()=>operSend('STATS p')},
      {label:'DIE',icon:'☠️',danger:true,action:()=>operConfirm('⚠ Shutdown','Shut down?',()=>operSend('DIE'))},
      {label:'RESTART',icon:'🔁',danger:true,action:()=>operConfirm('⚠ Restart','Restart?',()=>operSend('RESTART'))},
    ],
  }},
  hybrid:{label:'ircd-hybrid',commands:{
    bans:[
      {label:'List K-Lines',icon:'📋',action:()=>operSend('STATS K')},
      {label:'List D-Lines',icon:'📋',action:()=>operSend('STATS d')},
      {label:'Add K-Line',icon:'🔨',action:()=>operPrompt('Add K-Line',[{id:'duration',label:'Duration (mins)',placeholder:'1440'},{id:'mask',label:'user@host',placeholder:'*@bad.host'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`KLINE ${v.duration} ${v.mask} :${v.reason}`))},
      {label:'Remove K-Line',icon:'✖',action:()=>operPrompt('Remove K-Line',[{id:'mask',label:'user@host',placeholder:'*@bad.host'}],v=>operSend(`UNKLINE ${v.mask}`))},
      {label:'Add D-Line',icon:'🔨',action:()=>operPrompt('Add D-Line',[{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`DLINE ${v.ip} :${v.reason}`))},
      {label:'Remove D-Line',icon:'✖',action:()=>operPrompt('Remove D-Line',[{id:'ip',label:'IP/CIDR',placeholder:'192.168.1.0/24'}],v=>operSend(`UNDLINE ${v.ip}`))},
    ],
    users:[
      {label:'Kill',icon:'💀',danger:true,action:()=>operPrompt('Kill',[{id:'nick',label:'Nickname',placeholder:'baduser'},{id:'reason',label:'Reason',placeholder:'Violation'}],v=>operSend(`KILL ${v.nick} :${v.reason}`))},
      {label:'Wallops',icon:'📢',action:()=>operPrompt('Wallops',[{id:'msg',label:'Message',type:'textarea',placeholder:'Message...'}],v=>operSend(`WALLOPS :${v.msg}`))},
    ],
    channels:[
      {label:'Clear Bans',icon:'🧹',action:()=>operPrompt('Clear Bans',[{id:'chan',label:'Channel',placeholder:'#channel'}],v=>operSend(`MODE ${v.chan} -b *!*@*`))},
    ],
    server:[
      {label:'REHASH',icon:'🔄',action:()=>operConfirm('Rehash','Reload?',()=>operSend('REHASH'))},
      {label:'Map',icon:'🗺',action:()=>operSend('MAP')},
      {label:'LUSERS',icon:'📊',action:()=>operSend('LUSERS')},
      {label:'Uptime',icon:'⏱',action:()=>operSend('STATS u')},
      {label:'MOTD',icon:'📜',action:()=>operSend('MOTD')},
      {label:'DIE',icon:'☠️',danger:true,action:()=>operConfirm('⚠ Shutdown','Shut down?',()=>operSend('DIE'))},
      {label:'RESTART',icon:'🔁',danger:true,action:()=>operConfirm('⚠ Restart','Restart?',()=>operSend('RESTART'))},
    ],
  }},
  ngircd:{label:'ngIRCd',commands:{
    bans:[
      {label:'List K-Lines',icon:'📋',action:()=>operSend('STATS k')},
      {label:'Add K-Line',icon:'🔨',action:()=>operPrompt('Add K-Line',[{id:'mask',label:'user@host',placeholder:'*@bad.host'},{id:'reason',label:'Reason',placeholder:'Reason'}],v=>operSend(`KLINE ${v.mask} :${v.reason}`))},
    ],
    users:[
      {label:'Kill',icon:'💀',danger:true,action:()=>operPrompt('Kill',[{id:'nick',label:'Nickname',placeholder:'baduser'},{id:'reason',label:'Reason',placeholder:'Violation'}],v=>operSend(`KILL ${v.nick} :${v.reason}`))},
      {label:'Wallops',icon:'📢',action:()=>operPrompt('Wallops',[{id:'msg',label:'Message',type:'textarea',placeholder:'Message...'}],v=>operSend(`WALLOPS :${v.msg}`))},
    ],
    channels:[],
    server:[
      {label:'REHASH',icon:'🔄',action:()=>operConfirm('Rehash','Reload?',()=>operSend('REHASH'))},
      {label:'LUSERS',icon:'📊',action:()=>operSend('LUSERS')},
      {label:'MOTD',icon:'📜',action:()=>operSend('MOTD')},
      {label:'Connect',icon:'🔗',action:()=>operPrompt('Connect',[{id:'server',label:'Server',placeholder:'hub.irc.net'}],v=>operSend(`CONNECT ${v.server}`))},
      {label:'DIE',icon:'☠️',danger:true,action:()=>operConfirm('⚠ Shutdown','Shut down?',()=>operSend('DIE'))},
    ],
  }},
};
const OPER_CATEGORIES=[
  {key:'bans',label:'Server Bans',icon:'🛡'},
  {key:'users',label:'User Management',icon:'👤'},
  {key:'channels',label:'Channel Management',icon:'#️⃣'},
  {key:'server',label:'Server Management',icon:'🖥'},
];
function renderOperMain(){
  const body=document.getElementById('oper-body');
  let html='';
  html+='<div class="oper-section"><div class="oper-section-title">Network</div>';
  html+='<select class="oper-net-select" id="oper-net-select" onchange="_operConnId=this.value">';
  html+='<option value="">— Select network —</option>';
  for(const net of networks){
    const sel=_operConnId===net.config.id?' selected':'';
    html+=`<option value="${esc(net.config.id)}"${sel}>${esc(net.config.label||net.config.server)}</option>`;
  }
  html+='</select></div>';
  html+='<div class="oper-section"><div class="oper-section-title">IRCd Type</div>';
  html+='<select class="oper-net-select" id="oper-ircd-select" onchange="_operIRCd=this.value;renderOperMain()">';
  for(const[k,v] of Object.entries(OPER_IRCDS)){
    html+=`<option value="${k}"${_operIRCd===k?' selected':''}>${esc(v.label)}</option>`;
  }
  html+='</select></div>';
  html+='<div class="oper-section"><div class="oper-section-title">Authenticate</div><div class="oper-grid">';
  html+='<button class="oper-btn" data-oper-cmd="_operlogin">👑 OPER Login</button></div></div>';
  const ircd=OPER_IRCDS[_operIRCd];
  if(ircd){
    for(const cat of OPER_CATEGORIES){
      const cmds=ircd.commands[cat.key];
      if(!cmds||!cmds.length)continue;
      html+=`<div class="oper-section"><div class="oper-section-title">${cat.icon} ${cat.label}</div><div class="oper-grid">`;
      for(const cmd of cmds) html+=`<button class="oper-btn${cmd.danger?' danger':''}" data-oper-cmd="${esc(cmd.label)}">${cmd.icon||'▸'} ${esc(cmd.label)}</button>`;
      html+='</div></div>';
    }
  }
  body.innerHTML=html;
  // Bind oper login
  const loginBtn=body.querySelector('[data-oper-cmd="_operlogin"]');
  if(loginBtn) loginBtn.onclick=()=>{if(!_operConnId){showToast('Select a network first');return;}operPrompt('OPER Login',[{id:'name',label:'Oper name',placeholder:'admin'},{id:'pass',label:'Password',type:'password',placeholder:'oper password'}],v=>operSend(`OPER ${v.name} ${v.pass}`));};
  // Bind command buttons
  if(ircd){
    for(const cat of OPER_CATEGORIES){
      const cmds=ircd.commands[cat.key];if(!cmds)continue;
      for(const cmd of cmds){
        const btn=body.querySelector(`[data-oper-cmd="${cmd.label.replace(/"/g,'&quot;')}"]`);
        if(btn) btn.onclick=()=>{if(!_operConnId){showToast('Select a network first');return;}cmd.action();};
      }
    }
  }
}

// ─── Self-signed cert warning popup ──────────────────────────────────────────
function showCertWarning(conn_id){
  const net=networks.find(n=>n.config.id===conn_id);
  const label=net?.config?.label||net?.config?.server||'this server';
  const existing=document.getElementById('cert-warn-popup');
  if(existing)existing.remove();
  const popup=document.createElement('div');
  popup.id='cert-warn-popup';
  popup.style.cssText='position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:var(--bg2);border:1px solid var(--warn);border-radius:10px;padding:16px 20px;z-index:200;box-shadow:0 8px 30px rgba(0,0,0,.5);max-width:400px;width:90%;font-size:12px;color:var(--text);';
  popup.innerHTML=`
    <div style="display:flex;align-items:flex-start;gap:10px">
      <span style="font-size:22px;flex-shrink:0">⚠️</span>
      <div style="flex:1">
        <div style="font-weight:700;margin-bottom:6px;color:var(--warn)">SSL Certificate Error</div>
        <div style="color:var(--text2);line-height:1.5;margin-bottom:10px">
          <strong>${esc(label)}</strong> is using a self-signed or untrusted SSL certificate. This is common with ZNC bouncers and private IRC servers.<br><br>
          To connect, edit your network settings and set <strong>"Accept Invalid TLS"</strong> to <strong>Yes (self-signed)</strong>.
        </div>
        <div style="display:flex;gap:8px" id="cert-warn-btns"></div>
      </div>
    </div>`;
  document.body.appendChild(popup);
  // Attach button listeners safely (no inline onclick with conn_id)
  const btns=popup.querySelector('#cert-warn-btns');
  const editBtn=document.createElement('button');
  editBtn.textContent='Edit Network';editBtn.style.cssText='background:var(--accent);color:#000;border:none;border-radius:6px;padding:7px 14px;cursor:pointer;font-family:var(--mono);font-weight:700;font-size:12px';
  editBtn.addEventListener('click',()=>{editNetwork(conn_id);popup.remove();});
  const dismissBtn=document.createElement('button');
  dismissBtn.textContent='Dismiss';dismissBtn.style.cssText='background:var(--bg4);color:var(--text2);border:1px solid var(--border);border-radius:6px;padding:7px 14px;cursor:pointer;font-family:var(--mono);font-size:12px';
  dismissBtn.addEventListener('click',()=>popup.remove());
  btns.appendChild(editBtn);btns.appendChild(dismissBtn);
}

// ─── ZNC playback detection ──────────────────────────────────────────────────
let _zncPlayback={};
function zncDetectBatch(conn_id,target,msg){
  // ZNC sends server-time timestamps in the past during playback
  const now=Date.now()/1000;
  const age=now-msg.ts;
  const k=bk(conn_id,target);
  if(age>60){
    // Message is >60 seconds old — likely ZNC playback
    if(!_zncPlayback[k])_zncPlayback[k]={count:0,start:now};
    _zncPlayback[k].count++;
    return true; // batching
  } else if(_zncPlayback[k]){
    // First real-time message after batch — insert summary
    const batch=_zncPlayback[k];
    delete _zncPlayback[k];
    if(batch.count>3){
      addMessage(conn_id,target,{ts:now,from:'*',text:`── Playback: ${batch.count} buffered messages ──`,kind:'system'});
    }
  }
  return false;
}

// ─── Inline audio player ─────────────────────────────────────────────────────
const AUDIO_EXTS=/\.(mp3|ogg|flac|wav|m4a|aac|opus)(\?|#|$)/i;

// ─── Image lightbox zoom/pan ─────────────────────────────────────────────────
let _lbZoom=1,_lbPanX=0,_lbPanY=0,_lbDragging=false,_lbStartX=0,_lbStartY=0;
function toggleLightboxZoom(e){
  e.stopPropagation();
  const img=document.getElementById('lightbox-img');
  if(_lbZoom===1){_lbZoom=3;img.classList.add('zoomed');_lbPanX=0;_lbPanY=0;}
  else{_lbZoom=1;img.classList.remove('zoomed');_lbPanX=0;_lbPanY=0;}
  img.style.transform=`translate(${_lbPanX}px,${_lbPanY}px) scale(${_lbZoom})`;
}
function openLightbox(src){
  _lbZoom=1;_lbPanX=0;_lbPanY=0;
  const img=document.getElementById('lightbox-img');
  img.src=src;img.classList.remove('zoomed');img.style.transform='';
  document.getElementById('lightbox').classList.add('show');
  _overlayOpen('lightbox', closeLightbox);
}
function closeLightbox(){
  _overlayClose('lightbox');
  document.getElementById('lightbox').classList.remove('show');
  const img=document.getElementById('lightbox-img');img.classList.remove('zoomed');img.style.transform='';
}
(function(){
  const lb=document.getElementById('lightbox');if(!lb)return;
  // Pinch zoom for mobile
  let _lastDist=0;
  lb.addEventListener('touchstart',e=>{
    if(e.touches.length===2){
      _lastDist=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);
    } else if(e.touches.length===1&&_lbZoom>1){
      _lbDragging=true;_lbStartX=e.touches[0].clientX-_lbPanX;_lbStartY=e.touches[0].clientY-_lbPanY;
    }
  },{passive:true});
  lb.addEventListener('touchmove',e=>{
    const img=document.getElementById('lightbox-img');
    if(e.touches.length===2){
      e.preventDefault();
      const dist=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);
      _lbZoom=Math.max(1,Math.min(5,_lbZoom*(dist/_lastDist)));
      _lastDist=dist;
      if(_lbZoom<=1.05){_lbZoom=1;_lbPanX=0;_lbPanY=0;img.classList.remove('zoomed');}else{img.classList.add('zoomed');}
      img.style.transform=`translate(${_lbPanX}px,${_lbPanY}px) scale(${_lbZoom})`;
    } else if(_lbDragging&&e.touches.length===1){
      _lbPanX=e.touches[0].clientX-_lbStartX;_lbPanY=e.touches[0].clientY-_lbStartY;
      img.style.transform=`translate(${_lbPanX}px,${_lbPanY}px) scale(${_lbZoom})`;
    }
  },{passive:false});
  lb.addEventListener('touchend',()=>{_lbDragging=false;});
  // Mouse drag for desktop when zoomed
  lb.addEventListener('mousedown',e=>{
    if(_lbZoom>1){_lbDragging=true;_lbStartX=e.clientX-_lbPanX;_lbStartY=e.clientY-_lbPanY;e.preventDefault();}
  });
  lb.addEventListener('mousemove',e=>{
    if(_lbDragging){
      _lbPanX=e.clientX-_lbStartX;_lbPanY=e.clientY-_lbStartY;
      document.getElementById('lightbox-img').style.transform=`translate(${_lbPanX}px,${_lbPanY}px) scale(${_lbZoom})`;
    }
  });
  lb.addEventListener('mouseup',()=>{_lbDragging=false;});
  // Scroll wheel zoom on desktop
  lb.addEventListener('wheel',e=>{
    e.preventDefault();
    const img=document.getElementById('lightbox-img');
    _lbZoom=Math.max(1,Math.min(5,_lbZoom+(e.deltaY<0?0.3:-0.3)));
    if(_lbZoom<=1.05){_lbZoom=1;_lbPanX=0;_lbPanY=0;img.classList.remove('zoomed');}else{img.classList.add('zoomed');}
    img.style.transform=`translate(${_lbPanX}px,${_lbPanY}px) scale(${_lbZoom})`;
  },{passive:false});
})();

// ─── Message expiry ──────────────────────────────────────────────────────────
function getMessageExpiry(){return parseInt(localStorage.getItem('cryptirc_msg_expiry')||'0');}
function setMessageExpiry(hours){localStorage.setItem('cryptirc_msg_expiry',String(hours));savePrefsToServer();}
function runMessageExpiry(){
  const hours=getMessageExpiry();if(!hours)return;
  const cutoff=Date.now()/1000-(hours*3600);
  for(const k of Object.keys(buffers)){
    buffers[k]=buffers[k].filter(m=>m.ts>cutoff);
  }
}
// Run expiry check every 5 minutes + clean up stale bp: keys
setInterval(()=>{
  runMessageExpiry();
  // Clean up expired block-PM cooldown keys (>6 hours old)
  const now=Date.now();
  for(let i=localStorage.length-1;i>=0;i--){
    const k=localStorage.key(i);
    if(k&&k.startsWith('bp:')&&now-parseInt(localStorage.getItem(k)||'0')>6*3600*1000)localStorage.removeItem(k);
  }
},300000);

// ─── Vault auto-lock timer ───────────────────────────────────────────────────
let _vaultAutoLockTimer=null,_vaultLastActivity=Date.now();
function getVaultAutoLock(){return parseInt(localStorage.getItem('cryptirc_vault_autolock')||'0');}
function setVaultAutoLock(mins){localStorage.setItem('cryptirc_vault_autolock',String(mins));resetVaultAutoLock();}
function resetVaultAutoLock(){
  _vaultLastActivity=Date.now();
  clearTimeout(_vaultAutoLockTimer);
  const mins=getVaultAutoLock();
  if(!mins)return;
  _vaultAutoLockTimer=setTimeout(()=>{
    if(typeof lockVault==='function'){lockVault();showToast('Vault auto-locked after '+mins+' minutes of inactivity');}
  },mins*60000);
}
// Reset timer on any user interaction
['click','keydown','touchstart','mousemove'].forEach(ev=>document.addEventListener(ev,()=>{
  if(getVaultAutoLock())resetVaultAutoLock();
},{passive:true}));

// ─── Seen database ───────────────────────────────────────────────────────────
const _seenDb={};
function trackSeen(nick,channel,ts){
  if(!nick||nick==='*')return;
  _seenDb[nick.toLowerCase()]={nick,channel,ts};
  const keys=Object.keys(_seenDb);if(keys.length>5000){keys.sort((a,b)=>_seenDb[a].ts-_seenDb[b].ts);for(let i=0;i<1000;i++)delete _seenDb[keys[i]];}
}
function getSeen(nick){return _seenDb[nick.toLowerCase()]||null;}

// ─── Client-side rate limiter ────────────────────────────────────────────────
let _rateQueue=[],_rateTimer=null;
function getRateLimit(){return parseInt(localStorage.getItem('cryptirc_ratelimit')||'500');}
function setRateLimit(ms){localStorage.setItem('cryptirc_ratelimit',String(ms));savePrefsToServer();}
function rateLimitedSend(msg){
  _rateQueue.push(msg);
  if(!_rateTimer)drainRateQueue();
}
function drainRateQueue(){
  if(!_rateQueue.length){_rateTimer=null;return;}
  const msg=_rateQueue.shift();
  wsend(msg);
  _rateTimer=setTimeout(drainRateQueue,getRateLimit());
}

// ─── Session manager ─────────────────────────────────────────────────────────
function closeSessionsPanel(){_overlayClose('sessionsPanel');document.getElementById('sessions-overlay').classList.remove('show');}
async function showSessionManager(){
  const list=document.getElementById('sessions-list');
  list.innerHTML='<div style="color:var(--text3);font-size:12px;padding:20px;text-align:center">Loading...</div>';
  document.getElementById('sessions-overlay').classList.add('show');
  _overlayOpen('sessionsPanel', closeSessionsPanel);
  try{
    const r=await fetch(`${location.pathname}auth/sessions`,{headers:{'Authorization':`Bearer ${sessionToken}`}});
    const d=await r.json();
    if(!d.sessions||!d.sessions.length){list.innerHTML='<div style="color:var(--text3);font-size:12px;padding:20px;text-align:center">No active sessions.</div>';return;}
    list.innerHTML='';
    for(const s of d.sessions.sort((a,b)=>b.last_used-a.last_used)){
      const row=document.createElement('div');
      row.style.cssText='display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px;';
      const created=new Date(s.created_at*1000);
      const lastUsed=new Date(s.last_used*1000);
      const ago=Math.round((Date.now()/1000-s.last_used)/60);
      const agoStr=ago<1?'just now':ago<60?ago+'m ago':ago<1440?Math.round(ago/60)+'h ago':Math.round(ago/1440)+'d ago';
      row.innerHTML=`<span style="font-size:16px;flex-shrink:0">${s.current?'🟢':'⚪'}</span>
        <div style="flex:1;min-width:0">
          <div style="color:var(--text)">${s.prefix} ${s.current?'<span style="color:var(--accent);font-size:10px">(this device)</span>':''}</div>
          <div style="font-size:10px;color:var(--text3)">Active ${agoStr} · Created ${created.toLocaleDateString()}</div>
        </div>
        ${s.current?'':'<button onclick="revokeSession(\''+s.prefix+'\')" style="background:none;border:1px solid var(--border);color:var(--error);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:10px;flex-shrink:0;font-family:var(--mono)">Revoke</button>'}`;
      list.appendChild(row);
    }
  }catch(e){list.innerHTML='<div style="color:var(--error);font-size:12px;padding:20px;text-align:center">Failed to load sessions.</div>';}
}
async function revokeSession(prefix){
  if(!(await customConfirm('Revoke this session? The device will be logged out.','Revoke')))return;
  await fetch(`${location.pathname}auth/sessions/revoke`,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${sessionToken}`},body:JSON.stringify({prefix})});
  showSessionManager();
}

// ─── IRCv3 Caps panel ────────────────────────────────────────────────────────
const _IRCV3_CAPS=[
  {cap:'away-notify',label:'Away Notify',desc:'Get notified when users go away or return'},
  {cap:'account-notify',label:'Account Notify',desc:'Get notified when users log in/out of services'},
  {cap:'extended-join',label:'Extended Join',desc:'Show account and realname on join'},
  {cap:'server-time',label:'Server Time',desc:'Accurate timestamps from the server'},
  {cap:'multi-prefix',label:'Multi Prefix',desc:'Show all nick prefixes (@%+ etc)'},
  {cap:'cap-notify',label:'Cap Notify',desc:'Get notified of new/removed server capabilities'},
  {cap:'message-tags',label:'Message Tags',desc:'IRCv3 message metadata (required for many features)'},
  {cap:'batch',label:'Batch',desc:'Group related messages together'},
  {cap:'echo-message',label:'Echo Message',desc:'Server echoes your messages back (multi-device sync)'},
  {cap:'invite-notify',label:'Invite Notify',desc:'Get notified when someone is invited to a channel'},
  {cap:'setname',label:'Set Name',desc:'Real-time realname change notifications'},
  {cap:'account-tag',label:'Account Tag',desc:'Attach account name to messages'},
  {cap:'userhost-in-names',label:'Userhost in NAMES',desc:'Full user@host in NAMES reply'},
  {cap:'chghost',label:'Change Host',desc:'Real-time hostname/username change notifications'},
  {cap:'labeled-response',label:'Labeled Response',desc:'Match server responses to specific commands'},
  {cap:'draft/typing',label:'Typing Indicators',desc:'See when someone is typing'},
  {cap:'standard-replies',label:'Standard Replies',desc:'Structured error/warning messages from server'},
];

function showCapsPanel(){
  const sel=document.getElementById('caps-net-select');
  sel.innerHTML='';
  for(const net of networks){
    const opt=document.createElement('option');
    opt.value=net.config.id;
    opt.textContent=net.config.label||net.config.server;
    sel.appendChild(opt);
  }
  if(!networks.length) sel.innerHTML='<option>No networks</option>';
  renderCapsToggles();
  document.getElementById('caps-overlay').classList.add('show');
  _overlayOpen('capsPanel', closeCapsPanel);
}
function closeCapsPanel(){_overlayClose('capsPanel');document.getElementById('caps-overlay').classList.remove('show');}

function renderCapsToggles(){
  const list=document.getElementById('caps-list');
  const connId=document.getElementById('caps-net-select').value;
  const net=networks.find(n=>n.config.id===connId);
  if(!net){list.innerHTML='<div style="color:var(--text3);font-size:12px;padding:12px">Select a network.</div>';return;}
  const disabled=net.config.disabled_caps||[];
  list.innerHTML='';
  for(const c of _IRCV3_CAPS){
    const on=!disabled.includes(c.cap);
    const row=document.createElement('div');
    row.style.cssText='display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);';
    row.innerHTML=`<div style="flex:1;min-width:0">
      <div style="font-size:12px;color:var(--text);font-weight:500">${c.label}</div>
      <div style="font-size:10px;color:var(--text3)">${c.desc}</div>
    </div>
    <button class="appear-toggle${on?' on':''}" data-cap="${c.cap}" onclick="toggleCap(this,'${connId}','${c.cap}')"></button>`;
    list.appendChild(row);
  }
  const note=document.createElement('div');
  note.style.cssText='padding:10px 0 0;font-size:10px;color:var(--text3);';
  note.textContent='Changes apply on next connect. Reconnect the network for changes to take effect.';
  list.appendChild(note);
}

function toggleCap(btn,connId,cap){
  btn.classList.toggle('on');
  const net=networks.find(n=>n.config.id===connId);
  if(!net)return;
  if(!net.config.disabled_caps)net.config.disabled_caps=[];
  const isOn=btn.classList.contains('on');
  if(isOn){
    net.config.disabled_caps=net.config.disabled_caps.filter(c=>c!==cap);
  } else {
    if(!net.config.disabled_caps.includes(cap))net.config.disabled_caps.push(cap);
  }
  // Save to server
  wsend({type:'update_network',network:net.config});
}

// ─── Uploads panel ───────────────────────────────────────────────────────────
async function showUploadsPanel(){
  const list=document.getElementById('uploads-list');
  list.innerHTML='<div style="color:var(--text3);font-size:12px;padding:20px;text-align:center">Loading...</div>';
  document.getElementById('uploads-overlay').classList.add('show');
  _overlayOpen('uploadsPanel', closeUploadsPanel);
  try{
    const r=await fetch(`${location.pathname}uploads`,{headers:{'Authorization':`Bearer ${sessionToken}`}});
    const d=await r.json();
    if(!d.files||!d.files.length){list.innerHTML='<div style="color:var(--text3);font-size:12px;padding:20px;text-align:center">No uploads yet.</div>';return;}
    list.innerHTML='';
    const totalSize=d.files.reduce((a,f)=>a+f.size,0);
    const summary=document.createElement('div');
    summary.style.cssText='font-size:11px;color:var(--text3);padding:4px 0 8px;border-bottom:1px solid var(--border);margin-bottom:6px;';
    summary.textContent=`${d.files.length} file${d.files.length>1?'s':''} · ${formatBytes(totalSize)}`;
    list.appendChild(summary);
    for(const f of d.files.slice().reverse()){
      const row=document.createElement('div');
      row.style.cssText='display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;';
      const isImg=f.content_type.startsWith('image/');
      const preview=isImg?`<img src="${esc(f.url)}" style="width:36px;height:36px;object-fit:cover;border-radius:4px;flex-shrink:0">`:'<span style="font-size:20px;flex-shrink:0;width:36px;text-align:center">📄</span>';
      const date=new Date(f.uploaded_at*1000);
      const dateStr=date.toLocaleDateString()+' '+date.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
      const shareUrl=location.origin+f.url;
      row.innerHTML=`${preview}<div style="flex:1;min-width:0;overflow:hidden"><div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text)" title="${esc(f.original_name)}">${esc(f.original_name)}</div><div style="font-size:10px;color:var(--text3)">${formatBytes(f.size)} · ${dateStr}</div></div><button class="upload-copy-btn" style="background:none;border:1px solid var(--border);color:var(--accent);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:10px;flex-shrink:0;font-family:var(--mono)" title="Copy share link">📋</button><button class="upload-del-btn" style="background:none;border:1px solid var(--border);color:var(--error);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:10px;flex-shrink:0;font-family:var(--mono)">✕</button>`;
      row.querySelector('.upload-copy-btn').addEventListener('click',()=>{navigator.clipboard.writeText(shareUrl).then(()=>showToast('Link copied!')).catch(()=>{const t=document.createElement('textarea');t.value=shareUrl;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showToast('Link copied!');});});
      row.querySelector('.upload-del-btn').addEventListener('click',()=>deleteUpload(f.filename));
      list.appendChild(row);
    }
  }catch(e){list.innerHTML='<div style="color:var(--error);font-size:12px;padding:20px;text-align:center">Failed to load uploads.</div>';}
}
function closeUploadsPanel(){_overlayClose('uploadsPanel');document.getElementById('uploads-overlay').classList.remove('show');}
async function deleteUpload(filename){
  if(!(await customConfirm('Delete this file?','Delete')))return;
  await fetch(`${location.pathname}uploads/delete`,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${sessionToken}`},body:JSON.stringify({filename})});
  showUploadsPanel();
}
async function clearAllUploads(){
  if(!(await customConfirm('Delete ALL your uploaded files? This cannot be undone.','Delete all')))return;
  await fetch(`${location.pathname}uploads/clear`,{method:'POST',headers:{'Authorization':`Bearer ${sessionToken}`}});
  showUploadsPanel();
}
function formatBytes(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB';}

// ─── # Channel autocomplete ──────────────────────────────────────────────────
(function(){
  const inp=document.getElementById('msg-input');if(!inp)return;
  let chEl=document.createElement('div');chEl.id='chan-autocomplete';
  chEl.style.cssText='position:absolute;bottom:100%;left:0;right:0;background:var(--bg1);border:1px solid var(--border);border-radius:6px;max-height:200px;overflow-y:auto;display:none;z-index:102;';
  inp.parentNode.appendChild(chEl);
  let chIdx=-1;
  function getAllChannels(){
    const out=[];
    for(const net of (typeof networks!=='undefined'?networks:[])){
      for(const ch of (net.channels||[])){if(ch.name.startsWith('#')||ch.name.startsWith('&'))out.push(ch.name);}
    }
    return [...new Set(out)];
  }
  inp.addEventListener('input',()=>{
    const v=inp.value,pos=inp.selectionStart,before=v.slice(0,pos);
    const m=before.match(/(^|\s)(#[a-zA-Z0-9_\-]{0,30})$/);
    if(!m||m[2].length<2){chEl.style.display='none';chIdx=-1;return;}
    const q=m[2].toLowerCase();
    const chans=getAllChannels().filter(c=>c.toLowerCase().startsWith(q)).slice(0,10);
    if(!chans.length){chEl.style.display='none';chIdx=-1;return;}
    chEl.style.display='block';chIdx=0;
    chEl.innerHTML=chans.map((c,i)=>`<div class="emoji-ac-item${i===0?' active':''}" data-i="${i}" style="font-size:13px;color:var(--text2)">${esc(c)}</div>`).join('');
    chEl.querySelectorAll('.emoji-ac-item').forEach(el=>{
      // pointerdown + preventDefault — same iOS-blur-cascade fix as nick picker.
      el.addEventListener('pointerdown',e=>{
        if(e.button!==undefined && e.button!==0) return;
        e.preventDefault();
        completeChan(chans[+el.dataset.i]);
      });
    });
  });
  function completeChan(ch){
    const v=inp.value,pos=inp.selectionStart,before=v.slice(0,pos);
    const m=before.match(/(^|\s)(#[a-zA-Z0-9_\-]{0,30})$/);
    if(m){inp.value=before.slice(0,before.length-m[2].length)+ch+' '+v.slice(pos);inp.focus();}
    chEl.style.display='none';chIdx=-1;
  }
  inp.addEventListener('keydown',e=>{
    if(chEl.style.display==='none')return;
    const items=chEl.querySelectorAll('.emoji-ac-item');if(!items.length)return;
    // stopImmediatePropagation — see slash-picker comment for the why.
    if(e.key==='ArrowDown'){e.preventDefault();e.stopImmediatePropagation();chIdx=Math.min(chIdx+1,items.length-1);items.forEach((el,i)=>el.classList.toggle('active',i===chIdx));}
    else if(e.key==='ArrowUp'){e.preventDefault();e.stopImmediatePropagation();chIdx=Math.max(chIdx-1,0);items.forEach((el,i)=>el.classList.toggle('active',i===chIdx));}
    else if(e.key==='Tab'||e.key==='Enter'){if(chIdx>=0&&chIdx<items.length){e.preventDefault();e.stopImmediatePropagation();const chans=getAllChannels().filter(c=>c.toLowerCase().startsWith(((inp.value.slice(0,inp.selectionStart).match(/(^|\s)(#[a-zA-Z0-9_\-]{0,30})$/)||[])[2]||'').toLowerCase())).slice(0,10);if(chans[chIdx])completeChan(chans[chIdx]);}}
    else if(e.key==='Escape'){e.stopImmediatePropagation();chEl.style.display='none';chIdx=-1;}
  });
  document.addEventListener('click',e=>{if(!e.target.closest('#chan-autocomplete')&&!e.target.closest('#msg-input'))chEl.style.display='none';});
})();

// ─── ASCII art generator ─────────────────────────────────────────────────────
const _ASCIIFONT={
A:'01110,10001,11111,10001,10001',B:'11110,10001,11110,10001,11110',C:'01111,10000,10000,10000,01111',
D:'11110,10001,10001,10001,11110',E:'11111,10000,11110,10000,11111',F:'11111,10000,11110,10000,10000',
G:'01111,10000,10011,10001,01110',H:'10001,10001,11111,10001,10001',I:'11111,00100,00100,00100,11111',
J:'11111,00010,00010,10010,01100',K:'10001,10010,11100,10010,10001',L:'10000,10000,10000,10000,11111',
M:'10001,11011,10101,10001,10001',N:'10001,11001,10101,10011,10001',O:'01110,10001,10001,10001,01110',
P:'11110,10001,11110,10000,10000',Q:'01110,10001,10101,10010,01101',R:'11110,10001,11110,10010,10001',
S:'01111,10000,01110,00001,11110',T:'11111,00100,00100,00100,00100',U:'10001,10001,10001,10001,01110',
V:'10001,10001,01010,01010,00100',W:'10001,10001,10101,11011,10001',X:'10001,01010,00100,01010,10001',
Y:'10001,01010,00100,00100,00100',Z:'11111,00010,00100,01000,11111',
'0':'01110,10011,10101,11001,01110','1':'00100,01100,00100,00100,01110','2':'01110,10001,00110,01000,11111',
'3':'11110,00001,00110,00001,11110','4':'10010,10010,11111,00010,00010','5':'11111,10000,11110,00001,11110',
'6':'01110,10000,11110,10001,01110','7':'11111,00001,00010,00100,00100','8':'01110,10001,01110,10001,01110',
'9':'01110,10001,01111,00001,01110',' ':'00000,00000,00000,00000,00000',
'!':'00100,00100,00100,00000,00100','?':'01110,00001,00110,00000,00100','.':'00000,00000,00000,00000,00100',
'-':'00000,00000,11111,00000,00000','_':'00000,00000,00000,00000,11111',
};
function makeAsciiArt(text){
  text=text.toUpperCase().slice(0,20);const lines=['','','','',''];
  for(const ch of text){const data=_ASCIIFONT[ch]||_ASCIIFONT[' '];const rows=data.split(',');
  for(let r=0;r<5;r++)lines[r]+=rows[r].replace(/1/g,'█').replace(/0/g,' ')+' ';}
  return lines.join('\n');
}

// ─── DND (Do Not Disturb) ───────────────────────────────────────────────────
function isDndActive(){
  if(localStorage.getItem('cryptirc_dnd')==='1')return true;
  const start=localStorage.getItem('cryptirc_dnd_start'),end=localStorage.getItem('cryptirc_dnd_end');
  if(!start||!end)return false;
  const now=new Date(),h=now.getHours(),m=now.getMinutes(),cur=h*60+m;
  const[sh,sm]=(start||'0:0').split(':').map(Number),sv=sh*60+sm;
  const[eh,em]=(end||'0:0').split(':').map(Number),ev=eh*60+em;
  return sv<ev?(cur>=sv&&cur<ev):(cur>=sv||cur<ev);
}

// ─── User notes ──────────────────────────────────────────────────────────────
function loadUserNotes(){try{return JSON.parse(localStorage.getItem('cryptirc_user_notes')||'{}');}catch{return{};}}
function saveUserNotes(n){localStorage.setItem('cryptirc_user_notes',JSON.stringify(n));savePrefsToServer();}

// ─── Channel key manager ─────────────────────────────────────────────────────
function loadChanKeys(){try{return JSON.parse(localStorage.getItem('cryptirc_chankeys')||'{}');}catch{return{};}}
function saveChanKeys(k){localStorage.setItem('cryptirc_chankeys',JSON.stringify(k));}

// ─── Channel stats (persistent, encrypted in vault) ─────────────────────────
let _chanStats={};        // {channelKey: {nick: count}}
let _chanStatsEnabled=false;
let _chanStatsLoaded=false;
let _chanStatsDirty=false;
let _chanStatsSaveTimer=null;

function trackStat(conn_id,target,nick){
  if(!nick||nick==='*'||!_chanStatsEnabled)return;
  const k=bk(conn_id,target);if(!_chanStats[k])_chanStats[k]={};
  if(!_chanStats[k][nick])_chanStats[k][nick]=0;
  _chanStats[k][nick]++;
  _chanStatsDirty=true;
  if(!_chanStatsSaveTimer) _chanStatsSaveTimer=setTimeout(()=>{_chanStatsSaveTimer=null;saveStatsToServer();},30000);
}
function saveStatsToServer(){
  if(!_chanStatsDirty||!sessionToken)return;
  const payload=JSON.stringify({enabled:_chanStatsEnabled,channels:_chanStats});
  wsend({type:'save_stats',data:payload});
  _chanStatsDirty=false;
}
let _statsRefreshing=false;
let _statsLoadPending=false;
function loadStatsFromServer(){
  // Coalesce in-flight load requests. Previously, two near-simultaneous triggers
  // (vault_unlocked + state events) could both fire wsend before the first
  // response arrived, and the response handler's merge-branch would double-count
  // the server's stats into an already-populated local table.
  if(_statsLoadPending) return;
  _statsLoadPending=true;
  wsend({type:'load_stats'});
}
function refreshStats(){
  saveStatsToServer();
  _statsRefreshing=true;
  _statsLoadPending=false; // allow the refresh request to go through
  loadStatsFromServer();
}
function handleStatsData(data){
  _statsLoadPending=false;
  if(!data){_chanStatsLoaded=true;_statsRefreshing=false;return;}
  try{
    const d=JSON.parse(data);
    _chanStatsEnabled=!!d.enabled;
    const server=d.channels||{};
    // Always replace local with server's stored state. Any in-session increments
    // since the last auto-save would be lost here, but that window is at most
    // 30s (save timer) and the alternative — merging — double-counts the server
    // data into already-synced local state when handleStatsData runs twice.
    _chanStats=server;
    _chanStatsDirty=false;
    if(_statsRefreshing){
      _statsRefreshing=false;
      if(document.getElementById('chanstats-overlay').classList.contains('show')) renderStatsChannelList();
    }
    _chanStatsLoaded=true;
  }catch(e){_chanStatsLoaded=true;_statsRefreshing=false;}
}
window.addEventListener('beforeunload',()=>{if(_chanStatsDirty)saveStatsToServer();});

// /stats command — quick view for current channel (unchanged UX)
function showChannelStats(conn_id,target){
  showStatsPanel();
  setTimeout(()=>renderStatsDetail(bk(conn_id,target)),50);
}

// ─── Stats settings panel ────────────────────────────────────────────────────
function showStatsPanel(){
  document.getElementById('chanstats-overlay').classList.add('show');
  _overlayOpen('statsPanel', closeStatsPanel);
  renderStatsChannelList();
}
function closeStatsPanel(){
  _overlayClose('statsPanel');
  document.getElementById('chanstats-overlay').classList.remove('show');
}
function toggleStatsEnabled(btn){
  _chanStatsEnabled=btn.classList.contains('on');
  _chanStatsDirty=true;
  saveStatsToServer();
  renderStatsChannelList();
}
function renderStatsChannelList(){
  document.getElementById('chanstats-title').innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> Channel Stats';
  _bindStatsDelegation();   // idempotent; binds the delegated row/clear listener once
  const body=document.getElementById('chanstats-body');
  // Enable/disable toggle + refresh
  let html='<div class="appear-section"><div class="appear-row"><div><span class="appear-label">Enable channel stats</span><div style="font-size:10px;color:var(--text3)">Track message counts per nick across sessions</div></div>';
  html+=`<button class="appear-toggle${_chanStatsEnabled?' on':''}" id="cst-toggle" onclick="this.classList.toggle('on');toggleStatsEnabled(this)"></button></div>`;
  html+=`<div class="appear-row"><div><span class="appear-label">Sync from server</span><div style="font-size:10px;color:var(--text3)">Pull latest stats from all your devices</div></div>`;
  html+=`<button onclick="refreshStats()" style="background:var(--bg3);border:1px solid var(--border);color:var(--text2);padding:5px 12px;border-radius:6px;cursor:pointer;font-family:var(--mono);font-size:11px;display:flex;align-items:center;gap:4px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Refresh</button></div></div>`;
  if(!_chanStatsEnabled){
    html+='<div class="cst-empty">Stats tracking is disabled. Enable it above to start collecting channel statistics.</div>';
    body.innerHTML=html;return;
  }
  // Build channel list sorted by total messages
  const entries=[];
  for(const[k,nicks] of Object.entries(_chanStats)){
    const total=Object.values(nicks).reduce((a,b)=>a+b,0);
    const uniqueNicks=Object.keys(nicks).length;
    // Extract display name from key (conn_id/target)
    const parts=k.split('/');
    const chanName=parts.slice(1).join('/');
    const connId=parts[0];
    const net=networks.find(n=>n.config.id===connId);
    const netLabel=net?net.config.label||net.config.server:'Unknown';
    entries.push({key:k,chanName,netLabel,total,uniqueNicks});
  }
  entries.sort((a,b)=>b.total-a.total);
  if(!entries.length){
    html+='<div class="cst-empty">No stats collected yet. Chat in some channels and stats will appear here.</div>';
    body.innerHTML=html;return;
  }
  html+=`<div class="appear-section"><div class="appear-section-title">Channels (${entries.length})</div>`;
  for(const e of entries){
    // SECURITY: stats key embeds a channel name (user-influenced). Carry it in an
    // HTML-attribute-escaped data-stats-key opened via the delegated chanstats-body
    // listener, not an inline-handler JS-string (#10).
    html+=`<div class="cst-chan" data-stats-key="${esc(e.key)}">`;
    html+=`<div><div class="cst-chan-name">${esc(e.chanName)}</div><div class="cst-chan-meta">${esc(e.netLabel)} &middot; ${e.uniqueNicks} nicks</div></div>`;
    html+=`<div style="display:flex;align-items:center;gap:8px"><span style="font-size:14px;font-weight:700;color:var(--accent)">${e.total.toLocaleString()}</span><span class="cst-chan-arrow">&rsaquo;</span></div>`;
    html+=`</div>`;
  }
  html+='</div>';
  // Clear all button
  html+='<div style="text-align:center;padding:8px 0"><button onclick="customConfirm(\'Clear all channel stats? This cannot be undone.\',\'Clear all\').then(ok=>{if(ok){_chanStats={};_chanStatsDirty=true;saveStatsToServer();renderStatsChannelList();}})" style="background:none;border:1px solid var(--border);color:var(--text3);padding:6px 16px;border-radius:6px;cursor:pointer;font-family:var(--mono);font-size:11px">Clear All Stats</button></div>';
  body.innerHTML=html;
}
function renderStatsDetail(key){
  _bindStatsDelegation();   // idempotent; ensures back/clear delegation is bound
  document.getElementById('chanstats-title').innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> Channel Stats';
  const body=document.getElementById('chanstats-body');
  const nicks=_chanStats[key]||{};
  const sorted=Object.entries(nicks).sort((a,b)=>b[1]-a[1]);
  const max=sorted[0]?sorted[0][1]:1;
  const total=sorted.reduce((a,b)=>a+b[1],0);
  const parts=key.split('/');
  const chanName=parts.slice(1).join('/');
  let html='<button class="cst-back" onclick="renderStatsChannelList()">&larr; Back</button>';
  html+=`<div class="cst-detail-header"><div class="cst-detail-title">${esc(chanName)}</div><div class="cst-detail-total">${sorted.length} nicks &middot; ${total.toLocaleString()} msgs</div></div>`;
  if(!sorted.length){
    html+='<div class="cst-empty">No messages tracked for this channel.</div>';
    body.innerHTML=html;return;
  }
  // Top talkers with bar chart
  const show=sorted.slice(0,50);
  for(let i=0;i<show.length;i++){
    const[nick,count]=show[i];
    const pct=Math.max(Math.round(count/max*100),1);
    html+=`<div class="cst-bar-wrap">`;
    html+=`<span class="cst-rank">${i+1}</span>`;
    html+=`<span class="cst-bar-nick nc${nickHash(nick)}">${esc(nick)}</span>`;
    html+=`<div style="flex:1"><div class="cst-bar" style="width:${pct}%"></div></div>`;
    html+=`<span class="cst-bar-count">${count.toLocaleString()}</span>`;
    html+=`</div>`;
  }
  if(sorted.length>50) html+=`<div style="font-size:11px;color:var(--text3);text-align:center;padding:8px">...and ${sorted.length-50} more nicks</div>`;
  // Clear channel button — carries the stats key in a data attribute; the delegated
  // chanstats-body listener confirms and clears (no user data in a JS-string, #10).
  html+=`<div style="text-align:center;padding:12px 0"><button data-stats-clear="${esc(key)}" style="background:none;border:1px solid var(--border);color:var(--text3);padding:6px 16px;border-radius:6px;cursor:pointer;font-family:var(--mono);font-size:11px">Clear Channel Stats</button></div>`;
  body.innerHTML=html;
}
// SECURITY: delegated listener for stats rows / clear-channel button. Reads the
// channel stats key from data-* (HTML-attribute escaped) instead of an inline
// onclick JS-string (#10). Bound lazily on first render (the #chanstats-body element
// lives below this script tag). Idempotent via _statsDelegated.
function _bindStatsDelegation(){
  const body=document.getElementById('chanstats-body');
  if(!body||body._statsDelegated)return;
  body._statsDelegated=true;
  body.addEventListener('click',e=>{
    const row=e.target.closest('[data-stats-key]');
    if(row&&body.contains(row)){renderStatsDetail(row.dataset.statsKey);return;}
    const clr=e.target.closest('[data-stats-clear]');
    if(clr&&body.contains(clr)){
      const key=clr.dataset.statsClear;
      const chanName=key.split('/').slice(1).join('/');
      customConfirm('Clear stats for '+chanName+'?','Clear').then(ok=>{
        if(ok){delete _chanStats[key];_chanStatsDirty=true;saveStatsToServer();renderStatsChannelList();}
      });
    }
  });
}

// ─── Split view ──────────────────────────────────────────────────────────────
let _splitActive=false,_splitTarget=null;
function toggleSplitView(){
  _splitActive=!_splitActive;
  const main=document.getElementById('main');
  if(_splitActive){
    main.classList.add('split-active');
    updateSplitPanel();
    if(active)sysMsg(active.conn_id,active.target,'Split view enabled — use the dropdown in the right panel','system');
  } else {
    main.classList.remove('split-active');
    if(active)sysMsg(active.conn_id,active.target,'Split view disabled','system');
  }
}
function updateSplitPanel(){
  const sel=document.getElementById('split-chan-select');if(!sel)return;
  sel.innerHTML='';
  for(const net of (typeof networks!=='undefined'?networks:[])){
    for(const ch of (net.channels||[])){
      const opt=document.createElement('option');opt.value=net.config.id+'/'+ch.name;opt.textContent=ch.name;
      if(_splitTarget===opt.value)opt.selected=true;
      sel.appendChild(opt);
    }
  }
  renderSplitChat();
}
function renderSplitChat(){
  const area=document.getElementById('split-chat-area');if(!area)return;area.innerHTML='';
  if(!_splitTarget){area.innerHTML='<div style="padding:20px;color:var(--text3);font-size:12px">Select a channel above</div>';return;}
  const[cid,tgt]=_splitTarget.split('/');if(!cid||!tgt)return;
  const buf=getBuf(cid,tgt);
  for(const msg of buf.slice(-100)){const r=buildRow(msg);area.appendChild(r);}
  area.scrollTop=area.scrollHeight;
}

// ─── Smart paste ─────────────────────────────────────────────────────────────
let _smartPasteText='';
function smartPasteYes(){
  document.getElementById('smart-paste-dialog').classList.remove('show');
  if(!_smartPasteText||!active)return;
  // Create paste via API
  const token=sessionToken;
  fetch(`${location.pathname}paste`,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${token}`},
    body:JSON.stringify({content:_smartPasteText,language:'text',expires_in:0,password:null})
  }).then(r=>r.json()).then(d=>{
    if(d.url){document.getElementById('msg-input').value=d.url;showToast('Paste created — URL in input bar');}
  }).catch(()=>{document.getElementById('msg-input').value=_smartPasteText;});
  _smartPasteText='';
}
function smartPasteNo(){
  document.getElementById('smart-paste-dialog').classList.remove('show');
  document.getElementById('msg-input').value+=_smartPasteText;
  _smartPasteText='';
}

// ─── KeepNick — irssi keepnick.pl clone ──────────────────────────────────────
// Storage: { conn_id: { nick, active } }
const _keepnickTimers={},_keepnickIsonPending={};
function loadKeepNicks(){try{return JSON.parse(localStorage.getItem('cryptirc_keepnicks')||'{}');}catch{return{};}}
function saveKeepNicks(kn){localStorage.setItem('cryptirc_keepnicks',JSON.stringify(kn));savePrefsToServer();}
function keepnickSet(conn_id,nick){
  const kn=loadKeepNicks();
  kn[conn_id]={nick:nick,active:true};
  saveKeepNicks(kn);
  keepnickStartPoll(conn_id);
}
function keepnickRemove(conn_id){
  const kn=loadKeepNicks();
  delete kn[conn_id];
  saveKeepNicks(kn);
  keepnickStopPoll(conn_id);
}
function keepnickDeactivate(conn_id){
  const kn=loadKeepNicks();
  if(kn[conn_id]){kn[conn_id].active=false;saveKeepNicks(kn);}
  keepnickStopPoll(conn_id);
}
function keepnickReactivate(conn_id){
  const kn=loadKeepNicks();
  if(kn[conn_id]){kn[conn_id].active=true;saveKeepNicks(kn);keepnickStartPoll(conn_id);}
}
function keepnickStartPoll(conn_id){
  keepnickStopPoll(conn_id);
  const kn=loadKeepNicks();
  if(!kn[conn_id]||!kn[conn_id].active)return;
  // Don't poll if we already have the nick
  const cur=getNick(conn_id);
  if(cur&&cur.toLowerCase()===kn[conn_id].nick.toLowerCase())return;
  _keepnickTimers[conn_id]=setInterval(()=>{
    const kn2=loadKeepNicks();
    if(!kn2[conn_id]||!kn2[conn_id].active){keepnickStopPoll(conn_id);return;}
    const cur2=getNick(conn_id);
    if(cur2&&cur2.toLowerCase()===kn2[conn_id].nick.toLowerCase()){keepnickStopPoll(conn_id);return;}
    // Send ISON query and mark pending
    _keepnickIsonPending[conn_id]=Date.now();
    wsend({type:'send',conn_id,raw:'ISON '+kn2[conn_id].nick});
  },12000);
}
function keepnickStopPoll(conn_id){
  if(_keepnickTimers[conn_id]){clearInterval(_keepnickTimers[conn_id]);delete _keepnickTimers[conn_id];}
}
// Called when we detect the kept nick is available — grab it
function keepnickGrab(conn_id){
  const kn=loadKeepNicks();
  if(!kn[conn_id]||!kn[conn_id].active)return;
  wsend({type:'send',conn_id,raw:'NICK '+kn[conn_id].nick});
}
// Called on irc_nick when OUR nick changes — check if we got it back or lost it
function keepnickOnOwnNickChange(conn_id,oldNick,newNick){
  const kn=loadKeepNicks();
  if(!kn[conn_id])return;
  const desired=kn[conn_id].nick.toLowerCase();
  if(newNick.toLowerCase()===desired){
    // Got the nick back — stop polling
    keepnickStopPoll(conn_id);
    sysMsg(conn_id,'status',`✓ KeepNick: Got ${newNick} back`,'system');
  } else if(oldNick.toLowerCase()===desired){
    // Lost the nick — reactivate polling
    keepnickReactivate(conn_id);
  }
}
// Called on irc_quit — check if the quitter had our desired nick
function keepnickOnQuit(conn_id,nick){
  const kn=loadKeepNicks();
  if(!kn[conn_id]||!kn[conn_id].active)return;
  if(nick.toLowerCase()===kn[conn_id].nick.toLowerCase()){
    sysMsg(conn_id,'status',`KeepNick: ${nick} quit — reclaiming nick...`,'system');
    setTimeout(()=>keepnickGrab(conn_id),500);
  }
}
// Called on irc_nick — check if someone changed FROM our desired nick
function keepnickOnNickChange(conn_id,oldNick,newNick){
  const kn=loadKeepNicks();
  if(!kn[conn_id]||!kn[conn_id].active)return;
  if(oldNick.toLowerCase()===kn[conn_id].nick.toLowerCase()){
    sysMsg(conn_id,'status',`KeepNick: ${oldNick} changed nick — reclaiming...`,'system');
    setTimeout(()=>keepnickGrab(conn_id),500);
  }
}
// Handle ISON (303) reply — intercept before it renders
function keepnickHandleIson(conn_id,text){
  const kn=loadKeepNicks();
  if(!kn[conn_id]||!kn[conn_id].active)return false;
  const desired=kn[conn_id].nick.toLowerCase();
  // ISON reply is "nick1 nick2 ..." — if our nick is NOT in the list, it's free
  const onlineNicks=text.trim().split(/\s+/).map(n=>n.toLowerCase());
  if(!onlineNicks.includes(desired)||text.trim()===''){
    keepnickGrab(conn_id);
  }
  return true; // consumed — don't show in status
}
// Start polls for all active keepnicks on page load / reconnect
function keepnickInitAll(){
  const kn=loadKeepNicks();
  for(const cid of Object.keys(kn)){
    if(kn[cid].active)keepnickStartPoll(cid);
  }
}

// ─── Server-side preferences sync ─────────────────────────────────────────────
let _prefsSaveTimer=null;
function gatherPreferences(){
  return {
    favorites: loadFavorites(),
    _favsTs: parseInt(localStorage.getItem('cryptirc_favs_ts')||'0'),
    muted: loadMuted(),
    monitor: loadMonitor(),
    monitorNotifs: localStorage.getItem('cryptirc_monitor_notifs')||'on',
    monitorPush: localStorage.getItem('cryptirc_monitor_push')||'on',
    unread: (()=>{const o={};for(const[k,v] of unread)o[k]=v;return o;})(),
    mentions: mentionsList.slice(0,100),
    _mentionsTs: parseInt(localStorage.getItem('cryptirc_mentions_ts')||'0'),
    inputHistory: inputHistory.slice(-100),
    queries: (()=>{const o={};for(const[c,m] of Object.entries(queryBufs))o[c]=[...m.entries()];return o;})(),
    _queriesTs: parseInt(localStorage.getItem('cryptirc_queries_ts')||'0'),
    closedQueries: {...closedQueries},
    _closedQueriesTs: parseInt(localStorage.getItem('cryptirc_closed_queries_ts')||'0'),
    lastActive: (()=>{try{return JSON.parse(localStorage.getItem('cryptirc_active'));}catch{return null;}})(),
    stats: {tx:_txBytes,rx:_rxBytes,tc:_txCount,rc:_rxCount},
    ignoreList: (()=>{try{return JSON.parse(localStorage.getItem('cryptirc_ignore')||'[]');}catch{return[];}})(),
    pmAllow: [...pmAllowList],
    _pmAllowTs: parseInt(localStorage.getItem('cryptirc_pm_allow_ts')||'0'),
    pmBlock: localStorage.getItem('cryptirc_block_pms')==='true',
    pmCooldown: parseInt(localStorage.getItem('cryptirc_pm_cooldown')||'24'),
    pmNotify: localStorage.getItem('cryptirc_pm_notify')!=='false',
    pmDeliverFirst: localStorage.getItem('cryptirc_pm_deliver_first')!=='false',
    pmNet: loadPmNet(),
    _pmNetTs: parseInt(localStorage.getItem('cryptirc_pm_net_ts')||'0'),
    pmBlocked: loadPmBlocked(),
    highlightWords: (()=>{try{return JSON.parse(localStorage.getItem('cryptirc_highlight_words')||'[]');}catch{return[];}})(),
    favsOnly: localStorage.getItem('cryptirc_favs_only')==='true',
    _favsOnlyTs: parseInt(localStorage.getItem('cryptirc_favs_only_ts')||'0'),
    sidebarCollapsed: localStorage.getItem('cryptirc_sidebar_collapsed')==='1',
    nickCollapsed: localStorage.getItem('cryptirc_nick_collapsed')==='1',
    userNotes: loadUserNotes(),
    channelKeys: loadChanKeys(),
    autoRejoin: localStorage.getItem('cryptirc_autorejoin')!=='false',
    dnd: localStorage.getItem('cryptirc_dnd')==='1',
    dndStart: localStorage.getItem('cryptirc_dnd_start')||'',
    dndEnd: localStorage.getItem('cryptirc_dnd_end')||'',
    keepnicks: loadKeepNicks(),
    networkOrder: (()=>{try{return JSON.parse(localStorage.getItem('cryptirc_net_order')||'[]');}catch{return[];}})(),
    // Giphy: per-user API key + content rating, synced across devices via
    // the user's encrypted prefs blob so they only have to set it once.
    giphyKey: localStorage.getItem('cryptirc_giphy_key')||'',
    giphyRating: localStorage.getItem('cryptirc_giphy_rating')||'',
  };
}
function savePrefsToServer(){
  clearTimeout(_prefsSaveTimer);
  _prefsSaveTimer=setTimeout(flushPrefsToServer,2000);
}
let _lastFlushTs=0;
function flushPrefsToServer(){
  clearTimeout(_prefsSaveTimer);
  try{
    _lastFlushTs=Date.now();
    const gathered=gatherPreferences();
    gathered._saveTs=_lastFlushTs;
    wsend({type:'save_preferences',prefs:JSON.stringify(gathered)});
  }catch(e){}
}
// Flush preferences immediately before page unload to prevent data loss
window.addEventListener('beforeunload',flushPrefsToServer);
function restorePreferences(p){
  if(!p)return;
  // Skip if this is our own echo — the server broadcasts saved prefs back to
  // all sessions including the sender. Without this check, the echo overwrites
  // local state that the user may have changed since the save was debounced.
  if(p._saveTs&&p._saveTs===_lastFlushTs)return;
  try{
    if(p.favorites){
      // Use timestamps to resolve conflict — local wins if modified more recently than last server sync
      const localTs=parseInt(localStorage.getItem('cryptirc_favs_ts')||'0');
      const serverTs=p._favsTs||0;
      if(localTs>serverTs){
        // Local is newer — keep local, don't overwrite with stale server data
      } else {
        localStorage.setItem('cryptirc_favs',JSON.stringify(p.favorites));
      }
    }
    if(p.muted){
      const localMuted=loadMuted();
      const merged={...p.muted,...localMuted};
      localStorage.setItem('cryptirc_muted',JSON.stringify(merged));
    }
    if(p.monitor) localStorage.setItem('cryptirc_monitor',JSON.stringify(p.monitor));
    if(p.monitorNotifs) localStorage.setItem('cryptirc_monitor_notifs',p.monitorNotifs);
    if(p.monitorPush) localStorage.setItem('cryptirc_monitor_push',p.monitorPush);
    if(p.unread){
      // Merge server unread — but NEVER resurrect counts for channels the user has already read locally
      // Check: if we have a lastRead timestamp locally that's newer than the server sync, skip that channel
      for(const[k,v] of Object.entries(p.unread)){
        const lastReadKey='cryptirc_lastread_'+k;
        const localLastRead=parseFloat(localStorage.getItem(lastReadKey)||'0');
        const local=unread.get(k)||0;
        // Only accept server's count if local has no read marker AND server count is higher
        if(localLastRead===0&&+v>local) unread.set(k,+v);
      }
    }
    if(p.mentions){
      // Timestamp-guard like queries/favs: a read/clear on another device (the most
      // recent write) must win so it doesn't resurrect here as still-unread. Only
      // accept the server's list when our local copy isn't newer.
      const localTs=parseInt(localStorage.getItem('cryptirc_mentions_ts')||'0');
      const serverTs=p._mentionsTs||0;
      if(localTs<=serverTs){
        mentionsList=p.mentions;
        try{localStorage.setItem('cryptirc_mentions',JSON.stringify(mentionsList.slice(-100)));localStorage.setItem('cryptirc_mentions_ts',String(serverTs));}catch(e){}
        if(document.getElementById('mentions-panel')?.classList.contains('show')) renderMentionsList();
      }
    }
    if(p.inputHistory) inputHistory=p.inputHistory;
    if(p.queries){
      const localTs=parseInt(localStorage.getItem('cryptirc_queries_ts')||'0');
      const serverTs=p._queriesTs||0;
      if(localTs<=serverTs){for(const[c,entries] of Object.entries(p.queries))queryBufs[c]=new Map(entries);}
    }
    if(p.closedQueries){
      const localTs=parseInt(localStorage.getItem('cryptirc_closed_queries_ts')||'0');
      const serverTs=p._closedQueriesTs||0;
      if(localTs<=serverTs){
        closedQueries=p.closedQueries||{};
        try{localStorage.setItem('cryptirc_closed_queries',JSON.stringify(closedQueries));localStorage.setItem('cryptirc_closed_queries_ts',String(serverTs));}catch(e){}
        // a closed query must not also linger as open in the sidebar
        let _deduped=false;
        for(const k of Object.keys(closedQueries)){
          const i=k.indexOf('|'); if(i<0) continue;
          const c=k.slice(0,i), lc=k.slice(i+1);
          if(queryBufs[c] && queryBufs[c].delete(lc)) _deduped=true;
        }
        // persist the deduped open-query list so a hard reload before the next WS sync
        // doesn't resurrect the closed PM from stale localStorage
        if(_deduped) saveQueryBufs();
      }
    }
    if(p.lastActive) localStorage.setItem('cryptirc_active',JSON.stringify(p.lastActive));
    if(p.stats){_txBytes=p.stats.tx||0;_rxBytes=p.stats.rx||0;_txCount=p.stats.tc||0;_rxCount=p.stats.rc||0;}
    if(p.ignoreList) localStorage.setItem('cryptirc_ignore',JSON.stringify(p.ignoreList));
    if(Array.isArray(p.pmAllow)){
      const localTs=parseInt(localStorage.getItem('cryptirc_pm_allow_ts')||'0');
      const serverTs=p._pmAllowTs||0;
      if(localTs<=serverTs){pmAllowList=new Set(p.pmAllow.map(s=>String(s).toLowerCase()));localStorage.setItem('cryptirc_pm_allow',JSON.stringify([...pmAllowList]));}
    }
    if(p.pmBlock!=null) localStorage.setItem('cryptirc_block_pms',p.pmBlock?'true':'false');
    if(p.pmCooldown!=null) localStorage.setItem('cryptirc_pm_cooldown',String(p.pmCooldown));
    if(p.pmNotify!=null) localStorage.setItem('cryptirc_pm_notify',p.pmNotify?'true':'false');
    if(p.pmDeliverFirst!=null) localStorage.setItem('cryptirc_pm_deliver_first',p.pmDeliverFirst?'true':'false');
    if(p.pmNet&&typeof p.pmNet==='object'){
      const localTs=parseInt(localStorage.getItem('cryptirc_pm_net_ts')||'0');
      const serverTs=p._pmNetTs||0;
      if(localTs<=serverTs) localStorage.setItem('cryptirc_pm_net',JSON.stringify(p.pmNet));
    }
    if(Array.isArray(p.pmBlocked)) localStorage.setItem('cryptirc_pm_blocked',JSON.stringify(p.pmBlocked.slice(-PM_BLOCKED_MAX)));
    if(p.highlightWords) localStorage.setItem('cryptirc_highlight_words',JSON.stringify(p.highlightWords));
    if(p.userNotes) localStorage.setItem('cryptirc_user_notes',JSON.stringify(p.userNotes));
    if(p.channelKeys) localStorage.setItem('cryptirc_chankeys',JSON.stringify(p.channelKeys));
    if(p.dnd!=null){if(p.dnd)localStorage.setItem('cryptirc_dnd','1');else localStorage.removeItem('cryptirc_dnd');}
    if(p.dndStart) localStorage.setItem('cryptirc_dnd_start',p.dndStart);
    if(p.dndEnd) localStorage.setItem('cryptirc_dnd_end',p.dndEnd);
    if(p.keepnicks) localStorage.setItem('cryptirc_keepnicks',JSON.stringify(p.keepnicks));
    if(p.networkOrder) localStorage.setItem('cryptirc_net_order',JSON.stringify(p.networkOrder));
    if(p.favsOnly!=null){
      const localTs=parseInt(localStorage.getItem('cryptirc_favs_only_ts')||'0');
      const serverTs=p._favsOnlyTs||0;
      if(localTs<=serverTs) localStorage.setItem('cryptirc_favs_only',p.favsOnly?'true':'false');
    }
    if(p.sidebarCollapsed!=null) localStorage.setItem('cryptirc_sidebar_collapsed',p.sidebarCollapsed?'1':'');
    if(p.nickCollapsed!=null) localStorage.setItem('cryptirc_nick_collapsed',p.nickCollapsed?'1':'');
    // Giphy prefs: seed localStorage from the encrypted server prefs when the
    // user logs in on a fresh device. Empty string = cleared; distinguish from
    // "not present" (undefined) so we don't wipe a locally-set key if the user
    // happens to be running an older server payload.
    if(p.giphyKey!==undefined){
      if(p.giphyKey) localStorage.setItem('cryptirc_giphy_key',p.giphyKey);
      else localStorage.removeItem('cryptirc_giphy_key');
    }
    if(p.giphyRating){
      localStorage.setItem('cryptirc_giphy_rating',p.giphyRating);
    }
    // Re-apply UI state
    renderSidebar(); updateMentionsBadge(); applyFavsOnly();
    // Apply panel collapse states
    if(window.innerWidth>768){
      const sb=document.getElementById('sidebar');
      const np=document.getElementById('nick-panel');
      const sbBtn=document.getElementById('sidebar-toggle-btn');
      const nkIcon=document.querySelector('#nick-toggle .toggle-icon');
      const sIcon=document.getElementById('sidebar-toggle-icon');
      if(p.sidebarCollapsed){sb?.classList.add('collapsed');if(sIcon)sIcon.style.transform='rotate(180deg)';}
      else{sb?.classList.remove('collapsed');if(sIcon)sIcon.style.transform='';}
      const niIcon=document.getElementById('nick-toggle-icon');
      if(p.nickCollapsed){np?.classList.add('collapsed');if(niIcon)niIcon.style.transform='rotate(180deg)';}
      else{np?.classList.remove('collapsed');if(niIcon)niIcon.style.transform='';}
    }
  }catch(e){console.error('Restore prefs failed:',e);}
}

// ─── Favorites ────────────────────────────────────────────────────────────────
function loadFavorites(){try{return JSON.parse(localStorage.getItem('cryptirc_favs')||'[]');}catch{return[];}}
function saveFavorites(favs){try{localStorage.setItem('cryptirc_favs',JSON.stringify(favs));localStorage.setItem('cryptirc_favs_ts',String(Date.now()));}catch(e){} flushPrefsToServer();}
function toggleFavorite(conn_id,target){
  let favs=loadFavorites();
  const key=`${conn_id}/${target}`;
  const idx=favs.findIndex(f=>f.key===key);
  if(idx>=0)favs.splice(idx,1);
  else favs.push({key,conn_id,target,label:target});
  saveFavorites(favs);
  renderSidebar();
}
function isFavorite(conn_id,target){return loadFavorites().some(f=>f.key===`${conn_id}/${target}`);}
function closeAllPMs(conn_id){
  if(!queryBufs[conn_id])return;
  for(const [lc] of queryBufs[conn_id]){
    delete buffers[bk(conn_id,lc)];
    unread.delete(bk(conn_id,lc));
  }
  queryBufs[conn_id]=new Map();
  if(active&&active.conn_id===conn_id&&!active.target.startsWith('#')&&active.target!=='status') setActive(conn_id,'status');
  renderSidebar();
}
function closeQuery(conn_id,lc){
  lc=String(lc).toLowerCase();
  if(queryBufs[conn_id])queryBufs[conn_id].delete(lc);
  // Keep buffer so history reloads when reopened, just clear unread
  unread.delete(bk(conn_id,lc));
  mentionUnread.delete(bk(conn_id,lc));
  markQueryClosed(conn_id,lc);          // remember it's closed so replays don't reopen it
  saveQueryBufs();
  if(active&&active.conn_id===conn_id&&active.target.toLowerCase()===lc)setActive(conn_id,'status');
  renderSidebar();
}
// ─── SortableJS drag-and-drop (channels + networks) ─────────────────────────
// Replaces custom HTML5 drag + touch handlers with SortableJS (same library The Lounge uses)
let _sortableNetworks=null,_sortableChannels=[];
let _dragStartPos=null;
const LONG_TOUCH_MS=500;
function _isTouchEvt(e){const o=e.originalEvent||e;return !!((o.touches&&o.touches[0])||(o.pointerType&&o.pointerType==='touch'));}
function _distPts(a,b){return Math.hypot(a[0]-b[0],a[1]-b[1]);}
function initSortable(){
  destroySortable();
  const netList=document.getElementById('network-list');
  if(!netList||typeof Sortable==='undefined')return;
  // Network-level sortable: net-label is the drag handle (like Lounge's lobby)
  _sortableNetworks=Sortable.create(netList,{
    animation:150,
    handle:'.net-label',
    draggable:'.net-group',
    ghostClass:'ui-sortable-ghost',
    dragClass:'ui-sortable-dragging',
    group:'networks',
    delay:LONG_TOUCH_MS,
    delayOnTouchOnly:true,
    touchStartThreshold:10,
    onChoose(evt){if(_isTouchEvt(evt)){evt.item.classList.add('ui-sortable-touch-cue');const o=evt.originalEvent||evt;if(o.touches&&o.touches[0])_dragStartPos=[o.touches[0].clientX,o.touches[0].clientY];else if(o.clientX!=null)_dragStartPos=[o.clientX,o.clientY];}},
    onUnchoose(evt){evt.item.classList.remove('ui-sortable-touch-cue');_dragStartPos=null;},
    onStart(){_sidebarDragLock=true;},
    onEnd(evt){
      _sidebarDragLock=false;evt.item.classList.remove('ui-sortable-touch-cue');_dragStartPos=null;
      const groups=[...netList.querySelectorAll('.net-group')];
      const order=groups.map(g=>g.dataset.netId);
      localStorage.setItem('cryptirc_net_order',JSON.stringify(order));
      const netMap=Object.create(null);for(const n of networks)netMap[n.config.id]=n;
      networks.length=0;for(const id of order){if(netMap[id])networks.push(netMap[id]);}
      for(const n of Object.values(netMap)){if(!order.includes(n.config.id))networks.push(n);}
      flushPrefsToServer();
    },
  });
  // Channel-level sortables: one per network's .chan-list (like Lounge's per-network group)
  netList.querySelectorAll('.chan-list').forEach(cl=>{
    const connId=cl.dataset.connId;if(!connId)return;
    const s=Sortable.create(cl,{
      animation:150,
      draggable:'.chan-item',
      ghostClass:'ui-sortable-ghost',
      dragClass:'ui-sortable-dragging',
      group:connId,
      delay:LONG_TOUCH_MS,
      delayOnTouchOnly:true,
      touchStartThreshold:10,
      onChoose(evt){if(_isTouchEvt(evt)){evt.item.classList.add('ui-sortable-touch-cue');const o=evt.originalEvent||evt;if(o.touches&&o.touches[0])_dragStartPos=[o.touches[0].clientX,o.touches[0].clientY];else if(o.clientX!=null)_dragStartPos=[o.clientX,o.clientY];}},
      onUnchoose(evt){evt.item.classList.remove('ui-sortable-touch-cue');_dragStartPos=null;},
      onStart(){_sidebarDragLock=true;},
      onEnd(evt){
        _sidebarDragLock=false;evt.item.classList.remove('ui-sortable-touch-cue');_dragStartPos=null;
        const items=[...cl.querySelectorAll('.chan-item')];
        const order=items.map(el=>el.dataset.target);
        wsend({type:'save_channel_order',conn_id:connId,order});
        const net=networks.find(n=>n.config.id===connId);
        if(net)net.config.channel_order=order;
        flushPrefsToServer();
      },
    });
    _sortableChannels.push(s);
  });
  // Lounge-style touch handlers: force-no-select on touchstart, context menu cancel on touchmove.
  // Defensive cleanups on pointerup/mouseup/blur too — Electron doesn't fire touchend on
  // mouse-based drags, which previously could leave force-no-select stuck on <body>.
  netList.addEventListener('touchstart',e=>{if(e.touches.length===1)document.body.classList.add('force-no-select');},{passive:true});
  netList.addEventListener('touchmove',e=>{if(_dragStartPos&&e.touches.length>0){const t=e.touches[0];if(_distPts(_dragStartPos,[t.clientX,t.clientY])>10){/* cancel context menu */}}},{passive:true});
  netList.addEventListener('touchend',e=>{if(e.touches.length===0)document.body.classList.remove('force-no-select');},{passive:true});
  netList.addEventListener('touchcancel',()=>{document.body.classList.remove('force-no-select');},{passive:true});
}
// Dead-man switch: if force-no-select is somehow stuck on <body>, clear it the
// moment any pointer-up or blur happens. Registered once — repeated initSortable
// calls don't re-register because _forceNoSelectGuardInstalled is idempotent.
if(!window._forceNoSelectGuardInstalled){
  window._forceNoSelectGuardInstalled=true;
  const _clearFns=()=>{document.body.classList.remove('force-no-select');};
  document.addEventListener('pointerup',_clearFns,{passive:true});
  document.addEventListener('mouseup',_clearFns,{passive:true});
  window.addEventListener('blur',_clearFns,{passive:true});
}
function destroySortable(){
  if(_sortableNetworks){_sortableNetworks.destroy();_sortableNetworks=null;}
  _sortableChannels.forEach(s=>s.destroy());_sortableChannels=[];
}
// Re-init sortable after every sidebar render
const _origRenderSidebarForSort=window._renderSidebarNow;
window._renderSidebarNow=function(){
  // Apply network order before render
  const netOrder=(()=>{try{return JSON.parse(localStorage.getItem('cryptirc_net_order')||'[]');}catch{return[];}})();
  if(netOrder.length){networks.sort((a,b)=>{const ai=netOrder.indexOf(a.config.id),bi=netOrder.indexOf(b.config.id);if(ai===-1&&bi===-1)return 0;if(ai===-1)return 1;if(bi===-1)return -1;return ai-bi;});}
  _origRenderSidebarForSort();
  // Init sortable on the fresh DOM
  requestAnimationFrame(initSortable);
};

// Legacy compat — remove old custom drag code below
void((function(){/* old custom drag-and-drop removed — replaced by SortableJS */})());
void((function(){/* old network drag-and-drop removed — replaced by SortableJS */})());

let _sortableFavorites=null;
function renderFavorites(){
  const el=document.getElementById('favorites-list');
  let favs=loadFavorites();
  // Destroy old sortable before rebuilding DOM
  if(_sortableFavorites){_sortableFavorites.destroy();_sortableFavorites=null;}
  el.innerHTML='';
  if(!favs.length)return;
  const hdr=document.createElement('div');hdr.className='fav-header';hdr.textContent='Favorites';
  el.appendChild(hdr);
  for(const f of favs){
    const k=bk(f.conn_id,f.target),isA=isActive(f.conn_id,f.target),uc=unread.get(k)||0;
    const net=networks.find(n=>n.config.id===f.conn_id);
    const ci=document.createElement('div');
    ci.className=`chan-item fav-item${isA?' active':''}`;
    ci.dataset.favKey=f.key;
    ci.dataset.connId=f.conn_id;
    ci.dataset.target=f.target;
    const netLabel=net?esc(net.config.label||net.config.server):'?';
    const fmc=mentionUnread.get(k)||0;
    const isChan=f.target.startsWith('#')||f.target.startsWith('&')||f.target.startsWith('+')||f.target.startsWith('!');
    ci.dataset.isChannel=isChan?'1':'0';
    const muteKey=f.conn_id+'/'+f.target;
    const muted=isMuted(muteKey);
    const fDet=isDetached(f.conn_id,f.target)?'<span class="chan-detached" title="Popped out" style="color:var(--accent);font-size:11px;margin-right:4px;opacity:.85">⧉</span>':'';
    ci.innerHTML=`<span style="color:var(--warn);font-size:10px;margin-right:2px">★</span>${esc(f.target)}<span style="font-size:9px;color:var(--text3);margin-left:4px">${netLabel}</span><span class="chan-right">${fDet}${uc?`<span class="chan-unread-badge${fmc?' highlight':''}">${uc>99?'99+':uc}</span>`:''}${muted?'<span style="font-size:10px;opacity:.4">🔇</span>':''}<span class="chan-kebab">⋮</span></span>`;
    ci.style.position='relative';
    ((connId,target,isChannel)=>{
      ci.querySelector('.chan-kebab').addEventListener('click',e=>{e.stopPropagation();toggleFavMenu(e.currentTarget,connId,target,isChannel);});
    })(f.conn_id,f.target,isChan);
    ci.onclick=()=>_sidebarActivate(f.conn_id,f.target);
    el.appendChild(ci);
  }
  // Init SortableJS for favorite reordering
  if(typeof Sortable!=='undefined'&&favs.length>1){
    _sortableFavorites=Sortable.create(el,{
      animation:150,
      draggable:'.fav-item',
      ghostClass:'ui-sortable-ghost',
      dragClass:'ui-sortable-dragging',
      delay:LONG_TOUCH_MS,
      delayOnTouchOnly:true,
      touchStartThreshold:10,
      onStart(){_sidebarDragLock=true;},
      onEnd(evt){
        _sidebarDragLock=false;
        const items=[...el.querySelectorAll('.fav-item')];
        const newOrder=items.map(i=>i.dataset.favKey);
        const favMap=Object.create(null);for(const f of loadFavorites())favMap[f.key]=f;
        const reordered=newOrder.filter(k=>favMap[k]).map(k=>favMap[k]);
        // Add any favorites not in the DOM (shouldn't happen, but safety)
        for(const f of Object.values(favMap)){if(!newOrder.includes(f.key))reordered.push(f);}
        saveFavorites(reordered);
      },
    });
  }
}
function _favMenuItems(connId,target,isChannel){
  const muteKey=connId+'/'+target;
  const muted=isMuted(muteKey);
  const items=[
    {text:'★ Unfavorite',action:()=>toggleFavorite(connId,target)},
    {text:muted?'🔔 Unmute':'🔇 Mute',action:()=>toggleMute(muteKey)},
    {text:'🗑 Clear History',action:()=>clearBufHistory(connId,target)},
  ];
  if(_canPopOut()){
    const det=isDetached(connId,target);
    items.push({text: det?'⧉ Reattach':'⧉ Pop Out', action: ()=> det?reattachView(connId,target):detachView(connId,target)});
  }
  if(!isChannel){
    const pmAllowed=isPmAllowedFor(connId,target);
    items.push({
      text: pmAllowed?'🛡 Remove PM allow':'🛡 Allow PMs',
      action: ()=>{
        if(pmAllowed){removePmAllow(target,connId); showToast(`${target} removed from PM allow list`);}
        else {addPmAllow(target,connId); showToast(`PMs from ${target} will now bypass protection`);}
      },
    });
  }
  if(isChannel){
    items.push({text:'⚙ Channel Modes',action:()=>openChanModes(connId,target)});
    items.push({text:'Leave',action:()=>wsend({type:'part_channel',conn_id:connId,channel:target}),style:'color:#f87171'});
  } else {
    items.push({text:'Close',action:()=>{toggleFavorite(connId,target);closeQuery(connId,target.toLowerCase());},style:'color:#f87171'});
  }
  return items;
}
function toggleFavMenu(btn,connId,target,isChannel){toggleFloatDd(btn,_favMenuItems(connId,target,isChannel));}

function renderPMList(){
  const el=document.getElementById('pm-list');
  if(!el)return;
  el.innerHTML='';
  // Only show when favorites-only mode is active
  if(localStorage.getItem('cryptirc_favs_only')!=='true')return;
  const pms=[];
  for(const net of networks){
    const id=net.config.id;
    if(!queryBufs[id])continue;
    for(const [lc,display] of queryBufs[id]){
      if(isFavorite(id,lc))continue; // already in favorites section
      pms.push({conn_id:id,lc,display,net});
    }
  }
  if(!pms.length)return;
  const hdr=document.createElement('div');hdr.className='fav-header';hdr.textContent='Private Messages';
  el.appendChild(hdr);
  for(const pm of pms){
    const k=bk(pm.conn_id,pm.lc),isA=isActive(pm.conn_id,pm.lc)||isActive(pm.conn_id,pm.display),uc=unread.get(k)||0;
    const muted=isMuted(pm.conn_id+'/'+pm.lc)||isMuted('net:'+pm.conn_id);
    const ci=document.createElement('div');
    ci.className=`chan-item${isA?' active':''}`;
    ci.dataset.target=pm.lc;
    ci.dataset.connId=pm.conn_id;
    ci.style.fontStyle='italic';
    ci.style.position='relative';
    const netLabel=esc(pm.net.config.label||pm.net.config.server);
    const pmDet=isDetached(pm.conn_id,pm.display)?'<span class="chan-detached" title="Popped out" style="color:var(--accent);font-size:11px;margin-right:4px;opacity:.85">⧉</span>':'';
    ci.innerHTML=`${esc(pm.display)}<span style="font-size:9px;color:var(--text3);margin-left:4px">${netLabel}</span><span class="chan-right">${pmDet}${uc&&!muted?`<span class="chan-unread-badge highlight">${uc>99?'99+':uc}</span>`:''}${muted?'<span style="font-size:10px;opacity:.4">🔇</span>':''}<span class="chan-kebab">⋮</span></span>`;
    ((cid,lc2)=>{ci.querySelector('.chan-kebab').addEventListener('click',e=>{e.stopPropagation();toggleChanMenu(e.currentTarget,cid,lc2,'pm');});})(pm.conn_id,pm.lc);
    ((cid,disp)=>{ci.onclick=()=>_sidebarActivate(cid,disp);})(pm.conn_id,pm.display);
    el.appendChild(ci);
  }
}

function toggleFavsOnly(){
  const on=localStorage.getItem('cryptirc_favs_only')==='true';
  localStorage.setItem('cryptirc_favs_only',on?'false':'true');
  localStorage.setItem('cryptirc_favs_only_ts',String(Date.now()));
  savePrefsToServer();
  applyFavsOnly();
  renderSidebar();
}
function applyFavsOnly(){
  const on=localStorage.getItem('cryptirc_favs_only')==='true';
  document.getElementById('network-list').style.display=on?'none':'';
  document.getElementById('favorites-list').style.flex=on?'1':'';
  const bar=document.getElementById('favs-bar');
  if(bar){
    bar.className=on?'active':'inactive';
    document.getElementById('favs-label').textContent=on?'Showing Favorites Only':'Favorites';
    bar.title=on?'Click to show all channels':'Click to filter to favorites only';
  }
}
// Apply on load
document.addEventListener('DOMContentLoaded',()=>{
  applyFavsOnly();updateMentionsBadge();
  // Restore panel collapse state
  if(window.innerWidth>768){
    if(localStorage.getItem('cryptirc_sidebar_collapsed')==='1'){
      document.getElementById('sidebar')?.classList.add('collapsed');
      const si=document.getElementById('sidebar-toggle-icon');if(si)si.style.transform='rotate(180deg)';
    }
    if(localStorage.getItem('cryptirc_nick_collapsed')==='1'){
      document.getElementById('nick-panel')?.classList.add('collapsed');
      const niI=document.getElementById('nick-toggle-icon');if(niI)niI.style.transform='rotate(180deg)';
    }
  }
});

// ─── Channel list ─────────────────────────────────────────────────────────────
let chanListData=[];
let chanListConnId=null;
function openChanList(){
  chanListData=[];
  chanListConnId=active?.conn_id||null;
  if(!chanListConnId)return;
  document.getElementById('chanlist-body').innerHTML='<div class="chanlist-loading">Waiting for server response...</div>';
  document.getElementById('chanlist-count').textContent='';
  document.getElementById('chanlist-search').value='';
  document.getElementById('chanlist-overlay').classList.add('show');
  wsend({type:'send',conn_id:chanListConnId,raw:'LIST'});
}
function closeChanList(){_overlayClose('chanlist');document.getElementById('chanlist-overlay').classList.remove('show');chanListData=[];}

// ─── Links overlay ───────────────────────────────────────────────────────────
function showLinksOverlay(){
  document.getElementById('links-body').innerHTML='<div style="color:var(--text3);padding:20px;text-align:center">Waiting for server response...</div>';
  document.getElementById('links-count').textContent='';
  document.getElementById('links-overlay').style.display='flex';
  window._linksData=[];
}
function closeLinksOverlay(){document.getElementById('links-overlay').style.display='none';window._linksData=[];}
function addLinkEntry(text){
  if(!window._linksData) return;
  window._linksData.push(text);
}
function renderLinksOverlay(){
  const body=document.getElementById('links-body');
  const data=window._linksData||[];
  document.getElementById('links-count').textContent=data.length+' servers';
  if(!data.length){body.innerHTML='<div style="color:var(--text3);padding:20px;text-align:center">No links data.</div>';return;}
  body.innerHTML='';
  for(const text of data){
    const row=document.createElement('div');
    row.style.cssText='padding:8px 16px;border-bottom:1px solid var(--border);font-size:12px;color:var(--text);font-family:var(--mono);';
    row.innerHTML=parseMircColors(text);
    body.appendChild(row);
  }
}
function handleListEntry(ev){
  chanListData.push({channel:ev.channel,users:ev.users,topic:ev.topic});
  // Live count update
  document.getElementById('chanlist-count').textContent=`${chanListData.length} channels`;
}
function handleListEnd(){
  chanListData.sort((a,b)=>b.users-a.users);
  renderChanList(chanListData);
}
function renderChanList(data){
  const body=document.getElementById('chanlist-body');
  document.getElementById('chanlist-count').textContent=`${data.length} channels`;
  if(!data.length){body.innerHTML='<div class="chanlist-empty">No channels found.</div>';return;}
  body.innerHTML='';
  // Render in batches for performance
  const frag=document.createDocumentFragment();
  for(const ch of data){
    const row=document.createElement('div');
    row.className='chanlist-row';
    row.innerHTML=`<span class="chanlist-chan">${esc(ch.channel)}</span><span class="chanlist-users">${ch.users}</span><span class="chanlist-topic">${parseMircColors(ch.topic)}</span>`;
    row.onclick=()=>{
      if(chanListConnId){
        wsend({type:'join_channel',conn_id:chanListConnId,channel:ch.channel,key:null});
        closeChanList();
        setTimeout(()=>{setActive(chanListConnId,ch.channel);},500);
      }
    };
    frag.appendChild(row);
  }
  body.appendChild(frag);
}
function filterChanList(){
  const q=document.getElementById('chanlist-search').value.toLowerCase().trim();
  if(!q){renderChanList(chanListData);return;}
  const filtered=chanListData.filter(ch=>ch.channel.toLowerCase().includes(q)||ch.topic.toLowerCase().includes(q));
  renderChanList(filtered);
}

// ─── Remove network ───────────────────────────────────────────────────────────
// ─── Mute system ──────────────────────────────────────────────────────────────
function loadMuted(){try{return JSON.parse(localStorage.getItem('cryptirc_muted')||'{}');}catch{return {};}}
function saveMuted(m){try{localStorage.setItem('cryptirc_muted',JSON.stringify(m));}catch(e){} savePrefsToServer();}
function isMuted(key){return !!loadMuted()[key];}
function toggleMute(key){const m=loadMuted();if(m[key])delete m[key];else m[key]=true;saveMuted(m);renderSidebar();}

// ── Floating kebab dropdown (shared by net/chan/fav sidebar menus) ─────────
// Attached to <body> so it survives sidebar re-renders caused by IRC activity.
function _floatDd(){
  let el=document.getElementById('float-dropdown');
  if(!el){el=document.createElement('div');el.id='float-dropdown';document.body.appendChild(el);}
  return el;
}
function openFloatDd(anchorBtn,items){
  const el=_floatDd();
  el.innerHTML='';
  for(const it of items){
    const b=document.createElement('button');
    b.className='float-dropdown-item';
    b.textContent=it.text;
    if(it.style)b.style.cssText=it.style;
    b.addEventListener('click',e=>{e.stopPropagation();closeFloatDd();try{it.action();}catch(err){console.error(err);}});
    el.appendChild(b);
  }
  el.classList.add('open');
  el._anchorBtn=anchorBtn;
  const r=anchorBtn.getBoundingClientRect();
  // 0×0 anchors come from openFloatDdAt (right-click cursor); real buttons (kebabs)
  // have non-zero size. Cursor → align menu's LEFT edge to cursor (drops down-right).
  // Kebab → align menu's RIGHT edge to btn (matches the row's right edge).
  const isPoint=r.width===0&&r.height===0;
  el.style.top=(r.bottom+4)+'px';
  el.style.bottom='auto';
  if(isPoint){
    el.style.left=r.left+'px';
    el.style.right='auto';
  } else {
    el.style.left='auto';
    el.style.right=Math.max(8,window.innerWidth-r.right)+'px';
  }
  // Then clamp to viewport: flip up if overflowing bottom, slide horizontally if overflowing sides.
  requestAnimationFrame(()=>{
    let dr=el.getBoundingClientRect();
    if(dr.bottom>window.innerHeight-8){
      el.style.top='auto';
      el.style.bottom=Math.max(8,window.innerHeight-r.top+4)+'px';
    }
    dr=el.getBoundingClientRect();
    const w=el.offsetWidth;
    if(dr.right>window.innerWidth-8){
      el.style.left=Math.max(8,window.innerWidth-8-w)+'px';
      el.style.right='auto';
    } else if(dr.left<8){
      el.style.left='8px';
      el.style.right='auto';
    }
  });
}
function closeFloatDd(){
  const el=document.getElementById('float-dropdown');
  if(el){el.classList.remove('open');el._anchorBtn=null;el.innerHTML='';}
}
function toggleFloatDd(anchorBtn,items){
  const el=_floatDd();
  if(el.classList.contains('open')&&el._anchorBtn===anchorBtn){closeFloatDd();return;}
  openFloatDd(anchorBtn,items);
}
// Open the float dropdown anchored at an arbitrary viewport point (right-click).
function openFloatDdAt(x,y,items){
  const fake={getBoundingClientRect:()=>({top:y,bottom:y,left:x,right:x,width:0,height:0})};
  closeFloatDd();
  openFloatDd(fake,items);
}
function _netMenuItems(id,label){
  const muted=isMuted('net:'+id);
  return [
    {text:'⚡ Connect',action:()=>wsend({type:'connect',id})},
    {text:'✕ Disconnect',action:()=>wsend({type:'disconnect',id})},
    {text:muted?'🔔 Unmute':'🔇 Mute',action:()=>toggleMute('net:'+id)},
    {text:'✕ Close All PMs',action:()=>closeAllPMs(id)},
    {text:'✎ Edit',action:()=>editNetwork(id)},
    {text:'🗑 Remove',action:()=>removeNetwork(id,label),style:'color:#f87171'},
  ];
}
function toggleNetMenu(btn,id,label){toggleFloatDd(btn,_netMenuItems(id,label));}
function closeNetMenus(){closeFloatDd();}
function _chanMenuItems(connId,target,kind){
  const fav=isFavorite(connId,target);
  const muteKey=connId+'/'+target;
  const muted=isMuted(muteKey);
  const items=[
    {text:fav?'★ Unfavorite':'☆ Favorite',action:()=>toggleFavorite(connId,target)},
    {text:muted?'🔔 Unmute':'🔇 Mute',action:()=>toggleMute(muteKey)},
    {text:'🗑 Clear History',action:()=>clearBufHistory(connId,target)},
  ];
  if(_canPopOut()){
    const det=isDetached(connId,target);
    items.push({text: det?'⧉ Reattach':'⧉ Pop Out', action: ()=> det?reattachView(connId,target):detachView(connId,target)});
  }
  if(kind==='pm'){
    const pmAllowed=isPmAllowedFor(connId,target);
    items.push({
      text: pmAllowed?'🛡 Remove PM allow':'🛡 Allow PMs',
      action: ()=>{
        if(pmAllowed){removePmAllow(target,connId); showToast(`${target} removed from PM allow list`);}
        else {addPmAllow(target,connId); showToast(`PMs from ${target} will now bypass protection`);}
      },
    });
  }
  if(kind==='channel') items.push({text:'⚙ Channel Modes',action:()=>openChanModes(connId,target)});
  if(kind==='channel') items.push({text:'Leave',action:()=>wsend({type:'part_channel',conn_id:connId,channel:target}),style:'color:#f87171'});
  else items.push({text:'Close',action:()=>closeQuery(connId,target),style:'color:#f87171'});
  return items;
}
function toggleChanMenu(btn,connId,target,kind){toggleFloatDd(btn,_chanMenuItems(connId,target,kind));}
function closeChanMenus(){closeFloatDd();}

// ── Channel Modes dialog (mIRC-style; opened from the channel ⋮ menu) ───────
let _cm=null, _cmRefreshT=null;
// Channel mode letters + labels per the UnrealIRCd "Channel Modes" docs. All of
// these are no-parameter, operator-settable modes (+k key and +l limit have their
// own inputs; +b/+e/+I are the list tabs). NOTE: +r (lowercase) is "channel is
// registered at Services" and is set by Services only — the op-settable join
// restriction is +R (uppercase): "only registered users may join".
const _CM_FLAGS=[
  ['n','No external messages','Block messages from users who are not in the channel'],
  ['t','Topic locked','Only channel operators may change the topic'],
  ['m','Moderated','Only voiced (+v) users and operators may speak'],
  ['i','Invite only','Users must be invited (or match the +I list) to join'],
  ['R','Registered only','Only registered (Services-identified) users may join'],
  ['z','TLS only','Only users connected over SSL/TLS may join'],
  ['s','Secret','Hide the channel from /LIST and /WHOIS, as if it does not exist'],
  ['p','Private','Partially conceal that the channel exists'],
  ['c','Block colors','Reject messages containing mIRC/ANSI color codes'],
  ['S','Strip colors','Strip color codes from messages instead of blocking them'],
  ['C','Block CTCPs','Reject CTCPs sent to the channel'],
  ['T','Block channel notices','Reject NOTICEs sent to the channel'],
  ['N','No nick changes','Prevent users from changing nick while in the channel'],
  ['G','Filter bad words','Censor words from the network badword list'],
  ['Q','No kicks','Disallow /KICK (force kicks through Services)'],
];
const _CM_LISTS=[['b','Bans','🚫'],['e','Exempts','✅'],['I','Invex','✉']];
function _cmIsOp(connId,target){return /[~&@]/.test(getMyPrefix(connId,target));}
function _cmMatch(conn_id,channel){return _cm&&_cm.connId===conn_id&&String(_cm.target).toLowerCase()===String(channel||'').toLowerCase();}
function openChanModes(connId,target){
  _cm={connId,target,flags:new Set(),key:'',limit:'',lists:{b:[],e:[],I:[]},collecting:{b:true,e:true,I:true},tab:'b',isOp:_cmIsOp(connId,target),loaded:false};
  document.getElementById('chanmodes-overlay').classList.add('show');
  if(typeof _overlayOpen==='function')_overlayOpen('chanModes',closeChanModes);
  cmRender();
  cmQueryAll();
  // Safety: if the ircd never ends a list (e.g. +I unsupported), stop "Loading…".
  setTimeout(()=>{ if(_cm){ _cm.collecting={b:false,e:false,I:false}; cmRenderList(); } },5000);
}
function closeChanModes(){
  _cm=null; clearTimeout(_cmRefreshT);
  document.getElementById('chanmodes-overlay').classList.remove('show');
  document.getElementById('chanmodes-overlay').innerHTML='';
  if(typeof _overlayClose==='function')_overlayClose('chanModes');
}
function cmQueryAll(){
  if(!_cm)return;
  const t=_cm.target,c=_cm.connId;
  wsend({type:'send',conn_id:c,raw:`MODE ${t}`});
  wsend({type:'send',conn_id:c,raw:`MODE ${t} +b`});
  wsend({type:'send',conn_id:c,raw:`MODE ${t} +e`});
  wsend({type:'send',conn_id:c,raw:`MODE ${t} +I`});
}
function cmRefresh(){
  if(!_cm)return; clearTimeout(_cmRefreshT);
  _cmRefreshT=setTimeout(()=>{ if(!_cm)return; _cm.lists={b:[],e:[],I:[]}; _cm.collecting={b:true,e:true,I:true}; cmQueryAll();
    setTimeout(()=>{ if(_cm){ _cm.collecting={b:false,e:false,I:false}; cmRenderList(); } },5000); },250);
}
function cmParseModes(s){
  if(!_cm)return;
  _cm.flags=new Set(); _cm.key=''; _cm.limit=''; _cm.loaded=true;
  if(!s)return;
  const parts=String(s).trim().split(/\s+/); const flags=parts[0]||''; let argi=1, adding=true;
  for(const ch of flags){
    if(ch==='+'){adding=true;continue;} if(ch==='-'){adding=false;continue;}
    if(ch==='k'){const v=parts[argi++]||''; if(adding)_cm.key=v; continue;}
    if(ch==='l'){const v=parts[argi++]||''; if(adding)_cm.limit=v; continue;}
    if(adding)_cm.flags.add(ch);
  }
}
function _cmSend(raw){ if(_cm)wsend({type:'send',conn_id:_cm.connId,raw}); }
function cmToggleFlag(letter,on){ if(_cm&&_cm.isOp)_cmSend(`MODE ${_cm.target} ${on?'+':'-'}${letter}`); }
function cmSetKey(){ if(!_cm||!_cm.isOp)return; const v=(document.getElementById('cm-key-input').value||'').trim(); if(!v){showToast('Enter a key');return;} if(/\s/.test(v)){showToast('Key cannot contain spaces');return;} _cmSend(`MODE ${_cm.target} +k ${v}`); }
function cmClearKey(){ if(_cm&&_cm.isOp)_cmSend(`MODE ${_cm.target} -k ${_cm.key||'*'}`); }
function cmSetLimit(){ if(!_cm||!_cm.isOp)return; const v=parseInt(document.getElementById('cm-limit-input').value,10); if(!v||v<1){showToast('Enter a positive number');return;} _cmSend(`MODE ${_cm.target} +l ${v}`); }
function cmClearLimit(){ if(_cm&&_cm.isOp)_cmSend(`MODE ${_cm.target} -l`); }
function cmAddEntry(){ if(!_cm||!_cm.isOp)return; const inp=document.getElementById('cm-add-input'); let m=(inp.value||'').trim(); if(!m)return; if(!/[!@]/.test(m))m=m+'!*@*'; _cmSend(`MODE ${_cm.target} +${_cm.tab} ${m}`); inp.value=''; }
function cmRemoveEntry(mask){ if(_cm&&_cm.isOp&&mask)_cmSend(`MODE ${_cm.target} -${_cm.tab} ${mask}`); }
function cmSwitchTab(list){ if(_cm){_cm.tab=list; cmRender();} }
function cmListHtml(){
  const L=_cm.lists[_cm.tab];
  if(_cm.collecting[_cm.tab]&&!L.length)return `<div class="cm-list-empty">Loading…</div>`;
  if(!L.length)return `<div class="cm-list-empty">No entries</div>`;
  let h='';
  for(const e of L){
    const meta=e.by?`<span class="cm-meta">by ${esc(e.by)}</span>`:'';
    h+=`<div class="cm-list-row"><span class="cm-mask">${esc(e.mask)}</span>${meta}${_cm.isOp?`<button class="cm-del" data-mask="${esc(e.mask)}" aria-label="Remove ${esc(e.mask)}">✕</button>`:''}</div>`;
  }
  return h;
}
function cmRenderList(){
  if(!_cm)return;
  const el=document.getElementById('cm-list'); if(el)el.innerHTML=cmListHtml();
  const ov=document.getElementById('chanmodes-overlay');
  if(ov)ov.querySelectorAll('.cm-tab').forEach(t=>{const l=t.dataset.tab,c=t.querySelector('.cm-count');if(c)c.textContent=_cm.collecting[l]?'…':_cm.lists[l].length;});
  if(_cm.isOp){const db=ov&&ov.querySelectorAll('.cm-del');if(db)db.forEach(b=>b.addEventListener('click',()=>cmRemoveEntry(b.dataset.mask)));}
}
function cmRender(){
  if(!_cm)return;
  const ov=document.getElementById('chanmodes-overlay'); if(!ov.classList.contains('show'))return;
  const ro=!_cm.isOp;
  const prevAdd=(document.getElementById('cm-add-input')||{}).value||'';
  const known=new Set(_CM_FLAGS.map(f=>f[0]));
  let h=`<div class="cm-box"><div class="cm-header"><span class="cm-title">⚙ Channel Modes — ${esc(_cm.target)}</span><button class="cm-close" id="cm-close-btn" aria-label="Close">✕</button></div><div class="cm-body">`;
  if(ro)h+=`<div class="cm-readonly">👁 You are not a channel operator — view only.</div>`;
  h+=`<div class="cm-section"><div class="cm-section-title">Modes</div>`;
  for(const [c,label,sub] of _CM_FLAGS){
    h+=`<label class="cm-toggle"><input type="checkbox" data-flag="${c}"${_cm.flags.has(c)?' checked':''}${ro?' disabled':''}><span class="cm-switch"></span><span class="cm-toggle-label">${esc(label)}<div class="cm-toggle-sub">${esc(sub)}</div></span><span class="cm-flag">+${c}</span></label>`;
  }
  for(const c of _cm.flags){ if(!known.has(c)&&c!=='k'&&c!=='l'){ h+=`<label class="cm-toggle"><input type="checkbox" data-flag="${esc(c)}" checked${ro?' disabled':''}><span class="cm-switch"></span><span class="cm-toggle-label">Mode +${esc(c)}</span><span class="cm-flag">+${esc(c)}</span></label>`; } }
  h+=`</div>`;
  h+=`<div class="cm-section"><div class="cm-section-title">Channel key (+k)</div><div class="cm-row"><input class="cm-input" id="cm-key-input" placeholder="no key set" value="${esc(_cm.key)}"${ro?' disabled':''}><button class="cm-btn" id="cm-key-set"${ro?' disabled':''}>Set</button><button class="cm-btn" id="cm-key-clear"${ro||!_cm.key?' disabled':''}>Clear</button></div></div>`;
  h+=`<div class="cm-section"><div class="cm-section-title">User limit (+l)</div><div class="cm-row"><input class="cm-input" id="cm-limit-input" type="number" min="1" inputmode="numeric" placeholder="no limit" value="${esc(_cm.limit)}"${ro?' disabled':''}><button class="cm-btn" id="cm-limit-set"${ro?' disabled':''}>Set</button><button class="cm-btn" id="cm-limit-clear"${ro||!_cm.limit?' disabled':''}>Clear</button></div></div>`;
  h+=`<div class="cm-section"><div class="cm-tabs">`;
  for(const [l,label,icon] of _CM_LISTS){ h+=`<div class="cm-tab${_cm.tab===l?' active':''}" data-tab="${l}">${icon} ${label} <span class="cm-count">${_cm.collecting[l]?'…':_cm.lists[l].length}</span></div>`; }
  h+=`</div><div class="cm-list" id="cm-list">${cmListHtml()}</div>`;
  if(!ro)h+=`<div class="cm-add"><input class="cm-input" id="cm-add-input" placeholder="nick!user@host" value="${esc(prevAdd)}"><button class="cm-btn primary" id="cm-add-btn">Add</button></div>`;
  h+=`</div></div>`;
  ov.innerHTML=h;
  ov.querySelector('#cm-close-btn').addEventListener('click',closeChanModes);
  if(!ro){
    ov.querySelectorAll('input[data-flag]').forEach(cb=>cb.addEventListener('change',()=>cmToggleFlag(cb.dataset.flag,cb.checked)));
    ov.querySelector('#cm-key-set').addEventListener('click',cmSetKey);
    ov.querySelector('#cm-key-clear').addEventListener('click',cmClearKey);
    ov.querySelector('#cm-limit-set').addEventListener('click',cmSetLimit);
    ov.querySelector('#cm-limit-clear').addEventListener('click',cmClearLimit);
    const ab=ov.querySelector('#cm-add-btn'); if(ab){ab.addEventListener('click',cmAddEntry); ov.querySelector('#cm-add-input').addEventListener('keydown',e=>{if(e.key==='Enter')cmAddEntry();});}
    ov.querySelectorAll('.cm-del').forEach(b=>b.addEventListener('click',()=>cmRemoveEntry(b.dataset.mask)));
  }
  ov.querySelectorAll('.cm-tab').forEach(t=>t.addEventListener('click',()=>cmSwitchTab(t.dataset.tab)));
}
// Close when tapping the dark backdrop (not the box)
document.getElementById('chanmodes-overlay')?.addEventListener('click',e=>{ if(e.target.id==='chanmodes-overlay')closeChanModes(); });
document.addEventListener('click',e=>{
  if(!e.target.closest('.net-kebab')&&!e.target.closest('.chan-kebab')&&!e.target.closest('#float-dropdown'))
    closeFloatDd();
});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeFloatDd();});
// Close on sidebar scroll (kebab btn moves, floating menu would desync).
(function(){const sb=document.getElementById('sidebar');if(sb)sb.addEventListener('scroll',()=>closeFloatDd(),{passive:true});})();
window.addEventListener('resize',()=>closeFloatDd());
// Right-click context menus on sidebar rows + nick list (desktop only — touch
// devices don't fire `contextmenu`, so the kebab ⋮ remains the touch path).
(function(){
  const findKind=(el)=>{
    // Favorites are also .chan-item but carry .fav-item — check first.
    const fi=el.closest('.fav-item');
    if(fi&&fi.dataset.connId&&fi.dataset.target){
      return {kind:'fav', connId:fi.dataset.connId, target:fi.dataset.target, isChannel:fi.dataset.isChannel==='1'};
    }
    const ci=el.closest('.chan-item');
    if(ci&&ci.dataset.target){
      const connId=ci.dataset.connId||ci.closest('.net-group')?.dataset.netId;
      if(!connId) return null;
      const t=ci.dataset.target;
      const isChannel=t.startsWith('#')||t.startsWith('&')||t.startsWith('+')||t.startsWith('!');
      return {kind:isChannel?'channel':'pm', connId, target:t};
    }
    const nl=el.closest('.net-label');
    if(nl){
      const g=nl.closest('.net-group');
      if(!g) return null;
      const id=g.dataset.netId;
      const net=networks.find(n=>n.config.id===id);
      if(!net) return null;
      return {kind:'net', id, label:net.config.label||net.config.server};
    }
    return null;
  };
  document.addEventListener('contextmenu',e=>{
    // Right-click anywhere outside the float dropdown closes any open menu;
    // matching rows then open a fresh one at the cursor.
    if(!e.target.closest('#float-dropdown')) closeFloatDd();
    const hit=findKind(e.target);
    if(!hit)return;
    e.preventDefault();
    if(hit.kind==='channel'||hit.kind==='pm'){
      openFloatDdAt(e.clientX,e.clientY,_chanMenuItems(hit.connId,hit.target,hit.kind));
    } else if(hit.kind==='fav'){
      openFloatDdAt(e.clientX,e.clientY,_favMenuItems(hit.connId,hit.target,hit.isChannel));
    } else if(hit.kind==='net'){
      openFloatDdAt(e.clientX,e.clientY,_netMenuItems(hit.id,hit.label));
    }
  });
  // Nick list right-click → existing nick context menu (Whois/Query/Mention/etc).
  const nl=document.getElementById('nick-list');
  if(nl){
    nl.addEventListener('contextmenu',e=>{
      const entry=e.target.closest('.nick-entry');
      if(entry&&entry.dataset.nick){
        e.preventDefault();
        e.stopPropagation();
        showNickMenu(e,entry.dataset.nick);
      }
    });
  }
})();

async function removeNetwork(id,label){
  if(!(await customConfirm(`Remove server "${label}"? This will disconnect and delete its config.`,'Remove')))return;
  wsend({type:'remove_network',id});
  // Clean up favorites for this network
  let favs=loadFavorites().filter(f=>!f.key.startsWith(id+'/'));
  saveFavorites(favs);
  // Clean up query bufs
  delete queryBufs[id];
  // Clean up buffers for this network
  for(const k of Object.keys(buffers)){if(k.startsWith(id+'/'))delete buffers[k];}
  // Clean up unread counts
  for(const [k] of unread){if(k.startsWith(id+'/'))unread.delete(k);}
  // Clean up stale network order entry
  try{const no=JSON.parse(localStorage.getItem('cryptirc_net_order')||'[]').filter(x=>x!==id);localStorage.setItem('cryptirc_net_order',JSON.stringify(no));}catch(e){}
}

// ─── Nick context menu ────────────────────────────────────────────────────────
let nickCtx=null;
function getMyPrefix(conn_id,channel){
  const net=networks.find(n=>n.config.id===conn_id);
  if(!net)return '';
  const ch=net.channels.find(c=>c.name===channel);
  if(!ch)return '';
  const myNick=getNick(conn_id).toLowerCase();
  const entry=ch.names.find(n=>stripPfx(n).toLowerCase()===myNick);
  if(!entry)return '';
  let pfx='';for(let i=0;i<entry.length;i++){if('~&@%+'.includes(entry[i]))pfx+=entry[i];else break;}
  return pfx;
}
function getPowerLevel(pfx){
  if(pfx.includes('~'))return 5; // owner
  if(pfx.includes('&'))return 4; // admin
  if(pfx.includes('@'))return 3; // op
  if(pfx.includes('%'))return 2; // halfop
  if(pfx.includes('+'))return 1; // voice
  return 0;
}
function showNickMenu(e,nick){
  try{
  e.preventDefault(); e.stopPropagation();
  closeNickMenu();
  const isMobile=window.innerWidth<=768;
  const menu=document.createElement('div');
  menu.className='nick-ctx';
  const isChan=active&&(active.target.startsWith('#')||active.target.startsWith('&'));
  const myPower=isChan?getPowerLevel(getMyPrefix(active.conn_id,active.target)):0;
  const sendRaw=(r)=>{if(active)wsend({type:'send',conn_id:active.conn_id,raw:r});};
  const ch=active?active.target:'';
  const closeAfter=()=>{closeNickMenu();if(isMobile)closeNickPanelMobile();};
  const items=[
    {label:'Whois',     action:()=>{if(active){if(!window._pendingWhois)window._pendingWhois={};window._pendingWhois[active.conn_id]=nick;wsend({type:'send',conn_id:active.conn_id,raw:`WHOIS ${nick}`});closeAfter();}}},
    {label:'Query',     action:()=>{if(active){closeAfter();setActive(active.conn_id,nick);closeSidebar();}}},
    {label:'Mention',   action:()=>insertNick(nick)},
    {label:'Slap',      action:async()=>{if(!active)return;const st=`slaps ${nick} around a bit with a large trout`;const sw=(window.E2E?.ready||window.E2E?.channelKeys?.[active.target])?await e2eEncryptOutgoing(active.target,`\x01ACTION ${st}\x01`):null;if(sw)wsend({type:'send',conn_id:active.conn_id,raw:`PRIVMSG ${active.target} :${sw}`});else wsend({type:'send',conn_id:active.conn_id,raw:`PRIVMSG ${active.target} :\x01ACTION ${st}\x01`});addMessage(active.conn_id,active.target,{ts:Date.now()/1000|0,from:getNick(active.conn_id),text:st,kind:'action'});}},
    {label:loadMonitor()[nick.toLowerCase()]?'Unmonitor':'Monitor', action:()=>{const k=nick.toLowerCase();if(loadMonitor()[k]){monitorRemove(nick);showToast(`Removed ${nick} from monitor`);}else{monitorAdd(nick);showToast(`Added ${nick} to monitor`);}}},
    {label:'📝 Note', action:async()=>{const notes=loadUserNotes();const existing=notes[nick.toLowerCase()]||'';const n=await customPrompt(`Note for ${nick}:`,existing);if(n!==null){if(n.trim())notes[nick.toLowerCase()]=n.trim();else delete notes[nick.toLowerCase()];saveUserNotes(notes);showToast(n.trim()?`Note saved for ${nick}`:`Note removed for ${nick}`);}}},
    {label:isIgnored(nick)?'Unignore':'Ignore nick', action:()=>{if(isIgnored(nick)){removeIgnore(nick);showToast(`Unignored ${nick}`);}else{addIgnore(nick);showToast(`Ignoring ${nick}`);}}},
    {label:'Ignore by mask', action:async()=>{const mask=await customPrompt(`Ignore mask for ${nick}:\n\nExamples:\n  ${nick}!*@*  (nick only)\n  *!*@*.host.com  (by host)\n  *!user@*  (by username)`,`${nick}!*@*`);if(mask&&mask.trim()){addIgnore(mask.trim());showToast(`Ignoring ${mask.trim()}`);}}},
    {label:(active&&isPmAllowedFor(active.conn_id,nick))?'🛡 Remove PM allow':'🛡 Allow PMs', action:()=>{const cid=active?.conn_id;if(cid&&isPmAllowedFor(cid,nick)){removePmAllow(nick,cid);showToast(`${nick} removed from PM allow list`);}else{addPmAllow(nick,cid);showToast(`PMs from ${nick} will now bypass protection`);}}},
  ];
  // Channel power options — only show if we have sufficient power and in a channel
  if(isChan&&myPower>=2){
    items.push({label:'─────',action:()=>{}});
    items.push({label:'Kick',action:async()=>{const reason=await customPrompt('Kick reason (optional):','');if(reason===null)return;sendRaw(`KICK ${ch} ${nick}${reason?' :'+reason:''}`);}});
    items.push({label:'Ban',action:()=>sendRaw(`MODE ${ch} +b ${nick}!*@*`)});
    items.push({label:'Kick + Ban',action:()=>{sendRaw(`MODE ${ch} +b ${nick}!*@*`);setTimeout(()=>sendRaw(`KICK ${ch} ${nick} :Banned`),300);}});
  }
  if(isChan&&myPower>=2){
    items.push({label:'─────',action:()=>{}});
    items.push({label:'+Voice',action:()=>sendRaw(`MODE ${ch} +v ${nick}`)});
    items.push({label:'-Voice',action:()=>sendRaw(`MODE ${ch} -v ${nick}`)});
  }
  if(isChan&&myPower>=3){
    items.push({label:'+Half-Op',action:()=>sendRaw(`MODE ${ch} +h ${nick}`)});
    items.push({label:'-Half-Op',action:()=>sendRaw(`MODE ${ch} -h ${nick}`)});
    items.push({label:'+Op',action:()=>sendRaw(`MODE ${ch} +o ${nick}`)});
    items.push({label:'-Op',action:()=>sendRaw(`MODE ${ch} -o ${nick}`)});
  }
  if(isChan&&myPower>=4){
    items.push({label:'+Admin',action:()=>sendRaw(`MODE ${ch} +a ${nick}`)});
    items.push({label:'-Admin',action:()=>sendRaw(`MODE ${ch} -a ${nick}`)});
  }
  if(isChan&&myPower>=5){
    items.push({label:'+Owner',action:()=>sendRaw(`MODE ${ch} +q ${nick}`)});
    items.push({label:'-Owner',action:()=>sendRaw(`MODE ${ch} -q ${nick}`)});
  }
  for(const it of items){
    const el=document.createElement('div');
    el.className='nick-ctx-item';
    if(it.label.startsWith('───')){el.className='nick-ctx-sep';el.textContent='';} else {el.textContent=it.label;}
    el.addEventListener('click',()=>{if(!it.label.startsWith('───')){it.action();closeNickMenu();if(isMobile)closeNickPanelMobile();}});
    menu.appendChild(el);
  }
  if(isMobile){
    // On mobile: show a full-screen overlay with the menu centered
    const overlay=document.createElement('div');
    overlay.className='nick-ctx-overlay';
    overlay.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:199;';
    // Ignore a stray synthetic click that may fire right after the opening tap
    // (the iOS touchend→click cascade) so the menu doesn't open-then-close.
    menu._openedAt=Date.now();
    overlay.addEventListener('click',()=>{if(Date.now()-menu._openedAt<400)return;closeNickMenu();});
    // Add nick name header
    const hdr=document.createElement('div');
    hdr.style.cssText='padding:8px 12px;font-weight:700;color:var(--accent);border-bottom:1px solid var(--border);font-size:13px;';
    hdr.textContent=nick;
    menu.insertBefore(hdr,menu.firstChild);
    menu.style.cssText='position:fixed;z-index:200;background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:4px 0;min-width:180px;max-width:min(260px,85vw);max-height:min(65vh,400px);overflow-y:auto;box-shadow:0 8px 30px rgba(0,0,0,.6);font-size:13px;';
    document.body.appendChild(overlay);
    document.body.appendChild(menu);
    // Center after DOM insertion
    const mr=menu.getBoundingClientRect();
    menu.style.left=Math.max(8,(window.innerWidth-mr.width)/2)+'px';
    menu.style.top=Math.max(8,(window.innerHeight-mr.height)/2)+'px';
    nickCtx=menu;
    nickCtx._overlay=overlay;
  } else {
    document.body.appendChild(menu);
    const r=menu.getBoundingClientRect();
    // e may be a TouchEvent (no clientX/Y on the event itself) on touch tablets
    // wider than the mobile breakpoint — fall back to the touch point, then center.
    const _ct=e.changedTouches&&e.changedTouches[0];
    let x=(e.clientX!=null?e.clientX:(_ct?_ct.clientX:window.innerWidth/2));
    let y=(e.clientY!=null?e.clientY:(_ct?_ct.clientY:window.innerHeight/2));
    if(x+r.width>window.innerWidth) x=window.innerWidth-r.width-8;
    if(x<8) x=8;
    if(y+r.height>window.innerHeight) y=window.innerHeight-r.height-8;
    if(y<8) y=8;
    menu.style.left=x+'px'; menu.style.top=y+'px';
    nickCtx=menu;
    setTimeout(()=>document.addEventListener('click',closeNickMenu,{once:true}),100);
  }
  }catch(err){console.error('showNickMenu error:',err);}
}
function closeNickMenu(){if(nickCtx){if(nickCtx._overlay)nickCtx._overlay.remove();nickCtx.remove();nickCtx=null;}}
function closeNickPanelMobile(){
  const np=document.getElementById('nick-panel');
  if(np&&np.classList.contains('open')){np.classList.remove('open');document.getElementById('sidebar-backdrop').classList.remove('show');}
}
function showTopicMenu(e){
  if(e) e.stopPropagation();
  const m=document.getElementById('topic-menu');
  if(m.classList.contains('open')){m.classList.remove('open');return;}
  if(!active){return;}
  const{conn_id,target}=active;
  const isChan=target.startsWith('#')||target.startsWith('&');
  const isPM=!isChan&&target!=='status';
  // Build menu dynamically.
  // SECURITY: these handlers carry the PM/DM target nick (attacker-controlled) and
  // mute keys derived from it. They are NOT interpolated into inline-handler
  // JS-strings (the old onclick="…'${esc(target)}'…" sinks — #9/#10); instead each
  // button is a real element with an .onclick closure capturing the value as a
  // plain JS variable, so the data never enters a code/JS-string context.
  m.innerHTML='';
  // Helper: build a topic-menu button. `label` is set via textContent (no HTML
  // injection); `fn` runs on click and closeTopicMenu() is always called after.
  const _mkItem=(label,fn,danger)=>{
    const b=document.createElement('button');
    b.className='topic-menu-item';
    if(danger)b.style.color='#f87171';
    b.textContent=label;
    b.onclick=()=>{try{fn();}finally{closeTopicMenu();}};
    m.appendChild(b);
    return b;
  };
  // Open the channel-list overlay for a given connection (same behavior as the
  // former inline handler, just without string-built JS).
  const _openChanList=(cid)=>{
    chanListData=[];chanListConnId=cid;
    document.getElementById('chanlist-body').innerHTML='<div class=chanlist-loading>Waiting...</div>';
    document.getElementById('chanlist-count').textContent='';
    document.getElementById('chanlist-search').value='';
    document.getElementById('chanlist-overlay').classList.add('show');
    wsend({type:'send',conn_id:cid,raw:'LIST'});
  };
  if(isChan){
    _mkItem('👁 View topic',()=>viewFullTopic());
    _mkItem('✏️ Edit topic',()=>editTopic());
    _mkItem('📋 Copy topic',()=>copyTopic());
    const fav=isFavorite(conn_id,target);
    _mkItem(fav?'★ Unfavorite':'☆ Favorite',()=>toggleFavorite(conn_id,target));
    const muteKey=conn_id+'/'+target;
    const muted=isMuted(muteKey);
    _mkItem(muted?'🔔 Unmute':'🔇 Mute',()=>toggleMute(muteKey));
    _mkItem('⚙ Channel Modes',()=>openChanModes(conn_id,target));
    _mkItem('📋 Channel list',()=>_openChanList(conn_id));
    _mkItem('🗑 Clear History',()=>clearBufHistory(conn_id,target));
    _mkItem('🚪 Leave channel',()=>leaveCurrentChannel(),true);
  } else if(isPM){
    _mkItem('🔍 Whois',()=>wsend({type:'send',conn_id,raw:'WHOIS '+target}));
    const pmAllowed=isPmAllowedFor(conn_id,target);
    _mkItem(pmAllowed?'🛡 Remove PM allow':'🛡 Allow PMs',()=>{
      if(pmAllowed){removePmAllow(target,conn_id);showToast(target+' removed from PM allow list');}
      else{addPmAllow(target,conn_id);showToast('PMs from '+target+' will now bypass protection');}
    });
    const ignored=isIgnored(target);
    _mkItem(ignored?'👂 Unignore':'🚫 Ignore user',()=>{ignored?removeIgnore(target):addIgnore(target);});
    const muteKey=conn_id+'/'+target;
    const muted=isMuted(muteKey);
    _mkItem(muted?'🔔 Unmute':'🔇 Mute conversation',()=>toggleMute(muteKey));
    const fav=isFavorite(conn_id,target);
    _mkItem(fav?'★ Unfavorite':'☆ Favorite',()=>toggleFavorite(conn_id,target));
    _mkItem('📋 Channel list',()=>_openChanList(conn_id));
    _mkItem('🗑 Clear History',()=>clearBufHistory(conn_id,target));
    _mkItem('✕ Close PM',()=>leaveCurrentChannel(),true);
  } else if(target==='status'){
    // Status window — network management options
    const net=networks.find(n=>n.config.id===conn_id);
    const netLabel=net?(net.config.label||net.config.server):'Network';
    _mkItem('✎ Edit '+netLabel,()=>editNetwork(conn_id));
    // Join-channel button opened the prompt AFTER closing the menu; preserve order
    // by closing first then prompting (closeTopicMenu also runs again harmlessly).
    _mkItem('📺 Join channel',()=>{closeTopicMenu();promptJoinChannel(conn_id);});
    _mkItem('📋 List channels',()=>_openChanList(conn_id));
    _mkItem('🚫 Ignored users',()=>showIgnorePanel());
    const netMuted=isMuted('net:'+conn_id);
    _mkItem(netMuted?'🔔 Unmute network':'🔇 Mute network',()=>toggleMute('net:'+conn_id));
    if(net?.connected){
      _mkItem('⚡ Disconnect',()=>wsend({type:'disconnect',id:conn_id}));
    } else {
      _mkItem('⚡ Connect',()=>wsend({type:'connect',id:conn_id}));
    }
    _mkItem('🗑 Delete network',()=>removeNetwork(conn_id,netLabel),true);
  }
  const btn=document.getElementById('topic-menu-btn');
  const r=btn.getBoundingClientRect();
  m.style.top=(r.bottom+4)+'px';
  m.style.right=Math.max(8,window.innerWidth-r.right)+'px';
  m.style.left='auto';
  m.classList.add('open');
}
function closeTopicMenu(){
  document.getElementById('topic-menu').classList.remove('open');
}
async function leaveCurrentChannel(){
  if(!active)return;
  const{conn_id,target}=active;
  const isChan=target.startsWith('#')||target.startsWith('&');
  if(isChan){
    if(!(await customConfirm(`Leave ${target}?`,'Leave')))return;
    wsend({type:'part_channel',conn_id,channel:target});
  } else if(target!=='status'){
    // Close PM
    closeQuery(conn_id,target);
  }
}
function viewFullTopic(){
  if(!active)return;
  const net=networks.find(n=>n.config.id===active.conn_id);
  const ch=net?.channels.find(c=>c.name===active.target);
  const topic=ch?.topic;
  if(!topic){showToast('No topic set');return;}
  let ov=document.getElementById('topic-overlay');
  if(!ov){
    ov=document.createElement('div');ov.id='topic-overlay';
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:flex;align-items:center;justify-content:center;padding:20px;';
    ov.onclick=()=>ov.remove();
    document.body.appendChild(ov);
  }
  const box=document.createElement('div');
  box.style.cssText='background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;max-width:min(600px,90vw);max-height:min(60vh,60dvh);overflow-y:auto;color:var(--text);font-size:14px;line-height:1.6;word-break:break-word;';
  box.innerHTML=`<div style="font-size:11px;color:var(--text3);margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Topic — ${esc(active.target)}</div>${parseMircColors(topic)}`;
  ov.innerHTML='';ov.appendChild(box);
}
function customPrompt(message,defaultValue){
  return new Promise(resolve=>{
    const ov=document.getElementById('custom-prompt-overlay');
    const msg=document.getElementById('custom-prompt-msg');
    const inp=document.getElementById('custom-prompt-input');
    const ok=document.getElementById('custom-prompt-ok');
    const cancel=document.getElementById('custom-prompt-cancel');
    msg.textContent=message||'';
    inp.value=defaultValue||'';
    ov.classList.add('open');
    inp.focus();
    inp.select();
    function finish(val){ov.classList.remove('open');ok.onclick=null;cancel.onclick=null;inp.onkeydown=null;resolve(val);}
    ok.onclick=()=>finish(inp.value);
    cancel.onclick=()=>finish(null);
    inp.onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();finish(inp.value);}else if(e.key==='Escape'){e.preventDefault();finish(null);}};
  });
}
// customConfirm — Promise-based replacement for window.confirm(), which is
// unreliable in Electron. Resolves true on OK, false on Cancel/Escape/backdrop click.
function customConfirm(message, okLabel, cancelLabel){
  okLabel = okLabel || 'OK';
  cancelLabel = cancelLabel || 'Cancel';
  return new Promise(resolve=>{
    const ov=document.createElement('div');
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:10001;display:flex;align-items:center;justify-content:center;padding:20px;';
    const box=document.createElement('div');
    box.style.cssText='background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:20px;width:min(420px,92vw);max-height:min(80vh,80dvh);overflow-y:auto;box-shadow:0 8px 30px rgba(0,0,0,.5);';
    const msgDiv=document.createElement('div');
    msgDiv.style.cssText='color:var(--text);font-size:13px;white-space:pre-wrap;line-height:1.5;margin-bottom:14px;word-break:break-word;';
    msgDiv.textContent=message||'';
    const btnRow=document.createElement('div');
    btnRow.style.cssText='display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;';
    const cancelBtn=document.createElement('button');
    cancelBtn.textContent=cancelLabel;
    cancelBtn.style.cssText='padding:8px 20px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:500;font-family:var(--mono);background:var(--bg4);color:var(--text2);min-height:36px;';
    const okBtn=document.createElement('button');
    okBtn.textContent=okLabel;
    okBtn.style.cssText='padding:8px 20px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:500;font-family:var(--mono);background:var(--accent);color:#000;min-height:36px;';
    btnRow.appendChild(cancelBtn); btnRow.appendChild(okBtn);
    box.appendChild(msgDiv); box.appendChild(btnRow);
    ov.appendChild(box); document.body.appendChild(ov);
    const keyH=(e)=>{
      if(e.key==='Escape'){e.preventDefault();done(false);}
      else if(e.key==='Enter'){e.preventDefault();done(true);}
    };
    function done(val){document.removeEventListener('keydown',keyH,true);ov.remove();resolve(val);}
    cancelBtn.onclick=()=>done(false);
    okBtn.onclick=()=>done(true);
    ov.onclick=(e)=>{if(e.target===ov)done(false);};
    document.addEventListener('keydown',keyH,true);
    setTimeout(()=>okBtn.focus(),50);
  });
}
// customAlert — Promise-based replacement for window.alert(). Non-blocking to
// outside callers but awaitable if they want to wait for dismissal.
function customAlert(message){
  return new Promise(resolve=>{
    const ov=document.createElement('div');
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:10001;display:flex;align-items:center;justify-content:center;padding:20px;';
    const box=document.createElement('div');
    box.style.cssText='background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:20px;width:min(420px,92vw);max-height:min(80vh,80dvh);overflow-y:auto;box-shadow:0 8px 30px rgba(0,0,0,.5);';
    const msgDiv=document.createElement('div');
    msgDiv.style.cssText='color:var(--text);font-size:13px;white-space:pre-wrap;line-height:1.5;margin-bottom:14px;word-break:break-word;';
    msgDiv.textContent=message||'';
    const btnRow=document.createElement('div');
    btnRow.style.cssText='display:flex;justify-content:flex-end;';
    const okBtn=document.createElement('button');
    okBtn.textContent='OK';
    okBtn.style.cssText='padding:8px 24px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:500;font-family:var(--mono);background:var(--accent);color:#000;min-height:36px;';
    btnRow.appendChild(okBtn);
    box.appendChild(msgDiv); box.appendChild(btnRow);
    ov.appendChild(box); document.body.appendChild(ov);
    const keyH=(e)=>{if(e.key==='Escape'||e.key==='Enter'){e.preventDefault();done();}};
    function done(){document.removeEventListener('keydown',keyH,true);ov.remove();resolve();}
    okBtn.onclick=done;
    ov.onclick=(e)=>{if(e.target===ov)done();};
    document.addEventListener('keydown',keyH,true);
    setTimeout(()=>okBtn.focus(),50);
  });
}
async function editTopic(){
  if(!active)return;
  const net=networks.find(n=>n.config.id===active.conn_id);
  const ch=net?.channels.find(c=>c.name===active.target);
  const current=ch?.topic||'';
  const newTopic=await customPrompt('Edit topic for '+active.target+':',current);
  if(newTopic===null)return;
  wsend({type:'send',conn_id:active.conn_id,raw:`TOPIC ${active.target} :${newTopic}`});
}
async function promptJoinChannel(conn_id){
  const ch=await customPrompt('Channel name:');
  if(ch){let c=ch.trim();if(c&&!c.startsWith('#')&&!c.startsWith('&'))c='#'+c;if(c)wsend({type:'join_channel',conn_id,channel:c,key:null});}
}
function copyTopic(){
  if(!active)return;
  const net=networks.find(n=>n.config.id===active.conn_id);
  const ch=net?.channels.find(c=>c.name===active.target);
  const topic=ch?.topic||'';
  if(!topic){showToast('No topic set');return;}
  navigator.clipboard?.writeText(topic).then(()=>showToast('Topic copied'));
}
// Close topic menu on outside click
document.addEventListener('click',e=>{
  if(!e.target.closest('#topic-menu')&&!e.target.closest('#topic-menu-btn')&&!e.target.closest('#topic-inline'))
    closeTopicMenu();
});
function showToast(msg){
  let t=document.getElementById('generic-toast');
  if(!t){
    t=document.createElement('div');t.id='generic-toast';
    // a11y (#91): announce toast text to assistive tech. role=status + aria-live
    // polite makes screen readers read copy/error/status confirmations as they appear.
    t.setAttribute('role','status');t.setAttribute('aria-live','polite');t.setAttribute('aria-atomic','true');
    t.style.cssText='position:fixed;bottom:60px;left:50%;transform:translateX(-50%);background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px 16px;font-size:12px;z-index:9999;opacity:0;transition:opacity .3s;pointer-events:none;';document.body.appendChild(t);
  }
  t.textContent=msg;t.style.opacity='1';
  clearTimeout(t._timer);t._timer=setTimeout(()=>{t.style.opacity='0';},2500);
}

// ─── Mobile sidebar ───────────────────────────────────────────────────────────
function toggleSidebar(){document.getElementById('sidebar').classList.contains('open')?closeSidebar():openSidebar();}
function openSidebar(){
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-backdrop').classList.add('show');
  _overlayOpen('sidebar', closeSidebar);
}
function closeSidebar(){
  _overlayClose('sidebar');
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-backdrop').classList.remove('show');
  // Mobile: viewport settles after sidebar CSS transition. Re-anchor only
  // if the user was already near the bottom.
  setTimeout(()=>scrollBottom(),350);
}
function toggleNickPanel(){
  const np=document.getElementById('nick-panel');
  const bd=document.getElementById('sidebar-backdrop');
  const btn=document.getElementById('nick-toggle');
  const isMobile=window.innerWidth<=768;
  if(isMobile){
    if(np.classList.contains('open')){np.classList.remove('open');bd.classList.remove('show');}
    else{closeSidebar();np.classList.add('open');bd.classList.add('show');}
  } else {
    np.classList.toggle('collapsed');
    const collapsed=np.classList.contains('collapsed');
    const nIcon=document.getElementById('nick-toggle-icon');
    if(nIcon) nIcon.style.transform=collapsed?'rotate(180deg)':'';
    try{localStorage.setItem('cryptirc_nick_collapsed',collapsed?'1':'');}catch(e){}
    savePrefsToServer();
  }
}
function toggleSidebarCollapse(){
  const sb=document.getElementById('sidebar');
  const icon=document.getElementById('sidebar-toggle-icon');
  sb.classList.toggle('collapsed');
  const collapsed=sb.classList.contains('collapsed');
  if(icon) icon.style.transform=collapsed?'rotate(180deg)':'';
  try{localStorage.setItem('cryptirc_sidebar_collapsed',collapsed?'1':'');}catch(e){}
  savePrefsToServer();
}

// ─── Certificate management ───────────────────────────────────────────────────
let _certConnId=null;
function showCertModal(){
  if(!active)return;
  _certConnId=active.conn_id;
  const net=networks.find(n=>n.config.id===_certConnId);
  document.getElementById('cert-conn-label').textContent=net?`Network: ${net.config.label||net.config.server}`:_certConnId;
  document.getElementById('cert-loading').style.display='none';
  if(net?.has_cert&&net?.cert_fingerprint){
    document.getElementById('cert-none-state').style.display='none';
    document.getElementById('cert-has-state').style.display='';
    document.getElementById('cert-fingerprint').textContent=net.cert_fingerprint;
    wsend({type:'get_cert_info',conn_id:_certConnId});
  } else {
    document.getElementById('cert-none-state').style.display='';
    document.getElementById('cert-has-state').style.display='none';
  }
  document.getElementById('cert-modal-overlay').classList.add('open');
  _overlayOpen('certModal', closeCertModal);
}
function closeCertModal(){_overlayClose('certModal');document.getElementById('cert-modal-overlay').classList.remove('open');}
function generateCert(){if(!_certConnId)return;document.getElementById('cert-none-state').style.display='none';document.getElementById('cert-has-state').style.display='none';document.getElementById('cert-loading').style.display='';wsend({type:'generate_cert',conn_id:_certConnId});}
async function deleteCert(){if(!_certConnId)return;if(!(await customConfirm('Delete this certificate?\n\nMake sure to run: /msg NickServ CERT DEL <fingerprint> first.','Delete')))return;wsend({type:'delete_cert',conn_id:_certConnId});document.getElementById('cert-none-state').style.display='';document.getElementById('cert-has-state').style.display='none';const net=networks.find(n=>n.config.id===_certConnId);if(net){net.has_cert=false;net.cert_fingerprint=null;}updateCertBtn();}
function copyCertFp(){const fp=document.getElementById('cert-fingerprint').textContent;if(!fp)return;navigator.clipboard?.writeText(fp).then(()=>{const el=document.getElementById('cert-fingerprint');el.style.color='var(--join)';setTimeout(()=>el.style.color='',1500);});}
function autoCertAdd(){
  const fp=document.getElementById('cert-fingerprint').textContent;
  if(!fp||!_certConnId)return;
  wsend({type:'send',conn_id:_certConnId,raw:`PRIVMSG NickServ :CERT ADD ${fp}`});
  showToast('Sent CERT ADD to NickServ');
  closeCertModal();
}
function onCertInfo(ev){document.getElementById('cert-loading').style.display='none';document.getElementById('cert-none-state').style.display='none';document.getElementById('cert-has-state').style.display='';document.getElementById('cert-fingerprint').textContent=ev.fingerprint;document.getElementById('cert-pem').value=ev.cert_pem;_certConnId=ev.conn_id;const net=networks.find(n=>n.config.id===ev.conn_id);if(net){net.has_cert=true;net.cert_fingerprint=ev.fingerprint;}updateCertBtn();}
function updateCertBtn(){const btn=document.getElementById('cert-menu-btn');if(!btn)return;if(!active){btn.style.display='none';return;}const net=networks.find(n=>n.config.id===active.conn_id);btn.style.display=net?'block':'none';}

// ─── Push Notifications ───────────────────────────────────────────────────────
let _notifPrefs = null;

async function showNotifModal() {
  document.getElementById('notif-modal').classList.add('open');
  _overlayOpen('notifModal', closeNotifModal);
  await loadNotifPrefs();
  renderNotifModal();
  renderNotifNetworkList();
  renderHighlightTags();
  // Populate sound and desktop notification toggles
  const cfg=loadAppearance();
  const spm=document.getElementById('a-sound-pm');
  const smn=document.getElementById('a-sound-mention');
  const dnt=document.getElementById('a-desktop-notif');
  if(spm){cfg.soundPM!==false?spm.classList.add('on'):spm.classList.remove('on');}
  if(smn){cfg.soundMention!==false?smn.classList.add('on'):smn.classList.remove('on');}
  if(dnt){cfg.desktopNotif!==false?dnt.classList.add('on'):dnt.classList.remove('on');}
  const sss=document.getElementById('a-sound-style');
  if(sss){
    sss.innerHTML=NOTIF_SOUNDS.map(s=>`<option value="${esc(s.id)}">${esc(s.label)}</option>`).join('');
    sss.value=cfg.notifSound||'water-drop';
  }
  // Diagnostic status
  const ds=document.getElementById('notif-diag-status');
  if(ds){
    const perm=typeof Notification!=='undefined'?Notification.permission:'unavailable';
    const parts=[
      `API: ${typeof Notification!=='undefined'?'yes':'NO'}`,
      `Permission: ${perm}`,
      `SW: ${swRegistration?'yes':'no'}`,
      `Electron: ${window.electronAPI?.isElectron?'yes':'no'}`,
      `DND: ${isDndActive()?'ON':'off'}`,
      `Desktop popups: ${cfg.desktopNotif!==false?'on':'OFF'}`,
    ];
    ds.textContent=parts.join(' | ');
    ds.style.color=perm==='granted'?'var(--text3)':'#f87171';
  }
  const dl=document.getElementById('notif-diag-log');if(dl){dl.innerHTML='';dl.style.display='none';}
}
function saveHighlightWords(){
  const words=getHighlightWords();
  localStorage.setItem('cryptirc_highlight_words',JSON.stringify(words));
  savePrefsToServer();
  renderHighlightTags();
}
function addHighlightWord(){
  const inp=document.getElementById('notif-highlight-input');
  const word=inp.value.trim().toLowerCase();
  if(!word)return;
  const words=getHighlightWords();
  if(!words.includes(word)){words.push(word);localStorage.setItem('cryptirc_highlight_words',JSON.stringify(words));savePrefsToServer();}
  inp.value='';renderHighlightTags();
}
function removeHighlightWord(word){
  const words=getHighlightWords().filter(w=>w!==word);
  localStorage.setItem('cryptirc_highlight_words',JSON.stringify(words));
  savePrefsToServer();renderHighlightTags();
}
function renderHighlightTags(){
  const c=document.getElementById('highlight-tags');if(!c)return;
  const words=getHighlightWords();
  if(!words.length){c.innerHTML='<span style="font-size:11px;color:var(--text3)">No highlight words set.</span>';return;}
  // SECURITY: highlight words are arbitrary user input. Carry the word in an
  // HTML-attribute-escaped data-hl-word and remove via a delegated listener — never
  // interpolated into an inline-handler JS-string (#10). The attribute decodes back
  // to the exact word for dataset.hlWord.
  c.innerHTML=words.map(w=>`<span class="hl-tag">${esc(w)}<button class="hl-tag-x" data-hl-word="${esc(w)}">&times;</button></span>`).join('');
  if(!c._hlDelegated){
    c._hlDelegated=true;
    c.addEventListener('click',e=>{const b=e.target.closest('.hl-tag-x[data-hl-word]');if(b&&c.contains(b))removeHighlightWord(b.dataset.hlWord);});
  }
}
function closeNotifModal() { _overlayClose('notifModal'); document.getElementById('notif-modal').classList.remove('open'); }

async function loadNotifPrefs() {
  if (!sessionToken) return;
  try {
    const r = await fetch('/cryptirc/push/settings', { headers: {'Authorization': 'Bearer ' + sessionToken} });
    if (r.ok) _notifPrefs = await r.json();
  } catch(e) {}
  if (!_notifPrefs) _notifPrefs = { enabled: false, trigger: 'mentions_and_dms', muted_networks: [], muted_channels: [] };
}

async function saveNotifPrefs() {
  if (!sessionToken || !_notifPrefs) return;
  _notifPrefs.trigger = document.getElementById('notif-trigger').value;
  try {
    await fetch('/cryptirc/push/settings', {
      method: 'PUT',
      headers: {'Authorization':'Bearer '+sessionToken, 'Content-Type':'application/json'},
      body: JSON.stringify(_notifPrefs),
    });
  } catch(e) {}
}

function renderNotifModal() {
  const perm = Notification?.permission || 'default';
  const badge = document.getElementById('notif-status-badge');
  const banner = document.getElementById('notif-permission-banner');
  badge.className = 'notif-status-badge ' + perm;
  badge.textContent = perm === 'granted' ? '⬤ Notifications allowed' : perm === 'denied' ? '⬤ Notifications blocked' : '⬤ Permission not yet granted';

  if (perm === 'denied') {
    banner.className = 'notif-permission-banner show denied';
    banner.textContent = '🚫 Notifications are blocked in your browser settings. To enable them, open your browser settings and allow notifications for this site.';
  } else if (perm === 'default' && _notifPrefs?.enabled) {
    banner.className = 'notif-permission-banner show';
    banner.textContent = '⚠ Notification permission has not been granted. Click Enable to prompt.';
  } else { banner.className = 'notif-permission-banner'; }

  document.getElementById('notif-enabled').checked = !!_notifPrefs?.enabled;
  document.getElementById('notif-trigger').value = _notifPrefs?.trigger || 'mentions_and_dms';
  document.getElementById('notif-test-btn').disabled = !_notifPrefs?.enabled || perm !== 'granted';
}

function renderNotifNetworkList() {
  const list = document.getElementById('notif-network-list');
  if (!networks.length) { list.innerHTML = '<div style="color:var(--text3);font-size:12px;">Connect to networks to configure per-network settings.</div>'; return; }
  list.innerHTML = '';
  for (const net of networks) {
    const muted = _notifPrefs?.muted_networks?.includes(net.config.id);
    const row = document.createElement('div'); row.className = 'notif-row';
    row.innerHTML = `
      <div style="flex:1">
        <div class="notif-label">${esc(net.config.label||net.config.server)}</div>
        <div class="notif-sublabel">${net.connected ? '● Connected' : '○ Disconnected'}</div>
      </div>
      <label class="toggle toggle-wrap">
        <input type="checkbox" ${muted?'':'checked'} onchange="toggleMuteNetwork('${net.config.id}',this)">
        <span class="toggle-track"><span class="toggle-thumb"></span></span>
      </label>`;
    list.appendChild(row);
  }
}

function saveNotifSoundPrefs(){
  // Save sound/desktop notif settings without touching theme sliders
  const cfg=loadAppearance();
  const spm=document.getElementById('a-sound-pm');
  const smn=document.getElementById('a-sound-mention');
  const dnt=document.getElementById('a-desktop-notif');
  if(spm) cfg.soundPM=spm.classList.contains('on');
  if(smn) cfg.soundMention=smn.classList.contains('on');
  if(dnt) cfg.desktopNotif=dnt.classList.contains('on');
  const sss=document.getElementById('a-sound-style');
  if(sss) cfg.notifSound=sss.value||'water-drop';
  saveAppearance(cfg);
  applyThemeCSS(cfg);
  // Preview the newly-selected sound so the user hears it immediately.
  if(sss) previewNotifSound(cfg.notifSound);
}

async function toggleDesktopNotif() {
  const on=document.getElementById('a-desktop-notif').classList.contains('on');
  if(on && Notification?.permission!=='granted'){
    const perm=await Notification.requestPermission?.();
    if(perm!=='granted'){
      document.getElementById('a-desktop-notif').classList.remove('on');
      return;
    }
  }
  saveNotifSoundPrefs();
}

async function onNotifToggle() {
  const checked = document.getElementById('notif-enabled').checked;
  if (checked) {
    // Request permission
    const perm = await Notification.requestPermission?.();
    if (perm !== 'granted') {
      document.getElementById('notif-enabled').checked = false;
      renderNotifModal(); return;
    }
    await subscribePush();
    _notifPrefs.enabled = true;
  } else {
    await unsubscribePush();
    _notifPrefs.enabled = false;
  }
  await saveNotifPrefs();
  renderNotifModal();
}

async function toggleMuteNetwork(conn_id, checkbox) {
  if (!_notifPrefs) return;
  if (!checkbox.checked) {
    if (!_notifPrefs.muted_networks.includes(conn_id)) _notifPrefs.muted_networks.push(conn_id);
  } else {
    _notifPrefs.muted_networks = _notifPrefs.muted_networks.filter(id => id !== conn_id);
  }
  await saveNotifPrefs();
}

async function subscribePush() {
  if (!swRegistration) return;
  try {
    // Get VAPID public key
    const r = await fetch('/cryptirc/push/vapid-public-key');
    if (!r.ok) return;
    const vapidData = await r.json();
    const appServerKey = urlBase64ToUint8Array(vapidData.publicKey || vapidData.public_key);

    pushSubscription = await swRegistration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: appServerKey,
    });
    // Send subscription to server
    await fetch('/cryptirc/push/subscribe', {
      method: 'POST',
      headers: {'Authorization':'Bearer '+sessionToken, 'Content-Type':'application/json'},
      body: JSON.stringify({ ...pushSubscription.toJSON(), label: navigator.userAgent.slice(0,80) }),
    });
  } catch(e) { console.warn('Push subscribe failed:', e); }
}

async function unsubscribePush() {
  if (!pushSubscription) {
    // Try to get existing subscription
    if (swRegistration) pushSubscription = await swRegistration.pushManager.getSubscription();
  }
  if (!pushSubscription) return;
  try {
    await fetch('/cryptirc/push/subscribe', {
      method: 'DELETE',
      headers: {'Authorization':'Bearer '+sessionToken, 'Content-Type':'application/json'},
      body: JSON.stringify({ endpoint: pushSubscription.endpoint }),
    });
    await pushSubscription.unsubscribe();
    pushSubscription = null;
  } catch(e) { console.warn('Push unsubscribe failed:', e); }
}

async function reregisterPushSubscription(subJSON) {
  if (!sessionToken) return;
  try {
    await fetch('/cryptirc/push/subscribe', {
      method: 'POST',
      headers: {'Authorization':'Bearer '+sessionToken, 'Content-Type':'application/json'},
      body: JSON.stringify({ ...subJSON, label: navigator.userAgent.slice(0,80) }),
    });
  } catch(e) {}
}

function notifDiagLog(msg,ok){
  const el=document.getElementById('notif-diag-log');
  if(!el)return;
  el.style.display='block';
  const line=document.createElement('div');
  line.style.color=ok===true?'#4ade80':ok===false?'#f87171':'var(--text3)';
  line.textContent=(ok===true?'OK ':'ERR ')+msg;
  el.appendChild(line);
  el.scrollTop=el.scrollHeight;
}
function notifDiagClear(){
  const el=document.getElementById('notif-diag-log');if(el){el.innerHTML='';el.style.display='block';}
}
async function notifDiagTest(type){
  notifDiagClear();
  const log=notifDiagLog;
  // Status
  log(`Notification API: ${typeof Notification!=='undefined'?'yes':'NO'}`);
  if(typeof Notification==='undefined'){log('FATAL: Notification API not available',false);return;}
  log(`Permission: ${Notification.permission}`,Notification.permission==='granted');
  if(Notification.permission==='denied'){log('Notifications BLOCKED by browser/OS — go to browser settings to allow',false);return;}
  if(Notification.permission==='default'){
    log('Permission not granted — requesting...');
    try{const r=await Notification.requestPermission();log(`Permission result: ${r}`,r==='granted');if(r!=='granted')return;}catch(e){log(`Request failed: ${e}`,false);return;}
  }
  log(`SW registered: ${swRegistration?'yes':'no'}`);
  log(`Electron: ${window.electronAPI?.isElectron?'yes':'no'}`);
  log(`DND active: ${isDndActive()}`);
  const cfg=loadAppearance();
  log(`desktopNotif setting: ${cfg.desktopNotif!==false?'on':'OFF'}`,cfg.desktopNotif!==false);

  if(type==='sound-pm'){log('Playing PM sound...');_lastSoundAt=0;playNotifSound('pm');log('Sound played',true);return;}
  if(type==='sound-mention'){log('Playing mention sound...');_lastSoundAt=0;playNotifSound('mention');log('Sound played',true);return;}

  if(type==='sw'){
    if(!swRegistration){log('No service worker registration',false);return;}
    log('Calling swRegistration.showNotification...');
    try{
      await swRegistration.showNotification('CryptIRC — SW Test',{body:'Service Worker notification',icon:'/cryptirc/icon-192.png',tag:'diag-sw-'+Date.now(),renotify:true,requireInteraction:true});
      log('SW showNotification resolved — check if popup appeared',true);
    }catch(e){log(`SW showNotification FAILED: ${e}`,false);}
    return;
  }

  const opts={body:'Test notification from CryptIRC',icon:'/cryptirc/icon-192.png'};
  let label='';
  if(type==='basic'){label='Basic (no options)';}
  if(type==='tagged'){opts.tag='diag-tag-'+Date.now();label='With tag';}
  if(type==='sticky'){opts.tag='diag-sticky-'+Date.now();opts.requireInteraction=true;label='Sticky (requireInteraction:true)';}
  if(type==='silent'){opts.tag='diag-silent-'+Date.now();opts.silent=true;label='Silent (silent:true)';}

  log(`Testing: ${label}...`);
  log(`Options: ${JSON.stringify(opts)}`);

  // Electron: use native IPC notification
  if(window.electronAPI?.isElectron){
    log('Using Electron native notification via IPC...');
    try{
      window.electronAPI.showNotification('CryptIRC — '+label,opts.body);
      log('IPC sent — check if popup appeared',true);
    }catch(e){log(`Electron IPC failed: ${e}`,false);}
    return;
  }

  // Browser: use Web Notification API
  try{
    const n=new Notification('CryptIRC — '+label,opts);
    n.onshow=()=>log('onshow fired — notification VISIBLE',true);
    n.onerror=(e)=>log(`onerror fired: ${e.type||e}`,false);
    n.onclick=()=>{log('Clicked!',true);n.close();};
    setTimeout(()=>{
      if(type!=='sticky')n.close();
      log('Test complete — did you see a popup?');
    },10000);
  }catch(e){log(`new Notification THREW: ${e}`,false);}
}
async function sendTestNotification() {
  if (!sessionToken) return;
  if (!pushSubscription) {
    showToast('No push subscription — enable notifications first');
    return;
  }
  try {
    const r = await fetch('/cryptirc/push/test', {method:'POST', headers:{'Authorization':'Bearer '+sessionToken}});
    if (r.ok) showToast('Test notification sent!');
    else showToast('Test failed — try disabling and re-enabling notifications');
  } catch(e) { showToast('Test notification failed'); }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

// ─── PWA ─────────────────────────────────────────────────────────────────────
async function registerPwa() {
  if ('serviceWorker' in navigator) {
    try {
      swRegistration = await navigator.serviceWorker.register('/cryptirc/sw.js', {scope: '/cryptirc/'});
      // Check if already subscribed
      pushSubscription = await swRegistration.pushManager.getSubscription();
      // If the user has enabled notifications but we have no subscription, re-subscribe
      await loadNotifPrefs();
      if (_notifPrefs?.enabled && !pushSubscription && Notification.permission === 'granted') {
        await subscribePush();
      }
    } catch(e) { console.warn('SW registration failed:', e); }
  }
}

// ─── Command helpers ──────────────────────────────────────────────────────────

// IRC servers allow at most 4-6 mode changes per MODE command.
// We use 4 to be safe across all server types.
const MODE_BATCH = 4;

/**
 * Send batched MODE commands.
 * e.g. batchMode(id, '#ch', '+v', ['a','b','c','d','e'])
 * sends: MODE #ch +vvvv a b c d
 *        MODE #ch +v e
 */
function batchMode(conn_id, channel, modeChar, nicks) {
  const sign   = modeChar[0];   // + or -
  const letter = modeChar[1];   // o v h a q etc.
  for (let i = 0; i < nicks.length; i += MODE_BATCH) {
    const batch  = nicks.slice(i, i + MODE_BATCH);
    const modes  = sign + letter.repeat(batch.length);
    const cmd    = `MODE ${channel} ${modes} ${batch.join(' ')}`;
    // Stagger batches by 300ms to avoid server flood triggers
    setTimeout(() => wsend({type:'send', conn_id, raw: cmd}), (i / MODE_BATCH) * 300);
  }
}

// ── Nick list accessors ───────────────────────────────────────────────────────

function getChannelNicksByTarget(conn_id, channel) {
  const net = networks.find(n => n.config.id === conn_id);
  const ch  = net?.channels.find(c => c.name === channel);
  if (!ch) return [];
  // Return bare nicks (strip prefix)
  return ch.names.map(n => stripPfx(n));
}

function getChannelOps(conn_id, channel) {
  const net = networks.find(n => n.config.id === conn_id);
  const ch  = net?.channels.find(c => c.name === channel);
  if (!ch) return [];
  return ch.names.filter(n => n.startsWith('@')).map(n => stripPfx(n));
}

function getChannelNonOps(conn_id, channel) {
  const self = getNick(conn_id);
  const net  = networks.find(n => n.config.id === conn_id);
  const ch   = net?.channels.find(c => c.name === channel);
  if (!ch) return [];
  return ch.names
    .filter(n => !n.startsWith('@') && !n.startsWith('~') && !n.startsWith('&'))
    .map(n => stripPfx(n))
    .filter(n => n !== self);
}

function getChannelVoiced(conn_id, channel) {
  const net = networks.find(n => n.config.id === conn_id);
  const ch  = net?.channels.find(c => c.name === channel);
  if (!ch) return [];
  return ch.names.filter(n => n.startsWith('+')).map(n => stripPfx(n));
}

function getChannelNonVoiced(conn_id, channel) {
  const self = getNick(conn_id);
  const net  = networks.find(n => n.config.id === conn_id);
  const ch   = net?.channels.find(c => c.name === channel);
  if (!ch) return [];
  // Non-voiced = no + prefix AND no op/owner prefix (they already have >= voice)
  return ch.names
    .filter(n => !n.startsWith('+') && !n.startsWith('@') && !n.startsWith('~') && !n.startsWith('&') && !n.startsWith('%'))
    .map(n => stripPfx(n))
    .filter(n => n !== self);
}

// ── Jump to a specific message (used by notification clicks, search, mentions) ────
// Pending nav intent from a notification click — executed when networks are loaded.
let _pendingNotifNav = null;

function jumpToMessage(conn_id, target, ts, from){
  if(!conn_id || !target) return;
  // If networks haven't loaded yet (cold start from notification), stash the
  // intent and let the state handler retry once state arrives.
  if(!networks || networks.length === 0){
    _pendingNotifNav = {conn_id, target, ts, from};
    return;
  }
  const net = networks.find(n => n.config.id === conn_id);
  if(!net){
    // Network not available — stash and retry later
    _pendingNotifNav = {conn_id, target, ts, from};
    return;
  }
  setActive(conn_id, target);
  const tsNum = (ts!=null && ts!=='') ? parseInt(ts,10) : null;

  // Scan the rendered DOM for the target row. Matches on timestamp and, when a
  // sender is known, on the row's `from` OR its rendered nick text (covers
  // prefix/case quirks) so a correct row isn't rejected over a cosmetic diff.
  const flash = el => { el.classList.add('flash'); setTimeout(()=>el.classList.remove('flash'), 3000); };
  // Reveal + scroll to a row. Status messages (join/part/quit/nick/mode/…) are
  // rendered as hidden children inside a collapsed `.status-condensed` block —
  // they DO carry data-ts (built via buildRow) so the scan below matches them,
  // but scrollIntoView on a display:none element does nothing. Expand the parent
  // block first so the target is actually visible.
  const reveal = r => {
    const cond = r.closest('.status-condensed');
    if(cond) cond.classList.add('expanded');
    // Instant jump (behavior:'auto'), not a slow smooth-scroll animation — the
    // user wants to land on the message immediately.
    r.scrollIntoView({behavior:'auto', block:'center'});
    flash(r);
  };
  const tryFind = ()=>{
    for(const r of document.querySelectorAll('.msg-row')){
      if(r.dataset.ts !== String(ts)) continue;
      if(from){
        const nickEl = r.querySelector('.msg-nick');
        const nickText = nickEl ? stripPfx(nickEl.textContent.trim().replace(/^\* /,'')) : '';
        if(r.dataset.from !== from && nickText !== from) continue;
      }
      reveal(r);
      return true;
    }
    return false;
  };

  // If the target isn't in the currently-loaded buffer, load the exact history
  // window that contains it — get_logs before:(ts+1) returns the most-recent
  // chunk of messages with ts <= target, so the target is guaranteed to be the
  // newest message in that set. This reaches ANY depth in a single request and
  // puts the channel into "history view" (see _enterHistoryView). One shot — no
  // chunk-by-chunk paging, no depth cap.
  const lk = conn_id + '/' + target;
  const POLL = 100;          // fast re-check so we scroll the instant the window lands
  const PEND_MAX = 12000;    // a pending log request older than this is presumed lost
  const OFFLINE_MAX = 6000;  // max wait for the socket to (re)connect before giving up
  let windowLoaded = false;  // have we already loaded the focused window this jump?
  let noTsElapsed = 0;       // ms spent scanning when we have no ts to anchor on
  let offlineWaited = 0;     // ms spent waiting for the socket to come back

  const tick = ()=>{
    // User navigated away while we were working — abandon quietly.
    if(!isActive(conn_id, target)) return;
    if(tryFind()) return;

    // A log chunk (initial load or the window we asked for) is still in flight.
    // A genuinely young request is worth waiting for (huge channels take seconds
    // to decrypt), but a response can be silently dropped on iOS (WS zombie),
    // stranding the key in _pendingLogs forever and hanging this tick. Tell them
    // apart by the send-time: wait while the request is young; once it's older
    // than PEND_MAX it's presumed lost — drop it and proceed so a jump can never
    // hang. (_pendingLogs is a Map of key -> send-time for exactly this.)
    if(_pendingLogs.has(lk)){
      const sentAt = _pendingLogs.get(lk) || 0;
      if(Date.now() - sentAt < PEND_MAX){ setTimeout(tick, POLL); return; }
      _pendingLogs.delete(lk);
    }

    // No timestamp to anchor on — just scan for a few seconds while the initial
    // load streams in, then give up silently (keeps old no-ts callers working).
    if(tsNum == null){
      noTsElapsed += POLL;
      if(noTsElapsed < 4000) setTimeout(tick, POLL);
      return;
    }

    if(!windowLoaded){
      // Need a live socket to fetch the window. If we're mid-reconnect, wait a
      // bounded time for it to come back (the jump self-heals on reconnect)
      // rather than failing immediately. Don't tear down the buffer until we can
      // actually fetch — that would leave an empty channel.
      if(!(ws && ws.readyState===1)){
        offlineWaited += POLL;
        if(offlineWaited < OFFLINE_MAX){ setTimeout(tick, POLL); return; }
        showToast('Not connected — try again in a moment');
        return;
      }
      // Replace the buffer with the focused window around the target and enter
      // history view. wsend() registers lk in _pendingLogs, so the next tick
      // waits (bounded) for the window to land before scanning again.
      windowLoaded = true;
      _enterHistoryView(conn_id, target);
      getBuf(conn_id, target).length = 0;
      wsend({type:'get_logs', conn_id, target, limit:300, before:tsNum + 1});
      setTimeout(tick, POLL);
      return;
    }
    // Window loaded and its response processed, but the target still isn't
    // present → it's genuinely gone (deleted/cleared). Leave the user in the
    // window we loaded.
    showToast('Message no longer in history');
  };

  // setActive renders synchronously; a short beat lets the DOM settle, then go.
  setTimeout(tick, 60);
}

// ── History view: the active buffer holds a focused window from the past (loaded
// by jumpToMessage) rather than the live tail. A banner lets the user return to
// present, and addMessage suppresses live messages from grafting onto the window.
// State var `_historyView` is declared up near `buffers` to avoid any TDZ.
function _enterHistoryView(conn_id, target){
  _historyView = { bk: bk(conn_id, target), conn_id, target };
}
function _exitHistoryView(){
  if(!_historyView) return;
  const { conn_id, target } = _historyView;
  _historyView = null;
  getBuf(conn_id, target).length = 0;       // drop the historical window
  _lastMsgId[bk(conn_id, target)] = 0;      // force a fresh present load, not a sync
  if(isActive(conn_id, target)){
    renderChat();                            // clear the stale window + banner now
    wsend({type:'get_logs', conn_id, target, limit:200}); // prependLogs scrolls to bottom
  }
}

// Called by the state handler once networks are loaded, to drain any pending nav.
function _drainPendingNotifNav(){
  if(!_pendingNotifNav) return;
  const p = _pendingNotifNav;
  _pendingNotifNav = null;
  jumpToMessage(p.conn_id, p.target, p.ts, p.from);
}

// Reads SW-cached notification click intent (fallback for when postMessage is
// lost due to iOS PWA wake races / Electron reloads). Safe to call repeatedly.
async function _readNotifClickCache(){
  if(!('caches' in self)) return;
  try{
    const cache = await caches.open('cryptirc-notif-intent');
    const resp = await cache.match('/__notif_click__');
    if(!resp) return;
    const data = await resp.json();
    // Only honor recent intents (within 60 seconds) to avoid stale navigation
    if(!data.t || Date.now()-data.t > 60000){ await cache.delete('/__notif_click__'); return; }
    await cache.delete('/__notif_click__');
    if(data.conn_id && data.target){
      _pendingNotifNav = {conn_id:data.conn_id, target:data.target, ts:data.ts?parseInt(data.ts)||data.ts:null, from:data.from||null};
      if(networks && networks.length) _drainPendingNotifNav();
    }
  }catch(e){}
}

// ── PM allow list + per-network settings ─────────────────────────────────────
let pmAllowList = new Set((()=>{try{return JSON.parse(localStorage.getItem('cryptirc_pm_allow')||'[]');}catch{return[];}})());
function savePmAllow(){localStorage.setItem('cryptirc_pm_allow',JSON.stringify([...pmAllowList]));localStorage.setItem('cryptirc_pm_allow_ts',String(Date.now()));savePrefsToServer();}

// Per-network overrides: {[conn_id]: {override:bool, enabled, cooldown, notify, deliverFirst, allowList:[]}}
function loadPmNet(){try{return JSON.parse(localStorage.getItem('cryptirc_pm_net')||'{}');}catch{return{};}}
function savePmNet(obj){localStorage.setItem('cryptirc_pm_net',JSON.stringify(obj));localStorage.setItem('cryptirc_pm_net_ts',String(Date.now()));savePrefsToServer();}

// Blocked PMs log — capped at 100 most recent to prevent flood
const PM_BLOCKED_MAX = 100;
function loadPmBlocked(){try{const a=JSON.parse(localStorage.getItem('cryptirc_pm_blocked')||'[]');return Array.isArray(a)?a:[];}catch{return[];}}
function savePmBlocked(arr){
  if(arr.length>PM_BLOCKED_MAX) arr=arr.slice(-PM_BLOCKED_MAX);
  localStorage.setItem('cryptirc_pm_blocked',JSON.stringify(arr));
  savePrefsToServer();
}
function recordBlockedPm(conn_id, from, text, ts){
  const arr=loadPmBlocked();
  arr.push({
    conn_id: String(conn_id||''),
    from:    String(from||''),
    text:    String(text||'').slice(0,500),
    ts:      ts||Math.floor(Date.now()/1000),
  });
  savePmBlocked(arr);
}
function clearPmBlocked(){localStorage.setItem('cryptirc_pm_blocked','[]');savePrefsToServer();}

// Returns effective PM protection settings for a network (network override OR global)
function getPmSettings(conn_id){
  const net=loadPmNet();
  const n=conn_id?net[conn_id]:null;
  if(n&&n.override){
    return {
      enabled:       !!n.enabled,
      cooldown:      parseInt(n.cooldown||24),
      notify:        n.notify!==false,
      deliverFirst:  n.deliverFirst!==false,
      source:        'network',
    };
  }
  return {
    enabled:      localStorage.getItem('cryptirc_block_pms')==='true',
    cooldown:     parseInt(localStorage.getItem('cryptirc_pm_cooldown')||'24'),
    notify:       localStorage.getItem('cryptirc_pm_notify')!=='false',
    deliverFirst: localStorage.getItem('cryptirc_pm_deliver_first')!=='false',
    source:       'global',
  };
}
// Returns true if the nick is allowed for this network.
// Network override allow list takes priority; otherwise falls through to global list.
function isPmAllowedFor(conn_id, nick){
  const ln=String(nick).toLowerCase();
  const net=loadPmNet();
  const n=conn_id?net[conn_id]:null;
  if(n&&n.override&&Array.isArray(n.allowList)){
    return n.allowList.some(x=>String(x).toLowerCase()===ln);
  }
  return pmAllowList.has(ln);
}
// Adds/removes nick from the effective list (network override if present, else global)
function addPmAllow(nick, conn_id){
  const ln=String(nick).toLowerCase();
  if(conn_id){
    const net=loadPmNet();
    const n=net[conn_id];
    if(n&&n.override){
      n.allowList=Array.isArray(n.allowList)?n.allowList:[];
      if(!n.allowList.includes(ln)) n.allowList.push(ln);
      savePmNet(net);
      return;
    }
  }
  pmAllowList.add(ln);
  savePmAllow();
}
function removePmAllow(nick, conn_id){
  const ln=String(nick).toLowerCase();
  if(conn_id){
    const net=loadPmNet();
    const n=net[conn_id];
    if(n&&n.override){
      if(Array.isArray(n.allowList)) n.allowList=n.allowList.filter(x=>String(x).toLowerCase()!==ln);
      savePmNet(net);
      return;
    }
  }
  pmAllowList.delete(ln);
  savePmAllow();
}
function isPmAllowed(nick){return pmAllowList.has(String(nick).toLowerCase());}

// ── Client-side ignore list ───────────────────────────────────────────────────

let ignoreList = new Set(JSON.parse(localStorage.getItem('cryptirc_ignore') || '[]'));

// Tracks in-progress /unbanall requests: "conn_id/channel" → [mask, mask, ...]
const pendingUnbanAll = {};
const banListAccum    = {}; // "conn_id/channel" → [mask, ...]

function addIgnore(mask) {
  ignoreList.add(mask.toLowerCase());
  localStorage.setItem('cryptirc_ignore', JSON.stringify([...ignoreList]));
  savePrefsToServer();
}
function removeIgnore(mask) {
  ignoreList.delete(mask.toLowerCase());
  localStorage.setItem('cryptirc_ignore', JSON.stringify([...ignoreList]));
  savePrefsToServer();
}
function showIgnorePanel(){
  const ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:flex;align-items:center;justify-content:center;padding:16px;';
  const box=document.createElement('div');
  box.style.cssText='background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:min(400px,94vw);max-height:min(80vh,80dvh);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6);';
  function render(){
    const list=[...ignoreList].sort();
    let html=`<div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <span style="font-weight:700;font-size:14px;color:var(--text)">🚫 Ignored Users</span>
      <span onclick="this.closest('[style*=fixed]').remove()" style="cursor:pointer;color:var(--text3);font-size:18px">✕</span>
    </div>
    <div style="padding:12px 20px;overflow-y:auto;flex:1;-webkit-overflow-scrolling:touch">
      <div style="display:flex;gap:6px;margin-bottom:12px">
        <input id="ignore-add-input" placeholder="nick, nick!*@host, *!*@*.isp.com" style="flex:1;padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:13px;outline:none">
        <button onclick="const inp=document.getElementById('ignore-add-input');if(inp.value.trim()){addIgnore(inp.value.trim());inp.value='';this.closest('[style*=fixed]').remove();showIgnorePanel();}" style="padding:6px 12px;background:var(--accent);color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:700;font-size:13px">Add</button>
      </div>`;
    if(!list.length){
      html+=`<div style="color:var(--text3);text-align:center;padding:20px 0;font-size:13px">No ignored users</div>`;
    } else {
      html+=`<div id="ignore-panel-list">`;
      for(const nick of list){
        // SECURITY: the ignore mask is arbitrary user input. Carry it in an
        // HTML-attribute-escaped data-ignore-rm and remove via the delegated box
        // listener (re-renders the panel) instead of an inline-handler JS-string (#10).
        html+=`<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:13px;color:var(--text);font-family:var(--mono)">${esc(nick)}</span>
          <button data-ignore-rm="${esc(nick)}" style="padding:3px 10px;background:none;border:1px solid var(--error);color:var(--error);border-radius:4px;cursor:pointer;font-size:11px">Remove</button>
        </div>`;
      }
      html+=`</div>`;
    }
    html+=`</div>`;
    box.innerHTML=html;
  }
  render();
  // Delegated remove handler (see render(): buttons carry data-ignore-rm). Bound
  // once on the stable box element; re-renders after removal to update the list.
  box.addEventListener('click',e=>{const b=e.target.closest('[data-ignore-rm]');if(b&&box.contains(b)){removeIgnore(b.dataset.ignoreRm);render();}});
  ov.appendChild(box);
  ov.onclick=e=>{if(e.target===ov)ov.remove();};
  document.body.appendChild(ov);
  // Handle Enter key in add input
  setTimeout(()=>{
    const inp=document.getElementById('ignore-add-input');
    if(inp){
      inp.focus();
      inp.addEventListener('keydown',e=>{
        if(e.key==='Enter'&&inp.value.trim()){
          addIgnore(inp.value.trim());inp.value='';render();
        }
      });
    }
  },100);
}

// Tracks which "scope" the PM Protection panel is currently showing: null = Global, or conn_id
let _pmPanelScope = null;

// Mutates the per-network override for a conn_id, creating it if needed
function pmNetPatch(conn_id, patch){
  const net=loadPmNet();
  if(!net[conn_id]) net[conn_id]={override:false,enabled:false,cooldown:24,notify:true,deliverFirst:true,allowList:[]};
  Object.assign(net[conn_id], patch);
  savePmNet(net);
}

function showPmProtectionPanel(){
  const ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1100;display:flex;align-items:center;justify-content:center;padding:16px;';
  const box=document.createElement('div');
  box.style.cssText='background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:min(460px,94vw);max-height:min(88vh,88dvh);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6);';

  function render(){
    // Determine scope values
    const scope=_pmPanelScope; // null = global, else conn_id
    const isGlobal=scope===null;
    const pmNet=loadPmNet();
    const netData=(!isGlobal&&pmNet[scope])?pmNet[scope]:null;
    const overriding=!isGlobal&&!!(netData&&netData.override);

    // Values being edited
    let enabled, cooldown, notify, deliverFirst, list;
    if(isGlobal){
      enabled=localStorage.getItem('cryptirc_block_pms')==='true';
      cooldown=parseInt(localStorage.getItem('cryptirc_pm_cooldown')||'24');
      notify=localStorage.getItem('cryptirc_pm_notify')!=='false';
      deliverFirst=localStorage.getItem('cryptirc_pm_deliver_first')!=='false';
      list=[...pmAllowList].sort();
    } else if(overriding){
      enabled=!!netData.enabled;
      cooldown=parseInt(netData.cooldown||24);
      notify=netData.notify!==false;
      deliverFirst=netData.deliverFirst!==false;
      list=(Array.isArray(netData.allowList)?[...netData.allowList]:[]).sort();
    } else {
      enabled=false;cooldown=24;notify=true;deliverFirst=true;list=[];
    }

    // Build network selector options
    let selOpts=`<option value="__global__">🌐 Global (default)</option>`;
    for(const n of networks){
      const id=n.config.id;
      const label=n.config.label||n.config.server||id;
      const hasOverride=pmNet[id]&&pmNet[id].override;
      selOpts+=`<option value="${esc(id)}"${scope===id?' selected':''}>${esc(label)}${hasOverride?' ✱':''}</option>`;
    }

    let html=`<div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-shrink:0">
      <span style="font-weight:700;font-size:14px;color:var(--text)">🛡 PM Protection</span>
      <span onclick="this.closest('[style*=fixed]').remove()" style="cursor:pointer;color:var(--text3);font-size:18px">✕</span>
    </div>
    <div style="padding:14px 20px;overflow-y:auto;flex:1;-webkit-overflow-scrolling:touch">

      <div style="margin-bottom:14px">
        <label style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;display:block;margin-bottom:6px">Settings Scope</label>
        <select id="pm-prot-scope" style="width:100%;padding:8px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:13px;outline:none">
          ${selOpts}
        </select>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">${isGlobal?'Default rules applied to all networks unless overridden.':'Per-network rules — overrides Global when enabled.'}</div>
      </div>`;

    if(!isGlobal){
      html+=`<div style="margin-bottom:14px;padding:12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div>
            <div style="font-size:13px;color:var(--text);font-weight:600">Override global for this network</div>
            <div style="font-size:11px;color:var(--text3);margin-top:2px">${overriding?'Using custom settings below':'Using global defaults'}</div>
          </div>
          <button class="appear-toggle${overriding?' on':''}" id="pm-prot-override"></button>
        </div>
      </div>`;
    }

    if(isGlobal || overriding){
      html+=`<div style="margin-bottom:14px;padding:12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
          <span style="font-size:13px;color:var(--text);font-weight:600">Enable PM Protection</span>
          <button class="appear-toggle${enabled?' on':''}" id="pm-prot-enable"></button>
        </div>
        <div style="font-size:11px;color:var(--text3)">When enabled, strangers DMing you will be blocked based on the rules below.</div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">Options</div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px 8px 0 0;border-bottom:none">
          <div>
            <div style="font-size:12px;color:var(--text);font-weight:500">Cooldown</div>
            <div style="font-size:10px;color:var(--text3)">How long to block repeat DMs from the same user</div>
          </div>
          <select id="pm-prot-cooldown" style="background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:11px;padding:4px 6px;font-family:var(--mono)">
            <option value="1">1 hour</option>
            <option value="6">6 hours</option>
            <option value="12">12 hours</option>
            <option value="24">24 hours</option>
            <option value="72">3 days</option>
            <option value="168">7 days</option>
          </select>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--bg2);border:1px solid var(--border);border-bottom:none">
          <div>
            <div style="font-size:12px;color:var(--text);font-weight:500">Notify sender</div>
            <div style="font-size:10px;color:var(--text3)">Send a NOTICE explaining why they were blocked</div>
          </div>
          <button class="appear-toggle${notify?' on':''}" id="pm-prot-notify"></button>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:0 0 8px 8px">
          <div>
            <div style="font-size:12px;color:var(--text);font-weight:500">Deliver first message</div>
            <div style="font-size:10px;color:var(--text3)">Let the first message through, drop the rest during cooldown</div>
          </div>
          <button class="appear-toggle${deliverFirst?' on':''}" id="pm-prot-deliver"></button>
        </div>
      </div>

      <div>
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">${isGlobal?'Global Allow List':'Network Allow List'} <span style="color:var(--text3);font-weight:400;text-transform:none;font-size:10px">— these users bypass protection</span></div>
        <div style="display:flex;gap:6px;margin-bottom:10px">
          <input id="pm-allow-input" placeholder="nick" style="flex:1;padding:8px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:13px;outline:none">
          <button id="pm-allow-add-btn" style="padding:8px 14px;background:var(--accent);color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:700;font-size:13px">+ Add</button>
        </div>
        <!-- allow list items rendered via DOM API below -->
        <div id="pm-allow-list-holder"></div>
      </div>`;
    } else {
      html+=`<div style="padding:24px;background:var(--bg2);border:1px dashed var(--border);border-radius:8px;text-align:center;color:var(--text3);font-size:12px">
        <div style="margin-bottom:6px;font-size:24px">🌐</div>
        This network is using <b style="color:var(--text)">Global</b> settings.<br>
        Toggle "Override global" above to customize.
      </div>`;
    }

    // ── Recent Blocked Messages (always visible, read-only audit log) ──
    const blocked=loadPmBlocked();
    const blockedFiltered=isGlobal?blocked:blocked.filter(b=>b.conn_id===scope);
    const blockedShow=[...blockedFiltered].reverse();
    html+=`<div style="margin-top:16px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.08em">Recent Blocked Messages <span style="color:var(--text3);font-weight:400;text-transform:none;font-size:10px">— max ${PM_BLOCKED_MAX}, scrollable</span></div>
        ${blockedShow.length?`<button id="pm-blocked-clear" style="padding:3px 8px;background:none;border:1px solid var(--border);color:var(--text3);border-radius:4px;cursor:pointer;font-size:10px">Clear</button>`:''}
      </div>
      <!-- blocked list rendered via DOM API below -->
      <div id="pm-blocked-list-holder"></div>
    </div>`;

    html+=`</div>`;
    box.innerHTML=html;

    // ── DOM-API render of the allow list (safe for any character) ──
    if(isGlobal || overriding){
      const allowHolder=box.querySelector('#pm-allow-list-holder');
      if(allowHolder){
        allowHolder.innerHTML='';
        if(!list.length){
          const empty=document.createElement('div');
          empty.style.cssText='color:var(--text3);text-align:center;padding:20px 0;font-size:13px;background:var(--bg2);border:1px dashed var(--border);border-radius:6px';
          empty.textContent='No users in allow list';
          allowHolder.appendChild(empty);
        } else {
          const listWrap=document.createElement('div');
          listWrap.id='pm-allow-list';
          listWrap.style.cssText='max-height:220px;overflow-y:auto;-webkit-overflow-scrolling:touch;background:var(--bg2);border:1px solid var(--border);border-radius:6px';
          for(const nick of list){
            const row=document.createElement('div');
            row.style.cssText='display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-bottom:1px solid var(--border)';
            const label=document.createElement('span');
            label.style.cssText='font-size:13px;color:var(--text);font-family:var(--mono);word-break:break-all';
            label.textContent='✓ '+nick;
            const rm=document.createElement('button');
            rm.style.cssText='padding:3px 10px;background:none;border:1px solid var(--error);color:var(--error);border-radius:4px;cursor:pointer;font-size:11px;flex-shrink:0';
            rm.textContent='Remove';
            ((n)=>{
              rm.addEventListener('click',()=>{
                if(isGlobal){pmAllowList.delete(n.toLowerCase());savePmAllow();}
                else {
                  const pn=loadPmNet();
                  if(pn[_pmPanelScope]&&Array.isArray(pn[_pmPanelScope].allowList)){
                    pn[_pmPanelScope].allowList=pn[_pmPanelScope].allowList.filter(x=>String(x).toLowerCase()!==n.toLowerCase());
                    savePmNet(pn);
                  }
                }
                render();
              });
            })(nick);
            row.appendChild(label);
            row.appendChild(rm);
            listWrap.appendChild(row);
          }
          allowHolder.appendChild(listWrap);
        }
      }
    }

    // ── DOM-API render of the blocked messages list ──
    const blockedHolder=box.querySelector('#pm-blocked-list-holder');
    if(blockedHolder){
      blockedHolder.innerHTML='';
      if(!blockedShow.length){
        const empty=document.createElement('div');
        empty.style.cssText='color:var(--text3);text-align:center;padding:20px 0;font-size:12px;background:var(--bg2);border:1px dashed var(--border);border-radius:6px';
        empty.textContent='No blocked messages'+(isGlobal?'':' on this network');
        blockedHolder.appendChild(empty);
      } else {
        const listWrap=document.createElement('div');
        listWrap.id='pm-blocked-list';
        listWrap.style.cssText='max-height:260px;overflow-y:auto;-webkit-overflow-scrolling:touch;background:var(--bg2);border:1px solid var(--border);border-radius:6px';
        for(const b of blockedShow){
          const d=new Date((b.ts||0)*1000);
          const when=(d.getMonth()+1)+'/'+d.getDate()+' '+d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0');
          const net=networks.find(n=>n.config.id===b.conn_id);
          const netLabel=net?(net.config.label||net.config.server):'(unknown)';

          const row=document.createElement('div');
          row.style.cssText='padding:10px 12px;border-bottom:1px solid var(--border)';

          const head=document.createElement('div');
          head.style.cssText='display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px';

          const meta=document.createElement('div');
          meta.style.cssText='display:flex;align-items:center;gap:6px;min-width:0;flex:1;flex-wrap:wrap';
          const nickEl=document.createElement('span');
          nickEl.style.cssText='font-size:12px;color:var(--accent);font-family:var(--mono);font-weight:600;word-break:break-all';
          nickEl.textContent=b.from||'';
          const dot1=document.createElement('span');dot1.style.cssText='font-size:9px;color:var(--text3)';dot1.textContent='·';
          const netEl=document.createElement('span');netEl.style.cssText='font-size:10px;color:var(--text3)';netEl.textContent=netLabel;
          const dot2=document.createElement('span');dot2.style.cssText='font-size:9px;color:var(--text3)';dot2.textContent='·';
          const timeEl=document.createElement('span');timeEl.style.cssText='font-size:10px;color:var(--text3)';timeEl.textContent=when;
          meta.appendChild(nickEl);meta.appendChild(dot1);meta.appendChild(netEl);meta.appendChild(dot2);meta.appendChild(timeEl);

          const allowBtn=document.createElement('button');
          allowBtn.style.cssText='padding:3px 10px;background:rgba(0,212,170,.15);border:1px solid var(--accent);color:var(--accent);border-radius:4px;cursor:pointer;font-size:11px;flex-shrink:0;font-weight:600';
          allowBtn.textContent='✓ Allow';
          ((nick,conn)=>{
            allowBtn.addEventListener('click',()=>{
              if(!nick) return;
              addPmAllow(nick, isGlobal?null:_pmPanelScope);
              const arr=loadPmBlocked().filter(bb=>!(bb.from.toLowerCase()===nick.toLowerCase()&&bb.conn_id===conn));
              savePmBlocked(arr);
              try{localStorage.removeItem('bp:'+conn+':'+nick.toLowerCase());}catch(e){}
              showToast(`${nick} allowed — they can PM you now`);
              render();
            });
          })(b.from||'', b.conn_id||'');

          head.appendChild(meta);
          head.appendChild(allowBtn);

          const textEl=document.createElement('div');
          textEl.style.cssText='font-size:12px;color:var(--text);word-break:break-word;line-height:1.4';
          textEl.textContent=b.text||'';

          row.appendChild(head);
          row.appendChild(textEl);
          listWrap.appendChild(row);
        }
        blockedHolder.appendChild(listWrap);
      }
    }

    // All queries are scoped to `box` so they work whether box is attached
    // to the document or not (first render happens before appendChild).
    // Set current cooldown value after innerHTML
    const cd=box.querySelector('#pm-prot-cooldown');
    if(cd){const opts=[1,6,12,24,72,168];cd.value=opts.includes(cooldown)?String(cooldown):'24';}

    // ── Wire up scope selector ──
    const sel=box.querySelector('#pm-prot-scope');
    if(sel) sel.addEventListener('change',()=>{_pmPanelScope=sel.value==='__global__'?null:sel.value;render();});

    // ── Wire up override toggle ──
    const ovBtn=box.querySelector('#pm-prot-override');
    if(ovBtn) ovBtn.addEventListener('click',()=>{
      const willOverride=!overriding;
      pmNetPatch(_pmPanelScope,{override:willOverride});
      render();
    });

    // ── Wire up enable toggle ──
    const enBtn=box.querySelector('#pm-prot-enable');
    if(enBtn) enBtn.addEventListener('click',()=>{
      enBtn.classList.toggle('on');
      const v=enBtn.classList.contains('on');
      if(isGlobal){
        localStorage.setItem('cryptirc_block_pms',v?'true':'false');
        savePrefsToServer();
        const sb=document.getElementById('sec-block-pms');
        if(sb){v?sb.classList.add('on'):sb.classList.remove('on');}
      } else {
        pmNetPatch(_pmPanelScope,{enabled:v});
      }
    });

    // ── Wire up cooldown select ──
    if(cd) cd.addEventListener('change',()=>{
      if(isGlobal){localStorage.setItem('cryptirc_pm_cooldown',cd.value);savePrefsToServer();}
      else pmNetPatch(_pmPanelScope,{cooldown:parseInt(cd.value)});
    });

    // ── Wire up notify toggle ──
    const ntBtn=box.querySelector('#pm-prot-notify');
    if(ntBtn) ntBtn.addEventListener('click',()=>{
      ntBtn.classList.toggle('on');
      const v=ntBtn.classList.contains('on');
      if(isGlobal){localStorage.setItem('cryptirc_pm_notify',v?'true':'false');savePrefsToServer();}
      else pmNetPatch(_pmPanelScope,{notify:v});
    });

    // ── Wire up deliver toggle ──
    const dvBtn=box.querySelector('#pm-prot-deliver');
    if(dvBtn) dvBtn.addEventListener('click',()=>{
      dvBtn.classList.toggle('on');
      const v=dvBtn.classList.contains('on');
      if(isGlobal){localStorage.setItem('cryptirc_pm_deliver_first',v?'true':'false');savePrefsToServer();}
      else pmNetPatch(_pmPanelScope,{deliverFirst:v});
    });

    // ── Wire up allow list add input/button (remove buttons are wired inline during DOM build) ──
    const addBtn=box.querySelector('#pm-allow-add-btn');
    const addInp=box.querySelector('#pm-allow-input');
    const doAdd=()=>{
      const v=(addInp.value||'').trim();
      if(!v)return;
      const vl=v.toLowerCase();
      if(isGlobal){
        if(pmAllowList.has(vl)){showToast(`${v} is already allowed`);addInp.value='';return;}
        pmAllowList.add(vl);savePmAllow();
      } else {
        const pn=loadPmNet();
        if(!pn[_pmPanelScope]) pn[_pmPanelScope]={override:true,enabled:false,cooldown:24,notify:true,deliverFirst:true,allowList:[]};
        if(!Array.isArray(pn[_pmPanelScope].allowList)) pn[_pmPanelScope].allowList=[];
        if(pn[_pmPanelScope].allowList.includes(vl)){showToast(`${v} is already allowed`);addInp.value='';return;}
        pn[_pmPanelScope].allowList.push(vl);
        savePmNet(pn);
      }
      showToast(`✓ ${v} added to allow list`);
      addInp.value='';
      render();
    };
    if(addBtn) addBtn.addEventListener('click',doAdd);
    if(addInp) addInp.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();doAdd();}});

    // ── Wire up "Clear" button for blocked messages list ──
    const clrBtn=box.querySelector('#pm-blocked-clear');
    if(clrBtn) clrBtn.addEventListener('click',async()=>{
      if(!(await customConfirm('Clear all blocked message history?','Clear'))) return;
      clearPmBlocked();
      render();
    });
  }

  render();
  ov.appendChild(box);
  ov.onclick=e=>{if(e.target===ov){ov.remove();_pmPanelScope=null;}};
  document.body.appendChild(ov);
}

function isIgnored(nick, prefix) {
  const lnick = nick.toLowerCase();
  const lpfx = (prefix||'').toLowerCase();
  for (const mask of ignoreList) {
    // Exact nick match
    if (mask === lnick) return true;
    // Wildcard mask match (nick!user@host pattern)
    if (mask.includes('!') || mask.includes('@') || mask.includes('*')) {
      // Match against full prefix if available
      const target = lpfx || lnick;
      if (wildcardMatch(target, mask)) return true;
    }
  }
  return false;
}
function wildcardMatch(str, pattern) {
  // Convert IRC wildcard pattern to regex
  const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
  return re.test(str);
}

// ─── Unread PM flash (every 20 minutes) ───────────────────────────────────────
setInterval(()=>{
  document.querySelectorAll('.chan-item').forEach(el=>{
    // PM items have a data-query attribute or are not channels/status
    const target=el.dataset?.target||'';
    if(target.startsWith('#')||target==='status')return;
    const badge=el.querySelector('.chan-unread-badge');
    if(badge&&parseInt(badge.textContent)>0){
      el.classList.remove('pm-flash');
      void el.offsetWidth;
      el.classList.add('pm-flash');
    }
  });
},20*60*1000); // 20 minutes

// Filter ignored users from incoming messages (hook into addMessage)
const _origAddMessage = addMessage;
// Wrap addMessage to filter ignores
window.addMessage = function(conn_id, target, msg) {
  if (msg.kind === 'privmsg' || msg.kind === 'action' || msg.kind === 'notice') {
    if (isIgnored(msg.from, msg.prefix)) return; // silently drop
    monitorUpdate(msg.from, conn_id, target, msg.text);
  }
  _origAddMessage(conn_id, target, msg);
};

// ── /help ─────────────────────────────────────────────────────────────────────

const HELP_TEXT = {
  // Navigation
  join:        '/join <channel> [key]         — Join a channel',
  part:        '/part [channel]               — Leave a channel',
  cycle:       '/cycle                        — Part and rejoin current channel',
  query:       '/query <nick> [message]       — Open a DM buffer',
  list:        '/list [pattern]               — List channels on server',
  // Identity
  nick:        '/nick <newnick>               — Change your nickname',
  away:        '/away [message]               — Set away status',
  back:        '/back                         — Clear away status',
  // Messaging
  me:          '/me <action>                  — Send an action (/me waves)',
  say:         '/say <text>                   — Send message (bypasses / detection)',
  msg:         '/msg <target> <text>          — Send private message',
  notice:      '/notice <target> <text>       — Send a NOTICE',
  ctcp:        '/ctcp <nick> <command>        — Send CTCP query (VERSION, PING, TIME)',
  ping:        '/ping [nick]                  — CTCP ping a user',
  version:     '/version [nick]               — CTCP version query',
  slap:        '/slap [nick]                  — Classic trout slap',
  // Channel info
  topic:       '/topic [new topic]            — Get or set channel topic',
  names:       '/names [channel]              — Refresh nick list',
  who:         '/who [channel]                — WHO query',
  whois:       '/whois <nick>                 — WHOIS a user',
  banlist:     '/banlist [channel]            — Show ban list',
  unbanall:    '/unbanall [channel]           — Remove every ban in the ban list',
  // Mode shortcuts
  op:          '/op <nick> [nick2...]         — Give op (+o)',
  deop:        '/deop <nick> [nick2...]       — Remove op (-o)',
  voice:       '/voice <nick> [nick2...]      — Give voice (+v)',
  devoice:     '/devoice <nick> [nick2...]    — Remove voice (-v)',
  halfop:      '/halfop <nick> [nick2...]     — Give halfop (+h)',
  protect:     '/protect <nick>              — Give protect (+a)',
  owner:       '/owner <nick>                — Give owner (+q)',
  mode:        '/mode <modes>                — Raw MODE command',
  // Mass operations
  voiceall:    '/voiceall                    — Voice all unvoiced users',
  devoiceall:  '/devoiceall                  — Remove voice from all voiced users',
  opall:       '/opall                       — Op all non-op users',
  deopall:     '/deopall                     — Deop all ops',
  kickall:     '/kickall [reason]            — Kick everyone except yourself',
  mdop:        '/mdop                       — Mass deop all ops except yourself',
  massdeop:    '/massdeop                   — Same as /mdop',
  drop:        '/drop                       — Strip ALL status (~&@%+) from everyone except yourself',
  unexemptall: '/unexemptall [channel]      — Remove all ban exempts (+e) from the channel',
  clearexempt: '/clearexempt [channel]      — Same as /unexemptall',
  // Kick/Ban
  kick:        '/kick <nick> [reason]        — Kick a user',
  ban:         '/ban <nick|mask>             — Ban a user',
  unban:       '/unban <nick|mask>           — Remove a ban',
  kickban:     '/kickban <nick> [reason]     — Kick and ban (alias: /kb)',
  tban:        '/tban <nick> <seconds>       — Temporary ban',
  invite:      '/invite <nick> [channel]     — Invite a user to a channel',
  // Ignore
  ignore:      '/ignore <nick>              — Ignore a user (client-side)',
  unignore:    '/unignore <nick>            — Stop ignoring a user',
  ignorelist:  '/ignorelist                 — Show ignore list',
  // PM protection
  pmallow:      '/pmallow <nick>             — Allow PMs from user (bypass protection)',
  pmremove:     '/pmremove <nick>            — Remove user from PM allow list',
  pmallowlist:  '/pmallowlist                — Show PM allow list',
  pmprotection: '/pmprotection               — Open PM protection settings',
  // Services
  ns:          '/ns <command>               — Send to NickServ',
  cs:          '/cs <command>               — Send to ChanServ',
  identify:    '/identify [nick] <password> — Identify with NickServ',
  ghost:       '/ghost <nick> [password]    — Reclaim nick via NickServ GHOST',
  regain:      '/regain <nick> [password]   — Reclaim nick via NickServ REGAIN',
  // Oper
  oper:        '/oper <user> <password>     — Authenticate as IRC operator',
  kill:        '/kill <nick> [reason]       — KILL a user (oper only)',
  shun:        '/shun <mask> <duration>:r   — SHUN a user (UnrealIRCd oper)',
  gline:       '/gline <mask> <duration>:r  — G-LINE a user (oper)',
  kline:       '/kline <mask>               — K-LINE a user (oper)',
  rehash:      '/rehash                     — Rehash server config (oper)',
  // Encryption
  encrypt:     '/encrypt on|off|keygen|add  — Manage E2E encryption for channel or DM',
  // Fun
  prism:       '/prism <message>            — Send text in rainbow mIRC colors',
  rainbow:     '/rainbow <message>          — Same as /prism',
  shrug:       '/shrug [text]               — ¯\\_(ツ)_/¯',
  tableflip:   '/tableflip [text]           — (╯°□°)╯︵ ┻━┻',
  unflip:      '/unflip [text]              — ┬─┬ノ( º _ ºノ)',
  lenny:       '/lenny [text]               — ( ͡° ͜ʖ ͡°)',
  disapprove:  '/disapprove [text]          — ಠ_ಠ',
  rage:        '/rage [text]                — (ノಠ益ಠ)ノ彡┻━┻',
  bear:        '/bear [text]                — ʕ•ᴥ•ʔ',
  sparkle:     '/sparkle <text>             — ✧･ﾟ: *✧･ﾟ:* text *:･ﾟ✧*:･ﾟ✧',
  finger:      '/finger [text]              — ╭∩╮(︶︿︶)╭∩╮',
  dance:       '/dance [text]               — ♪┏(・o・)┛♪┗(・o・)┓♪',
  rip:         '/rip <name>                 — ⚰️ R.I.P. name ⚰️',
  hug:         '/hug [nick]                 — (づ｡◕‿‿◕｡)づ nick',
  // Utility
  quote:       '/quote <raw command>        — Send raw IRC (alias: /raw)',
  links:       '/links                      — Show server links',
  clear:       '/clear                      — Clear current buffer',
  clearall:    '/clearall                   — Clear all buffers',
  help:        '/help [command]             — Show this help or help for a command',
};

function showHelpPanel(){
  const body=document.getElementById('help-body');
  body.innerHTML='';
  // ── About / TwistedNet header ──
  const about=document.createElement('div');about.className='help-section';
  about.innerHTML=`<div style="text-align:center;padding:12px 0 16px">
    <div style="font-size:22px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px">CryptIRC</div>
    <div style="font-size:11px;color:var(--text3);margin-bottom:2px">End-to-end encrypted IRC client</div>
    <div style="font-size:11px;color:var(--text3);line-height:1.8;margin-top:6px">
      Designed &amp; developed by <span style="color:var(--accent);font-weight:600">gh0st</span><br>
      <span style="color:var(--text2);font-weight:500">Hallucinate</span> <span style="color:var(--text3)">— co-designer, QA testing &amp; feature ideas</span>
    </div>
    <div style="margin-top:12px;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;font-size:11px;color:var(--text3);line-height:1.7">
      <span style="color:var(--accent);font-weight:600">irc.twistednet.org</span><br>
      <span style="color:var(--accent2);font-weight:500">#dev</span> · <span style="color:var(--accent2);font-weight:500">#twisted</span><br>
      <span style="font-size:10px">Join us — support, feedback, and development chat</span>
    </div>
  </div>`;
  body.appendChild(about);

  const sections=[
    ['Channel',
      'join #channel [key] — Join a channel (auto-adds # if missing)',
      'part [#channel] [reason] — Leave a channel',
      'cycle — Part and rejoin current channel',
      'topic [text] — View or set channel topic',
      'list — List all channels on the server',
      'links — Show server links',
      'invite nick — Invite user to current channel',
      'names — Refresh the nick list',
      'key #channel [key] — Save or clear a channel key (+k)',
    ],
    ['Messaging',
      'msg nick text — Send a private message',
      'query nick [text] — Open a DM window',
      'me text — Send an action (/me waves)',
      'say text — Send raw text to current target',
      'notice nick text — Send a notice',
      'ctcp nick command — Send a CTCP command',
      'slap nick — Slap someone with a large trout',
    ],
    ['Identity &amp; Info',
      'nick newnick — Change your nickname',
      'away [message] — Set away status',
      'back — Remove away status',
      'whois nick — Look up user info',
      'whowas nick — Look up offline user',
      'who #channel — List users in a channel',
    ],
    ['User Modes',
      'mode +mode [args] — Set channel or user mode',
      'op nick — Give operator (+o)',
      'deop nick — Remove operator (-o)',
      'voice nick — Give voice (+v)',
      'devoice nick — Remove voice (-v)',
      'halfop nick — Give half-op (+h)',
      'dehalfop nick — Remove half-op (-h)',
      'admin nick — Give admin/protect (+a)',
      'deadmin nick — Remove admin (-a)',
      'owner nick — Give owner (+q)',
      'deowner nick — Remove owner (-q)',
    ],
    ['Mass Operations',
      'opall — Op everyone in the channel',
      'deopall — Deop everyone',
      'mdop — Mass deop all except yourself',
      'drop — Strip ALL status (~&amp;@%+) from everyone except you',
      'voiceall — Voice everyone',
      'devoiceall — Devoice everyone',
      'kickall — Kick everyone except yourself',
    ],
    ['Moderation',
      'kick nick [reason] — Kick a user',
      'ban nick — Ban a user (nick!*@*)',
      'unban mask — Remove a ban',
      'kickban nick [reason] — Kick and ban',
      'tban nick seconds [reason] — Temporary ban with auto-unban',
      'banlist — View the ban list',
      'unbanall — Remove ALL bans from channel',
      'unexemptall — Remove all ban exempts (+e)',
      'ignore nick|mask — Ignore a user (supports wildcard masks)',
      'unignore nick|mask — Stop ignoring a user',
      'ignorelist — Show your ignore list',
    ],
    ['Services',
      'ns command — Send to NickServ',
      'cs command — Send to ChanServ',
      'identify password — Identify with NickServ',
      'register password email — Register with NickServ',
      'ghost nick [pass] — Ghost a nick',
      'regain nick [pass] — Recover/regain a nick',
    ],
    ['IRCOp',
      'oper login password — Authenticate as IRCOp',
      'kill nick reason — Kill a user from the network',
      'shun mask duration reason — Shun a user',
      'gline mask duration reason — G-line (network ban)',
      'zline mask duration reason — Z-line (IP ban)',
      'kline mask duration reason — K-line (server ban)',
      'rehash — Reload server configuration',
      'squit server reason — Disconnect a linked server',
    ],
    ['Connection',
      'connect — Connect to the current server',
      'disconnect — Disconnect from the current server',
      'quote text — Send a raw IRC command',
    ],
    ['Encryption (E2E)',
      'encrypt keygen — Generate Signal protocol identity',
      'encrypt on — Enable E2E for current DM',
      'encrypt off — Disable E2E for current DM',
      'encrypt add #channel — Set a channel encryption key',
      'encrypt rotate — Rotate your E2E keys',
    ],
    ['Client',
      'close — Close the current DM or channel tab',
      'clear — Clear current chat history',
      'clearall — Clear ALL chat buffers',
      'help — Show this help panel',
      'ping nick — CTCP ping a user',
      'version nick — CTCP version a user',
      'time nick — CTCP time a user',
      'monitor nick — Monitor a nick for online/offline',
      'unmonitor nick — Stop monitoring a nick',
    ],
    ['Tools',
      'ascii text — Generate ASCII block-letter art',
      'ud word — Urban Dictionary lookup (sends to channel)',
      'shorten url — Shorten a URL with built-in shortener',
      'stats — Channel statistics dashboard (top talkers)',
      'note nick [text] — Set or view private notes on a nick',
      'dnd on|off — Toggle Do Not Disturb mode',
      'dnd schedule HH:MM HH:MM — Schedule quiet hours',
      'split — Toggle split view (two channels side by side)',
      'seen nick — When a nick was last seen and where',
      'ratelimit ms — Set message send rate (default 500ms, like irssi)',
      'expire hours — Auto-delete old messages (0 = off)',
      'autolock minutes — Vault auto-lock after inactivity (0 = off)',
      'keepnick [nick] — Keep a nick (auto-reclaim via ISON poll + QUIT/NICK events)',
      'unkeepnick — Stop keeping the nick for current network',
      'listnick — List all kept nicks with active/inactive status',
    ],
    ['Fun &amp; Emotes',
      'prism text — Rainbow mIRC colored text',
      'shrug [text] — ¯\\_(ツ)_/¯',
      'tableflip [text] — (╯°□°)╯︵ ┻━┻',
      'unflip [text] — ┬─┬ノ( º _ ºノ)',
      'lenny [text] — ( ͡° ͜ʖ ͡°)',
      'disapprove [text] — ಠ_ಠ',
      'rage [text] — (ノಠ益ಠ)ノ彡┻━┻',
      'bear [text] — ʕ•ᴥ•ʔ',
      'sparkle text — ✧･ﾟ: *✧ text ✧*:･ﾟ✧',
      'finger [text] — ╭∩╮(︶︿︶)╭∩╮',
      'dance [text] — ♪┏(・o・)┛♪┗(・o・)┓♪',
      'rip name — ⚰️ R.I.P. name ⚰️',
      'hug nick — (づ｡◕‿‿◕｡)づ nick',
    ],
  ];
  for(const[title,...cmds] of sections){
    const sec=document.createElement('div');sec.className='help-section';
    sec.innerHTML=`<div class="help-section-title">${title}</div>`;
    for(const cmd of cmds){
      const sep=cmd.indexOf(' — ');
      const name=sep>=0?cmd.slice(0,sep):cmd;
      const desc=sep>=0?cmd.slice(sep+3):'';
      sec.innerHTML+=`<div class="help-cmd"><span class="help-cmd-name">/${name}</span><span class="help-cmd-desc">${desc}</span></div>`;
    }
    body.appendChild(sec);
  }
  // Features section
  const feat=document.createElement('div');feat.className='help-section';
  feat.innerHTML=`<div class="help-section-title">Features</div>
    <div class="help-cmd"><span class="help-cmd-name">121 themes</span><span class="help-cmd-desc">32 animated (canvas effects) + 89 static themes</span></div>
    <div class="help-cmd"><span class="help-cmd-name">135 fonts</span><span class="help-cmd-desc">Monospace, sans-serif, serif, display, handwriting</span></div>
    <div class="help-cmd"><span class="help-cmd-name">E2E encryption</span><span class="help-cmd-desc">Signal protocol for DMs + AES-256-GCM for channels</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Encrypted vault</span><span class="help-cmd-desc">Argon2id KDF — all data encrypted at rest</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Auto-identify</span><span class="help-cmd-desc">NickServ IDENTIFY on connect (network settings)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Auto-rejoin</span><span class="help-cmd-desc">Rejoin channels automatically after being kicked</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Channel keys</span><span class="help-cmd-desc">Saved +k keys auto-sent on join (/key to manage)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">KeepNick</span><span class="help-cmd-desc">irssi-style nick keeper — ISON poll + QUIT/NICK events</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Smart paste</span><span class="help-cmd-desc">Multi-line paste auto-offers pastebin creation</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Read markers</span><span class="help-cmd-desc">"New messages" divider when switching channels</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Split view</span><span class="help-cmd-desc">View two channels side by side (/split)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">User notes</span><span class="help-cmd-desc">Private notes on nicks (right-click → Note)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">DND mode</span><span class="help-cmd-desc">Suppress notifications with scheduled quiet hours</span></div>
    <div class="help-cmd"><span class="help-cmd-name">URL shortener</span><span class="help-cmd-desc">Built-in /shorten command creates short links</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Channel stats</span><span class="help-cmd-desc">Top talkers dashboard (/stats)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Link previews</span><span class="help-cmd-desc">Images, YouTube cards, and metadata previews</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Pastebin</span><span class="help-cmd-desc">Share text snippets with password &amp; expiration</span></div>
    <div class="help-cmd"><span class="help-cmd-name">File uploads</span><span class="help-cmd-desc">Drag-and-drop or paperclip button</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Encrypted notepad</span><span class="help-cmd-desc">Private auto-saving notes (vault encrypted)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Push notifications</span><span class="help-cmd-desc">Desktop &amp; mobile push for DMs and mentions</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Nick monitoring</span><span class="help-cmd-desc">Track when users come online/offline</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Multi-device sync</span><span class="help-cmd-desc">Settings, themes, unread sync across devices</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Typing indicators</span><span class="help-cmd-desc">See when someone is typing (IRCv3)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Client TLS certs</span><span class="help-cmd-desc">ECDSA P-256 certs for SASL EXTERNAL</span></div>
    <div class="help-cmd"><span class="help-cmd-name">ZNC playback</span><span class="help-cmd-desc">Detects and batches ZNC buffer playback</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Audio player</span><span class="help-cmd-desc">Inline playback for mp3/ogg/flac/wav links</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Image lightbox</span><span class="help-cmd-desc">Click images to zoom — pinch/scroll/double-tap</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Message expiry</span><span class="help-cmd-desc">Auto-delete old messages (/expire hours)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Session manager</span><span class="help-cmd-desc">View and revoke active sessions (Settings → Sessions)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Vault auto-lock</span><span class="help-cmd-desc">Auto-lock vault after idle (/autolock minutes)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Seen database</span><span class="help-cmd-desc">Track when nicks were last active (/seen nick)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Rate limiter</span><span class="help-cmd-desc">Client-side flood protection (/ratelimit ms)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Metadata stripping</span><span class="help-cmd-desc">EXIF/GPS auto-removed from uploaded JPEG/PNG</span></div>`;
  body.appendChild(feat);
  // Keyboard shortcuts
  const kb=document.createElement('div');kb.className='help-section';
  kb.innerHTML=`<div class="help-section-title">Keyboard Shortcuts</div>
    <div class="help-cmd"><span class="help-cmd-name">Enter</span><span class="help-cmd-desc">Send message</span></div>
    <div class="help-cmd"><span class="help-cmd-name">↑ / ↓</span><span class="help-cmd-desc">Scroll through input history</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Tab</span><span class="help-cmd-desc">Nick tab completion</span></div>
    <div class="help-cmd"><span class="help-cmd-name">@ (at sign)</span><span class="help-cmd-desc">Nick autocomplete dropdown</span></div>
    <div class="help-cmd"><span class="help-cmd-name"># (hash)</span><span class="help-cmd-desc">Channel autocomplete dropdown</span></div>
    <div class="help-cmd"><span class="help-cmd-name">: (colon)</span><span class="help-cmd-desc">Emoji autocomplete (:wave: style)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">/ (slash)</span><span class="help-cmd-desc">Command autocomplete — shows all commands</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Ctrl+K</span><span class="help-cmd-desc">mIRC color picker (16 colors, fg+bg)</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Ctrl+B</span><span class="help-cmd-desc">Bold text formatting</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Ctrl+U</span><span class="help-cmd-desc">Underline text formatting</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Ctrl+I</span><span class="help-cmd-desc">Italic text formatting</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Ctrl+O</span><span class="help-cmd-desc">Reset all formatting</span></div>
    <div class="help-cmd"><span class="help-cmd-name">Escape</span><span class="help-cmd-desc">Close autocomplete / overlays</span></div>`;
  body.appendChild(kb);
  // Support section
  const sup=document.createElement('div');sup.className='help-support';
  sup.innerHTML=`<div class="help-support-title">💬 Need Help?</div>
    <div class="help-support-text">
      Join us on <span class="help-support-server">irc.twistednet.org</span><br>
      Channels: <span class="help-support-chan">#dev</span> and <span class="help-support-chan">#twisted</span><br><br>
      <span style="font-size:11px;color:var(--text3)">CryptIRC v${CRYPTIRC_VERSION} — Created by gh0st with Hallucinate</span>
    </div>`;
  body.appendChild(sup);
  var _hvp=document.getElementById('help-ver-pill'); if(_hvp) _hvp.textContent=_verLabel();
  document.getElementById('help-overlay').classList.add('show');
  _overlayOpen('helpPanel', closeHelpPanel);
}
function closeHelpPanel(){_overlayClose('helpPanel');document.getElementById('help-overlay').classList.remove('show');}

// ─── What's New / changelog ────────────────────────────────────────────────
const CRYPTIRC_VERSION='0.3.0';
// Build stamp (git short SHA, +'-dirty' if built with uncommitted changes). The
// placeholder is replaced at serve time by the Rust build (see build.rs / main.rs).
// If served un-replaced (still starts with '_'), the pill shows just the version.
const CRYPTIRC_BUILD='__CRYPTIRC_BUILD__';
function _verLabel(){ var b=CRYPTIRC_BUILD; return 'v'+CRYPTIRC_VERSION+(b && b.charAt(0)!=='_' ? ' · '+b : ''); }
// Newest release first; each item tagged new|fix|sec. Add new releases on top.
const NEWS=[
  {version:'0.3.0', date:'June 2026', items:[
    {tag:'new', text:'eSheep desktop pet — a little sheep wanders your client window: climbs the edges, naps, gets abducted by a UFO, and is draggable. Enable it for desktop, mobile, or both in Appearance ▸ Desktop Pet (off by default).'},
    {tag:'new', text:'Custom theme editor with 50+ built-in themes, animated scene backgrounds, your own background image, and a customizable chat link colour.'},
    {tag:'fix', text:'Fixed a freeze that could hit the web (PWA) and desktop apps when left open for a long time.'},
    {tag:'fix', text:'WHOIS results no longer flicker, and the channel-modes menu now matches UnrealIRCd (e.g. +R for registered-only join).'},
    {tag:'fix', text:'Uploads now work with cloud “online-only” placeholder files (OneDrive / iCloud) instead of failing with “No data uploaded.”'},
    {tag:'fix', text:'The user-list collapse state and Do-Not-Disturb settings now stay in sync across all your devices.'},
  ]},
];
function showNewsPanel(){
  var body=document.getElementById('news-body'); if(!body) return;
  var pill=document.getElementById('news-ver-pill'); if(pill) pill.textContent=_verLabel();
  var label={new:'New', fix:'Fix', sec:'Security'};
  body.innerHTML=NEWS.map(function(rel){
    return '<div class="news-rel"><div class="news-rel-head"><span class="news-rel-ver">v'+esc(rel.version)+'</span><span class="news-rel-date">'+esc(rel.date)+'</span></div>'+
      rel.items.map(function(it){
        return '<div class="news-item"><span><span class="news-tag '+esc(it.tag)+'">'+esc(label[it.tag]||it.tag)+'</span>'+esc(it.text)+'</span></div>';
      }).join('')+
    '</div>';
  }).join('');
  document.getElementById('news-overlay').classList.add('show');
  _overlayOpen('newsPanel', closeNewsPanel);
}
function closeNewsPanel(){_overlayClose('newsPanel');document.getElementById('news-overlay').classList.remove('show');}

// ─── Admin Panel ──────────────────────────────────────────────────────────────
let _isAdmin=false;
async function checkAdmin(){
  if(!sessionToken)return;
  try{
    const r=await fetch('/cryptirc/admin/settings',{headers:{'Authorization':'Bearer '+sessionToken}});
    if(r.ok){
      _isAdmin=true;
      const btn=document.getElementById('admin-menu-btn');
      if(btn) btn.style.display='';
    }
  }catch(e){}
}

async function showAdminPanel(){
  const body=document.getElementById('admin-body');
  body.innerHTML='<div style="color:var(--text3);text-align:center;padding:20px">Loading...</div>';
  document.getElementById('admin-overlay').classList.add('show');
  _overlayOpen('adminPanel', closeAdminPanel);

  try{
    // Load settings
    const sr=await fetch('/cryptirc/admin/settings',{headers:{'Authorization':'Bearer '+sessionToken}});
    const settings=sr.ok?await sr.json():{registration_open:true,registration_code:''};

    // Load users
    const ur=await fetch('/cryptirc/admin/users',{headers:{'Authorization':'Bearer '+sessionToken}});
    const users=ur.ok?await ur.json():[];

    const onlineCount=users.filter(u=>u.sessions>0).length;

    body.innerHTML='';

    // Stats
    const stats=document.createElement('div');
    stats.style.cssText='display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;';
    stats.innerHTML=`
      <div style="flex:1;min-width:100px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:24px;font-weight:700;color:var(--accent)">${users.length}</div>
        <div style="font-size:11px;color:var(--text3)">Total Users</div>
      </div>
      <div style="flex:1;min-width:100px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:24px;font-weight:700;color:var(--join)">${onlineCount}</div>
        <div style="font-size:11px;color:var(--text3)">Online Now</div>
      </div>
    `;
    body.appendChild(stats);

    // Registration settings
    const regSection=document.createElement('div');
    regSection.style.cssText='margin-bottom:16px;padding:14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;';
    regSection.innerHTML=`
      <div style="font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px">Registration</div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <span style="font-size:13px;color:var(--text)">Open Registration</span>
        <button class="appear-toggle${settings.registration_open?' on':''}" id="admin-reg-open" onclick="this.classList.toggle('on');adminSaveSettings()"></button>
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:8px">
        <span style="font-size:13px;color:var(--text);flex-shrink:0">Invite Code</span>
        <input id="admin-reg-code" value="${esc(settings.registration_code)}" placeholder="Leave empty for no code" style="flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:8px;outline:none" onchange="adminSaveSettings()">
      </div>
      <div style="font-size:10px;color:var(--text3);margin-top:6px">If set, users must enter this code when registering.</div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:12px">
        <span style="font-size:13px;color:var(--text);flex-shrink:0">Max Upload Size</span>
        <input id="admin-upload-mb" type="number" min="1" max="500" value="${settings.max_upload_mb||25}" style="width:70px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:8px;outline:none;text-align:center" onchange="adminSaveSettings()">
        <span style="font-size:13px;color:var(--text3)">MB</span>
      </div>
      <div style="font-size:10px;color:var(--text3);margin-top:4px">Maximum file upload size per file (1–500 MB).</div>
    `;
    body.appendChild(regSection);

    // Link preview settings
    const lpR=await fetch('/cryptirc/admin/link-preview',{headers:{'Authorization':'Bearer '+sessionToken}});
    const lpSettings=lpR.ok?await lpR.json():{mode:'whitelist',whitelist:[]};
    const lpSection=document.createElement('div');
    lpSection.style.cssText='margin-bottom:16px;padding:14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;';
    lpSection.innerHTML=`
      <div style="font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px">Link Previews</div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:13px;color:var(--text);flex-shrink:0">Mode</span>
        <select id="admin-lp-mode" style="flex:1;padding:6px;background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:13px" onchange="adminSaveLinkPreview()">
          <option value="off"${lpSettings.mode==='off'?' selected':''}>Off — No previews</option>
          <option value="whitelist"${lpSettings.mode==='whitelist'?' selected':''}>Whitelist — Approved domains only</option>
          <option value="all"${lpSettings.mode==='all'?' selected':''}>All — Preview any HTTPS link</option>
        </select>
      </div>
      <div style="font-size:10px;color:var(--text3);margin-bottom:8px">Whitelist mode only fetches metadata from approved domains. "All" mode fetches any HTTPS link (blocks private IPs).</div>
      <div style="margin-bottom:6px">
        <span style="font-size:11px;color:var(--text2);font-weight:600">Whitelist</span>
        <span style="font-size:10px;color:var(--text3);margin-left:4px">(one domain per line)</span>
      </div>
      <textarea id="admin-lp-whitelist" style="width:100%;min-height:120px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:12px;padding:8px;outline:none;resize:vertical;box-sizing:border-box" onchange="adminSaveLinkPreview()">${lpSettings.whitelist.join('\n')}</textarea>
    `;
    body.appendChild(lpSection);

    // User list
    const userSection=document.createElement('div');
    userSection.innerHTML='<div style="font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px">Users</div>';
    for(const u of users.sort((a,b)=>b.sessions-a.sessions)){
      const row=document.createElement('div');
      row.className='admin-user-row';
      row.style.cssText='display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);';
      const online=u.sessions>0;
      const uploadOn=u.admin||u.can_upload;
      // SECURITY: username is user-controlled. Carry it on the row via a DOM property
      // and tag each action button with a fixed data-admin-act; a delegated listener
      // reads row.dataset.username — never an inline-handler JS-string (#10).
      row.dataset.username=u.username;
      row.innerHTML=`
        <span style="font-size:10px">${online?'🟢':'⚫'}</span>
        <span style="flex:1;font-size:13px;color:var(--text);font-weight:${u.admin?'700':'400'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(u.username)}${u.admin?' 👑':''}</span>
        <span style="font-size:10px;color:var(--text3)">${u.sessions} session${u.sessions!==1?'s':''}</span>
        ${u.admin?'<span class="admin-always-upload" style="font-size:10px;color:var(--text3);padding:3px 8px">📎 always</span>':`<button data-admin-act="upload" data-admin-val="${!uploadOn}" title="${uploadOn?'Revoke':'Grant'} upload permission" style="background:${uploadOn?'rgba(0,212,170,.15)':'none'};border:1px solid ${uploadOn?'var(--accent)':'var(--border)'};color:${uploadOn?'var(--accent)':'var(--text3)'};border-radius:4px;font-size:10px;padding:3px 8px;cursor:pointer">📎 ${uploadOn?'On':'Off'}</button>`}
        ${u.admin?'':`<button data-admin-act="disable" style="background:none;border:1px solid var(--warn);color:var(--warn);border-radius:4px;font-size:10px;padding:3px 8px;cursor:pointer">Disable</button>
        <button data-admin-act="delete" style="background:none;border:1px solid var(--error);color:var(--error);border-radius:4px;font-size:10px;padding:3px 8px;cursor:pointer">Delete</button>`}
      `;
      userSection.appendChild(row);
    }
    // Delegated handler for the per-user admin buttons (reads the username from the
    // owning row's dataset — no user data in an inline-handler JS-string, #10).
    userSection.addEventListener('click',ev=>{
      const btn=ev.target.closest('[data-admin-act]');
      if(!btn||!userSection.contains(btn))return;
      const uname=btn.closest('.admin-user-row')?.dataset.username;
      if(!uname)return;
      switch(btn.dataset.adminAct){
        case 'upload': adminToggleUpload(uname, btn.dataset.adminVal==='true'); break;
        case 'disable': adminDisableUser(uname); break;
        case 'delete': adminDeleteUser(uname); break;
      }
    });
    body.appendChild(userSection);

    // Add user form
    const addSection=document.createElement('div');
    addSection.style.cssText='margin-top:16px;padding:14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;';
    addSection.innerHTML=`
      <div style="font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px">Add User</div>
      <div class="admin-add-row" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
        <div style="flex:1;min-width:100px"><label style="font-size:10px;color:var(--text3)">Username</label><input id="admin-add-user" placeholder="username" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:8px;outline:none;box-sizing:border-box"></div>
        <div style="flex:1;min-width:100px"><label style="font-size:10px;color:var(--text3)">Password (min 10)</label><input id="admin-add-pass" type="password" placeholder="password" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:8px;outline:none;box-sizing:border-box"></div>
        <div style="flex:1;min-width:100px"><label style="font-size:10px;color:var(--text3)">Email (optional)</label><input id="admin-add-email" placeholder="user@example.com" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:14px;padding:8px;outline:none;box-sizing:border-box"></div>
        <button onclick="adminAddUser()" style="background:linear-gradient(135deg,#00d4aa,#0099ff);border:none;border-radius:6px;color:#000;font-weight:700;padding:8px 16px;cursor:pointer;min-height:38px">Add</button>
      </div>
      <div id="admin-add-err" style="font-size:11px;color:var(--error);margin-top:6px"></div>
    `;
    body.appendChild(addSection);

  }catch(e){
    body.innerHTML='<div style="color:var(--error);padding:20px;text-align:center">Failed to load admin data</div>';
  }
}

function closeAdminPanel(){_overlayClose('adminPanel');document.getElementById('admin-overlay').classList.remove('show');}

async function adminSaveSettings(){
  const open=document.getElementById('admin-reg-open').classList.contains('on');
  const code=document.getElementById('admin-reg-code').value;
  const uploadEl=document.getElementById('admin-upload-mb');
  const uploadMb=uploadEl?Math.max(1,Math.min(500,parseInt(uploadEl.value)||25)):undefined;
  try{
    const payload={registration_open:open,registration_code:code};
    if(uploadMb!==undefined) payload.max_upload_mb=uploadMb;
    await fetch('/cryptirc/admin/settings',{
      method:'PUT',
      headers:{'Authorization':'Bearer '+sessionToken,'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    showToast('Admin settings saved');
  }catch(e){}
}
async function adminSaveLinkPreview(){
  const mode=document.getElementById('admin-lp-mode').value;
  const whitelist=document.getElementById('admin-lp-whitelist').value
    .split('\n').map(s=>s.trim().toLowerCase()).filter(s=>s.length>0);
  try{
    await fetch('/cryptirc/admin/link-preview',{
      method:'PUT',
      headers:{'Authorization':'Bearer '+sessionToken,'Content-Type':'application/json'},
      body:JSON.stringify({mode,whitelist})
    });
    showToast('Link preview settings saved');
  }catch(e){}
}

async function adminDisableUser(username){
  if(!(await customConfirm(`Disable user "${username}"? They won't be able to log in.`,'Disable')))return;
  try{
    await fetch(`/cryptirc/admin/user/${username}/disable`,{method:'POST',headers:{'Authorization':'Bearer '+sessionToken}});
    showToast(`${username} disabled`);
    showAdminPanel();
  }catch(e){}
}

async function adminToggleUpload(username,allow){
  try{
    const r=await fetch(`/cryptirc/admin/user/${username}/upload-permission`,{
      method:'POST',
      headers:{'Authorization':'Bearer '+sessionToken,'Content-Type':'application/json'},
      body:JSON.stringify({allow})
    });
    if(r.ok){showToast(`${username} upload: ${allow?'enabled':'disabled'}`);showAdminPanel();}
    else{showToast('Failed to update upload permission');}
  }catch(e){showToast('Failed to update upload permission');}
}

async function adminAddUser(){
  const username=document.getElementById('admin-add-user').value.trim();
  const password=document.getElementById('admin-add-pass').value;
  const email=document.getElementById('admin-add-email').value.trim();
  const err=document.getElementById('admin-add-err');
  if(!username||!password){err.textContent='Username and password required';return;}
  if(password.length<10){err.textContent='Password must be at least 10 characters';return;}
  err.textContent='';
  try{
    const r=await fetch('/cryptirc/admin/adduser',{
      method:'POST',
      headers:{'Authorization':'Bearer '+sessionToken,'Content-Type':'application/json'},
      body:JSON.stringify({username,password,email})
    });
    const d=await r.json();
    if(!r.ok){err.textContent=d.message||'Failed';return;}
    showToast(`User ${username} created`);
    showAdminPanel(); // refresh
  }catch(e){err.textContent='Failed to add user';}
}

async function adminDeleteUser(username){
  if(!(await customConfirm(`DELETE user "${username}"? This removes all their data permanently.`,'Delete')))return;
  if(!(await customConfirm(`Are you SURE? This cannot be undone.`,'Yes, delete')))return;
  try{
    await fetch(`/cryptirc/admin/user/${username}`,{method:'DELETE',headers:{'Authorization':'Bearer '+sessionToken}});
    showToast(`${username} deleted`);
    showAdminPanel();
  }catch(e){}
}

function showHelp(conn_id, target, specific) {
  if (specific) {
    const key  = specific.toLowerCase().replace(/^\//, '');
    const text = HELP_TEXT[key];
    sysMsg(conn_id, target, text || `No help for /${specific}`, 'system');
    return;
  }
  const categories = [
    ['Navigation',     ['join','part','cycle','query','list']],
    ['Identity',       ['nick','away','back']],
    ['Messaging',      ['me','say','msg','notice','ctcp','ping','slap']],
    ['Channel info',   ['topic','names','who','whois','banlist']],
    ['Mode shortcuts', ['op','deop','voice','devoice','halfop','protect','owner','mode']],
    ['Mass ops',       ['voiceall','devoiceall','opall','deopall','mdop','drop','kickall']],
    ['Kick/Ban',       ['kick','ban','unban','kickban','tban','invite','banlist','unbanall','unexemptall']],
    ['Ignore',         ['ignore','unignore','ignorelist']],
    ['PM Protection',  ['pmallow','pmremove','pmallowlist','pmprotection']],
    ['Services',       ['ns','cs','identify','ghost','regain']],
    ['Oper',           ['oper','kill','shun','gline','kline','rehash']],
    ['Encryption',     ['encrypt']],
    ['Fun',            ['prism','shrug','tableflip','unflip','lenny','disapprove','rage','bear','sparkle','finger','dance','rip','hug']],
    ['Utility',        ['quote','clear','clearall','links','help']],
  ];
  sysMsg(conn_id, target, '─── CryptIRC Commands ───────────────────────', 'system');
  for (const [cat, cmds] of categories) {
    sysMsg(conn_id, target, `${cat}: ${cmds.map(c => '/'+c).join('  ')}`, 'system');
  }
  sysMsg(conn_id, target, 'Use /help <command> for details on any command', 'system');
}

// ─── Utils ────────────────────────────────────────────────────────────────────
let _userScrolledAway=false;
let _scrollForceTimers=[];
let _scrollForceRO=null;
function _isNearBottom(a,thresh){return a.scrollHeight-a.scrollTop-a.clientHeight<thresh;}
// iPhone/iPad (incl. iPadOS reporting as Mac). Desktop Mac (no touch) is NOT iOS.
const _IS_IOS=(function(){try{const ua=navigator.userAgent||'';return /iP(hone|ad|od)/.test(ua)||(/Mac/.test(navigator.platform||'')&&(navigator.maxTouchPoints||0)>1);}catch(e){return false;}})();
// Force the chat to the bottom. The overflowY:hidden→'' toggle is an iOS-PWA-only
// workaround (Safari can swallow a bare scrollTop); on desktop with classic, space-
// reserving scrollbars that toggle reflows the view every message, which reads as a
// flicker/blink during bursts (e.g. a WHOIS reply). So only toggle overflow on iOS;
// everywhere else a plain scrollTop assignment (+ rAF re-pin) is enough and flicker-free.
function _iosFlushScroll(a){
  if(_IS_IOS){a.style.overflowY='hidden';void a.offsetHeight;a.scrollTop=a.scrollHeight;a.style.overflowY='';}
  else{a.scrollTop=a.scrollHeight;}
  requestAnimationFrame(()=>{a.scrollTop=a.scrollHeight;});
}
function scrollBottom(){
  const a=document.getElementById('chat-area');
  if(!a||_userScrolledAway)return;
  // `_userScrolledAway` (kept current by _onChatScroll) is the source of truth for
  // "user is reading history, don't yank them down." DON'T re-measure distance here:
  // scrollBottom runs AFTER the new row is in the DOM, so a tall message (several
  // lines pasted at once, or a just-loaded image) already pushes the distance past
  // any threshold — which used to make auto-scroll bail and force a manual scroll.
  _iosFlushScroll(a);
  updateScrollBtn();
}
function scrollForce(){
  const a=document.getElementById('chat-area');
  if(!a)return;
  _userScrolledAway=false;
  _iosFlushScroll(a);
  // Cancel any previous delayed scrolls
  _scrollForceTimers.forEach(t=>clearTimeout(t));
  _scrollForceTimers=[];
  if(_scrollForceRO){_scrollForceRO.disconnect();_scrollForceRO=null;}
  // Delayed re-anchors — but bail if user scrolls away in the meantime
  [50,150,300,600,1200,2000].forEach(ms=>{
    _scrollForceTimers.push(setTimeout(()=>{
      if(_userScrolledAway)return;
      a.scrollTop=a.scrollHeight;updateScrollBtn();
    },ms));
  });
  if(typeof ResizeObserver!=='undefined'){
    _scrollForceRO=new ResizeObserver(()=>{
      if(_userScrolledAway)return;
      if(_isNearBottom(a,150)){a.scrollTop=a.scrollHeight;updateScrollBtn();}
    });
    _scrollForceRO.observe(a);
    _scrollForceTimers.push(setTimeout(()=>{if(_scrollForceRO){_scrollForceRO.disconnect();_scrollForceRO=null;}},3000));
  }
}
function updateScrollBtn(){const a=document.getElementById('chat-area'),b=document.getElementById('scroll-bottom-btn');if(!a||!b)return;const far=a.scrollHeight-a.scrollTop-a.clientHeight>200;b.classList.toggle('show',far);}
function _onChatScroll(){
  const a=document.getElementById('chat-area');
  if(!a)return;
  _userScrolledAway=!_isNearBottom(a,200);
  updateScrollBtn();
}
// Attach scroll listener once DOM ready
document.addEventListener('DOMContentLoaded',()=>{document.getElementById('chat-area')?.addEventListener('scroll',_onChatScroll);});

// ─── Mentions system ──────────────────────────────────────────────────────────
let mentionsList=[];
try{mentionsList=JSON.parse(localStorage.getItem('cryptirc_mentions')||'[]');}catch(e){}
function saveMentions(){try{localStorage.setItem('cryptirc_mentions',JSON.stringify(mentionsList.slice(-100)));localStorage.setItem('cryptirc_mentions_ts',String(Date.now()));}catch(e){} savePrefsToServer();}
function getHighlightWords(){try{return JSON.parse(localStorage.getItem('cryptirc_highlight_words')||'[]');}catch{return[];}}
function checkMention(conn_id,target,from,text,ts){
  if(!currentUser)return false;
  const nick=getNick(conn_id);
  const t=text.toLowerCase();
  const n=nick.toLowerCase();
  let mentioned=false;
  if(n&&t.includes(n)){const re=new RegExp('\\b'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\b','i');if(re.test(text))mentioned=true;}
  if(!mentioned){const words=getHighlightWords();for(const w of words){if(w&&t.includes(w.toLowerCase()))mentioned=true;}}
  // Only channel mentions enter the Notices list. PMs are recorded separately
  // via addPmNotice (one entry per sender) to avoid duplicate rows.
  const isChan=target&&(target.startsWith('#')||target.startsWith('&')||target.startsWith('+')||target.startsWith('!'));
  if(mentioned && isChan){
    const net=networks.find(x=>x.config.id===conn_id);
    mentionsList.unshift({type:'mention',conn_id,target,from,text,ts,network:net?.config.label||net?.config.server||conn_id});
    if(mentionsList.length>100)mentionsList.length=100;
    saveMentions(); updateMentionsBadge();
  }
  return mentioned;
}
function addPmNotice(conn_id,from,msg){
  if(!from||from==='*')return;
  const fL=from.toLowerCase();
  if(mentionsList.some(m=>m.type==='pm'&&m.conn_id===conn_id&&(m.from||'').toLowerCase()===fL))return;
  const net=networks.find(x=>x.config.id===conn_id);
  mentionsList.unshift({type:'pm',conn_id,target:from,from,text:msg.text||'',ts:msg.ts,network:net?.config.label||net?.config.server||conn_id});
  if(mentionsList.length>100)mentionsList.length=100;
  saveMentions(); updateMentionsBadge();
}
function clearNoticesForTarget(conn_id,target){
  if(!target)return;
  const t=target.toLowerCase();
  const before=mentionsList.length;
  mentionsList=mentionsList.filter(m=>{
    if(m.conn_id!==conn_id)return true;
    return (m.target||'').toLowerCase()!==t;
  });
  if(mentionsList.length!==before){
    saveMentions(); updateMentionsBadge();
    if(document.getElementById('mentions-panel')?.classList.contains('show'))renderMentionsList();
  }
}
let _unseenMentions=0;
function updateMentionsBadge(){
  const btn=document.getElementById('mentions-btn');
  if(!btn)return;
  btn.classList.toggle('has-unread', mentionsList.length>0);
}
// ─── Search ───────────────────────────────────────────────────────────────────
function toggleSearchPanel(){
  const p=document.getElementById('search-panel');
  // Close mentions if open
  document.getElementById('mentions-panel').classList.remove('show');
  _overlayClose('mentionsPanel');
  p.classList.toggle('show');
  if(p.classList.contains('show')){
    _overlayOpen('searchPanel', closeSearchPanel);
    const inp=document.getElementById('search-input');
    inp.value='';
    inp.focus();
    const searchLabel=active&&!active.target.startsWith('#')?'conversation':'channel';
    document.getElementById('search-results').innerHTML=`<div class="search-empty">Type to search current ${searchLabel}</div>`;
  } else {
    _overlayClose('searchPanel');
  }
}
function closeSearchPanel(){_overlayClose('searchPanel');document.getElementById('search-panel').classList.remove('show');}

function doSearch(query){
  const el=document.getElementById('search-results');
  if(!query||query.length<2){el.innerHTML='<div class="search-empty">Type at least 2 characters</div>';window._searchReq=null;return;}
  if(!active){el.innerHTML='<div class="search-empty">No channel selected</div>';window._searchReq=null;return;}
  // Search the FULL server-side log history for this channel/chat — not just the
  // loaded buffer. The server decrypts + scans every day-file and returns the
  // matches. Track the in-flight request so a stale/late response (user typed a
  // newer query or switched channel) is discarded when it arrives.
  const sConn=active.conn_id, sTarget=active.target;
  window._searchReq={conn_id:sConn,target:sTarget,query};
  el.innerHTML='<div class="search-empty">Searching…</div>';
  // No `limit` → server returns EVERY match across the channel/chat's full history.
  wsend({type:'search_logs',conn_id:sConn,target:sTarget,query});
}
async function renderSearchResults(conn_id,target,query,results){
  const el=document.getElementById('search-results');
  if(!el)return;
  if(!results||!results.length){el.innerHTML='<div class="search-empty">No results found</div>';return;}
  results=await _decryptLogLines(target,results); // sd8~ search hits are ciphertext on disk — decrypt before display
  el.innerHTML='';
  // Count header so it's clear the full history was searched.
  const hdr=document.createElement('div');
  hdr.className='search-empty';
  hdr.style.cssText='padding:6px 10px;color:var(--text3);font-size:11px';
  hdr.textContent=`${results.length} result${results.length===1?'':'s'} across all history`;
  el.appendChild(hdr);
  // Server returns chronological (oldest→newest); show newest first.
  for(let i=results.length-1;i>=0;i--){
    const m=results[i];
    const d=document.createElement('div');d.className='search-result';
    const time=new Date(m.ts*1000).toLocaleString([],{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
    const highlighted=esc(m.text).replace(new RegExp('('+esc(query).replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi'),'<mark>$1</mark>');
    d.innerHTML=`<div class="search-result-meta">${esc(m.from)} · ${time}</div><div class="search-result-text">${highlighted}</div>`;
    d.onclick=()=>{
      closeSearchPanel();
      // jumpToMessage re-renders the channel and pages back through history as
      // needed, so clicking an old result still scrolls + flashes the message.
      jumpToMessage(conn_id,target,m.ts,m.from);
    };
    el.appendChild(d);
  }
}

// Search input listener
document.addEventListener('DOMContentLoaded',()=>{
  const sinp=document.getElementById('search-input');
  if(sinp){
    let searchTimer;
    sinp.addEventListener('input',()=>{
      clearTimeout(searchTimer);
      searchTimer=setTimeout(()=>doSearch(sinp.value),200);
    });
    sinp.addEventListener('keydown',e=>{if(e.key==='Escape')closeSearchPanel();});
  }
});
// Close search on outside click
document.addEventListener('click',e=>{
  if(!e.target.closest('#search-panel')&&!e.target.closest('#search-btn'))
    document.getElementById('search-panel')?.classList.remove('show');
});

function toggleMentionsPanel(){
  const p=document.getElementById('mentions-panel');
  p.classList.toggle('show');
  if(p.classList.contains('show')){
    _overlayOpen('mentionsPanel', ()=>{p.classList.remove('show'); _overlayClose('mentionsPanel');});
    renderMentionsList();
  } else {
    _overlayClose('mentionsPanel');
  }
}
function renderMentionsList(){
  const el=document.getElementById('mentions-list');
  if(!mentionsList.length){el.innerHTML='<div class="mention-empty">Nothing new</div>';return;}
  el.innerHTML='';
  for(const m of mentionsList){
    const d=document.createElement('div');d.className='mention-item';
    const time=new Date(m.ts*1000).toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
    const isPm=m.type==='pm';
    const meta=isPm
      ? `✉ PM from ${esc(m.from)} · ${esc(m.network)} · ${time}`
      : `@ ${esc(m.from)} in ${esc(m.target)} · ${esc(m.network)} · ${time}`;
    d.innerHTML=`<div class="mention-meta">${meta}</div><div class="mention-text">${esc(m.text)}</div>`;
    d.onclick=()=>{
      document.getElementById('mentions-panel').classList.remove('show');
      _overlayClose('mentionsPanel');
      // If this target is popped out, focus the popup instead of navigating main.
      if(!_detMode && isDetached(m.conn_id,m.target)){
        openDetachedWindow(m.conn_id,m.target);
        return;
      }
      // Channel mention OR PM notice — jumpToMessage scrolls to the exact message,
      // paging through history (windowed load) if it's older than the loaded
      // buffer. PM buffers render rows with data-ts just like channels, so this
      // takes you to the actual message for DMs too instead of only opening it.
      jumpToMessage(m.conn_id,m.target,m.ts,m.from);
    };
    el.appendChild(d);
  }
}
function clearMentions(){mentionsList=[];_unseenMentions=0;saveMentions();updateMentionsBadge();renderMentionsList();}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/\\/g,'&#92;').replace(/`/g,'&#96;');}
const MIRC_COLORS=['#fff','#000','#00007f','#009300','#ff0000','#7f0000','#9c009c','#fc7f00','#ffff00','#00fc00','#009393','#00ffff','#0000fc','#ff00ff','#7f7f7f','#d2d2d2'];
// Grapheme segmenter (cached). Lets parseMircColors iterate by visible
// glyph instead of UTF-16 code unit, so multi-codepoint emoji — surrogate
// pairs (💧🌡️🌙), variation selectors (☀️), ZWJ sequences (🤦🏻‍♂️), skin
// tones — are emitted as ONE unit. Without this, a colored emoji was split
// across per-char <span>s into two lone surrogates and rendered as □□.
const _graphemeSeg=(typeof Intl!=='undefined'&&Intl.Segmenter)
  ? new Intl.Segmenter(undefined,{granularity:'grapheme'}) : null;
function parseMircColors(s){
  // Process mIRC formatting: \x03fg[,bg] \x02bold \x1Funderline \x1Ditalic \x0F reset \x16 reverse
  let out='',bold=false,underline=false,italic=false,fg=null,bg=null;
  // Split into grapheme clusters; control codes are single-char clusters.
  const segs=_graphemeSeg?Array.from(_graphemeSeg.segment(s),x=>x.segment):Array.from(s);
  const isDigit=k=>{const g=segs[k];return g&&g.length===1&&g>='0'&&g<='9';};
  for(let gi=0;gi<segs.length;gi++){
    const g=segs[gi];
    if(g.length===1){
      const c=g.charCodeAt(0);
      if(c===0x03){ // color
        let fgStr='',bgStr='';
        if(isDigit(gi+1)){fgStr+=segs[++gi];if(isDigit(gi+1))fgStr+=segs[++gi];}
        if(fgStr&&segs[gi+1]===','){
          gi++;
          if(isDigit(gi+1)){bgStr+=segs[++gi];if(isDigit(gi+1))bgStr+=segs[++gi];}
        }
        if(fgStr){fg=parseInt(fgStr)%16;bg=bgStr?parseInt(bgStr)%16:bg;}else{fg=null;bg=null;}
        continue;
      }
      if(c===0x02){bold=!bold;continue;}
      if(c===0x1F){underline=!underline;continue;}
      if(c===0x1D){italic=!italic;continue;}
      if(c===0x16){const t=fg;fg=bg;bg=t;continue;}
      if(c===0x0F){bold=false;underline=false;italic=false;fg=null;bg=null;continue;}
    }
    // Build styled span if needed
    let styles=[];
    if(fg!==null)styles.push('color:'+MIRC_COLORS[fg]);
    if(bg!==null)styles.push('background:'+MIRC_COLORS[bg]);
    if(bold)styles.push('font-weight:bold');
    if(underline)styles.push('text-decoration:underline');
    if(italic)styles.push('font-style:italic');
    const ch=g==='&'?'&amp;':g==='<'?'&lt;':g==='>'?'&gt;':g==='"'?'&quot;':g==="'"?'&#39;':g;
    if(styles.length)out+=`<span style="${styles.join(';')}">${ch}</span>`;
    else out+=ch;
  }
  return out;
}
function renderText(s){
  // Detect Element-style reply quote: > <nick> text
  const quoteMatch=s.match(/^> <([^>]+)> (.+)/);
  if(quoteMatch){
    const qNick=esc(quoteMatch[1]);
    const qText=esc(quoteMatch[2]);
    return `<span class="msg-reply-quote"><span style="color:var(--accent);font-weight:600">${qNick}</span> ${qText}</span>`;
  }
  return highlightNicks(linkify(parseMircColors(s)));
}
// Render a status (join/part/quit/nick/mode/kick/away/back) message body. The
// channel names list is stale at sysMsg time (joins haven't been added yet,
// nick changes have already replaced old → new), so we explicitly wrap msg.subject
// (and subject2 for nick changes) as clickable, then run highlightNicks for any
// other names that happen to be present in the text.
// mIRC-style event line text (only when theme='mirc'), rebuilt from the message's
// structured fields so it re-renders correctly on a theme switch. Returns null for
// kinds we don't reformat (those keep their normal text). No host/ident is available
// in CryptIRC's join/part events, so those show just the nick (mIRC shows the host).
function _mircEventText(msg){
  const s=msg.subject||'', s2=msg.subject2||'', txt=msg.text||'';
  const reason=()=>{ const m=txt.match(/\(([^)]*)\)\s*$/); return m?` (${m[1]})`:''; };
  switch(msg.kind){
    case 'join':  return `* Joins: ${s||msg.from||''}`;
    case 'part':  return `* Parts: ${s||msg.from||''}${reason()}`;
    case 'quit':  return `* Quits: ${s||msg.from||''}${reason()}`;
    case 'nick':  return `* ${s2} is now known as ${s}`;
    case 'kick':  return `* ${s} was kicked by ${s2}${reason()}`;
    case 'mode': { const modes=(msg.rawModes||txt.replace(/^.*?sets mode\s*/i,'').replace(/^MODE\s*/i,'')); return s?`* ${s} sets mode: ${modes}`:`* sets mode: ${modes}`; }
    case 'topic': { const t=txt.replace(/^Topic:\s*/i,'').replace(/\s*\([^)]*\)\s*$/,''); return `* Topic is '${t}'`; }
    default: return null;
  }
}
function renderStatusText(msg){
  let raw=msg.text||'';
  if(document.documentElement.dataset.theme==='mirc'){ const _m=_mircEventText(msg); if(_m!=null) raw=_m; }
  let html=parseMircColors(raw);
  html=linkify(html);
  const explicit=[msg.subject,msg.subject2].filter(n=>typeof n==='string'&&n.length);
  for(const nick of explicit){
    const escaped=nick.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const re=new RegExp('(?<![\\w])('+escaped+')(?![\\w])','g');
    html=html.replace(/(<[^>]+>)|([^<]+)/g,(m,tag,text)=>{
      if(tag)return tag;
      // SECURITY: `match` is already HTML-escaped (came through parseMircColors),
      // so it is a safe HTML *attribute* value. We carry the nick in data-nick and
      // let the delegated body-nick listener open the menu — never interpolating
      // a nick into an inline-handler JS-string (findings #3/#9/#10). The HTML
      // parser decodes the attribute back to the real nick for dataset.nick.
      return text.replace(re,(match)=>{return `<span class="nick-mention nc${nickHash(match)}" data-nick="${match}" style="cursor:pointer;font-weight:600">${match}</span>`;});
    });
  }
  return highlightNicks(html);
}
function highlightNicks(html){
  if(!active)return html;
  const net=networks.find(n=>n.config.id===active.conn_id);
  const ch=net?.channels?.find(c=>c.name===active.target);
  if(!ch||!ch.names||!ch.names.length)return html;
  const nicks=ch.names.map(n=>stripPfx(n)).filter(n=>n.length>1);
  if(!nicks.length)return html;
  // Build regex matching any nick as a whole word, skip inside HTML tags
  const escaped=nicks.map(n=>n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'));
  const re=new RegExp('(?<![\\w])('+ escaped.join('|') +')(?![\\w])','g');
  // Split by HTML tags to avoid replacing inside <a href> etc
  return html.replace(/(<[^>]+>)|([^<]+)/g,(m,tag,text)=>{
    if(tag)return tag;
    // SECURITY: carry the nick in an HTML-attribute-escaped data-nick and open the
    // menu via the delegated body-nick listener instead of an inline-handler
    // JS-string (findings #3/#9/#10). `match` is already HTML-escaped here.
    return text.replace(re,(match)=>{return `<span class="nick-mention nc${nickHash(match)}" data-nick="${match}" style="cursor:pointer;font-weight:600">${match}</span>`;});
  });
}
function linkify(s){return s.replace(/(https?:\/\/[^\s<>"]+)/g,(m,url)=>{
  const href=url.includes('/files/')?appendFileToken(url):url;
  return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${url}</a>`;
});}
function nickHash(n){let h=0;for(const c of(n||''))h=(h*31+c.charCodeAt(0))&0xffffffff;return Math.abs(h)%10;}
function nickPri(n){const i='~&@%+'.indexOf(n[0]);return i>=0?i:5;}
function stripPfx(n){let i=0;while(i<n.length&&'~&@%+'.includes(n[i]))i++;return i?n.slice(i):n;}
function getNick(conn_id){return networks.find(n=>n.config.id===conn_id)?.nick||currentUser||'me';}

// ─── Nick Monitor ─────────────────────────────────────────────────────────────
function loadMonitor(){try{return JSON.parse(localStorage.getItem('cryptirc_monitor')||'{}');}catch{return {};}}
function saveMonitor(m){try{localStorage.setItem('cryptirc_monitor',JSON.stringify(m));}catch(e){} savePrefsToServer();}
function monitorAdd(nick){
  const m=loadMonitor();
  const k=nick.toLowerCase();
  if(!m[k]) m[k]={nick,lastSeen:null,network:null,channel:null,lastMsg:null,online:false};
  saveMonitor(m);
}
function monitorRemove(nick){
  const m=loadMonitor();
  delete m[nick.toLowerCase()];
  saveMonitor(m);
}
// Check if a nick is in any channel's names list
function isNickOnline(nick){
  const lc=nick.toLowerCase();
  for(const net of networks){
    for(const ch of net.channels||[]){
      if((ch.names||[]).some(n=>stripPfx(n).toLowerCase()===lc)) return {online:true,network:net.config.label||net.config.server,channel:ch.name};
    }
  }
  return {online:false};
}
function monitorUpdate(nick,conn_id,channel,text){
  const m=loadMonitor();
  const k=nick.toLowerCase();
  if(!m[k])return;
  const net=networks.find(n=>n.config.id===conn_id);
  const wasOnline=m[k].online;
  m[k].lastSeen=Date.now();
  m[k].online=true;
  m[k].network=net?.config.label||net?.config.server||conn_id;
  m[k].channel=channel;
  if(text) m[k].lastMsg=text;
  saveMonitor(m);
  // Alert if they just came online
  if(!wasOnline) monitorAlert(nick,'online');
}
function monitorOffline(nick){
  const m=loadMonitor();
  const k=nick.toLowerCase();
  if(!m[k])return;
  // Double-check they're not in another channel still
  const check=isNickOnline(nick);
  if(check.online)return;
  const wasOnline=m[k].online;
  m[k].online=false;
  saveMonitor(m);
  if(wasOnline) monitorAlert(nick,'offline');
}
function isMonitorNotifsOn(){
  try{return localStorage.getItem('cryptirc_monitor_notifs')!=='off';}catch{return true;}
}
function toggleMonitorNotifs(){
  const btn=document.getElementById('monitor-notif-toggle');
  const on=btn.classList.toggle('on');
  try{localStorage.setItem('cryptirc_monitor_notifs',on?'on':'off');}catch(e){}
  savePrefsToServer();
}
function isMonitorPushOn(){
  try{return localStorage.getItem('cryptirc_monitor_push')!=='off';}catch{return true;}
}
function toggleMonitorPush(){
  const btn=document.getElementById('monitor-push-toggle');
  const on=btn.classList.toggle('on');
  try{localStorage.setItem('cryptirc_monitor_push',on?'on':'off');}catch(e){}
  savePrefsToServer();
}
function monitorAlert(nick,status){
  if(!isMonitorNotifsOn())return;
  // In-app toast
  const color=status==='online'?'var(--join)':'var(--error)';
  const icon=status==='online'?'🟢':'🔴';
  let t=document.getElementById('monitor-toast');
  if(!t){
    t=document.createElement('div');t.id='monitor-toast';
    t.style.cssText='position:fixed;top:max(60px,calc(var(--sat) + 50px));left:50%;transform:translateX(-50%);background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:10px 18px;font-size:13px;z-index:9999;opacity:0;transition:opacity .3s;pointer-events:none;box-shadow:0 4px 16px rgba(0,0,0,.5);display:flex;align-items:center;gap:8px;';
    document.body.appendChild(t);
  }
  t.innerHTML=`${icon} <span style="color:var(--text)">${esc(nick)}</span> <span style="color:${color}">${status}</span>`;
  t.style.opacity='1';
  clearTimeout(t._timer);
  t._timer=setTimeout(()=>{t.style.opacity='0';},4000);
  // Push notification (lock screen)
  if(isMonitorPushOn()){
    wsend({type:'monitor_push',nick,status});
  }
}
// Refresh online status for all monitored nicks (called after names update)
function monitorRefreshOnline(){
  const m=loadMonitor();
  let changed=false;
  for(const[k,e] of Object.entries(m)){
    const check=isNickOnline(e.nick);
    const wasOnline=e.online;
    e.online=check.online;
    if(check.online){
      e.network=check.network;
      e.channel=check.channel;
    }
    if(wasOnline!==check.online){changed=true;monitorAlert(e.nick,check.online?'online':'offline');}
  }
  if(changed) saveMonitor(m);
}
function showMonitorPanel(){
  try{
  const m=loadMonitor();
  const ov=document.getElementById('monitor-overlay');
  const list=document.getElementById('monitor-list');
  _bindMonitorDelegation();   // idempotent; binds the delegated card listener once
  list.innerHTML='';
  // Set toggle states
  const toggle=document.getElementById('monitor-notif-toggle');
  if(toggle){isMonitorNotifsOn()?toggle.classList.add('on'):toggle.classList.remove('on');}
  const pushToggle=document.getElementById('monitor-push-toggle');
  if(pushToggle){isMonitorPushOn()?pushToggle.classList.add('on'):pushToggle.classList.remove('on');}
  const entries=Object.values(m);
  if(!entries.length){
    list.innerHTML=`<div style="color:var(--text3);padding:40px 20px;text-align:center">
      <div style="font-size:32px;margin-bottom:12px;opacity:.4">👁</div>
      <div style="font-size:13px;margin-bottom:8px">No monitored nicks</div>
      <div style="font-size:11px;line-height:1.6">Click a nick → Monitor, or type<br><code style="color:var(--accent)">/monitor &lt;nick&gt;</code></div>
    </div>`;
  } else {
    // Refresh online status from channel names before displaying
    monitorRefreshOnline();
    const mRefreshed=loadMonitor();
    const refreshedEntries=Object.values(mRefreshed);
    for(const e of refreshedEntries.sort((a,b)=>{
      // Online first, then by lastSeen
      if(a.online!==b.online) return a.online?-1:1;
      return (b.lastSeen||0)-(a.lastSeen||0);
    })){
      const ago=e.lastSeen?timeAgo(e.lastSeen):'Never seen';
      const statusDot=e.online?'🟢':'🔴';
      const statusText=e.online?'Online':'Offline';
      const lastDate=e.lastSeen?new Date(e.lastSeen).toLocaleString([], {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}):'—';
      const d=document.createElement('div');
      d.className='monitor-card';
      // SECURITY: monitored nick is attacker-controlled. Carry it on the card via a
      // DOM property (no HTML/JS-string context) and tag each control with a fixed
      // data-monitor-act; a delegated listener on the list reads card.dataset.nick.
      // Replaces the old onclick="monitorOpenQuery('${esc(e.nick)}')" sinks (#9/#10).
      d.dataset.nick=e.nick;
      d.innerHTML=`
        <div class="monitor-card-hdr">
          <span class="monitor-nick" data-monitor-act="query">${esc(e.nick)}</span>
          <span class="monitor-status">${statusDot} ${statusText}</span>
        </div>
        <div class="monitor-card-body">
          <div class="monitor-row"><span class="monitor-label">Network</span><span class="monitor-val">${esc(e.network||'—')}</span></div>
          <div class="monitor-row"><span class="monitor-label">Channel</span><span class="monitor-val">${esc(e.channel||'—')}</span></div>
          <div class="monitor-row"><span class="monitor-label">Last Active</span><span class="monitor-val">${ago}${e.lastSeen?' · '+lastDate:''}</span></div>
          ${e.lastMsg?`<div class="monitor-row monitor-msg-row" data-monitor-act="viewmsg"><span class="monitor-label">Last Msg</span><span class="monitor-val monitor-msg">${esc(e.lastMsg.slice(0,60))}${e.lastMsg.length>60?'…':''}</span></div>`:''}
        </div>
        <div class="monitor-card-actions">
          <button class="monitor-action-btn" data-monitor-act="query">💬 Query</button>
          <button class="monitor-action-btn" data-monitor-act="whois">🔍 Whois</button>
          <button class="monitor-action-btn monitor-remove" data-monitor-act="remove">✕ Remove</button>
        </div>`;
      list.appendChild(d);
    }
  }
  ov.classList.add('show');
  _overlayOpen('monitorPanel', closeMonitorPanel);
  }catch(e){console.error('Monitor panel error:',e);document.getElementById('monitor-overlay')?.classList.add('show');_overlayOpen('monitorPanel', closeMonitorPanel);}
}
// SECURITY: delegated handler for monitor-card controls. Reads the attacker-
// controlled nick from the owning card's dataset (set via DOM property) rather than
// from an inline-handler JS-string — closes the #9/#10 monitor-panel sinks while
// preserving exact click behavior (query / view last msg / whois / remove). Bound
// lazily on first panel render (the list element lives below this script tag, so a
// top-level binding would run before it exists). Idempotent via _monitorDelegated.
function _bindMonitorDelegation(){
  const list=document.getElementById('monitor-list');
  if(!list||list._monitorDelegated)return;
  list._monitorDelegated=true;
  list.addEventListener('click',function(ev){
    const el=ev.target.closest('[data-monitor-act]');
    if(!el||!list.contains(el))return;
    const card=el.closest('.monitor-card');
    const nick=card&&card.dataset.nick;
    if(!nick)return;
    switch(el.dataset.monitorAct){
      case 'query': monitorOpenQuery(nick); break;
      case 'viewmsg': monitorViewMsg(nick); break;
      case 'whois': monitorWhois(nick); break;
      case 'remove': monitorRemove(nick.toLowerCase()); showMonitorPanel(); break;
    }
  });
}
function monitorViewMsg(nick){
  const m=loadMonitor();
  const e=m[nick.toLowerCase()];
  if(!e||!e.lastMsg){showToast('No messages recorded');return;}
  let ov=document.getElementById('monitor-msg-overlay');
  if(!ov){
    ov=document.createElement('div');ov.id='monitor-msg-overlay';
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1100;display:flex;align-items:center;justify-content:center;padding:20px;';
    ov.onclick=()=>ov.remove();
    document.body.appendChild(ov);
  }
  const box=document.createElement('div');
  box.style.cssText='background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;max-width:min(500px,90vw);max-height:min(60vh,60dvh);overflow-y:auto;word-break:break-word;';
  box.innerHTML=`<div style="font-size:11px;color:var(--text3);margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Last message from ${esc(nick)}</div>
    <div style="color:var(--text);font-size:14px;line-height:1.6">${parseMircColors(e.lastMsg||'')}</div>
    ${e.channel?`<div style="font-size:10px;color:var(--text3);margin-top:10px">${esc(e.network||'')} / ${esc(e.channel)} · ${e.lastSeen?new Date(e.lastSeen).toLocaleString():''}</div>`:''}`;
  ov.innerHTML='';ov.appendChild(box);
}
function monitorOpenQuery(nick){
  closeMonitorPanel();
  if(active) setActive(active.conn_id,nick);
}
function monitorWhois(nick){
  closeMonitorPanel();
  if(active){
    if(!window._pendingWhois)window._pendingWhois={};
    window._pendingWhois[active.conn_id]=nick;
    wsend({type:'send',conn_id:active.conn_id,raw:`WHOIS ${nick}`});
  }
}
function closeMonitorPanel(){_overlayClose('monitorPanel');document.getElementById('monitor-overlay').classList.remove('show');}
function timeAgo(ts){
  const s=Math.floor((Date.now()-ts)/1000);
  if(s<60)return s+'s ago';
  if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
