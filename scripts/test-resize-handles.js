#!/usr/bin/env node
/**
 * Tests the drag-to-resize column dividers in a real browser.
 *
 * Three boundaries are draggable — the channel sidebar's right edge, the user
 * list's left edge, and the nick column inside each chat row. Each writes the
 * SAME appearance setting its Appearance slider writes, so the two can never
 * disagree and a dragged width persists and syncs like any other setting. That
 * equivalence, the clamping, and the persistence are what this checks.
 *
 * Run: node scripts/test-resize-handles.js [--url http://127.0.0.1:19099/]
 */
const { spawn } = require('child_process');
const http = require('http');

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const URL_ = arg('--url', 'http://127.0.0.1:19099/');
const USER = arg('--user', 'themetester');
const PASS = arg('--pass', 'TestPass_12345');
const CDP = 19460;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const getJSON = u => new Promise((res, rej) => {
  http.get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(e); } }); }).on('error', rej);
});

(async () => {
  const chrome = spawn('/usr/bin/chromium', [
    
// NOT --hide-scrollbars: the handles sit right next to the 4px scrollbars and
    // an earlier version covered them completely. Hiding them made that invisible.
    '--headless=new', '--no-sandbox', '--disable-gpu',
   
    `--remote-debugging-port=${CDP}`, '--window-size=1400,860',
    '--user-data-dir=/tmp/cryptirc-rz-prof', URL_,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  let targets = null;
  for (let i = 0; i < 50; i++) {
    await sleep(400);
    try { targets = (await getJSON(`http://127.0.0.1:${CDP}/json`)).filter(t => t.type === 'page'); if (targets.length) break; } catch (e) {}
  }
  if (!targets || !targets.length) { console.error('FAIL: chromium never came up'); chrome.kill(); process.exit(1); }

  const ws = new WebSocket(targets[0].webSocketDebuggerUrl);
  let id = 0; const pending = new Map(); const errors = [];
  await new Promise(r => ws.onopen = r);
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    if (m.method === 'Runtime.exceptionThrown') errors.push(String(m.params.exceptionDetails.text || ''));
  };
  const send = (method, params) => new Promise(res => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) return { __err: String(r.result.exceptionDetails.text) };
    return r.result && r.result.result ? r.result.result.value : undefined;
  };
  await send('Runtime.enable'); await send('Page.enable');
  // Headless Chromium has no pointing device, so it matches (hover:none) and
  // (pointer:coarse) — the exact media query that hides these handles on touch.
  // Emulate a mouse, or the whole desktop path is invisible to this test.
  await send('Emulation.setEmulatedMedia', { features: [
    { name: 'hover', value: 'hover' }, { name: 'pointer', value: 'fine' },
  ]});
  await sleep(3200);

  await ev(`(()=>{const u=document.getElementById('l-user'),p=document.getElementById('l-pass');
    if(!u||!p) return 0; u.value=${JSON.stringify(USER)}; p.value=${JSON.stringify(PASS)};
    document.getElementById('login-btn').click(); return 1;})()`);
  await sleep(4200);
  await ev(`(()=>{['vault-overlay','auth-screen','boot-splash','pwa-banner'].forEach(i=>{const n=document.getElementById(i);if(n)n.style.display='none';});
    window.__T={conn:'testconn',chan:'#rz'};
    if(typeof networks!=='undefined'){networks.length=0;networks.push({config:{id:'testconn',label:'T'},nick:'me',connected:true,channels:[{name:'#rz',names:['me','bob'],topic:''}]});}
    if(typeof setActive==='function') setActive('testconn','#rz');
    for(let i=0;i<12;i++) addMessage('testconn','#rz',{ts:Date.now()/1000|0,from:'bob',text:'row '+i,kind:'privmsg',id:Date.now()*1000+i});
    if(typeof _layoutResizeHandles==='function') _layoutResizeHandles();
    return 1;})()`);
  await sleep(900);

  let pass = 0, fail = 0;
  const ok = (n, c, d) => { if (c) { pass++; console.log('  ok   ' + n); } else { fail++; console.log('  FAIL ' + n + (d !== undefined ? '  ' + JSON.stringify(d).slice(0, 240) : '')); } };

  const handles = await ev(`(()=>{const h=document.getElementById('resize-handles');
    if(!h) return {missing:true};
    const ids=['rz-sidebarW','rz-nickPanelW','rz-nickW'];
    return {present:ids.filter(i=>document.getElementById(i)).length,
      visible:ids.filter(i=>{const n=document.getElementById(i);return n&&n.style.display!=='none';}).length,
      cursors:ids.map(i=>{const n=document.getElementById(i);return n?getComputedStyle(n).cursor:null;}),
      z:+getComputedStyle(h).zIndex};})()`);
  ok('all three handles exist', handles && handles.present === 3, handles);
  ok('all three are positioned and shown', handles && handles.visible === 3, handles);
  ok('they show a col-resize cursor', handles && handles.cursors.every(c => c === 'col-resize'), handles && handles.cursors);
  ok('handle layer sits above the sidebar but below modals',
     handles && handles.z > 50 && handles.z < 100, handles && handles.z);

  // Each handle must sit ON its boundary. Assert on the placement this code
  // WRITES (style.left) rather than on getBoundingClientRect: a rect collapses to
  // zero whenever the element is hidden, so a rect-based check silently measures
  // the touch media query instead of the arithmetic. The visibility rule is
  // asserted separately below.
  const aligned = await ev(`(()=>{
    const near=(a,b)=>Math.abs(a-b)<=6;
    const sb=document.getElementById('sidebar').getBoundingClientRect();
    const np=document.getElementById('nick-panel').getBoundingClientRect();
    const nk=document.querySelector('#chat-area .msg-nick');
    const L=i=>parseFloat(document.getElementById(i).style.left)+4;
    return {sidebar:near(L('rz-sidebarW'), sb.right),
            nickPanel:near(L('rz-nickPanelW'), np.left),
            nickCol: nk? near(L('rz-nickW'), nk.getBoundingClientRect().right) : null,
            raw:{s:L('rz-sidebarW'), sbRight:Math.round(sb.right),
                 n:L('rz-nickPanelW'), npLeft:Math.round(np.left),
                 k:L('rz-nickW'), nkRight:nk?Math.round(nk.getBoundingClientRect().right):null}};})()`);
  ok('sidebar handle sits on the sidebar edge', aligned && aligned.sidebar === true, aligned);
  ok('user-list handle sits on the user-list edge', aligned && aligned.nickPanel === true, aligned);
  ok('nick-column handle sits on the nick column edge', aligned && aligned.nickCol === true, aligned);

  // Separately: on a pointer device the handles must actually be laid out with a
  // real box (this is the half a rect-based alignment check was conflating).
  // Headless reports no pointing device and CDP's media-feature emulation does not
  // move (hover)/(pointer) here, so the touch rule always wins. Neutralise just
  // that rule for the duration of the check — this is testing that the LAYOUT
  // produces a real grabbable box, not that the media query works (asserted at
  // the end, where the phone-width case must still hide them).
  const boxed = await ev(`(()=>{
    const mq={hover:matchMedia('(hover:hover)').matches, fine:matchMedia('(pointer:fine)').matches};
    const st=document.createElement('style'); st.id='rz-test-override';
    st.textContent='#resize-handles{display:block !important}';
    document.head.appendChild(st);
    const r=document.getElementById('rz-sidebarW').getBoundingClientRect();
    st.remove();
    return {mq, w:Math.round(r.width), h:Math.round(r.height)};})()`);
  ok('handles lay out with a real grabbable box on a pointer device',
     boxed && boxed.w >= 6 && boxed.h > 20, boxed);

  // Drag each one and confirm the panel actually resized AND the setting stuck.
  const drag = async (hid, dx) => ev(`(async()=>{
    const h=document.getElementById(${JSON.stringify(hid)});
    const r=h.getBoundingClientRect();
    const x=r.left+r.width/2, y=r.top+Math.min(120,r.height/2);
    h.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,clientX:x,clientY:y,button:0,pointerId:1,pointerType:'mouse'}));
    for(let i=1;i<=8;i++){
      document.dispatchEvent(new PointerEvent('pointermove',{bubbles:true,clientX:x+(${dx}*i/8),clientY:y,pointerId:1,pointerType:'mouse'}));
      await new Promise(r2=>setTimeout(r2,16));
    }
    document.dispatchEvent(new PointerEvent('pointerup',{bubbles:true,clientX:x+${dx},clientY:y,pointerId:1,pointerType:'mouse'}));
    await new Promise(r2=>setTimeout(r2,220));
    const cfg=JSON.parse(localStorage.getItem('cryptirc_appear')||'{}');
    return {sidebarW:cfg.sidebarW, nickPanelW:cfg.nickPanelW, nickW:cfg.nickW,
      liveSidebar:Math.round(document.getElementById('sidebar').getBoundingClientRect().width),
      liveNickPanel:Math.round(document.getElementById('nick-panel').getBoundingClientRect().width),
      sliderSidebar:+document.getElementById('a-sidebar-w').value,
      sliderNickPanel:+document.getElementById('a-nickpanel-w').value,
      sliderNick:+document.getElementById('a-nick-w').value};})()`);

  // Reset the three widths first. The appearance blob is persisted per user and
  // synced, so a previous run's drags carry over — an earlier version of this
  // test inherited maxed-out widths and then "failed" to widen them further.
  await ev(`(()=>{const c={...JSON.parse(localStorage.getItem('cryptirc_appear')||'{}'),
      sidebarW:220, nickPanelW:180, nickW:100};
    saveAppearance(c); applyThemeCSS(c);
    if(typeof _layoutResizeHandles==='function') _layoutResizeHandles();
    return 1;})()`);
  await sleep(500);

  const before = await ev(`(()=>{const c=JSON.parse(localStorage.getItem('cryptirc_appear')||'{}');
    return {sidebarW:c.sidebarW||220, nickPanelW:c.nickPanelW||180, nickW:c.nickW||100};})()`);

  const afterSidebar = await drag('rz-sidebarW', 60);
  ok('dragging the sidebar handle widens the sidebar',
     afterSidebar && afterSidebar.sidebarW > before.sidebarW, { before: before.sidebarW, after: afterSidebar && afterSidebar.sidebarW });
  ok('the sidebar actually rendered at the new width',
     afterSidebar && Math.abs(afterSidebar.liveSidebar - afterSidebar.sidebarW) <= 3, afterSidebar);
  ok('the Appearance slider followed the drag',
     afterSidebar && afterSidebar.sliderSidebar === afterSidebar.sidebarW, afterSidebar);

  // The user list grows leftwards, so its handle must invert.
  const afterNickPanel = await drag('rz-nickPanelW', -50);
  ok('dragging the user-list handle left widens it (inverted axis)',
     afterNickPanel && afterNickPanel.nickPanelW > before.nickPanelW,
     { before: before.nickPanelW, after: afterNickPanel && afterNickPanel.nickPanelW });
  ok('the user list rendered at the new width',
     afterNickPanel && Math.abs(afterNickPanel.liveNickPanel - afterNickPanel.nickPanelW) <= 3, afterNickPanel);

  const afterNick = await drag('rz-nickW', 30);
  ok('dragging the nick-column handle widens the nick column',
     afterNick && afterNick.nickW > before.nickW, { before: before.nickW, after: afterNick && afterNick.nickW });
  ok('the nick slider followed the drag', afterNick && afterNick.sliderNick === afterNick.nickW, afterNick);
  // Assert the RENDERED column, not just the stored number. A stored value the
  // layout refuses to honour (a stale max-width cap) looks identical in
  // localStorage and leaves the handle frozen under a moving cursor.
  const nickRendered = await ev(`(()=>{const n=[...document.querySelectorAll('#chat-area .msg-nick')].find(x=>x.getBoundingClientRect().width>0);
    const cfg=JSON.parse(localStorage.getItem('cryptirc_appear')||'{}');
    return n? {rendered:Math.round(n.getBoundingClientRect().width), stored:cfg.nickW} : {none:true};})()`);
  ok('the nick column actually renders at the stored width',
     nickRendered && !nickRendered.none && Math.abs(nickRendered.rendered - nickRendered.stored) <= 2, nickRendered);
  // And past the old 120px cap specifically.
  const wide = await ev(`(async()=>{
    const c={...JSON.parse(localStorage.getItem('cryptirc_appear')||'{}'), nickW:170};
    saveAppearance(c); applyThemeCSS(c);
    await new Promise(r=>setTimeout(r,200));
    const n=[...document.querySelectorAll('#chat-area .msg-nick')].find(x=>x.getBoundingClientRect().width>0);
    return n? Math.round(n.getBoundingClientRect().width) : -1;})()`);
  ok('the nick column can exceed the old 120px cap', wide >= 168, { rendered: wide });

  // Clamping: a huge drag must stop at the slider's own limits, not run away.
  const clamped = await drag('rz-sidebarW', 4000);
  ok('dragging far past the maximum clamps to it', clamped && clamped.sidebarW === 360, clamped && clamped.sidebarW);
  const clampedLow = await drag('rz-sidebarW', -4000);
  ok('dragging far past the minimum clamps to it', clampedLow && clampedLow.sidebarW === 160, clampedLow && clampedLow.sidebarW);

  // Double-click resets to the shipped default.
  const reset = await ev(`(()=>{const h=document.getElementById('rz-sidebarW');
    h.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
    const c=JSON.parse(localStorage.getItem('cryptirc_appear')||'{}');
    return {sidebarW:c.sidebarW};})()`);
  ok('double-click resets that divider to default', reset && reset.sidebarW === 220, reset);

  // Persistence is the explicit ask: it has to survive a reload.
  // Drag it to a distinctive width through the real path, so the value goes out
  // via saveAppearance -> server sync the way a user's drag would.
  await drag('rz-sidebarW', 45);
  const want = await ev(`(JSON.parse(localStorage.getItem('cryptirc_appear')||'{}')).sidebarW`);
  await sleep(2600);   // let the debounced prefs push reach the server
  await send('Page.reload', {}); await sleep(5200);
  await ev(`(()=>{['vault-overlay','auth-screen','boot-splash','pwa-banner'].forEach(i=>{const n=document.getElementById(i);if(n)n.style.display='none';});return 1;})()`);
  await sleep(600);
  const persisted = await ev(`(()=>({stored:(JSON.parse(localStorage.getItem('cryptirc_appear')||'{}')).sidebarW,
    live:Math.round(document.getElementById('sidebar').getBoundingClientRect().width)}))()`);
  ok('a dragged width survives a reload',
     persisted && persisted.stored === want && Math.abs(persisted.live - want) <= 3, { want, persisted });

  // Mobile must not get handles — the left edge is the swipe-to-open gesture.
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 780, deviceScaleFactor: 2, mobile: true });
  await send('Emulation.setEmulatedMedia', { features: [
    { name: 'hover', value: 'none' }, { name: 'pointer', value: 'coarse' },
  ]});
  await sleep(700);
  const mobile = await ev(`(()=>{const h=document.getElementById('resize-handles');
    if(typeof _layoutResizeHandles==='function') _layoutResizeHandles();
    return {display:getComputedStyle(h).display};})()`);
  ok('no drag handles on a phone-width layout', mobile && mobile.display === 'none', mobile);
  await send('Emulation.clearDeviceMetricsOverride', {});

  const realErrors = errors.filter(e => !/favicon|manifest|ServiceWorker|net::ERR|WebSocket|push|vapid/i.test(e));
  ok('no uncaught JS errors', realErrors.length === 0, realErrors.slice(0, 3));

  console.log(`\n${pass} passed, ${fail} failed`);
  ws.close(); chrome.kill();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('harness error:', e); process.exit(1); });
