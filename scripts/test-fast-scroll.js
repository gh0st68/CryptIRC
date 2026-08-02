#!/usr/bin/env node
/**
 * Repro + regression harness for two reported chat-viewport bugs:
 *
 *   (A) "when people speak fast the client stops scrolling with it and I have to
 *        force it to scroll down"
 *   (B) "when it shows people typing it blocks the latest msg"
 *
 * Both are timing/layout bugs that only appear in a real engine, so this drives a
 * real headless Chromium against a real CryptIRC instance over CDP rather than
 * simulating anything. Reading the code alone cannot decide either one.
 *
 * The measurement in both cases is the same and is the user's actual complaint:
 * after the dust settles, is the newest message actually visible?
 *
 * Usage:  node scripts/test-fast-scroll.js [--url http://127.0.0.1:19099/] \
 *                                          [--user NAME] [--pass PASS] [--keep]
 * Exit 0 = all scenarios pass.
 */
const { spawn } = require('child_process');
const http = require('http');

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const URL_  = arg('--url', 'http://127.0.0.1:19099/');
const USER  = arg('--user', 'themetester');
const PASS  = arg('--pass', 'TestPass_12345');
const CDP   = 19420;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const getJSON = u => new Promise((res, rej) => {
  http.get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(e); } }); }).on('error', rej);
});

(async () => {
  const chrome = spawn('/usr/bin/chromium', [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--hide-scrollbars',
    `--remote-debugging-port=${CDP}`, '--window-size=1280,820',
    '--user-data-dir=/tmp/cryptirc-scrolltest-prof', URL_,
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
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
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
  await sleep(3200);

  await ev(`(()=>{const u=document.getElementById('l-user'),p=document.getElementById('l-pass');
    if(!u||!p) return 'no-form'; u.value=${JSON.stringify(USER)}; p.value=${JSON.stringify(PASS)};
    document.getElementById('login-btn').click(); return 'ok';})()`);
  await sleep(4200);

  // Put the client into a synthetic channel and hide the vault gate so #chat-area
  // is the live, scrolling element — exactly what it is in normal use.
  const setup = await ev(`(()=>{
    ['vault-overlay','auth-screen','boot-splash','pwa-banner'].forEach(i=>{const n=document.getElementById(i);if(n)n.style.display='none';});
    window.__T={conn:'testconn', chan:'#speedtest'};
    if(typeof networks!=='undefined'){
      networks.length=0;
      networks.push({config:{id:'testconn',label:'T'},nick:'me',connected:true,
        channels:[{name:'#speedtest',names:['me','fast'],topic:''}]});
    }
    if(typeof setActive==='function') setActive('testconn','#speedtest');
    const a=document.getElementById('chat-area');
    return a? {ok:true, h:Math.round(a.clientHeight)} : {ok:false};
  })()`);
  if (!setup || !setup.ok) { console.error('FAIL: could not reach #chat-area', setup); ws.close(); chrome.kill(); process.exit(1); }

  let pass = 0, fail = 0;
  const ok = (n, c, d) => { if (c) { pass++; console.log('  ok   ' + n); } else { fail++; console.log('  FAIL ' + n + (d !== undefined ? '  ' + JSON.stringify(d) : '')); } };

  // Distance from the true bottom. <= ~2px means the newest line is fully visible.
  const gap = () => ev(`(()=>{const a=document.getElementById('chat-area');
    return Math.round(a.scrollHeight-a.scrollTop-a.clientHeight);})()`);
  // Clear ONLY this conversation's buffer and re-establish the active view.
  // Blanking `buffers` wholesale orphans the view setActive() set up, and every
  // subsequent append then renders nowhere — which silently turned later
  // preconditions into vacuous passes.
  const reset = () => ev(`(()=>{
    const {conn,chan}=window.__T;
    const a=document.getElementById('chat-area');
    try{ if(typeof buffers!=='undefined'&&buffers[conn]) delete buffers[conn]; }catch(e){}
    if(typeof setActive==='function') setActive(conn,chan);
    a.innerHTML='';
    _userScrolledAway=false; _jumpAnchor=false;
    a.scrollTop=a.scrollHeight; return 1;})()`);
  // Guard against vacuous passes: a scenario that appended nothing must fail loudly.
  const assertContent = async (label, minRows) => {
    const n = await ev(`document.getElementById('chat-area').children.length`);
    ok(`${label} — rows actually rendered`, typeof n === 'number' && n >= minRows, { rows: n });
    return n;
  };

  // Feed n messages at `every` ms with a given body, through the REAL addMessage
  // path so appendMsgRow / _pruneChatDOM / scrollBottom all run for real.
  const flood = (n, every, body) => ev(`(async()=>{
    const {conn,chan}=window.__T;
    for(let i=0;i<${n};i++){
      addMessage(conn,chan,{ts:Date.now()/1000|0,from:'fast',text:${JSON.stringify(body)}+' '+i,kind:'privmsg',id:Date.now()*1000+i});
      await new Promise(r=>setTimeout(r,${every}));
    }
    await new Promise(r=>setTimeout(r,900));
    return 1;})()`);

  console.log('\n── (A) fast chat: does auto-follow survive? ──');

  for (const [label, n, every, body] of [
    ['slow chat (200ms apart)',            18, 200, 'hello there'],
    ['fast chat (30ms apart)',             60,  30, 'spamming away'],
    ['very fast chat (8ms apart)',        120,   8, 'flood'],
    ['fast + tall multi-line messages',    40,  25, 'line one\\nline two\\nline three\\nline four\\nline five\\nline six'],
  ]) {
    await reset();
    await flood(n, every, body);
    const g = await gap();
    const away = await ev('_userScrolledAway');
    ok(`${label} — still pinned to newest`, typeof g === 'number' && g <= 4, { gap: g, _userScrolledAway: away });
  }

  // The scenarios above await between messages, which hands the event loop a
  // chance to dispatch each 'scroll' before the next row lands. Real traffic does
  // not behave like that: messages arrive from ws.onmessage back-to-back, and a
  // burst can append many rows before a single scroll event is delivered. That is
  // the timing that can strand auto-follow, so exercise it directly.
  console.log('\n── (A5) burst delivery (no yield between messages) ──');
  for (const [label, n, body] of [
    ['20 rows in one task',            20, 'burst'],
    ['60 rows in one task',            60, 'burst'],
    ['30 tall rows in one task',       30, 'a\\nb\\nc\\nd\\ne\\nf\\ng\\nh'],
  ]) {
    await reset();
    await ev(`(()=>{const {conn,chan}=window.__T;
      for(let i=0;i<${n};i++) addMessage(conn,chan,{ts:Date.now()/1000|0,from:'burst',text:${JSON.stringify(body)}+' '+i,kind:'privmsg',id:Date.now()*1000+i});
      return 1;})()`);
    await sleep(900);
    const g = await gap();
    ok(`${label} — still pinned`, typeof g === 'number' && g <= 4, { gap: g, _userScrolledAway: await ev('_userScrolledAway') });
  }

  // Several bursts separated by exactly one animation frame — the worst case for
  // a scroll event landing after the geometry has already moved on.
  console.log('\n── (A6) rAF-aligned bursts ──');
  await reset();
  await ev(`(async()=>{const {conn,chan}=window.__T;
    for(let b=0;b<25;b++){
      for(let i=0;i<8;i++) addMessage(conn,chan,{ts:Date.now()/1000|0,from:'raf',text:'raf burst '+b+'.'+i,kind:'privmsg',id:Date.now()*1000+b*10+i});
      await new Promise(r=>requestAnimationFrame(()=>r()));
    }
    await new Promise(r=>setTimeout(r,800)); return 1;})()`);
  const gRaf = await gap();
  ok('rAF-aligned bursts — still pinned', typeof gRaf === 'number' && gRaf <= 4,
     { gap: gRaf, _userScrolledAway: await ev('_userScrolledAway') });

  // Late-loading media changes height after the row is already placed.
  console.log('\n── (A7) message with late-loading media ──');
  await reset();
  await flood(15, 30, 'before the image');
  // Deliberately NO width/height and no reserved box — that is how the real
  // renderer inserts them (app.js buildMediaEl sets only className and src), so
  // the row occupies ~0px when it is scrolled to and then jumps by the full image
  // height once it decodes. That late jump is the >200px geometry change that can
  // be misread as the user scrolling away.
  await ev(`(()=>{const a=document.getElementById('chat-area');
    for(let k=0;k<3;k++){
      const d=document.createElement('div'); d.className='msg-row';
      const img=document.createElement('img');
      img.src='data:image/svg+xml;utf8,'+encodeURIComponent("<svg xmlns='http://www.w3.org/2000/svg' width='420' height='"+(260+k*40)+"'><rect width='420' height='"+(260+k*40)+"' fill='%23234'/></svg>");
      img.onload=()=>{ if(!_userScrolledAway) scrollBottom(); };
      d.appendChild(img); a.appendChild(d);
    }
    return 1;})()`);
  await sleep(1400);
  const gImg = await gap();
  ok('late unsized media does not strand the view', typeof gImg === 'number' && gImg <= 4,
     { gap: gImg, _userScrolledAway: await ev('_userScrolledAway') });

  // Same thing but arriving DURING a burst — media decoding while more rows land
  // is the combination the reporter hits in a busy channel.
  await reset();
  await ev(`(()=>{const {conn,chan}=window.__T; const a=document.getElementById('chat-area');
    for(let i=0;i<25;i++) addMessage(conn,chan,{ts:Date.now()/1000|0,from:'x',text:'msg '+i,kind:'privmsg',id:Date.now()*1000+i});
    for(let k=0;k<4;k++){
      const d=document.createElement('div'); d.className='msg-row';
      const img=document.createElement('img');
      img.src='data:image/svg+xml;utf8,'+encodeURIComponent("<svg xmlns='http://www.w3.org/2000/svg' width='400' height='"+(300+k*30)+"'><rect width='400' height='"+(300+k*30)+"' fill='%23345'/></svg>");
      img.onload=()=>{ if(!_userScrolledAway) scrollBottom(); };
      d.appendChild(img); a.appendChild(d);
    }
    for(let i=0;i<25;i++) addMessage(conn,chan,{ts:Date.now()/1000|0,from:'y',text:'after '+i,kind:'privmsg',id:Date.now()*1000+500+i});
    return 1;})()`);
  await sleep(1600);
  const gMix = await gap();
  ok('burst interleaved with unsized media stays pinned', typeof gMix === 'number' && gMix <= 4,
     { gap: gMix, _userScrolledAway: await ev('_userScrolledAway') });

  // The DOM cap only engages above 1000 rows — a busy channel crosses that in
  // minutes, and every scenario above stayed well under it, so pruning was never
  // exercised. Removing rows from the top mutates scrollHeight under the
  // viewport, which is exactly the kind of event that can strand auto-follow.
  console.log('\n── (A4) crossing the 1000-row DOM prune cap ──');
  await reset();
  await ev(`(async()=>{const {conn,chan}=window.__T;
    for(let i=0;i<1100;i++){
      addMessage(conn,chan,{ts:Date.now()/1000|0,from:'bulk',text:'backlog '+i,kind:'privmsg',id:Date.now()*1000+i});
      if(i%50===0) await new Promise(r=>setTimeout(r,0));
    }
    await new Promise(r=>setTimeout(r,600)); return 1;})()`);
  const rowsAfterPrune = await ev(`document.getElementById('chat-area').children.length`);
  ok('prune cap actually engaged', rowsAfterPrune > 0 && rowsAfterPrune <= 1001, { rows: rowsAfterPrune });
  const gPrune = await gap();
  ok('still pinned to newest after pruning', typeof gPrune === 'number' && gPrune <= 4,
     { gap: gPrune, rows: rowsAfterPrune, _userScrolledAway: await ev('_userScrolledAway') });
  // ...and keep following once more arrive on top of a pruned buffer.
  await flood(30, 15, 'post-prune');
  const gPrune2 = await gap();
  ok('auto-follow survives past the prune cap', typeof gPrune2 === 'number' && gPrune2 <= 4,
     { gap: gPrune2, _userScrolledAway: await ev('_userScrolledAway') });

  console.log('\n── (A2) a real user scrolling up must still detach ──');
  await reset();
  await flood(80, 12, 'filler filler filler');
  await assertContent('A2 setup', 60);
  // Scroll far enough up that we are genuinely reading history, and ASSERT the
  // precondition — an earlier version of this test silently measured from the
  // bottom because the buffer was too short to scroll at all.
  const scrolled = await ev(`(()=>{const a=document.getElementById('chat-area');
    if(a.scrollHeight-a.clientHeight < 400) return {tooShort:true, sh:a.scrollHeight, ch:a.clientHeight};
    a.dispatchEvent(new WheelEvent('wheel',{deltaY:-400,bubbles:true}));
    a.scrollTop=Math.max(0,a.scrollHeight-a.clientHeight-800);
    a.dispatchEvent(new Event('scroll',{bubbles:true}));
    return {tooShort:false, gap:Math.round(a.scrollHeight-a.scrollTop-a.clientHeight)};})()`);
  ok('precondition: buffer is long enough to scroll up', scrolled && !scrolled.tooShort, scrolled);
  await sleep(400);
  const detached = await ev('_userScrolledAway');
  ok('scrolling up sets _userScrolledAway', detached === true, { _userScrolledAway: detached });
  await flood(10, 30, 'more while reading history');
  const gAfter = await ev(`(()=>{const a=document.getElementById('chat-area');return Math.round(a.scrollHeight-a.scrollTop-a.clientHeight);})()`);
  ok('new messages do NOT yank a reader back down', gAfter > 100, { gap: gAfter });

  console.log('\n── (A3) returning to the bottom re-attaches ──');
  await ev(`(()=>{const a=document.getElementById('chat-area');a.scrollTop=a.scrollHeight;
    a.dispatchEvent(new Event('scroll',{bubbles:true})); return 1;})()`);
  await sleep(300);
  const reattached = await ev('_userScrolledAway');
  ok('reaching the bottom clears _userScrolledAway', reattached === false, { _userScrolledAway: reattached });
  await flood(8, 40, 'following again');
  const gRe = await gap();
  ok('auto-follow resumes after re-attach', typeof gRe === 'number' && gRe <= 4, { gap: gRe });

  // These two come straight from an adversarial audit of the fix itself, and both
  // describe regressions the fix INTRODUCED. They are the cases that matter most:
  // a scroll fix that makes it impossible to scroll is worse than the bug.
  console.log('\n── (A8) the user can still scroll up DURING a flood ──');
  await reset();
  await flood(60, 15, 'noisy channel');
  await assertContent('A8 setup', 40);
  // Scroll up while messages are STILL arriving. An earlier version of this fix
  // suppressed detach for 350ms after any programmatic pin — and since every
  // arriving message pins, that window never closed and the user was trapped at
  // the bottom in exactly the busy channels this is meant to fix.
  const duringFlood = await ev(`(async()=>{
    const {conn,chan}=window.__T; const a=document.getElementById('chat-area');
    let stop=false;
    const pump=(async()=>{ let i=0; while(!stop){ addMessage(conn,chan,{ts:Date.now()/1000|0,from:'noise',text:'during '+(i++),kind:'privmsg',id:Date.now()*1000+i}); await new Promise(r=>setTimeout(r,20)); } })();
    await new Promise(r=>setTimeout(r,200));
    // A real upward drag: several small steps, like a trackpad.
    for(let k=0;k<12;k++){
      a.scrollTop=Math.max(0,a.scrollTop-60);
      a.dispatchEvent(new WheelEvent('wheel',{deltaY:-60,bubbles:true}));
      a.dispatchEvent(new Event('scroll',{bubbles:true}));
      await new Promise(r=>setTimeout(r,25));
    }
    await new Promise(r=>setTimeout(r,400));
    const away=_userScrolledAway;
    const gap1=Math.round(a.scrollHeight-a.scrollTop-a.clientHeight);
    await new Promise(r=>setTimeout(r,700));
    const gap2=Math.round(a.scrollHeight-a.scrollTop-a.clientHeight);
    stop=true; await pump;
    return {away, gap1, gap2};})()`);
  ok('scrolling up during a flood detaches', duringFlood && duringFlood.away === true, duringFlood);
  ok('and the view STAYS put while messages keep arriving',
     duringFlood && duringFlood.gap2 >= duringFlood.gap1, duringFlood);

  console.log('\n── (A9) "load older" must not snap back to the bottom ──');
  await reset();
  await flood(40, 15, 'recent');
  await assertContent('A9 setup', 30);
  // Reproduce what prependLogs' load-older branch does: renderChat() (which
  // scrollForce()s and arms re-anchor timers out to 2s), then restore position.
  const older = await ev(`(async()=>{
    const a=document.getElementById('chat-area');
    const oldHeight=a.scrollHeight;
    for(let i=0;i<40;i++){ const d=document.createElement('div'); d.className='msg-row'; d.textContent='older '+i; a.insertBefore(d,a.firstChild); }
    if(typeof scrollForce==='function') scrollForce();           // what renderChat does
    const newHeight=a.scrollHeight;
    a.scrollTop=newHeight-oldHeight;
    if(typeof _cancelScrollForce==='function') _cancelScrollForce();
    _userScrolledAway=true; _lastScrollTop=a.scrollTop;
    // The shipped path re-asserts the position on the next frame too — mirror it.
    await new Promise(r=>requestAnimationFrame(()=>r()));
    a.scrollTop=newHeight-oldHeight; _lastScrollTop=a.scrollTop;
    const right=Math.round(a.scrollTop);
    await new Promise(r=>setTimeout(r,2600));                    // outlast every timer
    return {restored:right, after:Math.round(a.scrollTop),
            gap:Math.round(a.scrollHeight-a.scrollTop-a.clientHeight), away:_userScrolledAway};})()`);
  ok('position held across all the delayed re-anchors',
     older && Math.abs(older.after - older.restored) <= 4, older);
  ok('did not end up pinned to the bottom', older && older.gap > 100, older);

  console.log('\n── (B) typing indicator must not cover the newest message ──');
  await reset();
  await flood(25, 40, 'last visible message');
  const before = await gap();
  const shown = await ev(`(()=>{
    const {conn,chan}=window.__T;
    window._typingState=window._typingState||{};
    window._typingState[conn+'/'+chan.toLowerCase()+'/somebody']=Date.now();
    if(typeof updateTypingIndicator==='function') updateTypingIndicator();
    const t=document.getElementById('typing-indicator');
    return {cls:t.className, h:Math.round(t.getBoundingClientRect().height)};
  })()`);
  ok('typing indicator became visible', shown && shown.cls === 'visible', shown);
  // The 120ms height transition is the whole point — measure AFTER it finishes.
  await sleep(700);
  const afterShow = await gap();
  ok('newest message still visible once typing appears',
     typeof afterShow === 'number' && afterShow <= 4, { gapBefore: before, gapAfterTypingShown: afterShow });

  // Typer list changing while already visible can re-wrap and change height.
  await ev(`(()=>{const {conn,chan}=window.__T;
    window._typingState[conn+'/'+chan.toLowerCase()+'/another']=Date.now();
    window._typingState[conn+'/'+chan.toLowerCase()+'/athird']=Date.now();
    if(typeof updateTypingIndicator==='function') updateTypingIndicator(); return 1;})()`);
  await sleep(700);
  const afterGrow = await gap();
  ok('newest message still visible when the typer list grows',
     typeof afterGrow === 'number' && afterGrow <= 4, { gap: afterGrow });

  await ev(`(()=>{window._typingState={}; if(typeof updateTypingIndicator==='function') updateTypingIndicator(); return 1;})()`);
  await sleep(700);
  const afterHide = await gap();
  ok('newest message still visible when typing stops',
     typeof afterHide === 'number' && afterHide <= 4, { gap: afterHide });

  console.log('\n── (B2) typing must not yank a user reading history ──');
  // Needs a buffer long enough to actually scroll up in — assert it rather than
  // silently measuring from the bottom.
  await reset();
  await flood(80, 12, 'history history history');
  await assertContent('B2 setup', 60);
  const hs = await ev(`(()=>{const a=document.getElementById('chat-area');
    if(a.scrollHeight-a.clientHeight < 400) return {tooShort:true};
    a.dispatchEvent(new WheelEvent('wheel',{deltaY:-400,bubbles:true}));
    a.scrollTop=Math.max(0,a.scrollHeight-a.clientHeight-800);
    a.dispatchEvent(new Event('scroll',{bubbles:true}));
    return {tooShort:false};})()`);
  ok('precondition: can scroll up for the typing test', hs && !hs.tooShort, hs);
  await sleep(300);
  const gHist = await gap();
  await ev(`(()=>{const {conn,chan}=window.__T;
    window._typingState[conn+'/'+chan.toLowerCase()+'/somebody']=Date.now();
    if(typeof updateTypingIndicator==='function') updateTypingIndicator(); return 1;})()`);
  await sleep(700);
  const gHist2 = await gap();
  ok('typing does not scroll a history reader to the bottom', gHist2 > 100, { before: gHist, after: gHist2 });

  const realErrors = errors.filter(e => !/favicon|manifest|ServiceWorker|net::ERR|WebSocket|push|vapid/i.test(e));
  ok('no uncaught JS errors during the run', realErrors.length === 0, realErrors.slice(0, 3));

  console.log(`\n${pass} passed, ${fail} failed`);
  ws.close();
  if (process.argv.indexOf('--keep') < 0) chrome.kill();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('harness error:', e); process.exit(1); });
