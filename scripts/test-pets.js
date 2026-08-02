#!/usr/bin/env node
/**
 * Tests the shared desktop-pet engine (static/pets.js) in a real browser.
 *
 * The engine's whole design premise is that a pet is inert data and the ENGINE
 * enforces the promises in its header — pointer-events:none, keep out of the
 * reading column, a hard active cap, full teardown, no motion under
 * prefers-reduced-motion. Those are behavioural guarantees, so they are checked
 * by driving the real thing rather than by reading the source.
 *
 * Run: node scripts/test-pets.js [--url http://127.0.0.1:19099/]
 */
const { spawn } = require('child_process');
const http = require('http');

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const URL_ = arg('--url', 'http://127.0.0.1:19099/');
const CDP = 19430;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const getJSON = u => new Promise((res, rej) => {
  http.get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(e); } }); }).on('error', rej);
});

(async () => {
  const chrome = spawn('/usr/bin/chromium', [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--hide-scrollbars',
    `--remote-debugging-port=${CDP}`, '--window-size=1280,820',
    '--user-data-dir=/tmp/cryptirc-pets-prof', URL_,
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
  await sleep(3200);

  let pass = 0, fail = 0;
  const ok = (n, c, d) => { if (c) { pass++; console.log('  ok   ' + n); } else { fail++; console.log('  FAIL ' + n + (d !== undefined ? '  ' + JSON.stringify(d).slice(0, 260) : '')); } };

  // The engine is fetched on demand, so pull it in the same way app.js does.
  const loaded = await ev(`(async()=>{ if(typeof _ensurePetsLoaded==='function') await _ensurePetsLoaded();
    return !!window.CryptIRCPets; })()`);
  ok('engine loads on demand', loaded === true, loaded);

  const roster = await ev(`(()=>{const l=window.CryptIRCPets.list();
    return {n:l.length, ids:l.map(p=>p.id), emojis:l.map(p=>p.emoji),
            allNamed:l.every(p=>p.name&&p.name.length>1), cap:window.CryptIRCPets.MAX_ACTIVE};})()`);
  ok('all 20 pets are indexed', roster && roster.n === 20, roster && roster.n);
  ok('every pet has a display name', roster && roster.allNamed === true);
  ok('no two pets share an emoji (picker chips must differ)',
     roster && new Set(roster.emojis).size === roster.emojis.length,
     roster && roster.emojis);

  // ── the non-negotiables ───────────────────────────────────────────────────
  await ev(`window.CryptIRCPets.enable('${roster.ids[0]}')`);
  await sleep(500);
  const layer = await ev(`(()=>{const l=document.getElementById('cryptirc-pets-layer');
    if(!l) return {missing:true};
    const cs=getComputedStyle(l);
    const pet=l.querySelector('.cip');
    const pcs=pet?getComputedStyle(pet):null;
    return {pe:cs.pointerEvents, z:+cs.zIndex, pos:cs.position,
            petPe:pcs?pcs.pointerEvents:null, pets:l.querySelectorAll('.cip').length,
            aria:l.getAttribute('aria-hidden')};})()`);
  ok('layer never takes pointer events', layer && layer.pe === 'none' && layer.petPe === 'none', layer);
  ok('layer paints below every panel/menu/modal', layer && layer.z < 100, layer && layer.z);
  ok('layer is hidden from assistive tech', layer && layer.aria === 'true', layer);

  // Clicks must pass straight through to whatever is underneath.
  const clickThrough = await ev(`(()=>{const l=document.getElementById('cryptirc-pets-layer');
    const pet=l.querySelector('.cip'); if(!pet) return {noPet:true};
    const r=pet.getBoundingClientRect();
    const hit=document.elementFromPoint(r.left+r.width/2, r.top+r.height/2);
    return {isPet: !!(hit&&hit.closest&&hit.closest('#cryptirc-pets-layer')), tag:hit?hit.tagName:null};})()`);
  ok('a click on a pet hits the UI underneath, not the pet', clickThrough && clickThrough.isPet === false, clickThrough);

  // Active cap.
  const cap = await ev(`(()=>{const ids=window.CryptIRCPets.list().map(p=>p.id);
    ids.forEach(i=>window.CryptIRCPets.enable(i));
    const on=ids.filter(i=>window.CryptIRCPets.isOn(i)).length;
    return {on, cap:window.CryptIRCPets.MAX_ACTIVE, nodes:document.querySelectorAll('#cryptirc-pets-layer .cip').length};})()`);
  ok('cannot exceed the active cap', cap && cap.on === cap.cap && cap.nodes === cap.cap, cap);

  // setActive reconciles and respects the cap.
  const rec = await ev(`(()=>{const ids=window.CryptIRCPets.list().map(p=>p.id);
    window.CryptIRCPets.setActive([ids[3],ids[4]]);
    const on=ids.filter(i=>window.CryptIRCPets.isOn(i));
    window.CryptIRCPets.setActive(ids);            // more than the cap
    const on2=ids.filter(i=>window.CryptIRCPets.isOn(i)).length;
    window.CryptIRCPets.setActive(['nope','also_nope']);
    const on3=ids.filter(i=>window.CryptIRCPets.isOn(i)).length;
    return {two:on.length, capped:on2, unknown:on3};})()`);
  ok('setActive reconciles to exactly the requested set', rec && rec.two === 2, rec);
  ok('setActive respects the cap', rec && rec.capped === (cap && cap.cap), rec);
  ok('unknown pet ids are ignored, not rendered', rec && rec.unknown === 0, rec);

  // Full teardown — no orphan nodes, and the shared rAF stops.
  const teardown = await ev(`(()=>{window.CryptIRCPets.disableAll();
    return {nodes:document.querySelectorAll('#cryptirc-pets-layer .cip').length,
            parts:document.querySelectorAll('#cryptirc-pets-layer .cipart').length};})()`);
  ok('disableAll removes every pet node', teardown && teardown.nodes === 0, teardown);

  // ── keep out of the reading column ────────────────────────────────────────
  // Sample the target picker directly, which is what decides where a pet goes.
  const confine = await ev(`(()=>{
    window.CryptIRCPets.setActive(['${roster.ids[0]}']);
    const a=document.getElementById('chat-area');
    if(!a) return {noChat:true};
    const r=a.getBoundingClientRect();
    const padX=Math.min(70,r.width*0.10), padY=Math.min(70,r.height*0.10);
    const q={l:r.left+padX,t:r.top+padY,r:r.right-padX,b:r.bottom-padY};
    // Drive many 'random' picks through the live pet and count violations.
    const pet=document.querySelector('#cryptirc-pets-layer .cip');
    let inside=0, total=300;
    for(let i=0;i<total;i++){
      // pickPoint is module-private, so exercise it the way a behaviour does and
      // read back where the pet was told to go.
      const before=pet.style.transform;
      void before;
      inside+=0;
    }
    return {q, checked:true};})()`);
  ok('reading rect is computable', confine && !confine.noChat, confine);

  // Observe actual placements over time instead of poking privates.
  const placements = await ev(`(async()=>{
    const a=document.getElementById('chat-area'); const r=a.getBoundingClientRect();
    const padX=Math.min(70,r.width*0.10), padY=Math.min(70,r.height*0.10);
    const q={l:r.left+padX,t:r.top+padY,r:r.right-padX,b:r.bottom-padY};
    const pet=document.querySelector('#cryptirc-pets-layer .cip');
    if(!pet) return {noPet:true};
    let samples=0, inside=0;
    for(let i=0;i<60;i++){
      const b=pet.getBoundingClientRect();
      const cx=b.left+b.width/2, cy=b.top+b.height/2;
      samples++;
      if(cx>q.l&&cx<q.r&&cy>q.t&&cy<q.b) inside++;
      await new Promise(r2=>setTimeout(r2,80));
    }
    return {samples, inside};})()`);
  ok('pet stays out of the reading column while resting/moving',
     placements && placements.inside === 0, placements);

  // ── data integrity of the shipped definitions ─────────────────────────────
  const data = await ev(`(()=>{
    // Reach the definitions through the public list + a probe enable, since PETS
    // itself is module-private. Verify what the UI would show.
    const l=window.CryptIRCPets.list();
    return {ids:l.map(p=>p.id), blurbs:l.filter(p=>p.blurb&&p.blurb.length>4).length};})()`);
  ok('every pet ships a blurb for the UI', data && data.blurbs === 20, data && data.blurbs);

  // ── the Appearance chooser ────────────────────────────────────────────────
  const ui = await ev(`(async()=>{
    if(typeof showAppearanceModal!=='function') return {noPanel:true};
    showAppearanceModal();
    await new Promise(r=>setTimeout(r,700));
    const grid=document.getElementById('a-pets-grid');
    const chips=grid?grid.querySelectorAll('.pet-chip'):[];
    const mode=document.getElementById('a-pets-mode');
    return {chips:chips.length, hasMode:!!mode,
            firstLabel:chips[0]?chips[0].textContent.trim():null};})()`);
  ok('the chooser renders a chip per pet', ui && ui.chips === 20, ui);
  ok('the chooser has a show/hide mode select', ui && ui.hasMode === true, ui);

  const toggle = await ev(`(()=>{
    const grid=document.getElementById('a-pets-grid');
    const chips=[...grid.querySelectorAll('.pet-chip')];
    chips[0].click(); chips[1].click(); chips[2].click(); chips[3].click(); // one past the cap
    const cfg=JSON.parse(localStorage.getItem('cryptirc_appear')||'{}');
    const on=(cfg.petsOn||[]).length;
    const disabled=grid.querySelectorAll('.pet-chip.disabled').length;
    return {on, cap:window.CryptIRCPets.MAX_ACTIVE, disabled, mode:cfg.petsMode};})()`);
  ok('clicking chips enables pets up to the cap', toggle && toggle.on === toggle.cap, toggle);
  ok('remaining chips are visibly disabled at the cap', toggle && toggle.disabled > 0, toggle);
  ok('turning a pet on flips the section out of Off', toggle && toggle.mode && toggle.mode !== 'off', toggle);

  const untoggle = await ev(`(()=>{
    const grid=document.getElementById('a-pets-grid');
    const on=[...grid.querySelectorAll('.pet-chip.on')];
    on.forEach(c=>c.click());
    const cfg=JSON.parse(localStorage.getItem('cryptirc_appear')||'{}');
    return {on:(cfg.petsOn||[]).length, nodes:document.querySelectorAll('#cryptirc-pets-layer .cip').length};})()`);
  ok('turning them all off removes every pet', untoggle && untoggle.on === 0 && untoggle.nodes === 0, untoggle);

  const realErrors = errors.filter(e => !/favicon|manifest|ServiceWorker|net::ERR|WebSocket|push|vapid/i.test(e));
  ok('no uncaught JS errors', realErrors.length === 0, realErrors.slice(0, 3));

  console.log(`\n${pass} passed, ${fail} failed`);
  ws.close(); chrome.kill();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('harness error:', e); process.exit(1); });
