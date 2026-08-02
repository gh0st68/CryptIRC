#!/usr/bin/env node
/**
 * test-pet-motion.js — pins the thing that makes a pet read as its species.
 *
 * WHY THIS EXISTS
 * The twenty shared-engine pets shipped with a `motion` field on every
 * definition that the engine never read. Every one of them — snail, paper plane,
 * wind-up key — travelled by the same straight-line easeInOut tween, fidgeted
 * with the same random nudge, and could sit at any height on the screen. The
 * only thing telling them apart was the drawing, and gh0st's report was that
 * they "dont move around like the actual thing they are".
 *
 * `motion` now drives a real locomotion profile (MOTION in static/pets.js). That
 * is easy to regress silently — deleting the one line that calls prof.ease()
 * would leave every existing test green and every pet moving identically again,
 * which is precisely the bug. So this checks it two ways:
 *
 *   Part 1 (deterministic, no browser): the profile MATH. Curves must be
 *   monotonic and exact at both ends or a pet stutters backwards / never
 *   arrives; body amplitudes must stay cosmetic; the profiles must actually
 *   DIFFER from each other and from a plain glide.
 *
 *   Part 2 (real browser, optional): the OBSERVABLE consequences. A snail is on
 *   the floor, a balloon is not, a machine has no idle body life and an animal
 *   does. These are chosen to be robust to sampling noise — a 16s window catches
 *   only a handful of behaviours, so anything tighter would flake.
 *
 * Run:  node scripts/test-pet-motion.js                      # part 1 only
 *       node scripts/test-pet-motion.js --url http://…/      # both
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const URL_ = arg('--url', null);

let pass = 0, fail = 0;
const ok = (n, c, d) => {
  if (c) { pass++; console.log('  ok   ' + n); }
  else { fail++; console.log('  FAIL ' + n + (d !== undefined ? '  ' + JSON.stringify(d).slice(0, 300) : '')); }
};

// ── load the REAL shipped profiles ──────────────────────────────────────────
// Extracted from the shipped file rather than retyped, and evaluated in a bare
// context that provides only what the real module can rely on — the lesson from
// scripts/test-timestamp-format.js is that a harness supplying a convenience
// global the page does not have will validate logic that cannot actually run.
const SRC = path.join(__dirname, '..', 'static', 'pets.js');
const src = fs.readFileSync(SRC, 'utf8');
const from = src.indexOf('function linearK');
const to = src.indexOf('function profileFor');
if (from < 0 || to < 0 || to < from) { console.error('could not locate the MOTION block in static/pets.js'); process.exit(1); }
const sandbox = { Math: Math, MOTION: null, DEFAULT_PROFILE: null };
vm.createContext(sandbox);
vm.runInContext(src.slice(from, to) + '\n;this.MOTION=MOTION;this.DEFAULT_PROFILE=DEFAULT_PROFILE;', sandbox);
const MOTION = sandbox.MOTION, DEFAULT_PROFILE = sandbox.DEFAULT_PROFILE;

// The pet definitions, read out of the same shipped file.
const A = '/* PETS_DATA */', B = '/* /PETS_DATA */';
const PETS = JSON.parse(src.slice(src.indexOf(A) + A.length, src.indexOf(B)).trim());

console.log('\n— profile math —');
ok('the MOTION table loaded from the shipped file', MOTION && Object.keys(MOTION).length >= 10, MOTION && Object.keys(MOTION).length);

const easeInOut = k => (k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2);
const names = Object.keys(MOTION);

// A curve that is not monotonic makes a pet visibly stutter backwards mid-move;
// one that misses 0 or 1 makes it teleport at the start or never reach its target.
let curveBad = [];
for (const n of names) {
  const e = MOTION[n].ease || easeInOut;
  if (Math.abs(e(0)) > 1e-9 || Math.abs(e(1) - 1) > 1e-9) { curveBad.push(n + ':endpoints'); continue; }
  let prev = -1;
  for (let i = 0; i <= 2000; i++) { const v = e(i / 2000); if (v < prev - 1e-9) { curveBad.push(n + ':nonmonotonic'); break; } prev = v; }
}
ok('every progress curve is monotonic and exact at both ends', curveBad.length === 0, curveBad);

// Body motion is cosmetic and must stay small: it is composited on top of the
// scripted transforms and is NOT subject to the keep-out clamp, so a large
// amplitude here could park a pet on the text.
let bodyBad = [];
for (const n of names) {
  const b = MOTION[n].body;
  if (!b) continue;
  let mxOff = 0, mxRot = 0, mxScale = 0;
  for (let t = 0; t < 40000; t += 7) {
    const o = { dx: 0, dy: 0, sx: 1, sy: 1, rot: 0 };
    b(t, { phase: 2.1 }, o);
    if (![o.dx, o.dy, o.sx, o.sy, o.rot].every(Number.isFinite)) { bodyBad.push(n + ':nonfinite'); break; }
    mxOff = Math.max(mxOff, Math.abs(o.dx), Math.abs(o.dy));
    mxRot = Math.max(mxRot, Math.abs(o.rot));
    mxScale = Math.max(mxScale, Math.abs(o.sx - 1), Math.abs(o.sy - 1));
  }
  if (mxOff > 6) bodyBad.push(`${n}:offset ${mxOff.toFixed(1)}px`);
  if (mxRot > 12) bodyBad.push(`${n}:rot ${mxRot.toFixed(1)}deg`);
  if (mxScale > 0.12) bodyBad.push(`${n}:scale ${mxScale.toFixed(3)}`);
}
ok('body dynamics stay within cosmetic bounds (<=6px, <=12deg, <=12% scale)', bodyBad.length === 0, bodyBad);

// A warp rewrites the path completely, so it MUST still start at the start and
// finish exactly on the target or the pet lands somewhere it was never cleared for.
let warpBad = [];
for (const n of names) {
  const w = MOTION[n].warp;
  if (!w) continue;
  for (const p of [{ sx: 100, sy: 100, tx: 400, ty: 300 }, { sx: 500, sy: 40, tx: 60, ty: 700 }, { sx: 10, sy: 10, tx: 10, ty: 10 }]) {
    const a = w(0, p), b = w(1, p);
    if (Math.hypot(a.x - p.sx, a.y - p.sy) > 0.01) warpBad.push(n + ':start');
    if (Math.hypot(b.x - p.tx, b.y - p.ty) > 0.01) warpBad.push(n + ':end');
    for (let i = 0; i <= 100; i++) { const q = w(i / 100, p); if (!Number.isFinite(q.x) || !Number.isFinite(q.y)) { warpBad.push(n + ':nonfinite'); break; } }
  }
}
ok('every warp starts at the origin and lands exactly on the target', warpBad.length === 0, warpBad);

// Bands must be ordered and inside 0..1, or bandClamp inverts and pins the pet.
let bandBad = [];
for (const n of names) {
  const b = MOTION[n].band || DEFAULT_PROFILE.band;
  if (!(Array.isArray(b) && b.length === 2 && b[0] >= 0 && b[1] <= 1 && b[0] < b[1])) bandBad.push(n + ':' + JSON.stringify(b));
}
ok('every vertical band is ordered and within the viewport', bandBad.length === 0, bandBad);

// Idle ranges must be ordered, or `min + rand*(max-min)` runs backwards.
let idleBad = [];
for (const n of names) {
  const i = MOTION[n].idle || DEFAULT_PROFILE.idle;
  for (const k of ['every', 'dist', 'dur']) {
    if (!(Array.isArray(i[k]) && i[k][0] > 0 && i[k][1] >= i[k][0])) idleBad.push(`${n}.${k}`);
  }
}
ok('every idle range is positive and ordered', idleBad.length === 0, idleBad);

// THE POINT OF THE WHOLE FEATURE: the profiles must actually differ. Sample each
// curve and each idle profile and require distinct fingerprints — if someone
// deletes the prof.ease() call or flattens the table, this is what catches it.
const fp = n => {
  const p = MOTION[n], e = p.ease || easeInOut;
  const curve = [];
  for (let i = 1; i < 20; i++) curve.push(e(i / 20).toFixed(3));
  const i2 = p.idle || DEFAULT_PROFILE.idle;
  return curve.join(',') + '|' + (p.band || DEFAULT_PROFILE.band).join(',') + '|' +
         i2.every.join(',') + ';' + i2.dist.join(',') + ';' + i2.dur.join(',') + ';' + (i2.vertical ? 'v' : '-') +
         '|' + (p.path ? 'P' : '-') + (p.warp ? 'W' : '-') + (p.body ? 'B' : '-') + (p.turn || 0);
};
const prints = new Map();
for (const n of names) {
  const f = fp(n);
  if (!prints.has(f)) prints.set(f, []);
  prints.get(f).push(n);
}
const dupes = [...prints.values()].filter(v => v.length > 1);
ok('no two motions are secretly the same profile', dupes.length === 0, dupes);

// A curve identical to plain easeInOut means that motion contributes nothing.
const glideish = names.filter(n => {
  const e = MOTION[n].ease;
  if (!e) return false;                       // null is an explicit, documented "use the default"
  for (let i = 1; i < 20; i++) if (Math.abs(e(i / 20) - easeInOut(i / 20)) > 0.02) return false;
  return true;
});
ok('no motion declares a custom curve that is really just the default', glideish.length === 0, glideish);

// Ground dwellers must not be able to reach the top of the screen, and things
// that float must not be able to sit on the floor. This is the assertion that
// would have failed against the original engine, where there were no bands.
const GROUND = ['crawl', 'walk', 'bounce', 'paddle'];
const groundBad = GROUND.filter(m => !MOTION[m] || MOTION[m].band[0] < 0.6);
ok('ground motions are confined to the lower screen', groundBad.length === 0, groundBad);
ok('drift (lighter than air) is confined to the upper screen',
   MOTION.drift && MOTION.drift.band[1] <= 0.45, MOTION.drift && MOTION.drift.band);

// Every shipped pet must name a motion the engine actually implements — an
// unknown value silently degrades to a plain glide, which is the original bug.
const unknown = PETS.filter(p => !MOTION[p.motion]).map(p => `${p.id}:${p.motion}`);
ok('every shipped pet declares a motion the engine implements', unknown.length === 0, unknown);
ok('the pets are spread across many motions, not all on one',
   new Set(PETS.map(p => p.motion)).size >= 10, [...new Set(PETS.map(p => p.motion))]);

// Physical plausibility of the shipped data (build-pets.js gates this too, but
// the data is what ships, so assert on the data).
const CANNOT = { crawl: ['hop', 'spin'], swim: ['hop', 'spin'], drift: ['hop'], soar: ['hop'],
                 flap: ['hop'], hover: ['hop'], phase: ['hop'], scan: ['hop'], glide: ['hop'], paddle: ['spin'] };
const impossible = [];
for (const p of PETS) {
  const banned = CANNOT[p.motion] || [];
  for (const b of p.behaviors) {
    for (const s of b.steps) for (const k of banned) if (k in s) impossible.push(`${p.id}.${b.name}:${k}`);
  }
}
ok('no pet performs a gesture its body cannot make', impossible.length === 0, impossible.slice(0, 8));

// ── the engine must actually CONSUME the profile ────────────────────────────
// These are structural, and deliberately so. The behavioural probes below do
// catch a missing band or a missing body (mutation-tested: both go red). They do
// NOT reliably catch a missing `ease` or `warp` — a mutation run with each of
// those deleted still passed, because over a 15s sample a straight-line tween
// and a stepped one produce similar summary statistics. Rather than ship an
// assertion that only looks like it covers them, pin the call sites: reverting
// any one of these is exactly how this feature regresses to "every pet moves
// identically", which is the bug this whole change exists to fix.
const WIRING = [
  ['progress curve', /var e = prof\.ease \? prof\.ease\(k\) : easeInOut\(k\)/],
  ['path override',  /if \(prof\.warp\) \{/],
  ['path offset',    /if \(prof\.path\) \{/],
  ['body dynamics',  /if \(prof\.body\) \{/],
  ['band on targets',/y: bandY\(p\)/],
  ['band on offsets',/bandClamp\(this, this\.y \+ \(\+s\.go\.dy \|\| 0\)\)/],
  ['continuous drift', /if \(!self\.moving\) self\.nudge\(idle, rng\)/],
];
const unwired = WIRING.filter(([, re]) => !re.test(src)).map(([n]) => n);
ok('the engine still consumes every part of the profile', unwired.length === 0, unwired);

// ── Part 2: observable behaviour in a real browser ──────────────────────────
(async () => {
  if (!URL_) {
    console.log('\n(skipping the browser half — pass --url to run it)');
    console.log(`\n${pass} passed, ${fail} failed`);
    process.exit(fail ? 1 : 0);
  }
  const { spawn } = require('child_process');
  const http = require('http');
  const CDP = 19442;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const getJSON = u => new Promise((res, rej) => {
    http.get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(e); } }); }).on('error', rej);
  });
  console.log('\n— observable movement —');
  const chrome = spawn('/usr/bin/chromium', [
    '--headless=new', '--no-sandbox', '--disable-gpu',
    `--remote-debugging-port=${CDP}`, '--window-size=1280,820',
    '--user-data-dir=/tmp/cryptirc-petmotion-prof', URL_,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let targets = null;
  for (let i = 0; i < 50; i++) {
    await sleep(400);
    try { targets = (await getJSON(`http://127.0.0.1:${CDP}/json`)).filter(t => t.type === 'page'); if (targets.length) break; } catch (e) {}
  }
  if (!targets || !targets.length) { console.error('FAIL: chromium never came up'); chrome.kill(); process.exit(1); }
  const ws = new WebSocket(targets[0].webSocketDebuggerUrl);
  let id = 0; const pendingMap = new Map();
  await new Promise(r => ws.onopen = r);
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pendingMap.has(m.id)) { pendingMap.get(m.id)(m); pendingMap.delete(m.id); } };
  const send = (m, p) => new Promise(res => { const i = ++id; pendingMap.set(i, res); ws.send(JSON.stringify({ id: i, method: m, params: p })); });
  const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    return r.result && r.result.result ? r.result.result.value : undefined;
  };
  await send('Runtime.enable'); await sleep(3000);
  await ev(`(async()=>{ if(typeof _ensurePetsLoaded==='function') await _ensurePetsLoaded(); })()`);

  const byMotion = {};
  for (const p of PETS) (byMotion[p.motion] = byMotion[p.motion] || []).push(p.id);

  // Sample in batches of MAX_ACTIVE. Measure only what is robust over a short
  // window: where the pet lives, and whether its body is alive at rest.
  const probe = async ids => ev(`(async()=>{
    window.CryptIRCPets.disableAll();
    window.CryptIRCPets.setActive(${JSON.stringify(ids)});
    await new Promise(r=>setTimeout(r,600));
    const H=window.innerHeight;
    const els=${JSON.stringify(ids)}.map(i=>document.querySelector('#cryptirc-pets-layer .cip[data-pet="'+i+'"]'));
    const rec=els.map(()=>[]);
    // No regex here: this whole block is a template literal, so backslash escapes
    // are eaten before the RegExp ever sees them and every match silently returns 0.
    const rot=el=>{ const t=el.style.transform||''; const i=t.indexOf('rotate('); return i<0?0:(parseFloat(t.slice(i+7))||0); };
    const t0=performance.now();
    while(performance.now()-t0<15000){
      els.forEach((el,i)=>{ if(el){ const r=el.getBoundingClientRect(); rec[i].push([performance.now(), r.left, r.top, rot(el)]); }});
      await new Promise(r=>setTimeout(r,33));
    }
    return ${JSON.stringify(ids)}.map((pid,i)=>{
      const s=rec[i]; if(!s||s.length<20) return {id:pid,none:true};
      // stillFrac = the share of frames where the pet did not move AT ALL.
      // A body() that is running makes this ~0 no matter how slowly the pet is
      // travelling; a machine with no body life parks dead still between moves.
      // (Measuring px-per-second at low speed instead conflated "gliding slowly"
      // with "breathing", and reported the motionless probe as alive.)
      let travel=0, still=0, diag=0, axial=0, rotChanges=0;
      for(let k=1;k<s.length;k++){
        const dx=Math.abs(s[k][1]-s[k-1][1]), dy=Math.abs(s[k][2]-s[k-1][2]);
        const d=Math.hypot(dx,dy);
        travel+=d;
        if(d < 0.05) still++;
        if(Math.abs(s[k][3]-s[k-1][3]) > 0.01) rotChanges++;
        // Only classify frames that are clearly travelling, so body wobble does
        // not register as a diagonal.
        if(d > 1.2){ if(dx > 0.5 && dy > 0.5) diag++; else axial++; }
      }
      const ys=s.map(p=>(p[2]+15)/H);
      // Median of the SECOND HALF: a pet may legitimately be shoved out of its
      // band by the keep-out clamp, and what matters is that it returns. A mean
      // over the whole window instead scores the recovery itself as a failure.
      const tail=ys.slice(Math.floor(ys.length/2)).sort((a,b)=>a-b);
      return {id:pid, travel:Math.round(travel),
              ySettled:+(tail[Math.floor(tail.length/2)]).toFixed(3),
              yMean:+(ys.reduce((a,c)=>a+c,0)/ys.length).toFixed(3),
              stillFrac:+(still/(s.length-1)).toFixed(2),
              rotFrac:+(rotChanges/(s.length-1)).toFixed(2),
              diagFrac:+(diag/Math.max(1,diag+axial)).toFixed(2),
              moveFrames:diag+axial};
    });
  })()`);

  const ids = PETS.map(p => p.id);
  const res = {};
  for (let i = 0; i < ids.length; i += 4) {
    const out = await probe(ids.slice(i, i + 4));
    (out || []).forEach(r => { if (r && !r.none) res[r.id] = r; });
  }
  ok('every pet reported a position sample', Object.keys(res).length === PETS.length,
     PETS.map(p => p.id).filter(i => !res[i]));

  const motionOf = {}; PETS.forEach(p => motionOf[p.id] = p.motion);
  const groundPets = PETS.filter(p => GROUND.includes(p.motion)).map(p => p.id);
  const lowGround = groundPets.filter(i => res[i] && res[i].ySettled < 0.68);
  ok('ground dwellers stay in the lower part of the screen', lowGround.length === 0,
     lowGround.map(i => `${i}(${motionOf[i]}) y=${res[i].ySettled}`));

  const skyPets = PETS.filter(p => p.motion === 'drift').map(p => p.id);
  const highSky = skyPets.filter(i => res[i] && res[i].ySettled > 0.45);
  ok('lighter-than-air pets stay in the upper part of the screen', highSky.length === 0,
     highSky.map(i => `${i} y=${res[i].ySettled}`));

  // A machine holds perfectly still between moves; an animal never does. This is
  // the clearest observable proof that body() is running and is per-species.
  // Proof that body() is actually wired up and is per-species.
  //
  // Measured on the ROTATION channel, not on position. Position is a bad probe
  // for this: paint() quantises translate to 0.1px, a deliberately slow body wave
  // moves far less than that per frame, and how often a pet is still depends
  // mostly on how much of the window it happened to spend travelling — that
  // metric swung between 0.33 and 0.59 for the same machine across runs. Only
  // body() drives rotation at frame rate, so this isolates body life cleanly.
  const machines = PETS.filter(p => p.motion === 'scan').map(p => p.id);
  const winged = PETS.filter(p => ['flit', 'flap'].includes(p.motion)).map(p => p.id);

  const stiffWing = winged.filter(i => res[i] && res[i].rotFrac < 0.7);
  ok('winged pets beat their wings continuously', stiffWing.length === 0,
     stiffWing.map(i => `${i}(${motionOf[i]}) rot=${res[i].rotFrac}`));

  // Threshold sits above the machines' own SCRIPTED rotate steps (a survey head
  // tilting is mechanical and wanted); what must not appear is the frame-rate
  // wobble that only body() produces. Measured: machines peak at 0.41, winged
  // pets sit at 0.88-0.99.
  const twitchyMachine = machines.filter(i => res[i] && res[i].rotFrac > 0.55);
  ok('machines have no idle body motion', twitchyMachine.length === 0,
     twitchyMachine.map(i => `${i} rot=${res[i].rotFrac}`));

  const minWing = Math.min(...winged.map(i => (res[i] || {}).rotFrac).filter(Number.isFinite));
  const maxMachine = Math.max(...machines.map(i => (res[i] || {}).rotFrac).filter(Number.isFinite));
  ok('body life is per-species: an animal is clearly livelier than a machine',
     minWing - maxMachine > 0.35, { minWing, maxMachine });

  // Floors reflect design intent: a snail is SUPPOSED to be the slowest thing on
  // the screen, so holding it to a moth's budget would either fail honestly or
  // force it to stop being a snail. What is being pinned is "not frozen".
  const FLOOR = { crawl: 25, drift: 30, swim: 30, glide: 30, scan: 30, paddle: 30, soar: 30, hover: 30 };
  const dead = Object.values(res)
    .filter(r => r.travel < (FLOOR[motionOf[r.id]] || 60))
    .map(r => `${r.id}(${motionOf[r.id]}):${r.travel}px`);
  ok('no pet is a statue over a 15s window', dead.length === 0, dead);

  console.log('\n  ' + Object.values(res).sort((a, b) => motionOf[a.id] < motionOf[b.id] ? -1 : 1)
    .map(r => `${r.id}(${motionOf[r.id]}) y${r.ySettled} travel${r.travel} still${r.stillFrac} rot${r.rotFrac} diag${r.diagFrac}`).join('\n  '));

  console.log(`\n${pass} passed, ${fail} failed`);
  ws.close(); chrome.kill();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('harness error:', e); process.exit(1); });
