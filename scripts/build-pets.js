#!/usr/bin/env node
/**
 * build-pets.js — validate authored pet definitions and inject them into
 * static/pets.js between the PETS_DATA markers.
 *
 * The definitions are bulk-authored data, so NOTHING here is taken on trust: a
 * pet that violates the contract is rejected with a reason rather than quietly
 * shipped. The engine has its own second gate (svgIsSafe) at load time, but a
 * bad definition should fail here, loudly, at build time.
 *
 *   node scripts/build-pets.js <pets.json>          # validate + inject
 *   node scripts/build-pets.js <pets.json> --check  # validate only, no write
 */
const fs = require('fs');
const path = require('path');

const SRC = process.argv[2];
const CHECK_ONLY = process.argv.includes('--check');
if (!SRC) { console.error('usage: build-pets.js <pets.json> [--check]'); process.exit(2); }

const TARGET = path.join(__dirname, '..', 'static', 'pets.js');
const RESERVED = new Set(['esheep', 'crab', 'ghost', 'fish', 'alien']);

const STEP_KEYS = new Set(['wait', 'go', 'hop', 'pose', 'flip', 'scale', 'rotate', 'fade', 'emit', 'wiggle', 'spin', 'ms', 'n']);
const GO_WORDS  = new Set(['random', 'edge', 'corner', 'home', 'perch']);
const POSES     = new Set(['idle', 'alert', 'sleep', 'happy', 'curious', 'shy', 'busy']);
const MOTIONS   = new Set(['drift', 'walk', 'crawl', 'hover', 'swim', 'flit', 'bounce']);
// Mirrors svgIsSafe() in static/pets.js — keep the two in step.
const SVG_SHAPE     = /^<svg[\s>][\s\S]*<\/svg>$/i;
const SVG_FORBIDDEN = /<\s*(script|foreignObject|image|use|iframe|object|embed|animate|set|handler|a)\b|javascript:|data:(?!image\/)|\son\w+\s*=|url\s*\(|xlink:href|href\s*=|<!--|<!\[CDATA/i;

const raw = JSON.parse(fs.readFileSync(SRC, 'utf8'));
const input = Array.isArray(raw) ? raw : (raw.pets || []);

// ── normalisation ───────────────────────────────────────────────────────────
// "Not annoying" is gh0st's hard requirement, so it is ENFORCED here rather than
// left to whoever authored the behaviour. An independent review of the authored
// set found real offenders: a firefly that literally strobed, a desk lamp that
// blinked, full-colour 💧 emoji raining out of a cloud, and startle-speed dashes.
// Rather than hand-editing a thousand behaviours, normalise mechanically — the
// same philosophy as the engine enforcing pointer-events:none.
const NORMALISE = {
  // Opacity dips below this read as a blink on a pet drawn as a light source.
  FADE_FLOOR: 0.55,
  FADE_MIN_MS: 1600,
  // Floors only against genuinely startling darts. These were once 900/1600,
  // which turned every pet into slow motion and, with the idle gaps, made them
  // look dead. Motion is not the problem — see the tuning note in static/pets.js.
  GO_MIN_MS: 320,
  GO_TRAVERSAL_MIN_MS: 650,
  // Colour emoji are far more salient than the '·'/'✦' text glyphs. Map them to
  // monochrome equivalents so no pet can out-shout the others.
  GLYPH: { '💧': '·', '❄': '✦', '🍂': '·', '💦': '·', '✨': '✦', '⭐': '✦', '🌟': '✦', '💫': '✦', '🔥': '·', '💨': '·' },
};
const TRAVERSAL = new Set(['edge', 'corner', 'home', 'random', 'perch']);
let normCount = 0;
function normalisePet(p) {
  const notes = [];
  const keep = [];
  for (const b of p.behaviors || []) {
    let steps = b.steps || [];
    // A behaviour that flips opacity two or more times is a strobe. Don't delete
    // it — collapse it to ONE slow fade. A firefly should read as breathing, not
    // blinking, and deleting instead of converting gutted the pet (it lost 20 of
    // its 50 behaviours, which is most of its personality).
    if (steps.filter(s => 'fade' in s).length >= 2) {
      let first = true;
      steps = steps.filter(s => {
        if (!('fade' in s)) return true;
        if (first) { first = false; return true; }
        return false;
      });
      notes.push(`collapsed strobe "${b.name}" to a single slow fade`);
      b.steps = steps;
    }
    for (const s of steps) {
      if ('fade' in s) {
        if (s.fade < NORMALISE.FADE_FLOOR) { s.fade = NORMALISE.FADE_FLOOR; notes.push(`raised ${b.name} fade floor`); }
        if ((s.ms || 0) < NORMALISE.FADE_MIN_MS) { s.ms = NORMALISE.FADE_MIN_MS; notes.push(`slowed ${b.name} fade`); }
      }
      if ('go' in s) {
        const min = (typeof s.go === 'string' && TRAVERSAL.has(s.go)) ? NORMALISE.GO_TRAVERSAL_MIN_MS : NORMALISE.GO_MIN_MS;
        if ((s.ms || 0) < min) { s.ms = min; notes.push(`slowed ${b.name} move`); }
      }
      if ('emit' in s && NORMALISE.GLYPH[s.emit]) { s.emit = NORMALISE.GLYPH[s.emit]; notes.push(`demoted ${b.name} particle glyph`); }
      if ('emit' in s && (s.n | 0) > 2) { s.n = 2; notes.push(`capped ${b.name} particle count`); }
    }
    keep.push(b);
  }
  // Bias the weighted draw TOWARD moving about. This used to do the opposite —
  // it clamped anything energetic down to weight 2 and floored pure-idle at 3,
  // so the draw overwhelmingly picked "sit still" and the pets barely budged.
  // Wandering is the whole point of a desktop pet; the calm rules above are what
  // keep it from being obnoxious.
  for (const b of keep) {
    const moves = (b.steps || []).some(s => 'go' in s || 'hop' in s);
    const flashy = (b.steps || []).some(s => 'emit' in s || 'spin' in s);
    if (moves && b.weight < 4) { b.weight = 4; notes.push(`raised weight of moving "${b.name}"`); }
    if (!moves && b.weight > 2) { b.weight = 2; notes.push(`capped weight of idle "${b.name}"`); }
    // Particles and spins are the showy ones — keep them occasional.
    if (flashy && b.weight > 2) { b.weight = 2; notes.push(`lowered weight of showy "${b.name}"`); }
  }
  p.behaviors = keep;
  if (notes.length) { normCount += notes.length; }
  return notes.length;
}

const problems = [];
const kept = [];
const seenIds = new Set();
// Two pets shipped the same emoji, which makes the picker chips indistinguishable.
const EMOJI_OVERRIDE = { datawisp: '💠' };

for (const p of input) {
  if (p && EMOJI_OVERRIDE[p.id]) p.emoji = EMOJI_OVERRIDE[p.id];
  if (p && p.behaviors) normalisePet(p);   // enforce the calm rules before validating
  const why = [];
  const id = p && p.id;
  if (typeof id !== 'string' || !/^[a-z][a-z0-9_]{2,13}$/.test(id)) why.push(`bad id ${JSON.stringify(id)}`);
  if (RESERVED.has(id)) why.push('id collides with an existing standalone pet');
  if (seenIds.has(id)) why.push('duplicate id');
  if (!p || typeof p.name !== 'string' || !p.name.trim()) why.push('missing name');
  if (!p || typeof p.emoji !== 'string' || !p.emoji.trim()) why.push('missing emoji');
  if (!p || !MOTIONS.has(p.motion)) why.push(`bad motion ${JSON.stringify(p && p.motion)}`);

  const svg = (p && p.svg || '').trim();
  if (!SVG_SHAPE.test(svg)) why.push('svg is not a single <svg>…</svg>');
  else if (SVG_FORBIDDEN.test(svg)) why.push('svg contains a forbidden element/attribute');
  else if (svg.length > 4000) why.push(`svg too large (${svg.length}b)`);
  if (/"/.test(svg)) why.push('svg uses double quotes (must be single)');

  const bs = (p && p.behaviors) || [];
  if (bs.length < 46 || bs.length > 50) why.push(`${bs.length} behaviors after normalisation (want 46..50)`);
  const bnames = new Set();
  let emitB = 0, spinB = 0, calm = 0;
  bs.forEach((b, bi) => {
    if (!b || typeof b.name !== 'string' || !/^[a-z][a-z0-9_]*$/.test(b.name)) why.push(`behavior ${bi} bad name`);
    else if (bnames.has(b.name)) why.push(`duplicate behavior name ${b.name}`);
    else bnames.add(b.name);
    const w = b && b.weight;
    if (typeof w !== 'number' || w < 1 || w > 5) why.push(`behavior ${b && b.name} weight ${w} out of 1..5`);
    const steps = (b && b.steps) || [];
    if (!steps.length || steps.length > 8) why.push(`behavior ${b && b.name} has ${steps.length} steps (want 1..8)`);
    // "Calm" is about visual SALIENCE, not about holding still. A jellyfish that
    // drifts 40px over three seconds is calm; a 200ms dart across the screen is
    // not, even though both are a single `go`. So what counts against a pet is
    // ABRUPTNESS — particles, spins, wiggles, hops, and any move/scale/rotate
    // fast enough to catch the eye — rather than movement as such.
    const ABRUPT_MS = 700;
    let dur = 0, abrupt = false, hasEmit = false, hasSpin = false;
    for (const s of steps) {
      if (!s || typeof s !== 'object') { why.push(`behavior ${b && b.name} has a non-object step`); continue; }
      for (const k of Object.keys(s)) if (!STEP_KEYS.has(k)) why.push(`behavior ${b && b.name}: unknown step key "${k}"`);
      if ('go' in s) {
        if ((s.ms || 0) < ABRUPT_MS) abrupt = true;
        if (typeof s.go === 'string') { if (!GO_WORDS.has(s.go)) why.push(`behavior ${b && b.name}: bad go "${s.go}"`); }
        else if (s.go && typeof s.go === 'object') {
          if (typeof s.go.dx !== 'number' && typeof s.go.dy !== 'number') why.push(`behavior ${b && b.name}: go offset needs dx or dy`);
        } else why.push(`behavior ${b && b.name}: bad go value`);
      }
      if ('pose' in s && !POSES.has(s.pose)) why.push(`behavior ${b && b.name}: bad pose "${s.pose}"`);
      if ('emit' in s) { hasEmit = true; abrupt = true; if (typeof s.emit !== 'string' || [...s.emit].length > 2) why.push(`behavior ${b && b.name}: bad emit`); }
      if ('spin' in s) { hasSpin = true; abrupt = true; if (!(s.spin >= 1 && s.spin <= 2)) why.push(`behavior ${b && b.name}: spin must be 1..2`); }
      if ('hop' in s || 'wiggle' in s) abrupt = true;
      if (('scale' in s || 'rotate' in s) && (s.ms || 0) < ABRUPT_MS) abrupt = true;
      if ('scale' in s && !(s.scale >= 0.7 && s.scale <= 1.35)) why.push(`behavior ${b && b.name}: scale out of range`);
      if ('rotate' in s && !(s.rotate >= -35 && s.rotate <= 35)) why.push(`behavior ${b && b.name}: rotate out of range`);
      if ('fade' in s && !(s.fade >= 0.25 && s.fade <= 1)) why.push(`behavior ${b && b.name}: fade out of range`);
      dur += (s.ms || 0) + (s.wait || 0);
    }
    if (dur > 9000) why.push(`behavior ${b && b.name} runs ${dur}ms (cap 9000)`);
    if (hasEmit) emitB++;
    if (hasSpin) spinB++;
    if (!abrupt) calm++;
  });
  if (emitB > 6) why.push(`${emitB} behaviors use emit (cap 6)`);
  if (spinB > 4) why.push(`${spinB} behaviors use spin (cap 4)`);
  if (bs.length >= 46 && calm < 20) why.push(`only ${calm}/50 behaviors are calm (want >=20) — would read as busy`);

  if (why.length) problems.push({ id: id || '(unnamed)', why });
  else { seenIds.add(id); kept.push(p); }
}

console.log(`input ${input.length} pets — ${kept.length} valid, ${problems.length} rejected (${normCount} normalisation edits applied)`);
for (const p of problems) console.log(`  REJECT ${p.id}:\n    - ${p.why.join('\n    - ')}`);

if (!kept.length) { console.error('nothing valid to inject'); process.exit(1); }

// Emit compactly — this file is downloaded by every client.
//
// The short keys MUST NOT collide with any step key. An earlier version used
// n/w/s, and `n` is also a real step key — emit steps are authored as
// {"emit":"·","n":3} — so the blanket rewrite turned every particle count into
// {"name":3} and silently broke every emit in all 20 pets. Sentinels it is.
const slim = kept.map(p => ({
  id: p.id, name: p.name, emoji: p.emoji, motion: p.motion,
  svg: p.svg.trim(), blurb: p.blurb || '',
  behaviors: p.behaviors.map(b => ({ __n: b.name, __w: b.weight, __s: b.steps })),
}));
const payload = JSON.stringify(slim)
  .replace(/"__n":/g, '"name":').replace(/"__w":/g, '"weight":').replace(/"__s":/g, '"steps":');
// Prove the round-trip rather than assume it: re-parse and compare against the
// authored objects. This is the check that would have caught the n/name bug.
(function verifyRoundTrip() {
  const back = JSON.parse(payload);
  if (back.length !== kept.length) { console.error('round-trip lost pets'); process.exit(1); }
  for (let i = 0; i < back.length; i++) {
    const a = kept[i], b = back[i];
    if (a.id !== b.id) { console.error(`round-trip id mismatch at ${i}`); process.exit(1); }
    if (a.behaviors.length !== b.behaviors.length) { console.error(`round-trip behavior count mismatch in ${a.id}`); process.exit(1); }
    for (let k = 0; k < a.behaviors.length; k++) {
      const x = a.behaviors[k], y = b.behaviors[k];
      if (x.name !== y.name || x.weight !== y.weight) { console.error(`round-trip name/weight mismatch in ${a.id}.${x.name}`); process.exit(1); }
      if (JSON.stringify(x.steps) !== JSON.stringify(y.steps)) {
        console.error(`round-trip STEP CORRUPTION in ${a.id}.${x.name}\n  authored: ${JSON.stringify(x.steps)}\n  emitted:  ${JSON.stringify(y.steps)}`);
        process.exit(1);
      }
    }
  }
  console.log('round-trip verified: names, weights and every step survive the compression');
})();

const totalBehaviors = kept.reduce((a, p) => a + p.behaviors.length, 0);
console.log(`payload ${(payload.length / 1024).toFixed(1)} KB for ${kept.length} pets / ${totalBehaviors} behaviors`);

if (CHECK_ONLY) { process.exit(problems.length ? 1 : 0); }

let js = fs.readFileSync(TARGET, 'utf8');
const A = '/* PETS_DATA */', B = '/* /PETS_DATA */';
const i = js.indexOf(A), j = js.indexOf(B);
if (i < 0 || j < 0 || j < i) { console.error('PETS_DATA markers not found in static/pets.js'); process.exit(1); }
js = js.slice(0, i + A.length) + '\n' + payload + '\n' + js.slice(j);
fs.writeFileSync(TARGET, js);
console.log(`injected into ${path.relative(process.cwd(), TARGET)}`);
