#!/usr/bin/env node
/**
 * Tests the v0.5.0 theme/background work by extracting the REAL functions out of
 * static/app.js (never a retyped copy) and running them in a bare vm context that
 * provides ONLY what the real page guarantees — no convenience globals, per the
 * lesson in scripts/test-timestamp-format.js.
 *
 * Covers:
 *   1. REGRESSION ORACLE — with the shipped defaults, background resolution is
 *      byte-identical to the pre-0.5.0 behavior for every one of the 224 themes
 *      and for a custom theme. This is the check that matters: the whole feature
 *      is opt-in and must be invisible until someone touches it.
 *   2. bgMode: theme / none / custom, including the "custom but no image set"
 *      fallback that keeps the app from going blank.
 *   3. bgFrom — a clone inherits a built-in's scene by reference, and an unknown
 *      or hostile key resolves to nothing rather than into a CSS url().
 *   4. _teSeedFrom — customizing a built-in carries its accent/link/semantic
 *      colors and animation across, instead of silently recoloring it.
 *   5. Clamping of opacity/blur/dim, and that _safeBgCss still rejects
 *      non-https / non-data: values.
 *
 * Run: node scripts/test-theme-background.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'static', 'app.js');
const src = fs.readFileSync(SRC, 'utf8');

// ── Extract the shipped blocks verbatim ─────────────────────────────────────
function slice(startMark, endMark, label) {
  const a = src.indexOf(startMark);
  if (a < 0) { console.error(`FAIL: could not locate ${label} start in app.js`); process.exit(1); }
  const b = src.indexOf(endMark, a);
  if (b < 0) { console.error(`FAIL: could not locate ${label} end in app.js`); process.exit(1); }
  return src.slice(a, b);
}

const themesBlock   = slice('const THEMES={', '\n// Default semantic message colors', 'THEMES');
const semanticBlock = slice('const SEMANTIC_DEFAULTS=', '\n// Every editable color', 'SEMANTIC_DEFAULTS');
const helperBlock   = slice('// Resolve a theme name to its color object.', 'const APPEAR_DEFAULTS=', 'background helpers');
const defaultsBlock = slice('const APPEAR_DEFAULTS=', '\nfunction isMobileView()', 'APPEAR_DEFAULTS');
const seedBlock     = slice('function _teSeedFrom(', '\nfunction openThemeEditor(', '_teSeedFrom');

// CT_COLOR_GROUPS sits between SEMANTIC_DEFAULTS and the helpers; helperBlock
// starts after it, so pull it in separately.
const groupsBlock = slice('const CT_COLOR_GROUPS=', '// Resolve a theme name to its color object.', 'CT_COLOR_GROUPS');

let store = {};
const sandbox = {
  // The real page guarantees `document` and `localStorage`. Nothing else.
  document: { documentElement: { style: { setProperty() {} }, setAttribute() {} },
              querySelector: () => null, getElementById: () => null },
  localStorage: {
    getItem: k => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; },
  },
  window: { innerWidth: 1400 },
  Math, JSON, Object, Array, String, Number, RegExp, Date,
};
vm.createContext(sandbox);
vm.runInContext(
  [themesBlock, semanticBlock, groupsBlock, helperBlock, defaultsBlock, seedBlock].join('\n') +
  '\n;globalThis.__api={THEMES,SEMANTIC_DEFAULTS,APPEAR_DEFAULTS,resolveThemeObj,_customThemeBgValue,' +
  '_themeSceneFrom,_globalBgValue,_resolveBackground,_safeBgCss,_safeColor,_teSeedFrom};',
  sandbox, { filename: 'app.js-extract' }
);
const A = sandbox.__api;

let pass = 0, fail = 0;
const ok = (name, cond, detail) => {
  if (cond) pass++;
  else { fail++; console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`); }
};
const cfgOf = over => ({ ...A.APPEAR_DEFAULTS, ...(over || {}) });

// ── 1. REGRESSION ORACLE ────────────────────────────────────────────────────
// Verbatim transcription of the PRE-0.5.0 applyThemeCSS background branch.
// If defaults ever stop matching this, the feature has changed something it
// promised not to.
function oracle(themeName, t, isCustom) {
  if (isCustom) {
    const cbg = A._customThemeBgValue(themeName, t);
    return {
      image: cbg ? A._safeBgCss(cbg) : 'none',
      opacity: t.bgOpacity != null ? (Math.max(0, Math.min(100, t.bgOpacity)) / 100) : 0.25,
      repeat: !!t.bgRepeat,
    };
  }
  return { image: t.bgImage || 'none', opacity: 0.25, repeat: false };
}

const themeKeys = Object.keys(A.THEMES);
ok('theme table has 224 entries', themeKeys.length === 224, `got ${themeKeys.length}`);

let drift = 0, driftEg = '';
for (const k of themeKeys) {
  const t = A.THEMES[k];
  const got = A._resolveBackground(cfgOf({ theme: k }), k, t, false);
  const want = oracle(k, t, false);
  if (got.image !== want.image || got.opacity !== want.opacity || got.repeat !== want.repeat) {
    drift++; if (!driftEg) driftEg = k;
  }
}
ok('defaults unchanged for all 224 built-ins', drift === 0, `${drift} differ, e.g. ${driftEg}`);

// Custom theme with its own uploaded background — must keep its own opacity/tiling.
store = {}; store['cryptirc_cbg_abc'] = 'data:image/png;base64,AAAA';
const ctUploaded = { label: 'Mine', bg0: '#111', bgKind: 'image', bgOpacity: 60, bgRepeat: true };
{
  const cfg = cfgOf({ theme: 'custom:abc', customThemes: { abc: ctUploaded } });
  const got = A._resolveBackground(cfg, 'custom:abc', ctUploaded, true);
  const want = oracle('custom:abc', ctUploaded, true);
  ok('defaults unchanged for a custom theme (uploaded bg)',
     got.image === want.image && got.opacity === want.opacity && got.repeat === want.repeat,
     JSON.stringify(got) + ' vs ' + JSON.stringify(want));
  ok('custom theme keeps its own 60% opacity', got.opacity === 0.6, String(got.opacity));
  ok('custom theme keeps its own tiling', got.repeat === true);
}
// Custom theme with NO background at all.
{
  const ct = { label: 'Flat', bg0: '#111' };
  const got = A._resolveBackground(cfgOf({ theme: 'custom:z' }), 'custom:z', ct, true);
  ok('custom theme with no bg resolves to none', got.image === 'none' && got.opacity === 0);
}

// ── 2. bgMode ───────────────────────────────────────────────────────────────
const lit = A.THEMES.blueprint;             // a built-in that ships a scene
ok('fixture theme ships a scene', !!lit.bgImage);

{
  const got = A._resolveBackground(cfgOf({ bgMode: 'none' }), 'blueprint', lit, false);
  ok("bgMode 'none' hides the theme scene", got.image === 'none' && got.opacity === 0 && got.repeat === false);
}
{
  store = {};
  const cfg = cfgOf({ bgMode: 'custom', bgUrl: 'https://example.com/a.png', bgOpacity: 70, bgRepeat: true });
  const got = A._resolveBackground(cfg, 'blueprint', lit, false);
  ok("bgMode 'custom' overrides a built-in's scene", got.image === 'url("https://example.com/a.png")', got.image);
  ok("bgMode 'custom' uses the global opacity", got.opacity === 0.7, String(got.opacity));
  ok("bgMode 'custom' uses the global tiling", got.repeat === true);
}
{
  // The same user image must also override a CUSTOM theme's own picture.
  store = {}; store['cryptirc_cbg_abc'] = 'data:image/png;base64,AAAA';
  const cfg = cfgOf({ bgMode: 'custom', bgUrl: 'https://example.com/a.png' });
  const got = A._resolveBackground(cfg, 'custom:abc', ctUploaded, true);
  ok("bgMode 'custom' overrides a custom theme's own picture", got.image === 'url("https://example.com/a.png")', got.image);
}
{
  // Picked "custom" but never set an image → fall back, never blank the app.
  store = {};
  const got = A._resolveBackground(cfgOf({ bgMode: 'custom', bgUrl: '' }), 'blueprint', lit, false);
  ok("bgMode 'custom' with no image falls back to the theme", got.image === lit.bgImage, got.image.slice(0, 40));
}
{
  // Uploaded (device-local) image is used when no https URL is set.
  store = {}; store['cryptirc_bg_custom'] = 'data:image/jpeg;base64,ZZZZ';
  const got = A._resolveBackground(cfgOf({ bgMode: 'custom' }), 'blueprint', lit, false);
  ok('device-local upload is used when no URL is set',
     got.image === 'url("data:image/jpeg;base64,ZZZZ")', got.image);
  // ...and the syncable URL wins over it when both exist.
  const got2 = A._resolveBackground(cfgOf({ bgMode: 'custom', bgUrl: 'https://e.com/b.png' }), 'blueprint', lit, false);
  ok('https URL takes precedence over the local upload',
     got2.image === 'url("https://e.com/b.png")', got2.image);
  store = {};
}
{
  // A built-in's scene is now tunable — previously hardcoded at 25%/cover.
  const got = A._resolveBackground(cfgOf({ bgOpacity: 80, bgRepeat: true }), 'blueprint', lit, false);
  ok("bgMode 'theme' applies global opacity to a built-in scene", got.opacity === 0.8, String(got.opacity));
  ok("bgMode 'theme' applies global tiling to a built-in scene", got.repeat === true);
}

// ── 3. bgFrom (inherited scene) ─────────────────────────────────────────────
{
  const clone = { label: 'My Blueprint', bg0: '#061426', bgFrom: 'blueprint' };
  ok('_themeSceneFrom resolves a real key', A._themeSceneFrom(clone) === lit.bgImage);
  const got = A._resolveBackground(cfgOf({ theme: 'custom:q' }), 'custom:q', clone, true);
  ok('clone inherits the source scene', got.image === lit.bgImage);
  ok('inherited scene defaults to 25% opacity', got.opacity === 0.25, String(got.opacity));
}
{
  // SECURITY: bgFrom is interpolated straight into a CSS url(). An unknown or
  // hostile value must resolve to nothing at all.
  for (const bad of ['nope', 'constructor', '__proto__', 'toString', 'valueOf',
                     'url(https://evil/x)', '', null, undefined, 42, {}, []]) {
    const got = A._themeSceneFrom({ bgFrom: bad });
    ok(`hostile bgFrom ${JSON.stringify(bad)} yields nothing`, got === '', String(got).slice(0, 60));
  }
}
{
  // Own image must beat an inherited scene.
  store = {};
  const clone = { label: 'X', bgFrom: 'blueprint', bgKind: 'image', bgUrl: 'https://e.com/c.png' };
  const got = A._resolveBackground(cfgOf({ theme: 'custom:w' }), 'custom:w', clone, true);
  ok('own image beats the inherited scene', got.image === 'url("https://e.com/c.png")', got.image);
}

// ── 4. _teSeedFrom fidelity ─────────────────────────────────────────────────
{
  const cfg = cfgOf({ accent: '#00d4aa', accent2: '#0099ff', linkColor: '' });
  // mIRC is the built-in that defines its own accent + all six semantic colors.
  const m = A.THEMES.mirc;
  const seed = A._teSeedFrom(m, false, cfg, 'mirc');
  ok('clone keeps the built-in accent', seed.accent === m.accent, `${seed.accent} vs ${m.accent}`);
  ok('clone keeps the built-in accent2', seed.accent2 === m.accent2);
  ok('clone keeps the built-in link', seed.link === m.link);
  for (const k of ['warn', 'error', 'join', 'part', 'notice', 'action']) {
    ok(`clone keeps the built-in ${k}`, seed[k] === m[k], `${seed[k]} vs ${m[k]}`);
  }
  // A theme with no accent of its own still falls back to the user's global one.
  const seedPlain = A._teSeedFrom(A.THEMES.midnight, false, cfg, 'midnight');
  ok('clone of a plain theme uses the global accent', seedPlain.accent === '#00d4aa', seedPlain.accent);
  for (const k of ['warn', 'error', 'join', 'part', 'notice', 'action']) {
    ok(`plain clone uses the default ${k}`, seedPlain[k] === A.SEMANTIC_DEFAULTS[k]);
  }
  // Scene is inherited by reference, not copied — the whole point of bgFrom.
  const seedLit = A._teSeedFrom(lit, false, cfg, 'blueprint');
  ok('clone points at the source scene by key', seedLit.bgFrom === 'blueprint', seedLit.bgFrom);
  ok('clone does NOT copy the scene bytes', !('bgImage' in seedLit));
  ok('clone carries the animation', A._teSeedFrom(A.THEMES.fog_bank, false, cfg, 'fog_bank').animation === 'fogDrift');
  // Cloning a theme with no scene must not invent one.
  ok('clone of a scene-less theme has empty bgFrom',
     A._teSeedFrom(A.THEMES.midnight, false, cfg, 'midnight').bgFrom === '');
  // Re-editing a saved clone must preserve, and re-validate, its bgFrom.
  ok('re-edit preserves a valid bgFrom',
     A._teSeedFrom({ bgFrom: 'blueprint' }, true, cfg).bgFrom === 'blueprint');
  ok('re-edit drops an unknown bgFrom',
     A._teSeedFrom({ bgFrom: 'not_a_theme' }, true, cfg).bgFrom === '');
}

// ── 5. Clamping and URL safety ──────────────────────────────────────────────
{
  const hi = A._resolveBackground(cfgOf({ bgOpacity: 9999 }), 'blueprint', lit, false);
  const lo = A._resolveBackground(cfgOf({ bgOpacity: -50 }), 'blueprint', lit, false);
  ok('opacity clamps high', hi.opacity === 1, String(hi.opacity));
  ok('opacity clamps low', lo.opacity === 0, String(lo.opacity));
  const nan = A._resolveBackground(cfgOf({ bgOpacity: 'abc' }), 'blueprint', lit, false);
  ok('non-numeric opacity does not produce NaN', !Number.isNaN(nan.opacity), String(nan.opacity));
  const ctHi = { bgKind: 'image', bgUrl: 'https://e.com/a.png', bgOpacity: 900 };
  ok('a custom theme opacity clamps too',
     A._resolveBackground(cfgOf({}), 'custom:k', ctHi, true).opacity === 1);
}
{
  for (const bad of ['http://evil/x.png', 'javascript:alert(1)', 'data:text/html,<script>',
                     'url(https://evil)', '  ', 'file:///etc/passwd', null, undefined, 42]) {
    ok(`_safeBgCss rejects ${JSON.stringify(bad)}`, A._safeBgCss(bad) === 'none', A._safeBgCss(bad));
  }
  ok('_safeBgCss accepts https', A._safeBgCss('https://e.com/a.png') === 'url("https://e.com/a.png")');
  ok('_safeBgCss accepts data:image', A._safeBgCss('data:image/png;base64,AA') === 'url("data:image/png;base64,AA")');
  ok('_safeBgCss strips quote-escape attempts',
     A._safeBgCss('https://e.com/a.png");background:url(https://evil/x') ===
     'url("https://e.com/a.png);background:url(https://evil/x")',
     A._safeBgCss('https://e.com/a.png");background:url(https://evil/x'));
}

// ── 6. Every theme is structurally complete ─────────────────────────────────
{
  const REQ = ['label', 'bg0', 'bg1', 'bg2', 'bg3', 'bg4', 'border', 'border2', 'text', 'text2', 'text3'];
  let bad = [];
  for (const k of themeKeys) for (const r of REQ) if (!A.THEMES[k][r]) bad.push(`${k}.${r}`);
  ok('every theme has the full base palette', bad.length === 0, bad.slice(0, 5).join(', '));
  // Any color a theme declares must survive _safeColor, or it silently degrades.
  let unsafe = [];
  for (const k of themeKeys) {
    for (const key of ['bg0','bg1','bg2','bg3','bg4','border','border2','text','text2','text3',
                       'accent','accent2','link','warn','error','join','part','notice','action']) {
      const v = A.THEMES[k][key];
      if (v && A._safeColor(v, '__BAD__') === '__BAD__') unsafe.push(`${k}.${key}=${v}`);
    }
  }
  ok('every declared color passes _safeColor', unsafe.length === 0, unsafe.slice(0, 5).join(', '));
  // Labels are rendered via innerHTML for built-ins — they must stay inert.
  const htmlish = themeKeys.filter(k => /[<>&"]/.test(A.THEMES[k].label));
  ok('no theme label contains HTML-significant characters', htmlish.length === 0, htmlish.join(', '));
  // Duplicate labels would make the grid ambiguous.
  const seen = new Set(), dup = [];
  for (const k of themeKeys) { const l = A.THEMES[k].label; if (seen.has(l)) dup.push(l); seen.add(l); }
  ok('no duplicate theme labels', dup.length === 0, dup.join(', '));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
