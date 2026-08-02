#!/usr/bin/env node
/**
 * sync-theme-gallery.js — static/app.js's THEMES table is the ONE source of truth
 * for themes. The GitHub Pages gallery (docs/index.html + docs/themes.js, served at
 * https://gh0st68.github.io/CryptIRC/) is a DERIVED copy and must never be
 * hand-edited.
 *
 * There was no generator before this, which is precisely how the gallery silently
 * fell 50 themes behind the app in v0.5.0 — nothing anywhere would have told us.
 *
 *   scripts/sync-theme-gallery.js check   # (default) exit 1 + report drift, no writes
 *   scripts/sync-theme-gallery.js fix     # rewrite docs/themes.js + docs/index.html counts
 *
 * Run `fix` after adding or changing any theme, and commit docs/ with the change.
 * `check` is meant to gate a release the same way sync-version.sh does.
 *
 * FIELD SET: the gallery renders a miniature IRC window from the background
 * layers, the three text tiers, the scene and the animation — it uses t.text2 as
 * each card's accent and never reads a theme's accent/link/semantic colors. So we
 * emit exactly those fields and no more; shipping the rest would just inflate a
 * file every visitor downloads.
 */
const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..');
const APP = path.join(REPO, 'static', 'app.js');
const THEMES_JS = path.join(REPO, 'docs', 'themes.js');
const DOCS_HTML = path.join(REPO, 'docs', 'index.html');

const MODE = process.argv[2] || 'check';
if (MODE !== 'check' && MODE !== 'fix') {
  console.error(`Usage: ${path.basename(process.argv[1])} [check|fix]`);
  process.exit(2);
}

const FIELDS = ['label', 'bg0', 'bg1', 'bg2', 'bg3', 'bg4',
                'border', 'border2', 'text', 'text2', 'text3', 'animation', 'bgImage'];

// ── Read THEMES straight out of the shipped app.js ──────────────────────────
// NOTE ON eval(): deliberate and safe here. THEMES is a JavaScript object literal
// (unquoted keys, single-quoted strings, trailing comments) so JSON.parse cannot
// read it, and the input is our own checked-in static/app.js — the same file that
// gets compiled into the binary, not user data. This is a developer-run build
// script, never something a request reaches. The repo's existing test harnesses
// (test-theme-background.js, test-timestamp-format.js) extract the same block the
// same way. If THEMES ever becomes machine-generated, emit JSON alongside it and
// switch this to JSON.parse.
function loadThemes() {
  const lines = fs.readFileSync(APP, 'utf8').split('\n');
  let s = -1;
  for (let i = 0; i < lines.length; i++) if (lines[i].startsWith('const THEMES={')) { s = i; break; }
  if (s < 0) throw new Error('could not find `const THEMES={` in static/app.js');
  let e = -1;
  for (let i = s + 1; i < lines.length; i++) if (lines[i].startsWith('};')) { e = i; break; }
  if (e < 0) throw new Error('could not find the end of the THEMES table');
  const body = lines.slice(s, e + 1).join('\n').replace(/^const THEMES=/, '').replace(/;\s*$/, '');
  return eval('(' + body + ')');
}

const THEMES = loadThemes();
const keys = Object.keys(THEMES);

// ── Build the gallery payload ───────────────────────────────────────────────
const out = {};
for (const k of keys) {
  const t = THEMES[k], o = {};
  for (const f of FIELDS) if (t[f] !== undefined && t[f] !== '') o[f] = t[f];
  out[k] = o;
}
const themesJs = 'window.CRYPTIRC_THEMES=' + JSON.stringify(out) + ';\n';

const total = keys.length;
const animated = keys.filter(k => THEMES[k].animation).length;

// ── Counts baked into the gallery's own prose ───────────────────────────────
// (#n and #count are populated at runtime from the data, so they need no help.)
function retargetCounts(html) {
  return html
    .replace(/\b\d{2,4} themes\b/g, `${total} themes`)
    .replace(/\b(Browse all )\d{2,4}( built-in)/g, `$1${total}$2`);
}

const curThemesJs = fs.readFileSync(THEMES_JS, 'utf8');
const curHtml = fs.readFileSync(DOCS_HTML, 'utf8');
const wantHtml = retargetCounts(curHtml);

let curCount = 0;
try {
  const vm = require('vm');
  const sb = { window: {} };
  vm.createContext(sb);
  vm.runInContext(curThemesJs, sb);
  curCount = Object.keys(sb.window.CRYPTIRC_THEMES || {}).length;
} catch (e) { /* unparseable = definitely drifted */ }

const dataDrift = curThemesJs !== themesJs;
const htmlDrift = curHtml !== wantHtml;

if (MODE === 'check') {
  if (!dataDrift && !htmlDrift) {
    console.log(`✓ Theme gallery matches static/app.js (${total} themes, ${animated} animated)`);
    process.exit(0);
  }
  if (dataDrift) console.error(`✗ docs/themes.js is out of sync — gallery has ${curCount}, app.js has ${total}`);
  if (htmlDrift) console.error('✗ docs/index.html theme counts are stale');
  console.error('  Run: node scripts/sync-theme-gallery.js fix');
  process.exit(1);
}

if (dataDrift) { fs.writeFileSync(THEMES_JS, themesJs); console.log(`  docs/themes.js: ${curCount} → ${total} themes`); }
if (htmlDrift) { fs.writeFileSync(DOCS_HTML, wantHtml); console.log('  docs/index.html: counts retargeted'); }
if (!dataDrift && !htmlDrift) console.log('  already in sync — nothing to do');
console.log(`✓ Gallery synced to ${total} themes (${animated} animated) — review the diff and commit docs/.`);
