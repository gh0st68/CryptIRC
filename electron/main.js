const { app, BrowserWindow, Tray, Menu, nativeImage, shell, ipcMain, Notification, dialog, session } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { autoUpdater } = require('electron-updater');
const certpin = require('./certpin');

// ─── Config ──────────────────────────────────────────────────────────────────
const CONFIG_FILE = path.join(app.getPath('userData'), 'config.json');
// Remembered (pinned) certificates of LAN/local servers — see certpin.js.
const PIN_FILE = path.join(app.getPath('userData'), 'cert-pins.json');
// Default server for fresh installs — TwistedNet's hosted CryptIRC. Only a user-chosen
// custom server is persisted (so the default can move with app updates); pointing at
// your own server is done via File ▸ Change Server URL… and is remembered after that.
const DEFAULT_URL = 'https://client.twistednet.org/cryptirc/';

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveConfig(cfg) {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  } catch (err) {
    console.error('[config] save failed:', err && err.message);
  }
}

// HTML-escape for any value interpolated into our local data: chrome pages.
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// Hosts where a self-signed / local cert is legitimately expected (self-hosting
// on a LAN or localhost). Everything else MUST present a valid TLS cert. Even
// here a certificate is not accepted blindly: it is trusted on first use and
// pinned (see the certificate-error handler).
// The private ranges are matched only on real IP LITERALS: as plain prefix
// regexes they also matched public DNS names like 10.example.com or
// 192.168.1.1.example.net, accepting an invalid certificate for them.
function isLocalOrLan(hostname) {
  if (!hostname) return false;
  const h = String(hostname).replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost') return true;
  if (/\.local$/.test(h)) return true;   // mDNS name (.local is reserved, never public DNS)
  const v = net.isIP(h);
  if (v === 4) {
    const [a, b] = h.split('.').map(Number);
    return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
  }
  if (v === 6) return h === '::1';
  return false;
}

// The server URL the user typed, validated HERE (the setup page's own check is
// only a convenience — the main process must not trust what a renderer sends).
// http is still allowed, exactly as the setup page has always allowed it.
function normalizeServerUrl(raw) {
  let u;
  try { u = new URL(String(raw == null ? '' : raw).trim()); } catch { return null; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (!u.hostname) return null;
  if (!u.pathname.endsWith('/')) u.pathname += '/';
  return u.href;
}

// Only hand web links to the OS. Anything else (file:, smb:, custom app
// protocols…) clicked in chat could launch local programs, so it is dropped.
// r5 (agy-flash electron/main.js:78): a mailto: link from chat may carry ?subject=/body=/
// cc=/attach= … that pre-fill (or, with some handlers, attach files to) a message the
// user never wrote. Only the address part is handed to the OS mail client.
function openExternalSafe(u) {
  let url;
  try { url = new URL(u); } catch { return; }
  if (url.protocol === 'http:' || url.protocol === 'https:') { shell.openExternal(u).catch(() => {}); return; }
  if (url.protocol === 'mailto:') {
    const addr = url.pathname;
    // one or more plain addresses, no parameters, nothing a shell handler could mis-parse
    if (!addr || addr.length > 320 || !/^[^\s?#&<>"'`\\]+$/.test(addr) || /%[01][0-9a-f]|%7f/i.test(addr)) return;
    shell.openExternal('mailto:' + addr).catch(() => {});
  }
}

// r6 (agy-flash electron/main.js:719): the native context menu can outlive its window
// (closed with a shortcut while the menu is open, or the renderer crashed and the window
// reloaded) — mainWindow is null / destroyed by the time an item is clicked, and the click
// threw a TypeError in the main process. Every click now re-checks the window it was built
// for and does nothing when it is gone.
function contextMenuTemplate(win, params) {
  const wc = win && !win.isDestroyed() ? win.webContents : null;
  const live = () => !!(wc && win && !win.isDestroyed() && !wc.isDestroyed());
  const items = [];
  if (params.misspelledWord) {
    if (params.dictionarySuggestions && params.dictionarySuggestions.length) {
      for (const s of params.dictionarySuggestions.slice(0, 5))
        items.push({ label: s, click: () => { if (live()) wc.replaceMisspelling(s); } });
    } else items.push({ label: '(no suggestions)', enabled: false });
    items.push({ type: 'separator' });
    items.push({ label: 'Add to Dictionary', click: () => { if (live()) wc.session.addWordToSpellCheckerDictionary(params.misspelledWord); } });
    items.push({ type: 'separator' });
  }
  if (params.isEditable) {
    items.push({ label: 'Cut', role: 'cut', enabled: params.editFlags.canCut });
    items.push({ label: 'Copy', role: 'copy', enabled: params.editFlags.canCopy });
    items.push({ label: 'Paste', role: 'paste', enabled: params.editFlags.canPaste });
    items.push({ label: 'Select All', role: 'selectAll', enabled: params.editFlags.canSelectAll });
  } else if (params.selectionText) {
    items.push({ label: 'Copy', role: 'copy' });
  }
  if (params.linkURL) {
    if (items.length) items.push({ type: 'separator' });
    items.push({ label: 'Open Link in Browser', click: () => openExternalSafe(params.linkURL) });
    // Electron 44: clipboard.writeText returns a Promise.
    items.push({ label: 'Copy Link', click: () => { Promise.resolve(require('electron').clipboard.writeText(params.linkURL)).catch(() => {}); } });
  }
  if (params.hasImageContents) {
    if (items.length) items.push({ type: 'separator' });
    items.push({ label: 'Copy Image', click: () => { if (live()) wc.copyImageAt(params.x, params.y); } });
    items.push({ label: 'Open Image in Browser', click: () => openExternalSafe(params.srcURL) });
  }
  return items;
}

// ─── App state ───────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let isQuitting = false;
let saveBoundsTimer = null;
// Origins the main window treats as "the app" (in-app navigation, popups). Reset
// to the configured server whenever one is loaded — it used to be captured once
// at window creation, so after Change Server the NEW server's links went to the
// system browser while the OLD server stayed trusted until a restart.
let appOrigins = new Set();
// True from the moment WE start loading the app URL until that navigation
// commits or fails, so a server-side redirect of our own load (http->https, a
// path fix-up) is followed instead of being bounced to the browser (blank window).
// See ownRedirectAllowed() for which redirects qualify.
let ownLoadPending = false;
// The configured server URL of that load. Its redirects are judged against it.
let ownLoadUrl = '';
// Recent renderer-crash timestamps, for the bounded crash-reload below.
let crashTimes = [];
// A crash reload waiting for its delay. Any other load of the app cancels it, so
// a Change Server made during the delay is not undone by a reload of the old URL.
let crashReloadTimer = null;
const CRASH_WINDOW_MS = 2 * 60 * 1000;
const CRASH_RELOAD_DELAYS = [0, 3000, 10000];   // then give up and show the error page

function setAppUrl(u) { appOrigins = new Set(); addAppOrigin(u); }
function addAppOrigin(u) {
  try { const o = new URL(u).origin; if (o && o !== 'null') appOrigins.add(o); } catch {}
}
// Load the server into the main window (the single path for every app load).
function loadApp(url) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (crashReloadTimer) { clearTimeout(crashReloadTimer); crashReloadTimer = null; }
  setAppUrl(url);
  ownLoadUrl = url;
  ownLoadPending = true;
  Promise.resolve(mainWindow.loadURL(url)).catch(() => {});   // failures surface via did-fail-load
}

// May a main-frame redirect of our own load be followed and become "the app"?
// Only when it stays on the configured server: the same origin (a path redirect
// such as /cryptirc -> /cryptirc/, or a hop already accepted), or a move to https
// on the same host (http -> https, or another https port). A downgrade to http
// or a different host (apex -> www, an auth proxy, anything else) is not: that
// page would get the notification/badge bridge and in-app popups.
function ownRedirectAllowed(target) {
  let t, base;
  try { t = new URL(target); base = new URL(ownLoadUrl); } catch { return false; }
  if (t.protocol !== 'https:' && t.protocol !== 'http:') return false;
  if (appOrigins.has(t.origin)) return true;
  return t.protocol === 'https:' && t.hostname === base.hostname;
}

// Is this IPC message from one of OUR local chrome pages (the data: setup and
// connection-error pages), sent by the top frame of the expected webContents?
// The preload bridge exists on every page the main window loads — including the
// remote server's — so the channel name alone proves nothing: without this a
// compromised server (or any XSS in the web app) could call changeServer() +
// setupSubmit() and silently repoint and persist the app's server URL.
function fromLocalPage(e, wc) {
  try {
    if (!wc || wc.isDestroyed() || !e || e.sender !== wc) return false;
    const f = e.senderFrame;
    if (!f || f.parent) return false;                       // top frame only
    return isLocalPage(wc, f.url);
  } catch { return false; }
}

// The exact data: URL of the local page (setup or connection error) we last
// loaded into each webContents. Only that page is "ours". Any other data: page,
// however it got there, gets neither the navigation exemption nor the IPC.
const localPages = new WeakMap();
const normUrl = (u) => { try { return new URL(String(u)).href; } catch { return null; } };
function loadLocalPage(wc, html) {
  const url = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
  localPages.set(wc, normUrl(url));
  return Promise.resolve(wc.loadURL(url)).catch(() => {});
}
function isLocalPage(wc, u) {
  const want = wc && localPages.get(wc);
  return !!want && normUrl(u) === want;
}

// ─── Branding ────────────────────────────────────────────────────────────────
const TEAL = '#00d4aa';
const TEAL_DK = '#00b894';
const BLUE = '#0099ff';

// ─── Setup prompt (first launch / change server) ─────────────────────────────
function showSetupPrompt(existingUrl) {
  return new Promise((resolve) => {
    const setup = new BrowserWindow({
      width: 480,
      height: 260,
      resizable: false,
      minimizable: false,
      maximizable: false,
      autoHideMenuBar: true,
      title: 'CryptIRC — Server Setup',
      icon: path.join(__dirname, 'icons', 'icon.png'),
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
      },
    });
    // The same link/navigation policy as the main window.
    hardenContents(setup.webContents);

    let done = false;
    // Only the setup window's own page may answer — see fromLocalPage().
    const onUrl = (e, url) => {
      if (!fromLocalPage(e, setup.webContents)) { console.error('[ipc] setup-url from a foreign page ignored'); return; }
      const norm = normalizeServerUrl(url);
      if (!norm) {
        console.error('[ipc] setup-url rejected: not a valid http(s) URL');
        // Say so on the page; a dead Connect button looked like a hang.
        const msg = 'That is not a valid server address (example: https://example.com/cryptirc/)';
        try {
          setup.webContents.executeJavaScript(
            `(function(){var e=document.getElementById('err');if(e)e.textContent=${JSON.stringify(msg)};})()`).catch(() => {});
        } catch {}
        return;
      }
      finish(norm);
    };
    const onQuit = (e) => { if (fromLocalPage(e, setup.webContents)) finish(null); };
    function finish(result) {
      if (done) return;
      done = true;
      ipcMain.removeListener('setup-url', onUrl);
      ipcMain.removeListener('setup-quit', onQuit);
      if (!setup.isDestroyed()) { setup.removeAllListeners('closed'); setup.close(); }
      resolve(result);
    }
    ipcMain.on('setup-url', onUrl);
    ipcMain.on('setup-quit', onQuit);
    setup.on('closed', () => finish(null));

    const val = esc(existingUrl || '');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:system-ui,-apple-system,sans-serif;background:#0a0e13;color:#dce6f2;display:flex;align-items:center;justify-content:center;height:100vh}
      .card{width:100%;padding:32px;display:flex;flex-direction:column;gap:16px}
      h2{font-size:18px;color:${TEAL};font-weight:700}
      p{font-size:13px;color:#8aa0b6;line-height:1.4}
      label{font-size:13px;color:#8aa0b6}
      input{padding:10px 12px;border-radius:8px;border:1px solid #26344a;background:#0f1622;color:#dce6f2;font-size:14px;width:100%;outline:none}
      input:focus{border-color:${TEAL}}
      .btns{display:flex;gap:10px;justify-content:flex-end;margin-top:4px}
      button{padding:9px 24px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600}
      .connect{background:${TEAL};color:#04110d}
      .connect:hover{background:${TEAL_DK}}
      .quit{background:#0f1622;color:#8aa0b6;border:1px solid #26344a}
      .quit:hover{background:#16202e}
      .err{color:#ff7a7a;font-size:12px;min-height:16px}
    </style></head><body>
    <div class="card">
      <h2>CryptIRC</h2>
      <p>Enter the URL of your CryptIRC server to connect.</p>
      <label>Server URL</label>
      <input id="url" value="${val}" placeholder="https://example.com/cryptirc/" spellcheck="false" />
      <div class="err" id="err"></div>
      <div class="btns">
        <button class="quit" id="quitBtn">Quit</button>
        <button class="connect" id="connBtn">Connect</button>
      </div>
    </div>
    <script>
      const urlEl=document.getElementById('url');
      const errEl=document.getElementById('err');
      urlEl.focus(); urlEl.select();
      function submit(){
        const v=urlEl.value.trim();
        if(!v){errEl.textContent='Please enter a URL';return;}
        if(!/^https?:\\/\\//.test(v)){errEl.textContent='URL must start with http:// or https://';return;}
        window.electronAPI.setupSubmit(v);
      }
      document.getElementById('connBtn').addEventListener('click',submit);
      document.getElementById('quitBtn').addEventListener('click',()=>window.electronAPI.setupQuit());
      urlEl.addEventListener('keydown',e=>{if(e.key==='Enter')submit();});
    </script></body></html>`;

    loadLocalPage(setup.webContents, html);
  });
}

// ─── Connection-error page (loaded INTO the secure main window) ──────────────
function showErrorPage(failedUrl, desc, code) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{font-family:system-ui;background:#0a0e13;color:#dce6f2;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .box{text-align:center;max-width:420px;padding:24px}
    h2{color:#ff7a7a;margin-bottom:12px}
    p{color:#8aa0b6;font-size:14px;line-height:1.5}
    code{background:#0f1622;padding:2px 8px;border-radius:4px;color:${BLUE};word-break:break-all}
    .btns{display:flex;gap:10px;justify-content:center;margin-top:20px}
    button{padding:10px 24px;border-radius:8px;border:none;cursor:pointer;font-size:14px;font-weight:600}
    .retry{background:${TEAL};color:#04110d}
    .retry:hover{background:${TEAL_DK}}
    .change{background:#0f1622;color:#dce6f2;border:1px solid #26344a}
    .change:hover{background:#16202e}
  </style></head><body><div class="box">
    <h2>Connection Failed</h2>
    <p>Could not connect to:<br><code>${esc(failedUrl)}</code></p>
    <p>Error: ${esc(desc)} (${esc(code)})</p>
    <div class="btns">
      <button class="change" id="changeBtn">Change Server</button>
      <button class="retry" id="retryBtn">Retry</button>
    </div>
  </div>
  <script>
    document.getElementById('changeBtn').addEventListener('click',()=>window.electronAPI.changeServer());
    document.getElementById('retryBtn').addEventListener('click',()=>window.electronAPI.retryLoad());
  </script></body></html>`;
  loadLocalPage(mainWindow.webContents, html);
}

// ─── LAN certificates: trust on first use, then pinned ───────────────────────
// A LAN/local server (isLocalOrLan) may present a certificate no authority
// vouches for (the installer's self-signed one). Accepting every such
// certificate let anyone on the LAN path impersonate the server: replace the
// web app, then read the login, the vault passphrase and every message. Now:
//  - first connection to a host:port: the user is shown the certificate and
//    decides; "Trust" pins it (cert-pins.json next to config.json);
//  - later connections: only the pinned certificate (same public key) is
//    accepted, silently; anything else is refused with a page that explains it
//    and offers a deliberate, confirmed re-trust of the certificate shown there;
//  - an install that was already using a LAN server over https before this
//    check existed may pin that server's certificate without a prompt, on the
//    FIRST connection after the update only: the window ends at the first
//    finished or failed load of the app, at the end of that launch, or after
//    24 h, and it is never granted when the pin file cannot be written
//    (certpin.initStore / takeAutoPin, endAutoPinWindow below);
//  - the exception exists only for the configured server (appOrigins: its
//    origin plus an accepted same-host https redirect of it) and only in the
//    app's own windows (the main window and windows it opened). Any other
//    LAN host, and any other webContents, gets Chromium's default: refused.
//    So a link or image in chat pointing at https://192.168.1.1/ is never
//    accepted, and never prompts; a pin of a server you no longer use is inert;
//  - only the page itself (a main-frame load) can raise the prompt.
let pinData = null;
function pins() { return pinData || (pinData = certpin.loadStore(PIN_FILE).data); }
function savePins() { return certpin.saveStore(PIN_FILE, pins()); }
function setPin(key, id) { pins().pins[key] = certpin.pinRecord(id); return savePins(); }
// The first load of the app after start-up has finished or failed: whatever
// happened, the existing-install silent pin is over.
function endAutoPinWindow() {
  if (pinData && certpin.endAutoPin(pinData)) { savePins(); console.error('[cert] first connection done; silent first-use pin window closed'); }
}

// The last certificate problem per host:port, so the failed load it causes shows
// a page that says what happened instead of a bare net::ERR_CERT_… code.
const certProblems = new Map();
// The certificate-changed page currently shown: what its re-trust would pin.
let shownCertChange = null;
// Open first-use prompts, so the parallel requests of one load ask once.
const certPrompts = new Map();
// The app's own webContents: the main window's and those of windows it opened.
const appContents = new WeakSet();
const isAppContents = (wc) => { try { return !!wc && !wc.isDestroyed() && appContents.has(wc); } catch { return false; } };
// Is this request for the configured server (wss:/ws: count as https:/http:)?
function isAppOriginUrl(u) {
  try {
    const x = new URL(u);
    if (x.protocol === 'wss:') x.protocol = 'https:'; else if (x.protocol === 'ws:') x.protocol = 'http:';
    return appOrigins.has(x.origin);
  } catch { return false; }
}

function certErrorText(error, key) {
  switch (error) {
    case 'net::ERR_CERT_AUTHORITY_INVALID': return 'is not issued by a certificate authority this computer trusts (for example, it is self-signed)';
    case 'net::ERR_CERT_COMMON_NAME_INVALID': return `was issued for a different name than ${certpin.keyHost(key)}`;
    case 'net::ERR_CERT_DATE_INVALID': return 'has expired or is not valid yet';
    default: return `could not be verified (${error})`;
  }
}
const fmtDate = (sec) => { try { return sec ? new Date(sec * 1000).toISOString().slice(0, 10) : 'unknown'; } catch { return 'unknown'; } };
const dialogParent = () => (mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()) ? mainWindow : null;
function showBox(opts) {
  const parent = dialogParent();
  return parent ? dialog.showMessageBox(parent, opts) : dialog.showMessageBox(opts);
}

function askFirstUse(key, id, error) {
  const pk = `${key}|${id.sha256}`;
  if (certPrompts.has(pk)) return certPrompts.get(pk);
  const p = showBox({
    type: 'warning',
    buttons: ['Trust and connect', 'Cancel'],
    defaultId: 1,
    cancelId: 1,
    noLink: true,
    title: 'Unverified server certificate',
    message: `Do you trust the certificate of ${key}?`,
    // The fingerprint (computed here) comes first; text taken from the
    // certificate (subject, issuer) only after it, stripped of control and bidi
    // characters and capped, so it cannot fake lines such as a fingerprint.
    detail:
      `SHA-256 fingerprint:\n${id.sha256}\n\n` +
      `This server's certificate ${certErrorText(error, key)}. That is normal for a CryptIRC server ` +
      'on your own network or computer that uses a self-signed certificate.\n\n' +
      `Certificate for: ${certpin.cleanText(id.subject) || '(no name)'}\n` +
      `Issued by: ${certpin.cleanText(id.issuer) || '(no name)'}\n` +
      `Valid until: ${fmtDate(id.validExpiry)}\n\n` +
      'Continue only if this is your server. To check, compare the fingerprint with the one the server ' +
      'shows for its certificate, e.g. `openssl x509 -in /etc/caddy/selfsigned/cert.pem -noout -fingerprint -sha256` ' +
      '(the path the CryptIRC installer uses).\n\n' +
      `If you trust it, CryptIRC remembers this certificate for ${key} and refuses to connect if the server ` +
      'ever presents a different one.',
  }).then((r) => r && r.response === 0, () => false)
    .finally(() => certPrompts.delete(pk));
  certPrompts.set(pk, p);
  return p;
}

// Decide one certificate error for a LAN/local host. Resolves true to accept.
async function checkLanCert(url, error, cert, isMainFrame) {
  const key = certpin.hostKey(url);
  const id = certpin.certIdentity(cert);
  if (!key || !id.sha256) return false;
  const pin = pins().pins[key];
  if (pin) {
    if (certpin.matchPin(pin, id)) {
      // Same key, re-issued certificate: keep what we show up to date.
      if (pin.sha256 !== id.sha256) setPin(key, id);
      return true;
    }
    console.error(`[cert] ${key}: certificate changed (pinned ${pin.sha256}, presented ${id.sha256}); refused`);
    certProblems.set(key, { kind: 'changed', key, pin, id, at: Date.now() });
    if (!isMainFrame) showChangedForRunningApp(key, url);
    return false;
  }
  if (pins().autoPin.length) {
    if (certpin.takeAutoPin(pins(), key)) {
      // Granted only if it is on disk: otherwise ask, like any other first use.
      if (setPin(key, id)) {
        console.error(`[cert] ${key}: pinned ${id.sha256} (first connection after the update to certificate pinning)`);
        return true;
      }
      delete pins().pins[key];
      console.error(`[cert] ${key}: could not save the pin file; asking instead of pinning silently`);
    } else savePins();
  }
  if (!isMainFrame) return false;
  if (await askFirstUse(key, id, error)) {
    // Another prompt for this host may have pinned a different certificate meanwhile.
    const now = pins().pins[key];
    if (now && !certpin.matchPin(now, id)) return false;
    setPin(key, id);
    return true;
  }
  certProblems.set(key, { kind: 'declined', key, id, at: Date.now() });
  return false;
}

// The app is already running and a later request to ITS server (the WebSocket
// reconnecting, say) met a different certificate: show the explanation instead
// of an app that silently never reconnects.
function showChangedForRunningApp(key, url) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (!isAppOriginUrl(url)) return;
  // One page for a burst of refused requests, and none while it is up.
  const now = Date.now();
  if (lastRunningAppCertPage.key === key && now - lastRunningAppCertPage.at < 10000) return;
  if (shownCertChange && shownCertChange.key === key && isLocalPage(mainWindow.webContents, mainWindow.webContents.getURL())) return;
  lastRunningAppCertPage = { key, at: now };
  const p = certProblems.get(key);
  if (p) setImmediate(() => showCertPage(url, p));
}
let lastRunningAppCertPage = { key: '', at: 0 };

// The failed main-frame load was caused by a certificate decision: say so.
// Only for certificate failures (net::ERR_CERT_* is -200…-299; a refused
// certificate can also surface as ERR_INSECURE_RESPONSE, -501); a server that is
// simply down still gets the ordinary connection-error page.
function certPageFor(failedUrl, code) {
  if (!((code <= -200 && code > -300) || code === -501)) return false;
  const key = certpin.hostKey(failedUrl);
  const p = key && certProblems.get(key);
  if (!p || Date.now() - p.at > 60000) return false;
  certProblems.delete(key);
  showCertPage(failedUrl, p);
  return true;
}

function showCertPage(failedUrl, p) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const changed = p.kind === 'changed';
  shownCertChange = changed ? { key: p.key, pin: p.pin, id: p.id } : null;
  const body = changed
    ? `<h2>Server certificate changed</h2>
      <p><code>${esc(p.key)}</code> presented a different certificate from the one CryptIRC remembered for it,
      so the connection was refused.</p>
      <p>This happens when the server's certificate was regenerated (a reinstall, a new self-signed certificate).
      It can also mean that someone on your network is impersonating the server to capture your password,
      vault passphrase and messages.</p>
      <table>
        <tr><td>Remembered</td><td><code>${esc(p.pin.sha256 || '?')}</code><br><span>${esc(certpin.cleanText(p.pin.subject))}${p.pin.pinnedAt ? ' · trusted ' + esc(String(p.pin.pinnedAt).slice(0, 10)) : ''}</span></td></tr>
        <tr><td>Presented now</td><td><code>${esc(p.id.sha256)}</code><br><span>${esc(certpin.cleanText(p.id.subject))} · valid until ${esc(fmtDate(p.id.validExpiry))}</span></td></tr>
      </table>
      <p>Trust the new certificate only if you changed it yourself and its fingerprint matches the one on the
      server (e.g. <code>openssl x509 -in /etc/caddy/selfsigned/cert.pem -noout -fingerprint -sha256</code>).
      A server that renews its certificate by itself (Caddy's <code>tls internal</code>) changes it every few hours:
      install its root certificate on this computer instead, and no exception is needed.</p>`
    : `<h2>Certificate not trusted</h2>
      <p>You chose not to trust the certificate of <code>${esc(p.key)}</code>
      (SHA-256 <code>${esc(p.id.sha256)}</code>), so CryptIRC did not connect.</p>
      <p>Retry to see the question again, or change the server.</p>`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{font-family:system-ui;background:#0a0e13;color:#dce6f2;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .box{max-width:620px;padding:24px}
    h2{color:#ff7a7a;margin-bottom:12px;text-align:center}
    p{color:#8aa0b6;font-size:14px;line-height:1.5}
    code{background:#0f1622;padding:2px 6px;border-radius:4px;color:${BLUE};word-break:break-all}
    table{border-collapse:collapse;margin:12px 0;font-size:13px;width:100%}
    td{padding:6px 8px;vertical-align:top;color:#8aa0b6;border-top:1px solid #26344a}
    td:first-child{white-space:nowrap;color:#dce6f2}
    td span{font-size:12px}
    .btns{display:flex;gap:10px;justify-content:center;margin-top:20px;flex-wrap:wrap}
    button{padding:10px 20px;border-radius:8px;border:none;cursor:pointer;font-size:14px;font-weight:600}
    .retry{background:${TEAL};color:#04110d}
    .retry:hover{background:${TEAL_DK}}
    .change{background:#0f1622;color:#dce6f2;border:1px solid #26344a}
    .change:hover{background:#16202e}
    .retrust{background:#0f1622;color:#ff7a7a;border:1px solid #5a2a2a}
  </style></head><body><div class="box">
    ${body}
    <div class="btns">
      <button class="change" id="changeBtn">Change Server</button>
      ${changed ? '<button class="retrust" id="retrustBtn">Trust the new certificate…</button>' : ''}
      <button class="retry" id="retryBtn">Retry</button>
    </div>
  </div>
  <script>
    document.getElementById('changeBtn').addEventListener('click',()=>window.electronAPI.changeServer());
    document.getElementById('retryBtn').addEventListener('click',()=>window.electronAPI.retryLoad());
    var rt=document.getElementById('retrustBtn');
    if(rt)rt.addEventListener('click',()=>window.electronAPI.retrustCert());
  </script></body></html>`;
  loadLocalPage(mainWindow.webContents, html);
}

// "Trust the new certificate…" on the certificate-changed page. A second,
// explicit confirmation, and it pins exactly the certificate shown on that page
// (never whatever the next connection happens to present).
async function retrustFlow() {
  const c = shownCertChange;
  if (!c) return;
  const r = await showBox({
    type: 'warning',
    buttons: ['Trust new certificate', 'Cancel'],
    defaultId: 1,
    cancelId: 1,
    noLink: true,
    title: 'Replace the remembered certificate?',
    message: `Trust the new certificate of ${c.key}?`,
    detail:
      'Only do this if you changed the server\'s certificate yourself and the new fingerprint matches the one on the server.\n\n' +
      `Remembered: ${c.pin.sha256}\nNew: ${c.id.sha256}`,
  }).catch(() => null);
  if (!r || r.response !== 0 || shownCertChange !== c) return;
  setPin(c.key, c.id);
  shownCertChange = null;
  console.error(`[cert] ${c.key}: re-trusted, now pinned ${c.id.sha256}`);
  // Start over on fresh connections, verified against the new pin.
  try { if (mainWindow && !mainWindow.isDestroyed()) await mainWindow.webContents.session.closeAllConnections(); } catch {}
  crashTimes = [];
  loadApp(loadConfig().url || DEFAULT_URL);
}

// ─── Navigation policy ───────────────────────────────────────────────────────
// Same-origin pages stay in-app; everything else opens in the system browser.
// Pastes are user-supplied content (an HTML paste is a runnable page), so they
// always open externally — they must never get a top-level Electron window with
// the electronAPI preload bridge.
const isPasteUrl = (u) => { try { return /\/paste\//.test(new URL(u).pathname); } catch { return false; } };
// Reads the CURRENT app origins on every call, so Change Server takes effect
// without re-hardening (and for windows opened before the change).
const inApp = (u) => { try { return appOrigins.has(new URL(u).origin) && !isPasteUrl(u); } catch { return false; } };

// Apply the policy to a webContents and, recursively, to every window it opens
// (detached channel windows included) — child windows otherwise get no guards.
function hardenContents(wc) {
  wc.setWindowOpenHandler(({ url: linkUrl }) => {
    if (!inApp(linkUrl)) { openExternalSafe(linkUrl); return { action: 'deny' }; }
    return { action: 'allow' };
  });
  const guardNav = (e, navUrl) => {
    if (isLocalPage(wc, navUrl)) return;     // our own error/setup page
    if (!inApp(navUrl)) { e.preventDefault(); openExternalSafe(navUrl); }
  };
  wc.on('will-navigate', guardNav);
  wc.on('will-redirect', (e, navUrl, isInPlace, isMainFrameArg) => {
    const isMainFrame = (e && typeof e.isMainFrame === 'boolean') ? e.isMainFrame : !!isMainFrameArg;
    // A redirect of the configured URL that WE asked the main window to load
    // and that stays on that server (http->https as in the INSTALL.md nginx
    // example, /cryptirc -> /cryptirc/) is the server itself: follow it and treat
    // the final origin as the app too. Bouncing it to the system browser left an
    // empty window, because the resulting ERR_ABORTED is (rightly) not an error.
    if (isMainFrame && ownLoadPending && mainWindow && !mainWindow.isDestroyed() && wc === mainWindow.webContents) {
      if (ownRedirectAllowed(navUrl)) { addAppOrigin(navUrl); return; }
      // Anything else is refused with a clear page instead of a blank window.
      e.preventDefault();
      ownLoadPending = false;
      const from = ownLoadUrl;
      setImmediate(() => showErrorPage(from,
        `The server redirected to ${navUrl}, which is not the same server (or is not https). ` +
        'If that is your server, use Change Server to connect to that address directly', 'redirect'));
      return;
    }
    guardNav(e, navUrl);
  });
  wc.on('did-create-window', (child) => {
    // A window the app opened is the app too (for the LAN certificate check).
    if (appContents.has(wc)) appContents.add(child.webContents);
    hardenContents(child.webContents);
  });
}

// ─── Main window ─────────────────────────────────────────────────────────────
function createWindow(url) {
  const cfg = loadConfig();
  const saved = cfg.bounds || {};
  mainWindow = new BrowserWindow({
    width: saved.width || 1200,
    height: saved.height || 800,
    x: saved.x,
    y: saved.y,
    minWidth: 400,
    minHeight: 300,
    title: 'CryptIRC',
    icon: path.join(__dirname, 'icons', 'icon.png'),
    autoHideMenuBar: true,
    backgroundColor: '#080b11',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true,
    },
  });
  if (cfg.isMaximized) mainWindow.maximize();

  mainWindow.webContents.session.setSpellCheckerLanguages(['en-US']);

  // Only allow camera/mic/etc. that the client actually needs; deny the rest.
  const ALLOWED_PERMS = new Set(['notifications', 'clipboard-read', 'clipboard-sanitized-write', 'fullscreen']);
  mainWindow.webContents.session.setPermissionRequestHandler((wc, permission, cb) => cb(ALLOWED_PERMS.has(permission)));
  mainWindow.webContents.session.setPermissionCheckHandler((wc, permission) => ALLOWED_PERMS.has(permission));

  // Connection error → show the error page IN this window (keeps tray/close
  // wiring intact). Ignore subframe failures and benign aborts (ERR_ABORTED).
  mainWindow.webContents.on('did-fail-load', (e, code, desc, failedUrl, isMainFrame) => {
    if (!isMainFrame) return;
    ownLoadPending = false;
    if (code === -3) return;
    endAutoPinWindow();
    if (certPageFor(failedUrl, code)) return;   // a refused/declined LAN certificate: explain it
    showErrorPage(failedUrl, desc, code);
  });
  // The navigation committed (redirects are over): later redirects are the
  // page's own and go through the normal same-origin policy.
  mainWindow.webContents.on('did-navigate', () => { ownLoadPending = false; });

  // Restore zoom, then persist it on change.
  mainWindow.webContents.on('did-finish-load', () => {
    endAutoPinWindow();
    if (typeof cfg.zoomLevel === 'number') mainWindow.webContents.setZoomLevel(cfg.zoomLevel);
  });
  mainWindow.webContents.on('zoom-changed', () => persistBounds());

  // External links / foreign navigation open in the browser (see hardenContents).
  appContents.add(mainWindow.webContents);
  hardenContents(mainWindow.webContents);

  loadApp(url);

  // Persist window bounds (debounced).
  const onBoundsChange = () => persistBounds();
  mainWindow.on('resize', onBoundsChange);
  mainWindow.on('move', onBoundsChange);
  mainWindow.on('maximize', onBoundsChange);
  mainWindow.on('unmaximize', onBoundsChange);

  // Minimize to tray instead of closing.
  mainWindow.on('close', (e) => {
    if (!isQuitting) { e.preventDefault(); persistBounds(); mainWindow.hide(); }
  });
  mainWindow.on('closed', () => { mainWindow = null; });

  // Flash + badge on unread/mention via the page title.
  mainWindow.webContents.on('page-title-updated', (e, title) => {
    if (title.includes('*')) mainWindow.flashFrame(true);
    const m = title.match(/[([](\d+)[)\]]/);
    setBadge(m ? parseInt(m[1], 10) : 0);
  });

  // Right-click context menu with spell-check suggestions (template: contextMenuTemplate).
  mainWindow.webContents.on('context-menu', (e, params) => {
    const items = contextMenuTemplate(mainWindow, params);
    if (items.length && mainWindow && !mainWindow.isDestroyed()) Menu.buildFromTemplate(items).popup({ window: mainWindow });
  });

  // ── Freeze / crash recovery ────────────────────────────────────────────────
  // Over a very long session the page can hang or its renderer can die. Rather
  // than make the user kill and relaunch the whole app, detect it and recover by
  // reloading just the window (the IRC connections live server-side, so nothing
  // is lost). A non-blocking dialog is used so the main process never stalls.
  let unresponsivePromptOpen = false;
  mainWindow.on('unresponsive', () => {
    if (unresponsivePromptOpen || !mainWindow || mainWindow.isDestroyed()) return;
    unresponsivePromptOpen = true;
    dialog.showMessageBox(mainWindow, {
      type: 'warning',
      buttons: ['Reload', 'Keep waiting'],
      defaultId: 0,
      cancelId: 1,
      title: 'CryptIRC is not responding',
      message: 'CryptIRC has stopped responding.',
      detail: 'Reload the window to recover — you stay connected on the server. Or keep waiting if it is just busy.',
    }).then(({ response }) => {
      unresponsivePromptOpen = false;
      if (response === 0 && mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.reload();
    }).catch(() => { unresponsivePromptOpen = false; });
  });
  mainWindow.on('responsive', () => { unresponsivePromptOpen = false; });

  // If the renderer process actually goes away (crash / OOM / killed), reload it
  // instead of leaving a blank, dead window — but with a limit: a page that
  // crashes on load used to be reloaded forever, pinning a CPU. Up to three
  // reloads (immediately, then after 3 s and 10 s) per two minutes; after that
  // the error page is shown and its Retry button starts over. A clean exit is
  // normal.
  mainWindow.webContents.on('render-process-gone', (e, details) => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    const reason = (details && details.reason) || 'unknown';
    if (reason === 'clean-exit') return;
    console.error('[render-process-gone]', reason);
    const now = Date.now();
    crashTimes = crashTimes.filter((t) => now - t < CRASH_WINDOW_MS);
    crashTimes.push(now);
    if (crashReloadTimer) { clearTimeout(crashReloadTimer); crashReloadTimer = null; }
    if (crashTimes.length > CRASH_RELOAD_DELAYS.length) {
      showErrorPage(loadConfig().url || DEFAULT_URL, 'The page keeps crashing, so automatic reloading was stopped', reason);
      return;
    }
    crashReloadTimer = setTimeout(() => {
      crashReloadTimer = null;
      // The server is read when the reload happens, not when the crash did.
      if (mainWindow && !mainWindow.isDestroyed()) loadApp(loadConfig().url || DEFAULT_URL);
    }, CRASH_RELOAD_DELAYS[crashTimes.length - 1]);
  });
}

function persistBounds() {
  if (saveBoundsTimer) clearTimeout(saveBoundsTimer);
  saveBoundsTimer = setTimeout(() => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    const cfg = loadConfig();
    cfg.isMaximized = mainWindow.isMaximized();
    if (!cfg.isMaximized) cfg.bounds = mainWindow.getBounds();
    try { cfg.zoomLevel = mainWindow.webContents.getZoomLevel(); } catch {}
    saveConfig(cfg);
  }, 400);
}

function setBadge(n) {
  try { app.setBadgeCount(n > 0 ? n : 0); } catch {}
}

// ─── Change-server flow (shared by tray, menu, error page) ───────────────────
async function changeServerFlow() {
  const cfg = loadConfig();
  const url = await showSetupPrompt(cfg.url || DEFAULT_URL);
  if (!url) return;
  cfg.url = url;
  saveConfig(cfg);
  // The silent first-connection pin was for the server this install already
  // used; a newly chosen server is asked about like any other.
  endAutoPinWindow();
  if (mainWindow && !mainWindow.isDestroyed()) loadApp(url);
  else createWindow(url);
}

// ─── Application menu (visible Quit/Ctrl+Q, copy/paste, zoom, reload) ─────────
function buildMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: 'File',
      submenu: [
        { label: 'Change Server URL…', click: () => changeServerFlow() },
        { type: 'separator' },
        { label: 'Quit', accelerator: 'CmdOrCtrl+Q', click: () => { isQuitting = true; app.quit(); } },
      ],
    },
    { role: 'editMenu' },
    {
      label: 'View',
      submenu: [
        { role: 'reload' }, { role: 'forceReload' }, { type: 'separator' },
        { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' },
        { role: 'togglefullscreen' }, { role: 'toggleDevTools' },
      ],
    },
    { role: 'windowMenu' },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ─── IPC: native notifications ───────────────────────────────────────────────
const _activeNotifs = new Set();
ipcMain.on('show-notification', (e, title, body, meta) => {
  try {
    if (!Notification.isSupported()) return;
    const notif = new Notification({ title: title || 'CryptIRC', body: body || '', icon: path.join(__dirname, 'icons', 'icon.png'), silent: true });
    _activeNotifs.add(notif);
    // Always release the reference, even if the platform never fires close/click/
    // failed (some don't), so the Set can't grow unbounded over a long session.
    const fallback = setTimeout(() => _activeNotifs.delete(notif), 30000);
    const cleanup = () => { clearTimeout(fallback); _activeNotifs.delete(notif); };
    notif.on('click', () => {
      if (mainWindow && !mainWindow.isDestroyed()) {   // r6: the window may be gone by now
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.show(); mainWindow.focus();
        // ONE path to the page. Every app.js that passes `meta` (since it first
        // did, 2026-04-05) handles this message via electronAPI.onNotificationClick;
        // also injecting a jumpToMessage() call ran every jump twice, the second
        // cancelling the first's scroll and re-fetching its history.
        if (meta) {
          try { mainWindow.webContents.send('notification-click', meta); } catch {}
        }
      }
      cleanup();
    });
    notif.on('close', cleanup);
    notif.on('failed', cleanup);
    notif.show();
  } catch (err) { console.error('[notif]', err && err.message); }
});

// ─── IPC: unread badge / retry / change server ───────────────────────────────
ipcMain.on('set-unread', (e, n) => setBadge(parseInt(n, 10) || 0));
// Retry / Change Server are buttons on our local error page, which is loaded
// into the main window — only that page may use them (see fromLocalPage).
ipcMain.on('retry-load', (e) => {
  if (!mainWindow || !fromLocalPage(e, mainWindow.webContents)) { console.error('[ipc] retry-load from a foreign page ignored'); return; }
  crashTimes = [];   // an explicit retry starts the crash budget over
  const cfg = loadConfig();
  loadApp(cfg.url || DEFAULT_URL);
});
ipcMain.on('change-server', (e) => {
  if (!mainWindow || !fromLocalPage(e, mainWindow.webContents)) { console.error('[ipc] change-server from a foreign page ignored'); return; }
  changeServerFlow();
});
// The re-trust button of the certificate-changed page (also a local page only).
ipcMain.on('retrust-cert', (e) => {
  if (!mainWindow || !fromLocalPage(e, mainWindow.webContents)) { console.error('[ipc] retrust-cert from a foreign page ignored'); return; }
  retrustFlow();
});

// ─── System tray ─────────────────────────────────────────────────────────────
function createTray() {
  const iconPath = path.join(__dirname, 'icons', 'icon.png');
  let trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  if (trayIcon.isEmpty()) trayIcon = nativeImage.createFromPath(iconPath);
  tray = new Tray(trayIcon.isEmpty() ? nativeImage.createEmpty() : trayIcon);
  tray.setToolTip('CryptIRC');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Show CryptIRC', click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } } },
    { label: 'Reload', click: () => { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.reload(); } },
    { label: 'Change Server URL…', click: () => changeServerFlow() },
    { type: 'separator' },
    { label: 'Quit', click: () => { isQuitting = true; app.quit(); } },
  ]));
  tray.on('click', () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } });
}

// ─── Auto-update (electron-updater, GitHub feed) ─────────────────────────────
function setupAutoUpdate() {
  if (!app.isPackaged) return; // no app-update.yml in dev
  // A build made without a publish config has no app-update.yml, and every
  // check then fails silently (every 6 h, forever). Say so once instead.
  try {
    if (!fs.existsSync(path.join(process.resourcesPath, 'app-update.yml'))) {
      console.error('[updater] this build has no app-update.yml (built without a publish config) — auto-update is off; install new releases manually');
      return;
    }
  } catch {}
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.on('update-downloaded', (info) => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    const r = dialog.showMessageBoxSync(mainWindow, {
      type: 'info',
      buttons: ['Restart now', 'Later'],
      defaultId: 0,
      cancelId: 1,
      title: 'Update ready',
      message: `CryptIRC ${info.version} is ready to install.`,
      detail: 'Restart now to update, or it will be installed automatically when you quit.',
    });
    if (r === 0) { isQuitting = true; autoUpdater.quitAndInstall(); }
  });
  autoUpdater.on('error', (err) => console.error('[updater]', err && err.message));
  autoUpdater.checkForUpdates().catch(() => {});
  setInterval(() => autoUpdater.checkForUpdates().catch(() => {}), 6 * 60 * 60 * 1000);
}

// ─── Process-level safety nets ───────────────────────────────────────────────
process.on('uncaughtException', (e) => console.error('[uncaughtException]', e));
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));

// ─── Windows notification app id ─────────────────────────────────────────────
if (process.platform === 'win32') app.setAppUserModelId('com.cryptirc.app');

// ─── App lifecycle ───────────────────────────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } });

  // Remote servers MUST present a valid TLS cert (this is an encrypted client).
  // A localhost / private-LAN host may use one no authority vouches for, but
  // only when it is the configured server, loaded in the app's own windows, and
  // only the certificate the user trusted on first use (see checkLanCert).
  // Everything else keeps Chromium's default: refused.
  app.on('certificate-error', (event, webContents, url, error, cert, callback, isMainFrame) => {
    let host = '';
    try { host = new URL(url).hostname; } catch {}
    if (!isLocalOrLan(host) || !isAppContents(webContents) || !isAppOriginUrl(url)) { callback(false); return; }
    event.preventDefault();
    checkLanCert(url, error, cert, isMainFrame !== false)
      .then((ok) => callback(!!ok), (err) => { console.error('[cert]', err && err.message); callback(false); });
  });

  app.on('ready', async () => {
    const cfg = loadConfig();
    // Load the certificate pins (and, on the first run of this version, arrange
    // the one silent pin for the LAN server this install was already using).
    pinData = certpin.initStore(PIN_FILE, cfg.url, isLocalOrLan);
    // Default to the TwistedNet-hosted client on a fresh install — no prompt. A custom
    // server (File ▸ Change Server URL…) is saved to config and used instead thereafter.
    const url = cfg.url || DEFAULT_URL;
    buildMenu();
    createWindow(url);
    createTray();
    setupAutoUpdate();
  });

  app.on('before-quit', () => { isQuitting = true; });
  app.on('activate', () => { if (!mainWindow) { const cfg = loadConfig(); createWindow(cfg.url || DEFAULT_URL); } });
  app.on('window-all-closed', () => { /* tray keeps the app alive; quit only via menu/tray */ });
}
