const { app, BrowserWindow, Tray, Menu, nativeImage, shell, ipcMain, Notification, dialog, session } = require('electron');
const path = require('path');
const fs = require('fs');
const { autoUpdater } = require('electron-updater');

// ─── Config ──────────────────────────────────────────────────────────────────
const CONFIG_FILE = path.join(app.getPath('userData'), 'config.json');
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
// on a LAN or localhost). Everything else MUST present a valid TLS cert.
function isLocalOrLan(hostname) {
  if (!hostname) return false;
  const h = hostname.replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/\.local$/i.test(h)) return true;
  return false;
}

// ─── App state ───────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let isQuitting = false;
let saveBoundsTimer = null;

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

    let done = false;
    const onUrl = (e, url) => finish((url || '').endsWith('/') ? url : url + '/');
    const onQuit = () => finish(null);
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

    setup.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
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
  mainWindow.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
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
    if (!isMainFrame || code === -3) return;
    showErrorPage(failedUrl, desc, code);
  });

  // Restore zoom, then persist it on change.
  mainWindow.webContents.on('did-finish-load', () => {
    if (typeof cfg.zoomLevel === 'number') mainWindow.webContents.setZoomLevel(cfg.zoomLevel);
  });
  mainWindow.webContents.on('zoom-changed', () => persistBounds());

  mainWindow.loadURL(url);

  // External links open in the browser; same-origin stays in-app.
  const sameOrigin = (a, b) => { try { return new URL(a).origin === new URL(b).origin; } catch { return false; } };
  mainWindow.webContents.setWindowOpenHandler(({ url: linkUrl }) => {
    if (!sameOrigin(linkUrl, url)) { shell.openExternal(linkUrl); return { action: 'deny' }; }
    return { action: 'allow' };
  });
  // Keep the shell pinned to the server origin; anything else opens externally.
  const guardNav = (e, navUrl) => {
    if (navUrl.startsWith('data:')) return; // our own error/setup chrome
    if (!sameOrigin(navUrl, url)) { e.preventDefault(); shell.openExternal(navUrl); }
  };
  mainWindow.webContents.on('will-navigate', guardNav);
  mainWindow.webContents.on('will-redirect', guardNav);

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

  // Right-click context menu with spell-check suggestions.
  mainWindow.webContents.on('context-menu', (e, params) => {
    const items = [];
    if (params.misspelledWord) {
      if (params.dictionarySuggestions.length) {
        for (const s of params.dictionarySuggestions.slice(0, 5))
          items.push({ label: s, click: () => mainWindow.webContents.replaceMisspelling(s) });
      } else items.push({ label: '(no suggestions)', enabled: false });
      items.push({ type: 'separator' });
      items.push({ label: 'Add to Dictionary', click: () => mainWindow.webContents.session.addWordToSpellCheckerDictionary(params.misspelledWord) });
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
      items.push({ label: 'Open Link in Browser', click: () => shell.openExternal(params.linkURL) });
      items.push({ label: 'Copy Link', click: () => require('electron').clipboard.writeText(params.linkURL) });
    }
    if (params.hasImageContents) {
      if (items.length) items.push({ type: 'separator' });
      items.push({ label: 'Copy Image', click: () => mainWindow.webContents.copyImageAt(params.x, params.y) });
      items.push({ label: 'Open Image in Browser', click: () => shell.openExternal(params.srcURL) });
    }
    if (items.length) Menu.buildFromTemplate(items).popup({ window: mainWindow });
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

  // If the renderer process actually goes away (crash / OOM / killed), auto-reload
  // it once instead of leaving a blank, dead window. A clean exit is normal.
  mainWindow.webContents.on('render-process-gone', (e, details) => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (details && details.reason === 'clean-exit') return;
    console.error('[render-process-gone]', details && details.reason);
    const cfg = loadConfig();
    mainWindow.loadURL(cfg.url || DEFAULT_URL);
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
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.loadURL(url);
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
      if (mainWindow) {
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.show(); mainWindow.focus();
        if (meta) {
          const js = `(function(){try{if(typeof jumpToMessage==='function'){jumpToMessage(${JSON.stringify(meta.conn_id)},${JSON.stringify(meta.target)},${JSON.stringify(meta.ts)},${JSON.stringify(meta.from)});}else if(typeof setActive==='function'){setActive(${JSON.stringify(meta.conn_id)},${JSON.stringify(meta.target)});}}catch(e){}})();`;
          mainWindow.webContents.executeJavaScript(js).catch(() => {});
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
ipcMain.on('retry-load', () => { const cfg = loadConfig(); if (mainWindow) mainWindow.loadURL(cfg.url || DEFAULT_URL); });
ipcMain.on('change-server', () => { changeServerFlow(); });

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

  // Only accept self-signed/invalid certs for localhost / private-LAN hosts.
  // Remote servers MUST present a valid TLS cert (this is an encrypted client).
  app.on('certificate-error', (event, webContents, url, error, cert, callback) => {
    let host = '';
    try { host = new URL(url).hostname; } catch {}
    if (isLocalOrLan(host)) { event.preventDefault(); callback(true); }
    else callback(false);
  });

  app.on('ready', async () => {
    const cfg = loadConfig();
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
