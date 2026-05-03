const { app, BrowserWindow, Tray, Menu, nativeImage, shell, ipcMain, Notification } = require('electron');
const path = require('path');
const fs = require('fs');

// ─── Config ──────────────────────────────────────────────────────────────────
const CONFIG_FILE = path.join(app.getPath('userData'), 'config.json');

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

// ─── App state ───────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let isQuitting = false;

// ─── Setup prompt (first launch) ─────────────────────────────────────────────
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
      webPreferences: { nodeIntegration: true, contextIsolation: false },
    });

    const val = existingUrl || '';
    const html = `<!DOCTYPE html><html><head><style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a14;color:#e0e0e0;display:flex;align-items:center;justify-content:center;height:100vh}
      .card{width:100%;padding:32px;display:flex;flex-direction:column;gap:16px}
      h2{font-size:18px;color:#a78bfa;font-weight:600}
      p{font-size:13px;color:#888;line-height:1.4}
      label{font-size:13px;color:#aaa}
      input{padding:10px 12px;border-radius:8px;border:1px solid #333;background:#12121f;color:#e0e0e0;font-size:14px;width:100%;outline:none}
      input:focus{border-color:#7c3aed}
      .btns{display:flex;gap:10px;justify-content:flex-end;margin-top:4px}
      button{padding:9px 24px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:500}
      .connect{background:#7c3aed;color:white}
      .connect:hover{background:#6d28d9}
      .quit{background:#1e1e2e;color:#888;border:1px solid #333}
      .quit:hover{background:#2a2a3a}
      .err{color:#f87171;font-size:12px;min-height:16px}
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
      const {ipcRenderer}=require('electron');
      const urlEl=document.getElementById('url');
      const errEl=document.getElementById('err');
      urlEl.focus();
      urlEl.select();
      function submit(){
        const v=urlEl.value.trim();
        if(!v){errEl.textContent='Please enter a URL';return;}
        if(!v.startsWith('http://')&&!v.startsWith('https://')){errEl.textContent='URL must start with http:// or https://';return;}
        ipcRenderer.send('setup-url',v);
      }
      document.getElementById('connBtn').addEventListener('click',submit);
      document.getElementById('quitBtn').addEventListener('click',()=>ipcRenderer.send('setup-quit'));
      urlEl.addEventListener('keydown',e=>{if(e.key==='Enter')submit();});
    </script></body></html>`;

    setup.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));

    ipcMain.once('setup-url', (e, url) => {
      setup.close();
      resolve(url.endsWith('/') ? url : url + '/');
    });

    ipcMain.once('setup-quit', () => {
      setup.close();
      resolve(null);
    });

    setup.on('closed', () => {
      resolve(null);
    });
  });
}

// ─── Main window ─────────────────────────────────────────────────────────────
function createWindow(url) {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 400,
    minHeight: 300,
    title: 'CryptIRC',
    icon: path.join(__dirname, 'icons', 'icon.png'),
    autoHideMenuBar: true,
    backgroundColor: '#0a0a0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      spellcheck: true,
    },
  });

  // Ensure spellcheck language is set (Electron doesn't always auto-detect)
  mainWindow.webContents.session.setSpellCheckerLanguages(['en-US']);

  // Handle load errors — show error page with working buttons
  mainWindow.webContents.on('did-fail-load', (e, code, desc, failedUrl) => {
    // Destroy the main window and show error in a node-enabled window
    const bounds = mainWindow.getBounds();
    mainWindow.removeAllListeners('close');
    mainWindow.destroy();
    mainWindow = new BrowserWindow({
      ...bounds,
      title: 'CryptIRC — Connection Failed',
      icon: path.join(__dirname, 'icons', 'icon.png'),
      autoHideMenuBar: true,
      backgroundColor: '#0a0a14',
      webPreferences: { nodeIntegration: true, contextIsolation: false },
    });
    mainWindow.loadURL('data:text/html,' + encodeURIComponent(`<!DOCTYPE html><html><head><style>
      body{font-family:system-ui;background:#0a0a14;color:#e0e0e0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
      .box{text-align:center;max-width:400px}
      h2{color:#f87171;margin-bottom:12px}
      p{color:#888;font-size:14px;line-height:1.5}
      code{background:#1e1e2e;padding:2px 8px;border-radius:4px;color:#a78bfa}
      .btns{display:flex;gap:10px;justify-content:center;margin-top:20px}
      button{padding:10px 24px;border-radius:8px;border:none;cursor:pointer;font-size:14px}
      .retry{background:#7c3aed;color:white}
      .change{background:#1e1e2e;color:#ccc;border:1px solid #333}
    </style></head><body><div class="box">
      <h2>Connection Failed</h2>
      <p>Could not connect to:<br><code>${failedUrl}</code></p>
      <p>Error: ${desc} (${code})</p>
      <div class="btns">
        <button class="change" onclick="require('electron').ipcRenderer.send('change-server')">Change Server</button>
        <button class="retry" onclick="require('electron').ipcRenderer.send('retry-load')">Retry</button>
      </div>
    </div></body></html>`));
  });

  mainWindow.loadURL(url);

  // Open external links in default browser
  mainWindow.webContents.setWindowOpenHandler(({ url: linkUrl }) => {
    if (!linkUrl.startsWith(url)) {
      shell.openExternal(linkUrl);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });

  // Minimize to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Flash taskbar on notification
  mainWindow.webContents.on('page-title-updated', (e, title) => {
    if (title.includes('*')) {
      mainWindow.flashFrame(true);
    }
  });

  // ── Right-click context menu with spell check suggestions ──────────────────
  mainWindow.webContents.on('context-menu', (e, params) => {
    const menuItems = [];

    // Spelling suggestions
    if (params.misspelledWord) {
      if (params.dictionarySuggestions.length > 0) {
        for (const suggestion of params.dictionarySuggestions.slice(0, 5)) {
          menuItems.push({
            label: suggestion,
            click: () => mainWindow.webContents.replaceMisspelling(suggestion),
          });
        }
      } else {
        menuItems.push({ label: '(no suggestions)', enabled: false });
      }
      menuItems.push({ type: 'separator' });
      menuItems.push({
        label: 'Add to Dictionary',
        click: () => mainWindow.webContents.session.addWordToSpellCheckerDictionary(params.misspelledWord),
      });
      menuItems.push({ type: 'separator' });
    }

    // Edit actions — only show relevant ones
    if (params.isEditable) {
      menuItems.push({ label: 'Cut', role: 'cut', enabled: params.editFlags.canCut });
      menuItems.push({ label: 'Copy', role: 'copy', enabled: params.editFlags.canCopy });
      menuItems.push({ label: 'Paste', role: 'paste', enabled: params.editFlags.canPaste });
      menuItems.push({ label: 'Select All', role: 'selectAll', enabled: params.editFlags.canSelectAll });
    } else if (params.selectionText) {
      menuItems.push({ label: 'Copy', role: 'copy' });
    }

    // Link actions
    if (params.linkURL) {
      if (menuItems.length > 0) menuItems.push({ type: 'separator' });
      menuItems.push({
        label: 'Open Link in Browser',
        click: () => shell.openExternal(params.linkURL),
      });
      menuItems.push({
        label: 'Copy Link',
        click: () => { require('electron').clipboard.writeText(params.linkURL); },
      });
    }

    // Image actions
    if (params.hasImageContents) {
      if (menuItems.length > 0) menuItems.push({ type: 'separator' });
      menuItems.push({
        label: 'Copy Image',
        click: () => mainWindow.webContents.copyImageAt(params.x, params.y),
      });
      menuItems.push({
        label: 'Open Image in Browser',
        click: () => shell.openExternal(params.srcURL),
      });
    }

    if (menuItems.length > 0) {
      Menu.buildFromTemplate(menuItems).popup({ window: mainWindow });
    }
  });
}

// ─── IPC: native notifications ───────────────────────────────────────────────
// Keep a reference to active notifications so they don't get GC'd before click.
const _activeNotifs = new Set();

ipcMain.on('show-notification', (e, title, body, meta) => {
  try {
    if (!Notification.isSupported()) {
      console.error('[NOTIF] Notifications not supported on this system');
      return;
    }
    const notif = new Notification({
      title: title || 'CryptIRC',
      body: body || '',
      icon: path.join(__dirname, 'icons', 'icon.png'),
      silent: true,
    });
    _activeNotifs.add(notif);
    const cleanup = () => _activeNotifs.delete(notif);
    notif.on('click', () => {
      console.log('[NOTIF] Clicked:', title, 'meta:', meta ? JSON.stringify(meta) : 'none');
      if (mainWindow) {
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.show();
        mainWindow.focus();
        if (meta) {
          // Primary path: inject JavaScript directly into the renderer. Doesn't
          // require any preload wiring, so works across Electron shell versions.
          const js = `(function(){try{if(typeof jumpToMessage==='function'){jumpToMessage(${JSON.stringify(meta.conn_id)},${JSON.stringify(meta.target)},${JSON.stringify(meta.ts)},${JSON.stringify(meta.from)});}else if(typeof setActive==='function'){setActive(${JSON.stringify(meta.conn_id)},${JSON.stringify(meta.target)});}}catch(e){console.error('[NOTIF] nav failed:',e);}})();`;
          mainWindow.webContents.executeJavaScript(js).catch(err => console.error('[NOTIF] executeJavaScript failed:', err));
          // Fallback: also send via IPC (for preload-based listeners if present)
          try { mainWindow.webContents.send('notification-click', meta); } catch (err) {}
        }
      }
      cleanup();
    });
    notif.on('close', cleanup);
    notif.on('show', () => console.log('[NOTIF] Notification shown:', title));
    notif.on('failed', (e, err) => { console.error('[NOTIF] Failed:', err); cleanup(); });
    notif.show();
  } catch (err) {
    console.error('[NOTIF] Exception:', err);
  }
});

// ─── IPC: retry / change server ──────────────────────────────────────────────
ipcMain.on('retry-load', () => {
  const cfg = loadConfig();
  if (cfg.url) {
    if (mainWindow) { mainWindow.removeAllListeners('close'); mainWindow.destroy(); mainWindow = null; }
    createWindow(cfg.url);
  }
});

ipcMain.on('change-server', async () => {
  const cfg = loadConfig();
  const url = await showSetupPrompt(cfg.url);
  if (url) {
    cfg.url = url;
    saveConfig(cfg);
    if (mainWindow) { mainWindow.removeAllListeners('close'); mainWindow.destroy(); mainWindow = null; }
    createWindow(url);
  }
});

// ─── System tray ─────────────────────────────────────────────────────────────
function createTray() {
  const iconPath = path.join(__dirname, 'icons', 'icon.png');
  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  } catch {
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.setToolTip('CryptIRC');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show CryptIRC',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      },
    },
    {
      label: 'Change Server URL',
      click: async () => {
        const cfg = loadConfig();
        const url = await showSetupPrompt(cfg.url);
        if (url) {
          cfg.url = url;
          saveConfig(cfg);
          if (mainWindow) mainWindow.loadURL(url);
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.focus();
      } else {
        mainWindow.show();
        mainWindow.focus();
      }
    }
  });
}

// ─── Windows notification setup ──────────────────────────────────────────────
// Required for Windows toast notifications to work
if (process.platform === 'win32') {
  app.setAppUserModelId('com.cryptirc.app');
}

// ─── App lifecycle ───────────────────────────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });

  // Accept self-signed / local certs
  app.on('certificate-error', (event, webContents, url, error, cert, callback) => {
    event.preventDefault();
    callback(true);
  });

  app.on('ready', async () => {
    const cfg = loadConfig();

    // First launch or no URL saved — show setup prompt
    if (!cfg.url) {
      const url = await showSetupPrompt();
      if (!url) {
        app.quit();
        return;
      }
      cfg.url = url;
      saveConfig(cfg);
    }

    createWindow(cfg.url);
    createTray();
  });

  app.on('before-quit', () => {
    isQuitting = true;
  });

  app.on('activate', () => {
    if (!mainWindow) {
      const cfg = loadConfig();
      if (cfg.url) createWindow(cfg.url);
    }
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
      // Don't quit — tray keeps running
    }
  });
}
