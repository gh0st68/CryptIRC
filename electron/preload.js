const { contextBridge, ipcRenderer } = require('electron');

// Minimal, audited bridge. No Node primitives are exposed to page content.
const api = {
  isElectron: true,

  // Native notifications (web frontend → main)
  showNotification: (title, body, meta) => ipcRenderer.send('show-notification', title, body, meta),
  // Replace any prior handler so repeated registration (e.g. on reconnect) can't
  // stack ipcRenderer listeners over a long session.
  onNotificationClick: (cb) => {
    ipcRenderer.removeAllListeners('notification-click');
    ipcRenderer.on('notification-click', (e, meta) => cb(meta));
  },

  // Taskbar/dock unread badge — frontend can call window.electronAPI.setUnread(n)
  setUnread: (n) => ipcRenderer.send('set-unread', n),
};

// Trusted local chrome (setup + connection-error pages). These are our own
// data: pages; the remote server's page shares this preload (the error page is
// loaded into the main window) but must not get them, so they are only exposed
// when the page itself is a data: URL. The main process ALSO checks the sending
// frame on every one of these messages — this just keeps them off the remote
// page's bridge entirely.
let isLocalPage = false;
try { isLocalPage = window.location.protocol === 'data:'; } catch {}
if (isLocalPage) {
  api.setupSubmit = (url) => ipcRenderer.send('setup-url', url);
  api.setupQuit = () => ipcRenderer.send('setup-quit');
  api.retryLoad = () => ipcRenderer.send('retry-load');
  api.changeServer = () => ipcRenderer.send('change-server');
  api.retrustCert = () => ipcRenderer.send('retrust-cert');
}

contextBridge.exposeInMainWorld('electronAPI', api);
