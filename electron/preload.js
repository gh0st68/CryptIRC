const { contextBridge, ipcRenderer } = require('electron');

// Minimal, audited bridge. No Node primitives are exposed to page content.
contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,

  // Native notifications (web frontend → main)
  showNotification: (title, body, meta) => ipcRenderer.send('show-notification', title, body, meta),
  onNotificationClick: (cb) => ipcRenderer.on('notification-click', (e, meta) => cb(meta)),

  // Taskbar/dock unread badge — frontend can call window.electronAPI.setUnread(n)
  setUnread: (n) => ipcRenderer.send('set-unread', n),

  // Trusted local chrome (setup + connection-error pages) — these channels are
  // only ever wired by our own local data: pages loaded with this preload.
  setupSubmit: (url) => ipcRenderer.send('setup-url', url),
  setupQuit: () => ipcRenderer.send('setup-quit'),
  retryLoad: () => ipcRenderer.send('retry-load'),
  changeServer: () => ipcRenderer.send('change-server'),
});
