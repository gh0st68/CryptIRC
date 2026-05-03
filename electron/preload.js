const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  showNotification: (title, body, meta) => ipcRenderer.send('show-notification', title, body, meta),
  onNotificationClick: (cb) => ipcRenderer.on('notification-click', (e, meta) => cb(meta)),
});
