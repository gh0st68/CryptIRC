const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  showNotification: (title, body) => ipcRenderer.send('show-notification', title, body),
});
