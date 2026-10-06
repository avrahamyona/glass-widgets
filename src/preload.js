const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('api',{
  stats:()=>ipcRenderer.invoke('sys:stats'),
  notesGet:()=>ipcRenderer.invoke('notes:get'),
  notesSave:t=>ipcRenderer.invoke('notes:save',t),
  clipList:()=>ipcRenderer.invoke('clip:list'),
  clipCopy:t=>ipcRenderer.invoke('clip:copy',t),
  clipClear:()=>ipcRenderer.invoke('clip:clear'),
  onClip:cb=>ipcRenderer.on('clip:update',(_,l)=>cb(l)),
  config:()=>ipcRenderer.invoke('cfg:get')
});
