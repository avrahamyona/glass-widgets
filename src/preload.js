const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('api',{
  stats:()=>ipcRenderer.invoke('sys:stats'),
  notesGet:()=>ipcRenderer.invoke('notes:get'),
  notesSave:t=>ipcRenderer.invoke('notes:save',t),
  clipList:()=>ipcRenderer.invoke('clip:list'),
  clipCopy:t=>ipcRenderer.invoke('clip:copy',t),
  clipClear:()=>ipcRenderer.invoke('clip:clear'),
  onClip:cb=>ipcRenderer.on('clip:update',(_,l)=>cb(l)),
  net:()=>ipcRenderer.invoke('net:get'),
  calStatus:()=>ipcRenderer.invoke('cal:status'),calConnect:(u,p)=>ipcRenderer.invoke('cal:connect',u,p),calDisconnect:()=>ipcRenderer.invoke('cal:disconnect'),calEvents:()=>ipcRenderer.invoke('cal:events'),
  media:()=>ipcRenderer.invoke('media:get'),mediaCmd:c=>ipcRenderer.invoke('media:cmd',c),
  setGet:()=>ipcRenderer.invoke('set:get'),setToggle:(i,o)=>ipcRenderer.invoke('set:toggle',i,o),setSave:p=>ipcRenderer.invoke('set:save',p),
  geocode:async n=>{const r=await fetch('https://geocoding-api.open-meteo.com/v1/search?count=5&language=he&name='+encodeURIComponent(n));return (await r.json()).results||[]},
  bat:()=>ipcRenderer.invoke('bat:get'),
  config:()=>ipcRenderer.invoke('cfg:get')
});
