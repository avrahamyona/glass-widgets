const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('api',{
  cloudOpen:s=>ipcRenderer.invoke('cloud:open',s),cloudChrome:s=>ipcRenderer.invoke('cloud:chrome',s),cloudStatus:()=>ipcRenderer.invoke('cloud:status'),cloudLogout:()=>ipcRenderer.invoke('cloud:logout'),settingsOpen:()=>ipcRenderer.invoke('settings:open'),
  instanceAdd:(t,i)=>ipcRenderer.invoke('instance:add',t,i),instanceRemove:i=>ipcRenderer.invoke('instance:remove',i),instanceSave:(i,p)=>ipcRenderer.invoke('instance:save',i,p),instanceSelf:()=>ipcRenderer.invoke('instance:self'),instanceSelfSave:p=>ipcRenderer.invoke('instance:self-save',p),widgetsShow:()=>ipcRenderer.invoke('widgets:show'),icloudStatus:()=>ipcRenderer.invoke('icloud:status'),icloudLogin:(u,p)=>ipcRenderer.invoke('icloud:login',u,p),icloudRequestCode:()=>ipcRenderer.invoke('icloud:request-code'),icloudCode:(c,m)=>ipcRenderer.invoke('icloud:code',c,m),icloudRefresh:()=>ipcRenderer.invoke('icloud:refresh'),icloudData:()=>ipcRenderer.invoke('icloud:data'),icloudForget:()=>ipcRenderer.invoke('icloud:forget'),
  stats:()=>ipcRenderer.invoke('sys:stats'),beep:()=>ipcRenderer.invoke('sys:beep'),
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
  invSearch:q=>ipcRenderer.invoke('inv:search',q),invGet:()=>ipcRenderer.invoke('inv:get'),invCheck:s=>ipcRenderer.invoke('inv:check',s),
  bat:()=>ipcRenderer.invoke('bat:get'),
  config:()=>ipcRenderer.invoke('cfg:get'),
  theme:()=>ipcRenderer.invoke('theme:get'),invOpen:s=>ipcRenderer.invoke('inv:open',s),feedbackSend:t=>ipcRenderer.invoke('feedback:send',t),updateCheck:()=>ipcRenderer.invoke('update:check'),updateState:()=>ipcRenderer.invoke('update:state'),updateInstall:()=>ipcRenderer.invoke('update:install')
});
