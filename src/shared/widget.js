(()=>{
 const q=new URLSearchParams(location.search);document.documentElement.dataset.size=q.get('size')||'square';
 const id=q.get('id')||location.pathname.split('/').slice(-2,-1)[0];
 document.documentElement.dataset.widget=id;
 if(['notes','calendar','reminders'].includes(id)){
  const b=document.createElement('button');b.className='cloud-link nd';b.title='פתח ב-iCloud בתוך האפליקציה';b.setAttribute('aria-label','פתח את '+id+' ב-iCloud בתוך האפליקציה');b.textContent='↗';b.onclick=()=>window.api?.cloudOpen(id);document.querySelector('.widget')?.append(b);
 }
 window.gwDragRefresh=()=>{const d=document.createElement('div');d.style.cssText='position:fixed;top:-2px;left:-2px;width:1px;height:1px;-webkit-app-region:no-drag;opacity:0;pointer-events:none';document.body.append(d);setTimeout(()=>d.remove(),50)};
 const applyTheme=t=>{document.documentElement.dataset.theme=!t||t==='system'?(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'):t};
 if(window.api&&api.theme){let lastTheme=document.documentElement.dataset.theme;
  setInterval(async()=>{try{const t=await api.theme();if(t&&t!=='system'&&t!==lastTheme){lastTheme=t;applyTheme(t)}}catch{}},60000);
  if(api.onTheme)api.onTheme(t=>{lastTheme=t;applyTheme(t)});
 }
})();
