(()=>{
 const q=new URLSearchParams(location.search);document.documentElement.dataset.size=q.get('size')||'square';
 const id=q.get('id')||location.pathname.split('/').slice(-2,-1)[0];
 document.documentElement.dataset.widget=id;
 if(['notes','calendar','reminders'].includes(id)){
  const b=document.createElement('button');b.className='cloud-link nd';b.title='פתח ב-Chrome · iCloud';b.setAttribute('aria-label','פתח ב-Chrome את '+id+' ב-iCloud');b.textContent='↗';b.onclick=()=>window.api?.cloudChrome(id);document.querySelector('.widget')?.append(b);
 }
 if(window.api&&api.theme){let lastTheme=document.documentElement.dataset.theme;
  setInterval(async()=>{try{const t=await api.theme();if(t&&t!=='system'&&t!==lastTheme){lastTheme=t;document.documentElement.dataset.theme=t}}catch{}},60000);
 }
})();
