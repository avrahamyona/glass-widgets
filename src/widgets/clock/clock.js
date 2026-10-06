(function(){
  const NS='http://www.w3.org/2000/svg';
  window.buildClock=function(svg){
    svg.setAttribute('viewBox','-100 -100 200 200');
    const e=(n,a,p=svg)=>{const x=document.createElementNS(NS,n);for(const k in a)x.setAttribute(k,a[k]);p.appendChild(x);return x};
    const dial=e('circle',{r:96,fill:'var(--dial)'});
    e('circle',{r:96,fill:'none',stroke:'rgba(128,128,128,.25)','stroke-width':1});
    for(let i=0;i<60;i++){
      const big=i%5===0,a=i*6*Math.PI/180,r1=big?80:88,r2=92;
      e('line',{x1:Math.sin(a)*r1,y1:-Math.cos(a)*r1,x2:Math.sin(a)*r2,y2:-Math.cos(a)*r2,stroke:'var(--tick)','stroke-width':big?2.6:1,'stroke-linecap':'round',opacity:big?1:.45});
    }
    for(let h=1;h<=12;h++){const a=h*30*Math.PI/180;
      const t=e('text',{x:Math.sin(a)*66,y:-Math.cos(a)*66+8,'text-anchor':'middle','font-size':23,'font-weight':500,fill:'var(--tick)','font-family':'var(--font)'});t.textContent=h;}
    const hh=e('line',{y2:-50,stroke:'var(--tick)','stroke-width':6,'stroke-linecap':'round'});
    const mm=e('line',{y2:-76,stroke:'var(--tick)','stroke-width':4.5,'stroke-linecap':'round'});
    const ss=e('g',{});e('line',{y1:16,y2:-84,stroke:'var(--accent)','stroke-width':1.8,'stroke-linecap':'round'},ss);
    e('circle',{r:5,fill:'var(--accent)'});e('circle',{r:1.8,fill:'var(--dial)'});
    return function set(d,night){
      if(night!==undefined){dial.setAttribute('fill',night?'#3a3a3c':'#fff');svg.style.setProperty('--tick',night?'#fff':'#000');}
      const s=d.getSeconds()+d.getMilliseconds()/1000,m=d.getMinutes()+s/60,h=(d.getHours()%12)+m/60;
      hh.setAttribute('transform',`rotate(${h*30})`);mm.setAttribute('transform',`rotate(${m*6})`);ss.setAttribute('transform',`rotate(${s*6})`);
    };
  };
})();
