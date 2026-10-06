// Network throughput sampler. Windows: `netstat -e` (first row of two big numbers = bytes rx/tx). Linux: /proc/net/dev.
const {execFile}=require('child_process'),fs=require('fs');
function read(){return new Promise(res=>{
  if(process.platform==='win32')execFile('netstat',['-e'],{windowsHide:true},(e,o)=>{
    if(e)return res(null);const m=String(o).split(/\r?\n/).map(l=>l.match(/(\d{4,})\s+(\d{4,})\s*$/)).find(Boolean);
    res(m?{rx:+m[1],tx:+m[2]}:null)});
  else try{let rx=0,tx=0;for(const l of fs.readFileSync('/proc/net/dev','utf8').split('\n').slice(2)){const [n,v]=l.split(':');if(!v||n.trim()==='lo')continue;const f=v.trim().split(/\s+/);rx+=+f[0];tx+=+f[8]}res({rx,tx})}catch{res(null)}
})}
let last=null,cur={down:0,up:0};
setInterval(async()=>{const s=await read();if(!s)return;const t=Date.now();
  if(last){const dt=(t-last.t)/1000;cur={down:Math.max(0,(s.rx-last.rx)/dt),up:Math.max(0,(s.tx-last.tx)/dt)}}last={...s,t}},1000);
module.exports={get:()=>cur};
