// Minimal CalDAV client for iCloud (caldav.icloud.com). Needs Apple ID + app-specific password.
const BASE='https://caldav.icloud.com';
const auth=(u,p)=>'Basic '+Buffer.from(u+':'+p).toString('base64');
async function dav(url,method,body,u,p,depth='0'){
  const r=await fetch(url,{method,headers:{Authorization:auth(u,p),Depth:depth,'Content-Type':'application/xml; charset=utf-8'},body,redirect:'follow'});
  if(r.status===401)throw new Error('AUTH');
  if(r.status>=400)throw new Error('HTTP '+r.status);
  return {text:await r.text(),url:r.url};
}
const hrefs=(xml,tag)=>[...xml.matchAll(new RegExp('<(?:\\w+:)?'+tag+'[^>]*>\\s*<(?:\\w+:)?href[^>]*>([^<]+)<','g'))].map(m=>m[1]);
const abs=(h,from)=>new URL(h,from).toString();
async function discover(u,p){
  let r=await dav(BASE+'/.well-known/caldav','PROPFIND','<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>',u,p);
  const pr=abs(hrefs(r.text,'current-user-principal')[0],r.url);
  r=await dav(pr,'PROPFIND','<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/></d:prop></d:propfind>',u,p);
  const home=abs(hrefs(r.text,'calendar-home-set')[0],pr);
  r=await dav(home,'PROPFIND','<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:resourcetype/><d:displayname/><c:supported-calendar-component-set/></d:prop></d:propfind>',u,p,'1');
  const cals=[];
  for(const m of r.text.matchAll(/<(?:\w+:)?response>([\s\S]*?)<\/(?:\w+:)?response>/g)){
    const b=m[1];if(!/calendar\s*\/>|:calendar\/>|<calendar/.test(b)&&!/resourcetype>[\s\S]*calendar/.test(b))continue;
    if(!/VEVENT/.test(b))continue;
    cals.push(abs(b.match(/<(?:\w+:)?href[^>]*>([^<]+)</)[1],home));
  }
  return cals;
}
const fmt=d=>d.toISOString().replace(/[-:]/g,'').replace(/\.\d+/,'');
async function fetchEvents(u,p,from,to){
  const cals=await discover(u,p);const out=[];
  const body=`<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data><c:expand start="${fmt(from)}" end="${fmt(to)}"/></c:calendar-data></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="${fmt(from)}" end="${fmt(to)}"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>`;
  for(const c of cals){
    try{const r=await dav(c,'REPORT',body,u,p,'1');
      for(const m of r.text.matchAll(/<(?:\w+:)?calendar-data[^>]*>([\s\S]*?)<\/(?:\w+:)?calendar-data>/g))out.push(...parseICS(decode(m[1])));}catch(e){if(e.message==='AUTH')throw e}
  }
  return out.sort((a,b)=>a.start-b.start);
}
const decode=s=>s.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&amp;/g,'&').replace(/&#13;/g,'');
function parseDate(v,params){
  if(/VALUE=DATE(?!-)/.test(params)||/^\d{8}$/.test(v)){return {d:new Date(+v.slice(0,4),+v.slice(4,6)-1,+v.slice(6,8)),allDay:true}}
  const m=v.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)/);if(!m)return null;
  const a=m.slice(1,7).map(Number);
  return {d:m[7]?new Date(Date.UTC(a[0],a[1]-1,a[2],a[3],a[4],a[5])):new Date(a[0],a[1]-1,a[2],a[3],a[4],a[5]),allDay:false};
}
function parseICS(ics){
  const lines=ics.replace(/\r?\n[ \t]/g,'').split(/\r?\n/);const evs=[];let cur=null;
  for(const l of lines){
    if(l==='BEGIN:VEVENT')cur={};else if(l==='END:VEVENT'){if(cur&&cur.start)evs.push(cur);cur=null}
    else if(cur){const i=l.indexOf(':');if(i<0)continue;const [k,...ps]=l.slice(0,i).split(';');const v=l.slice(i+1);const params=ps.join(';');
      if(k==='SUMMARY')cur.title=v.replace(/\\,/g,',').replace(/\\n/g,' ').replace(/\\;/g,';');
      else if(k==='DTSTART'){const x=parseDate(v,params);if(x){cur.start=x.d;cur.allDay=x.allDay}}
      else if(k==='DTEND'){const x=parseDate(v,params);if(x)cur.end=x.d}
      else if(k==='LOCATION')cur.location=v}
  }
  return evs;
}
module.exports={fetchEvents,parseICS};
