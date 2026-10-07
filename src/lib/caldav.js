// Original read-only CalDAV client. XML and iCalendar use standard parsers.
const {XMLParser}=require('fast-xml-parser');
const ICAL=require('ical.js');
const parser=new XMLParser({removeNSPrefix:true,ignoreAttributes:false,attributeNamePrefix:'@',parseTagValue:false,trimValues:true});
const arr=x=>x==null?[]:Array.isArray(x)?x:[x];
const props=r=>Object.assign({},...arr(r.propstat).filter(x=>!x.status||/ 200 /.test(x.status)).map(x=>x.prop||{}));
const auth=(u,p)=>'Basic '+Buffer.from(u+':'+p).toString('base64');
class DavError extends Error{constructor(kind,step,status,detail){super(kind);Object.assign(this,{kind,step,status,detail})}}
function trusted(url){const u=new URL(url);if(u.protocol!=='https:'||!/(^|\.)icloud\.com$/.test(u.hostname))throw new DavError('HTTP','redirect',0,'untrusted server');return u.toString()}
async function dav(url,method,body,u,p,depth='0',step='request'){
 let cur=trusted(url);
 for(let hop=0;hop<6;hop++){
  let r;try{r=await fetch(cur,{method,headers:{Authorization:auth(u,p),Depth:depth,'Content-Type':'application/xml; charset=utf-8',Accept:'application/xml'},body,redirect:'manual',signal:AbortSignal.timeout(20000)})}catch(e){throw new DavError('NET',step,0,e.cause?.code||e.message)}
  if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get('location');if(!loc)throw new DavError('HTTP',step,r.status,'redirect without location');cur=trusted(new URL(loc,cur).toString());continue}
  const text=await r.text();if([401,403].includes(r.status))throw new DavError('AUTH',step,r.status,new URL(cur).host);
  if(r.status>=400)throw new DavError('HTTP',step,r.status,new URL(cur).host);
  let xml;try{xml=parser.parse(text)}catch{throw new DavError('PARSE',step,r.status,'invalid XML')}
  const responses=arr(xml.multistatus?.response);return {responses,url:cur,status:r.status};
 }throw new DavError('HTTP',step,0,'too many redirects');
}
const href=(x)=>typeof x==='string'?x:x?.href;
async function discover(u,p){
 const root='https://caldav.icloud.com/';
 const principalBody='<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>';
 let r=await dav(root,'PROPFIND',principalBody,u,p,'0','principal');
 let h=href(props(r.responses[0]||{})['current-user-principal']);if(!h)throw new DavError('PARSE','principal',r.status,'principal missing');
 const pr=trusted(new URL(h,r.url).toString());
 r=await dav(pr,'PROPFIND','<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/></d:prop></d:propfind>',u,p,'0','home');
 h=href(props(r.responses[0]||{})['calendar-home-set']);if(!h)throw new DavError('PARSE','home',r.status,'calendar home missing');
 const home=trusted(new URL(h,r.url).toString());
 r=await dav(home,'PROPFIND','<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:resourcetype/><d:displayname/><c:supported-calendar-component-set/></d:prop></d:propfind>',u,p,'1','calendars');
 return r.responses.flatMap(x=>{const prop=props(x),comps=arr(prop['supported-calendar-component-set']?.comp);if(!prop.resourcetype||!Object.hasOwn(prop.resourcetype,'calendar')||!comps.some(c=>c['@name']==='VEVENT'))return [];return [{url:trusted(new URL(href(x),home).toString()),name:prop.displayname||''}]});
}
const fmt=d=>d.toISOString().replace(/[-:]/g,'').replace(/\.\d+/,'');
function parseICS(text){
 const root=new ICAL.Component(ICAL.parse(text));
 for(const zone of root.getAllSubcomponents('vtimezone')){const id=zone.getFirstPropertyValue('tzid');if(id)ICAL.TimezoneService.register(id,new ICAL.Timezone({component:zone,tzid:id}))}
 return root.getAllSubcomponents('vevent').flatMap(comp=>{try{const e=new ICAL.Event(comp);if(e.component.getFirstPropertyValue('status')==='CANCELLED')return [];return [{title:e.summary||'',start:e.startDate.toJSDate(),end:e.endDate.toJSDate(),allDay:e.startDate.isDate,location:e.location||'',uid:e.uid}]}catch{return []}});
}
async function fetchEvents(u,p,from,to){
 u=String(u).trim();p=String(p).replace(/\s+/g,'');const cals=await discover(u,p);const out=[];
 const body=`<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data><c:expand start="${fmt(from)}" end="${fmt(to)}"/></c:calendar-data></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="${fmt(from)}" end="${fmt(to)}"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>`;
 for(const c of cals){const r=await dav(c.url,'REPORT',body,u,p,'1','events');for(const x of r.responses){const data=props(x)['calendar-data'];if(typeof data==='string')out.push(...parseICS(data).map(e=>({...e,calendar:c.name})))}}
 return out.sort((a,b)=>a.start-b.start);
}
const explain=e=>e?.kind?({AUTH:'Apple דחתה את ההתחברות. נדרשת סיסמה ייעודית לאפליקציה, לא הסיסמה הרגילה',NET:'אין חיבור לשרת של Apple',HTTP:'שגיאת שרת iCloud',PARSE:'תשובה לא צפויה מ-iCloud'}[e.kind]||e.message)+' [שלב '+e.step+(e.status?', קוד '+e.status:'')+'] '+(e.detail||''):e?.message||String(e);
module.exports={fetchEvents,parseICS,explain,discover};
