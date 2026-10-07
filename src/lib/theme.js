// Time-based theme: dark after sunset, light after sunrise, computed locally (NOAA solar approximation).
// 'auto' = follow the sun at the configured city; 'system' = follow Windows; 'light'/'dark' = manual override.
function sunTimes(date,lat,lon){
  const rad=Math.PI/180;
  const start=new Date(Date.UTC(date.getFullYear(),0,0));
  const N=Math.floor((Date.UTC(date.getFullYear(),date.getMonth(),date.getDate())-start)/864e5);
  const gamma=2*Math.PI/365*(N-1+0.5);
  const eqtime=229.18*(0.000075+0.001868*Math.cos(gamma)-0.032077*Math.sin(gamma)-0.014615*Math.cos(2*gamma)-0.040849*Math.sin(2*gamma));
  const decl=0.006918-0.399912*Math.cos(gamma)+0.070257*Math.sin(gamma)-0.006758*Math.cos(2*gamma)+0.000907*Math.sin(2*gamma)-0.002697*Math.cos(3*gamma)+0.00148*Math.sin(3*gamma);
  const cosH=(Math.cos(90.833*rad)-Math.sin(lat*rad)*Math.sin(decl))/(Math.cos(lat*rad)*Math.cos(decl));
  if(cosH>1||cosH<-1)return null; // polar day/night: caller falls back to fixed hours
  const ha=Math.acos(cosH)/rad*4; // minutes
  const noonUTC=720-4*lon-eqtime;
  const tz=-date.getTimezoneOffset(); // local offset in minutes (handles DST automatically)
  return {sunrise:noonUTC-ha+tz,sunset:noonUTC+ha+tz};
}
function effectiveTheme(setting,date,lat,lon){
  if(setting==='light'||setting==='dark')return setting;
  if(setting==='system')return 'system';
  const mins=date.getHours()*60+date.getMinutes();
  const sun=Number.isFinite(lat)&&Number.isFinite(lon)?sunTimes(date,lat,lon):null;
  const rise=sun?sun.sunrise:7*60,set=sun?sun.sunset:19*60;
  return (mins>=rise&&mins<set)?'light':'dark';
}
module.exports={sunTimes,effectiveTheme};
