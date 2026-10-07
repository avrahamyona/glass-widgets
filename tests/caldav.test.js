const assert=require('node:assert/strict');
const {parseICS,discover}=require('../src/lib/caldav');
const out=parseICS('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:sample\r\nSUMMARY:Test\\, Hebrew\r\nDTSTART:20261007T100000Z\r\nDTEND:20261007T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR');
assert.equal(out.length,1);assert.equal(out[0].start.toISOString(),'2026-10-07T10:00:00.000Z');assert.equal(out[0].title,'Test, Hebrew');
global.fetch=async()=>new Response('',{status:302,headers:{location:'https://untrusted.invalid'}});
(async()=>{await assert.rejects(()=>discover('dummy','dummy'),/HTTP/);console.log('iCalendar and redirect guard PASS')})();
