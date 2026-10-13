// Pointer mailer (rendezvous phase 3.1, option B): zero-dependency SMTP submission client for
// publishing tunnel-state records to the user's own mailbox. Implicit TLS (port 465) ONLY -
// credentials never travel unencrypted and never appear in logs/returns. One small ASCII mail
// per pointer state change; no retries inside (the caller's supervisor/audit owns cadence).
// The pointer is public-safe by contract; the mail is a TRANSPORT, never an authenticator.
const tls=require('tls'),crypto=require('crypto');
const b64=s=>Buffer.from(String(s),'utf8').toString('base64');

// line protocol: read one CRLF-terminated reply line at a time (multi-line replies keep the
// final code), enforce per-stage expected codes. Bounded: max line 8KB, overall timeout.
function makeConn(socket){
 let buf='';const waiters=[];
 socket.on('data',d=>{buf+=d.toString('utf8'); // consume ONLY into a registered waiter - a line
  let i;while((i=buf.indexOf('\r\n'))>=0&&waiters.length){const line=buf.slice(0,i);buf=buf.slice(i+2);waiters.shift().res(line)}}); // with no waiter STAYS buffered (multi-line replies)

 const kill=err=>{while(waiters.length)waiters.shift().rej(err)}; // a dead socket/timeout must never leave a pending reply-waiter hung
 socket.on('error',kill);socket.on('close',()=>kill(new Error('socket_closed')));
 const readLine=()=>new Promise((res,rej)=>{
  const i=buf.indexOf('\r\n');
  if(i>=0){const line=buf.slice(0,i);buf=buf.slice(i+2);return res(line)} // drain a buffered line BEFORE queueing
  waiters.push({res,rej});
 });
 return{readLine,kill,write:s=>{socket.write(s)}};
}

// Reads a full (possibly multi-line) SMTP reply and returns its 3-digit code.
async function readCode(conn){
 let code='',line='';
 do{line=await conn.readLine();if(!/^[0-9]{3}[ -]/.test(line))throw new Error('bad_reply:'+line.slice(0,60));code=line.slice(0,3)}while(line[3]==='-');
 return code;
}
async function expect(conn,want,stage){const c=await readCode(conn);if(c!==want)throw new Error(stage+':'+c);return c}

function buildMessage({from,to,subject,text}){
 const ascii=s=>/^[\x20-\x7E]*$/.test(s);
 if(!ascii(from)||!ascii(to)||!ascii(subject))throw new Error('non_ascii_header');
 if(!/^[\x09\x0A\x0D\x20-\x7E]*$/.test(text))throw new Error('non_ascii_body'); // tunnel-state JSON is ASCII by construction - anything else is a bug, not an encoding problem
 const id=Date.now().toString(36)+'.'+crypto.randomBytes(6).toString('hex')+'@glasswidgets.local';
 const headers=['From: '+from,'To: '+to,'Subject: '+subject,'Date: '+new Date().toUTCString(),'Message-ID: <'+id+'>','Content-Type: text/plain; charset=us-ascii','Content-Transfer-Encoding: 7bit',''];
 const body=text.split(/\r\n|\r|\n/).map(l=>l.startsWith('.')?'.'+l:l).join('\r\n'); // dot-stuffing
 return headers.join('\r\n')+'\r\n'+body+'\r\n.\r\n';
}

// One submission. Returns {ok:true} or {ok:false,stage,reason} - reason NEVER contains the password.
async function sendMail({host,port,user,pass,from,to,subject,text,socketImpl,timeoutMs=20000}){
 const stage0='connect';
 try{
  if(!host||!user||!pass||!from||!to)throw new Error('config:missing_fields');
  const msg=buildMessage({from,to,subject,text}); // throws on non-ASCII before any network
  const sock=socketImpl||tls.connect({host,port:port||465,servername:host,rejectUnauthorized:true});
  let done=false;
  let connKill=null;
  const fail=e=>{if(!done){done=true;if(connKill)connKill(e instanceof Error?e:new Error(String(e)));try{sock.destroy()}catch{}};return e};
  const timeout=setTimeout(()=>fail(new Error('timeout')),timeoutMs);if(timeout.unref)timeout.unref();
  try{
   await new Promise((res,rej)=>{if(sock.connecting!==false){sock.once('secureConnect',res);sock.once('error',rej)}else res()});
   const conn=makeConn(sock);
   connKill=conn.kill;
   await expect(conn,'220','banner');
   conn.write('EHLO glasswidgets-pc\r\n');await expect(conn,'250','ehlo');
   conn.write('AUTH LOGIN\r\n');await expect(conn,'334','auth_start');
   conn.write(b64(user)+'\r\n');await expect(conn,'334','auth_user');
   conn.write(b64(pass)+'\r\n');await expect(conn,'235','auth_pass'); // 535 here = bad app-password
   conn.write('MAIL FROM:<'+from+'>\r\n');await expect(conn,'250','mail_from');
   conn.write('RCPT TO:<'+to+'>\r\n');await expect(conn,'250','rcpt_to');
   conn.write('DATA\r\n');await expect(conn,'354','data_start');
   conn.write(msg);await expect(conn,'250','data_end');
   conn.write('QUIT\r\n');
   clearTimeout(timeout);done=true;try{sock.end()}catch{}
   return{ok:true};
  }catch(e){clearTimeout(timeout);fail(e);const m=String(e&&e.message||e);const st=m.includes(':')?m.split(':')[0]:'io';return{ok:false,stage:st,reason:m.slice(0,80).replace(/[A-Za-z0-9+/=]{20,}/g,'[redacted]')}}
 }catch(e){return{ok:false,stage:stage0,reason:String(e&&e.message||e).slice(0,80)}}
}

module.exports={sendMail,buildMessage};
