// server-ui-ops-unit: stage-3 screenshot + ui_automation ops with a stubbed psRun.
// Validates op semantics (root policy, validation, generated script shape, result
// wiring) against the REAL implementation in server/lib/ops.js, without a Windows
// host. Generated scripts are parser-validated (pwsh ParseFile, errors: 0).
const assert=require('assert');
const fs=require('fs');const os=require('os');const path=require('path');const crypto=require('crypto');
const ops=require('../server/lib/ops.js');

(async()=>{
 const fold=fs.mkdtempSync(path.join(os.tmpdir(),'gwui-'));
 fs.writeFileSync(path.join(fold,'Login Data'),'deny');
 const ctx={roots:[fold],deny:[],rootsName:'test',workDir:fold,deviceId:'d1'};

 // screenshot: stub writes the image where the generated script was told to save it
 let capScript='';
 ops.__setPsRunForTests((script)=>{capScript=script;
  const om=script.match(/\$bmp\.Save\('([^']+)'/);
  assert(om,'screenshot script carries an output path');
  fs.writeFileSync(om[1],Buffer.from([0xff,0xd8,0xff,0x01,0x02])); // fake JPEG magic
  return{ok:true,stdout:'SHOT 1920x1080'};
 });
 const s=await ops.OPS.screenshot({quality:60,scale:0.5},ctx);
 assert(s.ok===true,'screenshot ok: '+JSON.stringify(s));
 assert(s.result&&s.result.path.startsWith(fold),'shot path under workDir roots: '+JSON.stringify(s.result));
 assert(s.result.bytes===5,'shot bytes');
 assert(s.result.screenWidth===1920&&s.result.screenHeight===1080,'shot dims');
 assert(s.result.quality===60&&s.result.scale===0.5,'shot params echoed');
 assert(s.result.sha256===crypto.createHash('sha256').update(fs.readFileSync(s.result.path)).digest('hex'),'shot sha256 matches bytes');
 assert(capScript.includes('[long]60')&&capScript.includes('*0.5'),'quality+scale embedded in script');

 // screenshot with a workDir outside the configured roots fails closed
 const s2=await ops.OPS.screenshot({},{roots:[fold],deny:[],workDir:os.tmpdir(),deviceId:'d1'});
 assert(s2.ok===false&&s2.error==='outside_roots','screenshot workDir outside roots refused: '+JSON.stringify(s2));
 const s3=await ops.OPS.screenshot({scale:5},ctx);
 assert(s3.ok===false&&s3.error==='bad_scale','scale out of range refused');

 // ui_automation validation
 const bad=await ops.OPS.ui_automation({action:'click'},ctx);
 assert(bad.ok===false&&bad.error==='bad_coords','click without coords refused');
 const badAct=await ops.OPS.ui_automation({action:'format_c_drive'},ctx);
 assert(badAct.ok===false&&badAct.error==='bad_action','unknown action refused');
 const neg=await ops.OPS.ui_automation({action:'click',x:-5,y:10},ctx);
 assert(neg.ok===false&&neg.error==='bad_coords','negative coords refused');
 const noText=await ops.OPS.ui_automation({action:'type',text:''},ctx);
 assert(noText.ok===false&&noText.error==='bad_text','empty type refused');
 const badKey=await ops.OPS.ui_automation({action:'key',key:'f13'},ctx);
 assert(badKey.ok===false&&badKey.error==='bad_key','unknown key refused');

 let uiScript='';
 ops.__setPsRunForTests((script)=>{uiScript=script;return{ok:true,stdout:'POS 7,9'}});

 const c=await ops.OPS.ui_automation({action:'click',x:100,y:200,button:'right'},ctx);
 assert(c.ok===true,'click ok');
 assert(uiScript.includes('[GWUI]::SetCursorPos(100,200)|Out-Null'),'click moves cursor to coords');
 assert((uiScript.match(/\[GWUI\]::mouse_event\(8,0,0,0/g)||[]).length===1,'right-down event');
 assert((uiScript.match(/\[GWUI\]::mouse_event\(16,0,0,0/g)||[]).length===1,'right-up event');

 const t=await ops.OPS.ui_automation({action:'type',text:"a'b\\c"},ctx);
 assert(t.ok===true&&t.result.action==='type','type ok');
 assert(uiScript.includes("TypeText('a''b\\c')"),"text single-quote escaped for PS: "+uiScript.split('\n').find(l=>l.includes('TypeText')));

 const k=await ops.OPS.ui_automation({action:'key',key:'enter',modifiers:['ctrl','alt']},ctx);
 assert(k.ok===true&&k.result.action==='key','key ok');
 const keyCalls=(uiScript.match(/\[GWUI\]::Key\(/g)||[]).length;
 assert(keyCalls===6,'down+up for 2 modifiers + key: '+keyCalls);
 assert(uiScript.indexOf('Key(17,$true)')<uiScript.indexOf('Key(13,$true)')&&uiScript.indexOf('Key(13,$false)')<uiScript.indexOf('Key(17,$false)'),'modifier wraps the key press');

 const p2=await ops.OPS.ui_automation({action:'position'},ctx);
 assert(p2.ok===true&&p2.result.pos.x===7&&p2.result.pos.y===9,'position parsed from POS line: '+JSON.stringify(p2));

 const m2=await ops.OPS.ui_automation({action:'move',x:1,y:2},ctx);
 assert(m2.ok===true&&uiScript.includes('[GWUI]::SetCursorPos(1,2)')&&!uiScript.includes('[GWUI]::mouse_event('),'move only repositions');

 ops.__setPsRunForTests(null);
 console.log('SERVER-UI-OPS-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e.message);process.exit(1)});
