// Decodes the unencrypted Apple proximity-pairing BLE advert (message type 0x07)
// that AirPods broadcast. Layout per public community documentation.
// data = manufacturer data bytes AFTER Apple's company id (0x004C).
const MODELS={'2':'AirPods','f':'AirPods','3':'AirPods','e':'AirPods Pro','4':'AirPods Pro','a':'AirPods Max'};
const pct=n=>n>10?null:n*10;
function parseAirPods(data){
  if(!data||data.length<27||data[0]!==0x07)return null;
  const h=Buffer.from(data).toString('hex');
  const nib=i=>parseInt(h[i],16);
  const flipped=(nib(10)&2)===0;
  const l=pct(nib(flipped?12:13)),r=pct(nib(flipped?13:12)),c=pct(nib(15));
  const ch=nib(14);
  return {model:MODELS[h[7]]||'AirPods',left:l,right:r,case:c,
    leftCharging:!!(ch&(flipped?2:1)),rightCharging:!!(ch&(flipped?1:2)),caseCharging:!!(ch&4)};
}
module.exports={parseAirPods};
