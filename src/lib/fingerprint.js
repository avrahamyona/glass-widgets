// Pairing fingerprint: short, human-comparable, derived from a device pubkey. ONE canonical -
// the orchestrator shows it for approval and the PC shows the SAME string locally, so the user
// can compare what the sender asks to approve against the PC's own display.
const crypto=require('crypto');
module.exports.fingerprint=pubkey=>{
 const h=crypto.createHash('sha256').update(String(pubkey),'utf8').digest('hex');
 return h.slice(0,4)+'-'+h.slice(4,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16); // e.g. 3f9a-01bc-77d2-e540
};
module.exports.FINGERPRINT_RE=/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/;
