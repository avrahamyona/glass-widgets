// Reviewed durable store - the REAL module lives in src/lib/durable-store.js (packed with the app).
// This shim keeps the server-side path stable; both names resolve to ONE implementation.
module.exports=require('../../src/lib/durable-store.js');
