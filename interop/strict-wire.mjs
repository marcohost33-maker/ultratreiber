// Independent Node.js reference parser for UDX/0.1. No JSON Schema library dependency.
// Checks wire-level duplicate names, UTF-8, bounded size, strict numbers and nesting.
// NOT an authorization or OS identity component.
import { TextDecoder } from 'node:util';
const VERSION='udx/0.1', MAX_BYTES=4096, MAX_DEPTH=16, SAFE=9007199254740991;
const capRE=/^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$/;
const objRE=/^[a-z][a-z0-9-]{0,63}$/;
const ridRE=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
class Refusal extends Error { constructor(code){super(code); this.code=code;} }
function bad(code){throw new Refusal(code);}
function scan(wire) {
  let p=0;
  const ws=()=>{while(p<wire.length && /[\x20\t\r\n]/.test(wire[p]))p++;};
  function str(){
    const start=p;
    if(wire[p++]!=='"')bad('MALFORMED_JSON');
    while(p<wire.length){
      const x=wire[p++];
      if(x==='"'){
        const value=JSON.parse(wire.slice(start,p));
        // JS string iteration produces code units for lone surrogate;
        // valid surrogate pairs are decoded into scalar code points by for..of.
        for(const ch of value){const c=ch.codePointAt(0);if((c>=0xd800&&c<=0xdfff)||(c>=0xfdd0&&c<=0xfdef)||((c&0xffff)===0xfffe)||((c&0xffff)===0xffff))bad('MALFORMED_JSON');}
        return value;
      }
      if(x==='\\') {
        if(p>=wire.length)bad('MALFORMED_JSON');
        const escaped=wire[p++];
        if(escaped==='u'){for(let j=0;j<4;j++){
          if(p>=wire.length || !/[0-9a-fA-F]/.test(wire[p++]))bad('MALFORMED_JSON');
        }}else if(!'"\\/bfnrt'.includes(escaped))bad('MALFORMED_JSON');
      } else if(x.charCodeAt(0)<32)bad('MALFORMED_JSON');
    }
    bad('MALFORMED_JSON');
  }
  function value(depth){
    if(depth>MAX_DEPTH)bad('NESTING_LIMIT');
    ws();const c=wire[p];
    if(c==='"'){str();return;}
    if(c==='{'){
      p++;ws();const seen=new Set();if(wire[p]==='}'){p++;return;}
      while(true){ws();if(wire[p]!=='"')bad('MALFORMED_JSON');const key=str();
        if(seen.has(key))bad('DUPLICATE_JSON_KEY');seen.add(key);
        ws();if(wire[p++]!==':')bad('MALFORMED_JSON');value(depth+1);ws();
        const x=wire[p++];if(x==='}')return;if(x!==',')bad('MALFORMED_JSON');
      }
    }
    if(c==='['){p++;ws();if(wire[p]===']'){p++;return;}
      while(true){value(depth+1);ws();const x=wire[p++];if(x===']')return;if(x!==',')bad('MALFORMED_JSON');}
    }
    for(const tok of ['true','false','null'])if(wire.startsWith(tok,p)){p+=tok.length;return;}
    const rest=wire.slice(p);const m=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(rest);
    if(!m)bad('MALFORMED_JSON');p+=m[0].length;
    if(/[.eE]/.test(m[0]))bad('NON_INTEGER_JSON_NUMBER');
    if(!Number.isSafeInteger(Number(m[0])))bad('NON_INTEROPERABLE_JSON_NUMBER');
  }
  ws();value(0);ws();if(p!==wire.length)bad('MALFORMED_JSON');
}
export function decodeRequest(buffer){
  if(!Buffer.isBuffer(buffer))bad('INVALID_FRAME');
  if(buffer.length>MAX_BYTES)bad('FRAME_TOO_LARGE');
  let wire;
  try {wire=decoder.decode(buffer);}catch{bad('MALFORMED_JSON');}
  scan(wire);
  let obj;try{obj=JSON.parse(wire);}catch{bad('MALFORMED_JSON');}
  if(!obj || Array.isArray(obj) || typeof obj!=='object'
      || Object.keys(obj).length!==4 || !['version','request_id','capability','params'].every(k=>Object.hasOwn(obj,k)))bad('INVALID_ENVELOPE');
  if(obj.version!==VERSION)bad('UNSUPPORTED_VERSION');
  if(typeof obj.request_id!=='string'||!ridRE.test(obj.request_id))bad('INVALID_REQUEST_ID');
  // Python uuid.UUID() canonical normalization permits any hex UUID, including all-zero.
  if(typeof obj.capability!=='string'||obj.capability.length>72||!capRE.test(obj.capability))bad('INVALID_CAPABILITY');
  if(!obj.params || typeof obj.params!=='object' || Array.isArray(obj.params))bad('INVALID_PARAMS');
  return obj;
}
export function parseCode(buffer){try{decodeRequest(buffer);return 'OK';}catch(e){return e instanceof Refusal?e.code:'INTERNAL_ERROR';}}
