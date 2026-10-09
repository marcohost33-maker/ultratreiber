import {readFileSync} from 'node:fs';
import {parseCode} from './strict-wire.mjs';
const cases=JSON.parse(readFileSync(process.argv[2],'utf8'));
const results=cases.map(({id,raw,raw_b64})=>({id,parse:parseCode(
    raw_b64===undefined ? Buffer.from(raw,'utf8') : Buffer.from(raw_b64,'base64'))}));
process.stdout.write(JSON.stringify(results));
