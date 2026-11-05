import { readFileSync } from 'node:fs';
const file = process.argv[2];
const t = readFileSync(file, 'utf8');
const start = t.indexOf('{\n    "root_label"') >= 0 ? t.indexOf('{\n    "root_label"') : t.indexOf('{\r\n    "root_label"');
const j = JSON.parse(t.slice(start >= 0 ? start : t.indexOf('{')));
for (const [k, v] of Object.entries(j.checks) as Array<[string, { exposed: boolean }]>) {
  console.log((v.exposed ? 'EXPOSED ' : 'safe    ') + k + '  ' + JSON.stringify(v));
}
console.log(`exposed ${j.exposed_count}/${j.total}`);
