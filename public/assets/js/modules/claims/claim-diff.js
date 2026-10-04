import { claimMap, remapClaimEntries } from './claims.js';
import { claimInfo, SET_LIKE_CLAIMS } from './claim-dictionary.js';

function stable(value) {
  if (Array.isArray(value)) return JSON.stringify(value.map(stable));
  if (value && typeof value === 'object') return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));
  return JSON.stringify(value);
}

function comparable(name, values) {
  if (!SET_LIKE_CLAIMS.has(name)) return values;
  return [...values].map((value) => String(value)).sort();
}

export function compareClaims(leftEntries, rightEntries, customMapping = {}) {
  const left = claimMap(remapClaimEntries(leftEntries, customMapping));
  const right = claimMap(remapClaimEntries(rightEntries, customMapping));
  const names = [...new Set([...left.keys(), ...right.keys()])].sort();
  return names.map((name) => {
    const l = left.get(name);
    const r = right.get(name);
    const info = claimInfo(name);
    if (l === undefined) return { name, title: info.title, status: 'added', left: null, right: r.normalised, leftNames: [], rightNames: [...r.names] };
    if (r === undefined) return { name, title: info.title, status: 'removed', left: l.normalised, right: null, leftNames: [...l.names], rightNames: [] };
    const leftComparable = comparable(name, l.normalised);
    const rightComparable = comparable(name, r.normalised);
    const same = stable(leftComparable) === stable(rightComparable);
    const renamed = same && stable([...l.names].sort()) !== stable([...r.names].sort());
    return {
      name,
      title: info.title,
      status: same ? (renamed ? 'mapped' : 'same') : 'changed',
      left: l.normalised,
      right: r.normalised,
      leftNames: [...l.names],
      rightNames: [...r.names],
    };
  });
}

const HIGH_IMPACT = new Set(['sub', 'aud', 'roles', 'groups', 'scope', 'email', 'preferred_username', 'oid', 'tid']);

export function buildMigrationReport(leftResult, rightResult, diff, customMapping = {}) {
  const counts = Object.fromEntries(['same', 'mapped', 'changed', 'added', 'removed'].map((status) => [status, diff.filter((item) => item.status === status).length]));
  const attention = diff.filter((item) => item.status !== 'same' && HIGH_IMPACT.has(item.name)).map((item) => ({
    claim: item.name,
    status: item.status,
    detail: `${item.title}: ${item.status}. Source names: ${item.leftNames.join(', ') || '(none)'}; target names: ${item.rightNames.join(', ') || '(none)'}.`,
  }));
  const mappingLines = Object.entries(customMapping).map(([from, to]) => `${from} -> ${to}`);
  const lines = [
    'IDENTITY TOOLKIT CLAIMS MIGRATION REPORT',
    '========================================',
    '',
    `Source: ${leftResult.detected?.label ?? leftResult.kind}`,
    `Target: ${rightResult.detected?.label ?? rightResult.kind}`,
    `Claims compared: ${diff.length}`,
    `Unchanged: ${counts.same}`,
    `Mapped/renamed: ${counts.mapped}`,
    `Changed: ${counts.changed}`,
    `Added: ${counts.added}`,
    `Removed: ${counts.removed}`,
    '',
    'HIGH-IMPACT DIFFERENCES',
    '-----------------------',
    ...(attention.length ? attention.map((item) => `- ${item.claim}: ${item.status}`) : ['- None detected by the built-in high-impact claim set.']),
    '',
    'CLAIM DIFFERENCES',
    '-----------------',
    ...diff.filter((item) => item.status !== 'same').map((item) => `- ${item.name}: ${item.status}\n  source=${JSON.stringify(item.left)}\n  target=${JSON.stringify(item.right)}\n  names=${item.leftNames.join(', ') || '(none)'} -> ${item.rightNames.join(', ') || '(none)'}`),
  ];
  if (mappingLines.length) lines.push('', 'CUSTOM CLAIM MAPPING', '--------------------', ...mappingLines.map((line) => `- ${line}`));
  lines.push('', 'Note: semantic equivalence is inferred from built-in aliases and the supplied mapping. Application authorisation behaviour must still be tested end-to-end.');
  return { counts, attention, text: lines.join('\n') };
}
