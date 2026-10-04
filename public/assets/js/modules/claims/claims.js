import { canonicalClaimName, claimInfo, SET_LIKE_CLAIMS } from './claim-dictionary.js';

function normaliseValue(value) {
  if (Array.isArray(value)) return value.map((item) => normaliseValue(item));
  if (value && typeof value === 'object') return JSON.stringify(value, Object.keys(value).sort());
  return value;
}

function flatten(values) {
  return values.flatMap((value) => Array.isArray(value) ? flatten(value) : [value]);
}

export function normaliseClaimEntries(entries, source = 'unknown', customMapping = {}) {
  return entries.map((entry) => {
    const name = String(entry.name ?? entry.type ?? '');
    const info = claimInfo(name, customMapping);
    return {
      source,
      name,
      canonical: info.canonical,
      title: info.title,
      description: info.description,
      value: normaliseValue(entry.value),
      mapped: info.canonical !== name,
    };
  });
}

export function claimsFromJwt(claims, customMapping = {}) {
  return normaliseClaimEntries(Object.entries(claims ?? {}).map(([name, value]) => ({ name, value })), 'jwt', customMapping);
}

export function claimsFromSaml(attributes = [], customMapping = {}) {
  return claimsFromAttributes(attributes, 'saml', customMapping);
}

export function claimsFromWsFed(attributes = [], customMapping = {}) {
  return claimsFromAttributes(attributes, 'wsfed', customMapping);
}

function claimsFromAttributes(attributes = [], source = 'unknown', customMapping = {}) {
  return normaliseClaimEntries(attributes.map((attribute) => ({
    name: attribute.name,
    value: attribute.values?.length === 1 ? attribute.values[0] : attribute.values ?? [],
  })), source, customMapping);
}

export function remapClaimEntries(entries = [], customMapping = {}) {
  return entries.map((entry) => {
    const info = claimInfo(entry.name, customMapping);
    return { ...entry, canonical: info.canonical, title: info.title, description: info.description, mapped: info.canonical !== entry.name };
  });
}

export function claimMap(entries) {
  const map = new Map();
  for (const entry of entries) {
    const key = canonicalClaimName(entry.canonical ?? entry.name);
    const current = map.get(key) ?? { values: [], names: new Set(), entries: [] };
    current.values.push(entry.value);
    current.names.add(entry.name);
    current.entries.push(entry);
    map.set(key, current);
  }
  for (const [name, item] of map.entries()) {
    let values = flatten(item.values).filter((value) => value !== undefined);
    if (name === 'scope') {
      values = values.flatMap((value) => typeof value === 'string' ? value.trim().split(/\s+/).filter(Boolean) : [value]);
    }
    if (SET_LIKE_CLAIMS.has(name)) values = [...new Set(values.map((value) => String(value)))].sort();
    item.normalised = values;
  }
  return map;
}
