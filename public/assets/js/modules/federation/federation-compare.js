function pickComparable(result) {
  if (!result) return {};
  if (result.kind === 'oidc-discovery') return {
    issuer: result.summary.issuer,
    authorizationEndpoint: result.summary.authorizationEndpoint,
    tokenEndpoint: result.summary.tokenEndpoint,
    jwksUri: result.summary.jwksUri,
    userinfoEndpoint: result.summary.userinfoEndpoint,
    endSessionEndpoint: result.summary.endSessionEndpoint,
    responseTypes: result.capabilities?.responseTypes ?? result.summary.responseTypes ?? [],
    grantTypes: result.capabilities?.grantTypes ?? result.summary.grantTypes ?? [],
    scopes: result.capabilities?.scopes ?? result.summary.scopes ?? [],
    subjectTypes: result.capabilities?.subjectTypes ?? result.summary.subjectTypes ?? [],
    idTokenAlgorithms: result.capabilities?.idTokenAlgorithms ?? result.summary.idTokenAlgorithms ?? [],
    codeChallengeMethods: result.capabilities?.codeChallengeMethods ?? result.summary.codeChallengeMethods ?? [],
    tokenEndpointAuthMethods: result.capabilities?.tokenEndpointAuthMethods ?? [],
  };
  if (result.kind === 'saml-metadata') {
    const first = result.entities?.[0] ?? {};
    return {
      entityId: first.entityId ?? '',
      roles: first.roles ?? [],
      ssoServices: first.ssoServices ?? [],
      sloServices: first.sloServices ?? [],
      acsServices: first.acsServices ?? [],
      nameIdFormats: first.nameIdFormats ?? [],
      wantAuthnRequestsSigned: first.wantAuthnRequestsSigned,
      authnRequestsSigned: first.authnRequestsSigned,
      wantAssertionsSigned: first.wantAssertionsSigned,
      requestedAttributes: first.requestedAttributes ?? [],
      signingKeyCount: (first.keys ?? []).filter((key) => key.use === 'signing' || key.use === 'unspecified').reduce((count, key) => count + key.certificates.length, 0),
    };
  }
  if (result.kind === 'jwks') return { keyCount: result.summary.keyCount, kids: result.summary.keys.map((key) => key.kid).filter(Boolean), algorithms: result.summary.keys.map((key) => key.alg).filter(Boolean), keyTypes: result.summary.keys.map((key) => key.kty).filter(Boolean) };
  if (result.kind === 'openid-federation') return result.summary;
  return result.summary ?? {};
}

function stable(value) {
  if (Array.isArray(value)) return JSON.stringify(value.map(stable).sort());
  if (value && typeof value === 'object') return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));
  return JSON.stringify(value);
}

function setDelta(left = [], right = []) {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return {
    retained: [...leftSet].filter((value) => rightSet.has(value)),
    added: [...rightSet].filter((value) => !leftSet.has(value)),
    removed: [...leftSet].filter((value) => !rightSet.has(value)),
  };
}

async function shortSha256(text) {
  const bytes = new TextEncoder().encode(String(text));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...digest.slice(0, 8)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function samlSigningIdentifiers(result) {
  const entity = result?.entities?.[0];
  if (!entity) return [];
  const certs = (entity.keys ?? []).filter((key) => key.use === 'signing' || key.use === 'unspecified').flatMap((key) => key.certificates ?? []);
  return Promise.all(certs.map(async (cert) => `sha256:${await shortSha256(cert.replace(/\s+/g, ''))}`));
}

function jwksSigningIdentifiers(result) {
  return (result?.summary?.keys ?? []).filter((key) => !key.use || key.use === 'sig').map((key) => key.kid || `${key.kty}:${key.alg}:${key.index}`);
}

async function keyRotation(leftResult, rightResult) {
  let left = [];
  let right = [];
  let basis = '';
  if (leftResult.kind === 'jwks' && rightResult.kind === 'jwks') {
    left = jwksSigningIdentifiers(leftResult);
    right = jwksSigningIdentifiers(rightResult);
    basis = 'JWKS signing key IDs';
  } else if (leftResult.kind === 'saml-metadata' && rightResult.kind === 'saml-metadata') {
    left = await samlSigningIdentifiers(leftResult);
    right = await samlSigningIdentifiers(rightResult);
    basis = 'SAML signing certificate SHA-256 prefixes';
  } else if (leftResult.kind === 'openid-federation' && rightResult.kind === 'openid-federation') {
    const leftKeys = leftResult.parsed?.claims?.jwks?.keys ?? [];
    const rightKeys = rightResult.parsed?.claims?.jwks?.keys ?? [];
    left = leftKeys.map((key, index) => key.kid || `${key.kty}:${key.alg}:${index}`);
    right = rightKeys.map((key, index) => key.kid || `${key.kty}:${key.alg}:${index}`);
    basis = 'Federation Entity signing key IDs';
  } else {
    return null;
  }
  const delta = setDelta(left, right);
  return {
    basis,
    ...delta,
    classification: !delta.added.length && !delta.removed.length ? 'unchanged'
      : delta.added.length && delta.retained.length && !delta.removed.length ? 'overlap-addition'
        : delta.added.length && delta.retained.length && delta.removed.length ? 'overlap-rotation'
          : delta.added.length && !delta.retained.length && delta.removed.length ? 'hard-cutover'
            : delta.removed.length && !delta.added.length ? 'key-removal'
              : 'changed',
  };
}

function issuerMigration(leftResult, rightResult) {
  const left = leftResult.kind === 'saml-metadata' ? leftResult.entities?.[0]?.entityId : leftResult.summary?.issuer ?? leftResult.summary?.entityId;
  const right = rightResult.kind === 'saml-metadata' ? rightResult.entities?.[0]?.entityId : rightResult.summary?.issuer ?? rightResult.summary?.entityId;
  if (!left || !right || left === right) return null;
  let sameHost = false;
  try { sameHost = new URL(left).host === new URL(right).host; } catch { /* not both URLs */ }
  return { from: left, to: right, sameHost, classification: sameHost ? 'identifier-path-change' : 'issuer-host-change' };
}

export async function compareFederation(leftResult, rightResult) {
  const left = pickComparable(leftResult);
  const right = pickComparable(rightResult);
  const names = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort();
  const rows = names.map((name) => ({
    name,
    left: left[name] ?? null,
    right: right[name] ?? null,
    status: left[name] === undefined ? 'added' : right[name] === undefined ? 'removed' : stable(left[name]) === stable(right[name]) ? 'same' : 'changed',
  }));
  return {
    rows,
    keyRotation: await keyRotation(leftResult, rightResult),
    issuerMigration: issuerMigration(leftResult, rightResult),
    changedFields: rows.filter((row) => row.status !== 'same').map((row) => row.name),
  };
}

export function buildFederationMigrationReport(leftResult, rightResult, comparison) {
  const lines = [
    'IDENTITY TOOLKIT FEDERATION MIGRATION REPORT',
    '============================================',
    '',
    `Source type: ${leftResult.detected?.label ?? leftResult.kind}`,
    `Target type: ${rightResult.detected?.label ?? rightResult.kind}`,
    `Changed fields: ${comparison.changedFields.length ? comparison.changedFields.join(', ') : 'none'}`,
  ];
  if (comparison.issuerMigration) {
    lines.push('', 'ISSUER / ENTITY IDENTIFIER MIGRATION', '------------------------------------', `From: ${comparison.issuerMigration.from}`, `To:   ${comparison.issuerMigration.to}`, `Classification: ${comparison.issuerMigration.classification}`);
  }
  if (comparison.keyRotation) {
    const rotation = comparison.keyRotation;
    lines.push('', 'SIGNING KEY ROTATION', '--------------------', `Basis: ${rotation.basis}`, `Classification: ${rotation.classification}`, `Retained: ${rotation.retained.join(', ') || '(none)'}`, `Added: ${rotation.added.join(', ') || '(none)'}`, `Removed: ${rotation.removed.join(', ') || '(none)'}`);
  }
  lines.push('', 'CONFIGURATION DIFFERENCES', '-------------------------', ...comparison.rows.filter((row) => row.status !== 'same').map((row) => `- ${row.name}: ${row.status}\n  source=${JSON.stringify(row.left)}\n  target=${JSON.stringify(row.right)}`));
  lines.push('', 'Note: configuration comparison does not prove that clients, relying parties or trust anchors have been updated. Validate the migration end-to-end before cutover.');
  return lines.join('\n');
}
