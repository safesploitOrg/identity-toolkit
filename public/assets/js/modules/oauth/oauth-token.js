import { finding, SEVERITY } from '../validation/findings.js';

function stringList(value) {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
  if (value === undefined || value === null || value === '') return [];
  return [String(value)];
}

export function extractOAuthPermissions(claims) {
  const scopes = stringList(claims?.scope ?? claims?.scp ?? []);
  const roles = stringList(claims?.roles ?? claims?.role ?? []);
  const groups = stringList(claims?.groups ?? []);
  const entitlements = stringList(claims?.entitlements ?? []);
  return {
    scopes,
    roles,
    groups,
    entitlements,
    clientId: claims?.client_id ?? claims?.azp ?? claims?.appid ?? '',
    audience: claims?.aud ?? '',
  };
}

export function analyseOAuthAccessToken(parsed, options = {}) {
  const { header = {}, claims = {} } = parsed;
  const findings = [];
  const permissions = extractOAuthPermissions(claims);
  const profile = options.oauthProfile ?? 'auto';
  const typ = String(header.typ ?? '').toLowerCase();
  const looksRfc9068 = profile === 'rfc9068' || typ === 'at+jwt' || typ === 'application/at+jwt';

  if (looksRfc9068) {
    for (const required of ['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti']) {
      if (claims[required] === undefined || claims[required] === null || claims[required] === '') {
        findings.push(finding(`oauth.rfc9068.required.${required}`, SEVERITY.ERROR, `RFC 9068 claim missing: ${required}`, 'The JWT access-token profile requires this claim.'));
      }
    }
    findings.push(finding(
      'oauth.rfc9068.typ',
      typ === 'at+jwt' || typ === 'application/at+jwt' ? SEVERITY.PASS : SEVERITY.ERROR,
      typ === 'at+jwt' || typ === 'application/at+jwt' ? 'JWT access-token media type is explicit' : 'JWT access-token typ is missing or incorrect',
      typ === 'at+jwt' || typ === 'application/at+jwt'
        ? `typ=${header.typ}`
        : 'RFC 9068 access tokens require typ=at+jwt (or application/at+jwt) to reduce token-confusion risk.',
    ));
    if (header.alg === 'none') {
      findings.push(finding('oauth.rfc9068.alg.none', SEVERITY.ERROR, 'RFC 9068 forbids alg=none', 'JWT access tokens conforming to RFC 9068 must be signed.'));
    }
    if (/^HS(?:256|384|512)$/.test(String(header.alg ?? ''))) {
      findings.push(finding('oauth.rfc9068.alg.symmetric', SEVERITY.WARNING, 'Symmetric signing used for RFC 9068 access token', 'RFC 9068 permits signed JWT access tokens with symmetric algorithms but recommends asymmetric signing because resource servers can acquire validation keys more cleanly.'));
    } else if (header.alg && header.alg !== 'none') {
      findings.push(finding('oauth.rfc9068.alg.asymmetric', SEVERITY.PASS, 'Asymmetric JWT access-token signing algorithm', `alg=${header.alg}.`));
    }
  } else {
    findings.push(finding('oauth.profile.vendor', SEVERITY.INFO, 'Provider-specific JWT access-token profile', 'The token does not explicitly identify itself as RFC 9068 at+jwt. Identity Toolkit will analyse common claims without assuming full RFC 9068 conformance.'));
  }

  if (!permissions.scopes.length && !permissions.roles.length && !permissions.entitlements.length) {
    findings.push(finding('oauth.permissions.none', SEVERITY.INFO, 'No common authorisation claims found', 'No scope/scp, roles or entitlements claims were found. The resource server may use provider-specific claims or external policy.'));
  } else {
    if (permissions.scopes.length) findings.push(finding('oauth.scopes.present', SEVERITY.INFO, `${permissions.scopes.length} OAuth scope(s)`, permissions.scopes.join(', ')));
    if (permissions.roles.length) findings.push(finding('oauth.roles.present', SEVERITY.INFO, `${permissions.roles.length} role value(s)`, permissions.roles.join(', ')));
    if (permissions.entitlements.length) findings.push(finding('oauth.entitlements.present', SEVERITY.INFO, `${permissions.entitlements.length} entitlement value(s)`, permissions.entitlements.join(', ')));
  }

  if (claims.cnf && typeof claims.cnf === 'object') {
    const methods = Object.keys(claims.cnf);
    findings.push(finding('oauth.cnf.present', SEVERITY.INFO, 'Proof-of-possession confirmation claim present', `cnf contains: ${methods.join(', ') || '(no recognised members)'}. Identity Toolkit does not possess the request-side proof material, so sender-constraining cannot be independently confirmed.`));
  }

  if (claims.act !== undefined || claims.may_act !== undefined) {
    findings.push(finding('oauth.delegation.present', SEVERITY.INFO, 'Delegation / actor information present', 'act or may_act claims can materially change the authorisation context and should be reviewed by the resource server.'));
  }

  if (claims.scope && typeof claims.scope !== 'string' && !Array.isArray(claims.scope)) {
    findings.push(finding('oauth.scope.type', SEVERITY.WARNING, 'Unexpected scope representation', 'Standard OAuth scope values are normally represented as a space-delimited string; provider-specific formats should be interpreted cautiously.'));
  }

  return { findings, permissions, rfc9068: looksRfc9068 };
}
