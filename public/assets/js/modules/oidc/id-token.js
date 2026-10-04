import { bytesToBase64Url } from '../encoding/base64url.js';
import { finding, SEVERITY } from '../validation/findings.js';

function hashNameForJwsAlg(alg = '') {
  if (/^(?:HS|RS|PS|ES)256$/.test(alg)) return 'SHA-256';
  if (/^(?:HS|RS|PS|ES)384$/.test(alg)) return 'SHA-384';
  if (/^(?:HS|RS|PS|ES)512$/.test(alg)) return 'SHA-512';
  return null;
}

function asAudienceList(aud) {
  if (Array.isArray(aud)) return aud.map(String);
  if (aud === undefined || aud === null || aud === '') return [];
  return [String(aud)];
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

async function validateHalfHash({ claimName, claimValue, sourceValue, alg }) {
  if (!claimValue) return null;
  if (!sourceValue) {
    return finding(
      `oidc.${claimName}.unverified`,
      SEVERITY.INDETERMINATE,
      `${claimName} present but not verified`,
      `Supply the corresponding ${claimName === 'at_hash' ? 'access token' : 'authorisation code'} to verify this binding locally.`,
    );
  }
  const hashName = hashNameForJwsAlg(alg);
  if (!hashName) {
    return finding(
      `oidc.${claimName}.algorithm`,
      SEVERITY.INDETERMINATE,
      `${claimName} verification unsupported for ${alg || 'unknown algorithm'}`,
      'Identity Toolkit derives OIDC half-hashes for HS/RS/PS/ES SHA-2 algorithm families in this version.',
    );
  }
  const input = new TextEncoder().encode(String(sourceValue));
  const digest = new Uint8Array(await crypto.subtle.digest(hashName, input));
  const expected = bytesToBase64Url(digest.slice(0, digest.length / 2));
  return finding(
    `oidc.${claimName}.result`,
    expected === claimValue ? SEVERITY.PASS : SEVERITY.ERROR,
    expected === claimValue ? `${claimName} binding verified` : `${claimName} binding mismatch`,
    expected === claimValue
      ? `${claimName} matches the supplied value using ${hashName}.`
      : `${claimName} does not match the supplied value using ${hashName}.`,
    { expected, actual: claimValue },
  );
}

export async function analyseOidcIdToken(parsed, options = {}) {
  const { header = {}, claims = {} } = parsed;
  const findings = [];
  const audiences = asAudienceList(claims.aud);

  if (!isNonEmptyString(claims.sub)) {
    findings.push(finding('oidc.sub.type', SEVERITY.ERROR, 'OIDC subject is missing or invalid', 'The sub claim must identify the End-User and should be a non-empty string.'));
  }

  if (audiences.length > 1) {
    findings.push(finding(
      'oidc.aud.additional-trust',
      SEVERITY.WARNING,
      'Additional ID Token audiences require client trust',
      `aud contains ${audiences.length} values. The client must decide whether every additional audience is trusted; Identity Toolkit only knows the explicitly supplied expected audience.`,
      { audiences },
    ));
    if (!isNonEmptyString(claims.azp)) {
      findings.push(finding('oidc.azp.absent', SEVERITY.INFO, 'No azp claim with multiple audiences', 'This is not inherently invalid under OpenID Connect Core. If an extension causes azp to be present, the client should validate it according to that extension and can compare it with the expected client ID here.'));
    } else {
      findings.push(finding('oidc.azp.present', SEVERITY.PASS, 'Authorised party present', `azp=${claims.azp}`));
    }
  } else if (isNonEmptyString(claims.azp)) {
    findings.push(finding('oidc.azp.present', SEVERITY.INFO, 'Authorised party present', `azp=${claims.azp}`));
  }

  if (claims.azp !== undefined && !isNonEmptyString(claims.azp)) {
    findings.push(finding('oidc.azp.type', SEVERITY.ERROR, 'Invalid azp claim', 'azp must be a non-empty string when present.'));
  }

  if (options.expectedAudience && claims.azp) {
    findings.push(finding(
      'oidc.azp.expected',
      claims.azp === options.expectedAudience ? SEVERITY.PASS : SEVERITY.ERROR,
      claims.azp === options.expectedAudience ? 'azp matches expected client' : 'azp does not match expected client',
      `Expected ${options.expectedAudience}; token contains ${claims.azp}.`,
    ));
  }

  if (options.expectedNonce) {
    findings.push(finding(
      'oidc.nonce.expected',
      claims.nonce === options.expectedNonce ? SEVERITY.PASS : SEVERITY.ERROR,
      claims.nonce === options.expectedNonce ? 'Nonce matches authentication request' : 'Nonce mismatch',
      claims.nonce === options.expectedNonce
        ? 'The ID Token nonce exactly matches the expected request nonce.'
        : 'The ID Token nonce is absent or differs from the expected authentication-request nonce.',
      { expected: options.expectedNonce, actual: claims.nonce ?? null },
    ));
  } else if (claims.nonce !== undefined) {
    findings.push(finding('oidc.nonce.present', SEVERITY.INFO, 'Nonce claim present', 'A nonce is present, but no request-side expected nonce was supplied so replay binding cannot be checked.'));
  }

  const maxAgeConfigured = Number.isFinite(options.maxAuthenticationAgeSeconds) && options.maxAuthenticationAgeSeconds >= 0;
  if (claims.auth_time !== undefined) {
    if (!Number.isFinite(Number(claims.auth_time))) {
      findings.push(finding('oidc.auth_time.type', SEVERITY.ERROR, 'Invalid auth_time claim', 'auth_time must be a NumericDate when present.'));
    } else if (maxAgeConfigured) {
      const nowSeconds = Math.floor((options.now ? new Date(options.now) : new Date()).getTime() / 1000);
      const age = nowSeconds - Number(claims.auth_time);
      findings.push(finding(
        'oidc.auth_time.age',
        age <= options.maxAuthenticationAgeSeconds + Number(options.clockSkewSeconds ?? 0) ? SEVERITY.PASS : SEVERITY.ERROR,
        age <= options.maxAuthenticationAgeSeconds + Number(options.clockSkewSeconds ?? 0) ? 'Authentication age within limit' : 'Authentication is older than allowed',
        `Authentication age is ${Math.max(0, age)} seconds; configured maximum is ${options.maxAuthenticationAgeSeconds} seconds.`,
      ));
    }
  } else if (maxAgeConfigured) {
    findings.push(finding('oidc.auth_time.missing', SEVERITY.ERROR, 'auth_time missing for maximum-age validation', 'A maximum authentication age was supplied, but the ID Token has no auth_time claim to validate against that request-side requirement.'));
  }

  if (claims.acr !== undefined) {
    findings.push(finding('oidc.acr.present', SEVERITY.INFO, 'Authentication Context Class reported', `acr=${String(claims.acr)}. Identity Toolkit reports issuer assertions but does not independently observe the authentication event.`));
  }
  if (claims.amr !== undefined) {
    if (!Array.isArray(claims.amr) || claims.amr.some((value) => typeof value !== 'string')) {
      findings.push(finding('oidc.amr.type', SEVERITY.WARNING, 'Unexpected amr representation', 'OIDC defines amr as an array of case-sensitive strings.'));
    } else {
      findings.push(finding('oidc.amr.present', SEVERITY.INFO, 'Authentication methods reported', claims.amr.join(', ') || '(empty array)'));
    }
  }

  const atHash = await validateHalfHash({ claimName: 'at_hash', claimValue: claims.at_hash, sourceValue: options.relatedAccessToken, alg: header.alg });
  if (atHash) findings.push(atHash);
  const cHash = await validateHalfHash({ claimName: 'c_hash', claimValue: claims.c_hash, sourceValue: options.relatedAuthorizationCode, alg: header.alg });
  if (cHash) findings.push(cHash);

  if (claims.s_hash !== undefined) {
    findings.push(finding('oidc.s_hash.present', SEVERITY.INFO, 'State hash present', 's_hash is present. This alpha reports it but does not yet validate state-hash profiles.'));
  }

  return {
    findings,
    details: {
      audiences,
      authorisedParty: claims.azp ?? '',
      nonce: claims.nonce ?? '',
      authenticationTime: claims.auth_time ?? '',
      acr: claims.acr ?? '',
      amr: claims.amr ?? [],
      atHash: claims.at_hash ?? '',
      cHash: claims.c_hash ?? '',
    },
  };
}
