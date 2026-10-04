import { analyseJwtTimes } from '../validation/time.js';
import { finding, SEVERITY } from '../validation/findings.js';

const KNOWN_CRIT = new Set();

export function validateJwt(parsed, options = {}) {
  const findings = [];
  const { header, claims } = parsed;
  const profile = options.profile ?? 'generic-jwt';

  if (!header.alg) findings.push(finding('jwt.alg.missing', SEVERITY.ERROR, 'Missing JOSE algorithm', 'The JOSE header does not contain alg.'));
  else if (header.alg === 'none') findings.push(finding(
    'jwt.alg.none',
    profile === 'oidc-id-token' ? SEVERITY.INDETERMINATE : SEVERITY.ERROR,
    profile === 'oidc-id-token' ? 'Unsecured OIDC ID Token needs flow/registration context' : 'Unsecured JWT',
    profile === 'oidc-id-token'
      ? 'OpenID Connect permits alg=none only in narrowly constrained registered flows. Identity Toolkit does not have registration/response-flow context, so it will not claim this token is acceptable or verified.'
      : 'The JOSE header requests alg=none. This toolkit does not treat an unsecured token as verified.',
  ));
  else findings.push(finding('jwt.alg.present', SEVERITY.INFO, `JOSE algorithm: ${header.alg}`, 'Algorithm selection must still be constrained by the relying party and matched to trusted key material.'));

  if (!header.typ) findings.push(finding('jwt.typ.missing', SEVERITY.INFO, 'No typ header', 'Explicit typing can reduce token-confusion risk in deployments that process several JWT kinds.'));

  for (const name of ['jku', 'x5u']) {
    if (header[name]) findings.push(finding(`jwt.header.${name}`, SEVERITY.WARNING, `${name} URL present in JOSE header`, `Identity Toolkit will not contact ${header[name]}. Key URLs embedded in untrusted tokens must not be trusted automatically.`));
  }
  if (header.jwk) findings.push(finding('jwt.header.jwk', SEVERITY.INFO, 'Embedded JWK present', 'A JWK is embedded in the JOSE header. Its presence does not make the key trusted.'));
  if (Array.isArray(header.x5c) && header.x5c.length) findings.push(finding('jwt.header.x5c', SEVERITY.INFO, `${header.x5c.length} certificate(s) embedded in JOSE header`, 'Certificate presence does not establish certificate-chain or issuer trust.'));

  if (/^HS\d+$/.test(String(header.alg ?? ''))) findings.push(finding('jwt.alg.symmetric', SEVERITY.INFO, 'Symmetric HMAC signing algorithm', 'HMAC JWT validation requires the issuer and verifier to share secret key material; key distribution and token-type separation deserve particular care.'));
  if (/^(RS|PS|ES)\d+$/.test(String(header.alg ?? '')) || header.alg === 'EdDSA') findings.push(finding('jwt.alg.asymmetric', SEVERITY.INFO, 'Asymmetric signing algorithm', 'Signature validity still depends on selecting trusted issuer key material and enforcing an allowed algorithm set.'));
  if (Array.isArray(header.crit)) {
    const unknown = header.crit.filter((name) => !KNOWN_CRIT.has(name));
    if (unknown.length) findings.push(finding('jwt.crit.unknown', SEVERITY.INDETERMINATE, 'Unsupported critical JOSE header', `Critical header parameter(s) are not implemented by this version: ${unknown.join(', ')}.`, { unknown }));
  }
  if (header.b64 === false) {
    findings.push(finding('jwt.b64.unsupported', SEVERITY.INDETERMINATE, 'Unencoded JWS payload is not supported', 'The JOSE b64=false extension changes compact-JWS payload processing. This version will not claim a valid interpretation or signature result for it.'));
  }

  findings.push(...analyseJwtTimes(claims, options.now, options.clockSkewSeconds));

  if (options.expectedIssuer) {
    if (claims.iss === options.expectedIssuer) findings.push(finding('jwt.iss.expected', SEVERITY.PASS, 'Issuer matches expectation', 'The iss claim exactly matches the expected issuer.'));
    else findings.push(finding('jwt.iss.mismatch', SEVERITY.ERROR, 'Issuer mismatch', 'The iss claim does not match the expected issuer.', { actual: claims.iss ?? null, expected: options.expectedIssuer }));
  }

  if (options.expectedAudience) {
    const audiences = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
    if (audiences.includes(options.expectedAudience)) findings.push(finding('jwt.aud.expected', SEVERITY.PASS, 'Audience matches expectation', 'The expected audience is present.'));
    else findings.push(finding('jwt.aud.mismatch', SEVERITY.ERROR, 'Audience mismatch', 'The expected audience is not present in aud.', { actual: audiences, expected: options.expectedAudience }));
  }

  if (profile === 'oidc-id-token') {
    for (const required of ['iss', 'sub', 'aud', 'exp', 'iat']) {
      if (claims[required] === undefined || claims[required] === null || claims[required] === '') {
        findings.push(finding(`oidc.required.${required}`, SEVERITY.ERROR, `Missing OIDC claim: ${required}`, `An OpenID Connect ID Token is expected to contain ${required}.`));
      }
    }
  }

  if (profile === 'oauth-access-token') {
    if (!claims.aud) findings.push(finding('oauth.aud.missing', SEVERITY.WARNING, 'No audience claim', 'JWT access tokens commonly identify their resource server using aud, but token profiles vary.'));
    if (!claims.scope && !claims.scp && !claims.roles) findings.push(finding('oauth.permission.missing', SEVERITY.INFO, 'No obvious scope/role claim', 'No scope, scp or roles claim was found. Authorisation information may use another claim or be evaluated elsewhere.'));
  }

  return findings;
}
