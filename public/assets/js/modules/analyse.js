import { detectInput } from './input-detector.js';
import { parseJwt, looksLikeOpenIdFederationEntityStatement } from './jwt/jwt-parser.js';
import { analyseJwks, parseJwkMaterial, selectJwk } from './jwt/jwk.js';
import { verifyCompactJws } from './crypto/signature.js';
import { validateJwt } from './jwt/jwt-validator.js';
import { analyseOAuthAccessToken } from './oauth/oauth-token.js';
import { analyseOidcDiscovery } from './oidc/discovery.js';
import { analyseOidcIdToken } from './oidc/id-token.js';
import { parseSaml } from './saml/saml-parser.js';
import { verifySamlXmlSignatures } from './saml/xmldsig-verifier.js';
import { analyseSamlMetadata } from './saml/saml-metadata.js';
import { parseWsFed } from './wsfed/wsfed-parser.js';
import { claimsFromJwt, claimsFromSaml, claimsFromWsFed } from './claims/claims.js';
import { finding, overallFromFindings, SEVERITY } from './validation/findings.js';
import { analyseOpenIdFederationStatement } from './federation/openid-federation.js';

function resolveJwtProfile(requested, parsed) {
  if (requested && requested !== 'auto') return requested;
  if (looksLikeOpenIdFederationEntityStatement(parsed.claims) || parsed.header?.typ === 'entity-statement+jwt') return 'openid-federation';
  if (parsed.header?.typ && ['at+jwt', 'application/at+jwt'].includes(String(parsed.header.typ).toLowerCase())) return 'oauth-access-token';
  if (parsed.claims?.nonce !== undefined || parsed.claims?.auth_time !== undefined || parsed.claims?.acr !== undefined || parsed.claims?.amr !== undefined) return 'oidc-id-token';
  if (parsed.claims?.scope !== undefined || parsed.claims?.scp !== undefined || parsed.claims?.client_id !== undefined || parsed.claims?.roles !== undefined) return 'oauth-access-token';
  return 'generic-jwt';
}

async function verifyJwtWithMaterial(parsed, materialText, findings, provenance) {
  try {
    const material = typeof materialText === 'string' ? parseJwkMaterial(materialText) : materialText;
    const selected = selectJwk(material.keys, parsed.header);
    if (!selected.key) {
      findings.push(finding('jwt.signature.key', SEVERITY.INDETERMINATE, 'Signing key not uniquely resolved', selected.reason));
      return { supported: false, valid: null, detail: selected.reason, provenance };
    }
    const signature = await verifyCompactJws(parsed, selected.key);
    findings.push(finding(
      'jwt.signature.result',
      signature.valid === true ? SEVERITY.PASS : signature.valid === false ? SEVERITY.ERROR : SEVERITY.INDETERMINATE,
      signature.valid === true ? 'JWT signature verified' : signature.valid === false ? 'JWT signature invalid' : 'JWT signature not verified',
      `${signature.detail} Key provenance: ${provenance}; issuer/trust-anchor trust is not established by this result.`,
    ));
    return { ...signature, provenance };
  } catch (error) {
    findings.push(finding('jwt.signature.material', SEVERITY.INDETERMINATE, 'Verification material could not be used', error.message));
    return { supported: false, valid: null, detail: error.message, provenance };
  }
}

async function analyseJwt(input, detected, options) {
  const parsed = parseJwt(input);
  const profile = resolveJwtProfile(options.profile, parsed);
  const findings = validateJwt(parsed, { ...options, profile });
  let signature = { supported: false, valid: null, detail: 'No verification material supplied.', provenance: 'none' };

  if (profile === 'oidc-id-token') {
    const oidc = await analyseOidcIdToken(parsed, options);
    findings.push(...oidc.findings);
  }

  let oauth = null;
  if (profile === 'oauth-access-token') {
    oauth = analyseOAuthAccessToken(parsed, options);
    findings.push(...oauth.findings);
  }

  let federation = null;
  if (profile === 'openid-federation') {
    federation = analyseOpenIdFederationStatement(parsed, options);
    findings.push(...federation.findings);
  }

  const unsupportedCritical = Array.isArray(parsed.header.crit) && parsed.header.crit.length > 0;
  if (parsed.header.b64 === false || unsupportedCritical) {
    findings.push(finding('jwt.signature.blocked', SEVERITY.INDETERMINATE, 'JWT signature verification blocked', 'Critical JOSE processing semantics are not implemented for this token, so verification would risk validating the wrong signing-input semantics.'));
  } else if (String(options.verificationMaterial ?? '').trim()) {
    signature = await verifyJwtWithMaterial(parsed, options.verificationMaterial, findings, 'user-supplied JWK/JWKS');
  } else if (profile === 'openid-federation' && parsed.claims?.iss === parsed.claims?.sub && Array.isArray(parsed.claims?.jwks?.keys)) {
    signature = await verifyJwtWithMaterial(parsed, { keys: parsed.claims.jwks.keys, source: 'entity-statement-jwks' }, findings, 'self-published Federation Entity jwks claim');
    findings.push(finding('federation.signature.trust', SEVERITY.INFO, 'Self-contained Entity Configuration signature check', 'A valid signature against the Entity Configuration\'s own jwks proves self-consistency only. Trust still requires a validated federation trust chain to a configured Trust Anchor.'));
  } else {
    findings.push(finding('jwt.signature.missing', SEVERITY.INDETERMINATE, 'JWT signature not verified', 'Supply a JWK or JWKS to verify the compact JWS signature locally.'));
  }

  const claims = claimsFromJwt(parsed.claims);
  let summary = {
    algorithm: parsed.header.alg ?? '',
    keyId: parsed.header.kid ?? '',
    type: parsed.header.typ ?? '',
    issuer: parsed.claims.iss ?? '',
    subject: parsed.claims.sub ?? '',
    audience: parsed.claims.aud ?? '',
    authorisedParty: parsed.claims.azp ?? '',
    nonce: parsed.claims.nonce ?? '',
    acr: parsed.claims.acr ?? '',
    amr: parsed.claims.amr ?? [],
    issuedAt: parsed.claims.iat ?? '',
    notBefore: parsed.claims.nbf ?? '',
    expires: parsed.claims.exp ?? '',
  };
  if (oauth) summary = { ...summary, ...oauth.permissions, rfc9068Profile: oauth.rfc9068 };
  if (federation) summary = { ...summary, ...federation.summary };

  return { kind: profile === 'openid-federation' ? 'openid-federation' : 'jwt', detected, profile, summary, claims, findings, signature, parsed, raw: input };
}

export async function analyseArtifact(input, options = {}) {
  const detected = detectInput(input);
  let result;

  if (detected.type === 'jwt') result = await analyseJwt(input, detected, options);
  else if (detected.type === 'saml') {
    const saml = parseSaml(input, options);
    const verification = await verifySamlXmlSignatures(input);
    const findings = [...saml.findings, ...verification.findings];
    const first = saml.assertions[0];
    result = {
      kind: 'saml', detected, profile: 'saml2', summary: {
        ...saml.summary,
        subject: first?.subject?.nameId ?? '',
        nameIdFormat: first?.subject?.nameIdFormat ?? '',
        audience: first?.conditions?.audiences ?? [],
        audienceRestrictions: first?.conditions?.audienceRestrictions ?? [],
        notBefore: first?.conditions?.notBefore ?? '',
        notOnOrAfter: first?.conditions?.notOnOrAfter ?? '',
        authnContext: first?.authn?.contextClass ?? '',
        sessionIndex: first?.authn?.sessionIndex ?? '',
        attributeCount: first?.attributes?.length ?? 0,
      },
      claims: claimsFromSaml(first?.attributes ?? []), findings, verification, parsed: saml, raw: input,
    };
  } else if (detected.type === 'wsfed') {
    const wsfed = parseWsFed(input, options);
    result = {
      kind: 'wsfed', detected, profile: 'wsfed', summary: wsfed.summary,
      claims: claimsFromWsFed(wsfed.claims ?? []), findings: wsfed.findings, parsed: wsfed, raw: input,
    };
  } else if (detected.type === 'oidc-discovery') {
    const parsed = analyseOidcDiscovery(JSON.parse(input));
    result = { ...parsed, detected, profile: 'oidc-discovery', claims: [] };
  } else if (detected.type === 'jwks' || detected.type === 'jwk') {
    const json = JSON.parse(input);
    const analysis = analyseJwks(detected.type === 'jwk' ? { keys: [json] } : json);
    result = { kind: 'jwks', detected, profile: 'jwks', summary: analysis.summary, findings: analysis.findings, claims: [], raw: json };
  } else if (detected.type === 'saml-metadata') {
    const parsed = analyseSamlMetadata(input, options);
    const verification = await verifySamlXmlSignatures(input);
    result = {
      ...parsed,
      detected,
      profile: 'saml-metadata',
      summary: {
        entityCount: parsed.entities.length,
        firstEntityId: parsed.entities[0]?.entityId ?? '',
        roles: parsed.entities[0]?.roles ?? [],
        signingKeyCount: (parsed.entities[0]?.keys ?? []).filter((key) => key.use === 'signing' || key.use === 'unspecified').reduce((count, key) => count + key.certificates.length, 0),
        ssoServices: parsed.entities[0]?.ssoServices?.length ?? 0,
        acsServices: parsed.entities[0]?.acsServices?.length ?? 0,
      },
      findings: [...parsed.findings, ...verification.findings],
      verification,
      claims: [],
    };
  } else {
    throw new Error(`Unsupported input: ${detected.label}.`);
  }

  result.overall = overallFromFindings(result.findings ?? []);
  return result;
}
