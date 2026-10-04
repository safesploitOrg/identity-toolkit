import { analyseJwtTimes } from '../validation/time.js';
import { finding, SEVERITY } from '../validation/findings.js';
import { inspectJwks } from '../jwt/jwk.js';

function validHttpsEntityIdentifier(value) {
  if (typeof value !== 'string' || !value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && Boolean(url.host) && !url.hash;
  } catch {
    return false;
  }
}

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function validateStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0);
}

export function analyseOpenIdFederationStatement(parsedJwt, options = {}) {
  const header = parsedJwt.header ?? {};
  const claims = parsedJwt.claims ?? {};
  const findings = [];
  const selfConfiguration = claims.iss && claims.sub && claims.iss === claims.sub;

  findings.push(finding(
    'federation.typ',
    header.typ === 'entity-statement+jwt' ? SEVERITY.PASS : SEVERITY.ERROR,
    header.typ === 'entity-statement+jwt' ? 'Entity Statement is explicitly typed' : 'Invalid or missing Entity Statement typ',
    `Expected typ=entity-statement+jwt; actual=${header.typ ?? '(missing)'}.`,
  ));

  if (!header.alg || header.alg === 'none') findings.push(finding('federation.alg', SEVERITY.ERROR, 'Entity Statement must be signed', `alg=${header.alg ?? '(missing)'}`));
  if (typeof header.kid !== 'string' || !header.kid) findings.push(finding('federation.kid', SEVERITY.ERROR, 'Entity Statement kid missing', 'OpenID Federation Entity Statements require a non-empty kid header parameter.'));

  for (const name of ['iss', 'sub', 'iat', 'exp']) {
    if (claims[name] === undefined || claims[name] === null || claims[name] === '') findings.push(finding(`federation.${name}.missing`, SEVERITY.ERROR, `Entity Statement missing ${name}`, `The Entity Statement requires ${name}.`));
  }
  findings.push(...analyseJwtTimes(claims, options.now, options.clockSkewSeconds).map((item) => ({ ...item, id: `federation.${item.id}` })));

  if (claims.iss && !validHttpsEntityIdentifier(claims.iss)) findings.push(finding('federation.iss.format', SEVERITY.ERROR, 'Issuer is not a valid HTTPS Entity Identifier', String(claims.iss)));
  if (claims.sub && !validHttpsEntityIdentifier(claims.sub)) findings.push(finding('federation.sub.format', SEVERITY.ERROR, 'Subject is not a valid HTTPS Entity Identifier', String(claims.sub)));

  if (selfConfiguration) findings.push(finding('federation.statement.type', SEVERITY.INFO, 'Entity Configuration', 'iss and sub are identical, so this is structurally an Entity Configuration.'));
  else if (claims.iss && claims.sub) findings.push(finding('federation.statement.type', SEVERITY.INFO, 'Subordinate Statement', 'iss and sub differ, so this is structurally a Subordinate Statement.'));

  if (!isObject(claims.jwks) || !Array.isArray(claims.jwks.keys)) {
    findings.push(finding('federation.jwks.missing', SEVERITY.ERROR, 'Federation Entity JWKS missing or invalid', 'The final OpenID Federation 1.0 Entity Statement profile requires a valid jwks claim except for a specific explicit-registration response case.'));
  } else {
    const jwks = inspectJwks(claims.jwks);
    if (jwks.duplicateKids.length) findings.push(finding('federation.jwks.duplicate-kid', SEVERITY.ERROR, 'Federation JWKS contains duplicate kid values', JSON.stringify(jwks.duplicateKids)));
    if (jwks.missingKidCount) findings.push(finding('federation.jwks.missing-kid', SEVERITY.ERROR, 'Federation JWKS key without kid', `${jwks.missingKidCount} key(s) do not have kid.`));
    if (header.kid && !jwks.keys.some((key) => key.kid === header.kid) && selfConfiguration) findings.push(finding('federation.jwks.header-kid', SEVERITY.ERROR, 'Entity Configuration signing kid absent from its jwks', `Header kid ${header.kid} is not present in the subject Federation Entity JWKS.`));
    else if (header.kid && selfConfiguration) findings.push(finding('federation.jwks.header-kid', SEVERITY.PASS, 'Entity Configuration signing kid is present in its jwks', header.kid));
  }

  if (claims.authority_hints !== undefined) {
    if (!selfConfiguration) findings.push(finding('federation.authority_hints.statement', SEVERITY.ERROR, 'authority_hints used in a Subordinate Statement', 'OpenID Federation 1.0 permits authority_hints in Entity Configurations, not Subordinate Statements.'));
    if (!validateStringArray(claims.authority_hints)) findings.push(finding('federation.authority_hints.type', SEVERITY.ERROR, 'Invalid authority_hints', 'authority_hints must be an array of non-empty Entity Identifier strings.'));
    else {
      const invalid = claims.authority_hints.filter((value) => !validHttpsEntityIdentifier(value));
      if (invalid.length) findings.push(finding('federation.authority_hints.url', SEVERITY.ERROR, 'Invalid Entity Identifier in authority_hints', invalid.join(', ')));
      else findings.push(finding('federation.authority_hints', SEVERITY.INFO, `${claims.authority_hints.length} authority hint(s)`, claims.authority_hints.join(', ') || '(empty)'));
    }
  }

  if (claims.trust_anchor_hints !== undefined) {
    if (!selfConfiguration) findings.push(finding('federation.trust_anchor_hints.statement', SEVERITY.ERROR, 'trust_anchor_hints used in a Subordinate Statement', 'trust_anchor_hints is defined for Entity Configurations.'));
    if (!validateStringArray(claims.trust_anchor_hints)) findings.push(finding('federation.trust_anchor_hints.type', SEVERITY.ERROR, 'Invalid trust_anchor_hints', 'trust_anchor_hints must be an array of Entity Identifier strings.'));
  }

  if (claims.metadata !== undefined) {
    if (!isObject(claims.metadata)) findings.push(finding('federation.metadata.type', SEVERITY.ERROR, 'Invalid federation metadata', 'metadata must be a JSON object keyed by Entity Type.'));
    else {
      const nullEntries = Object.entries(claims.metadata).filter(([, value]) => value === null);
      if (nullEntries.length) findings.push(finding('federation.metadata.null', SEVERITY.ERROR, 'Federation metadata contains null values', nullEntries.map(([name]) => name).join(', ')));
      findings.push(finding('federation.metadata', SEVERITY.INFO, `${Object.keys(claims.metadata).length} Entity Type metadata object(s)`, Object.keys(claims.metadata).join(', ')));
    }
  }

  if (claims.metadata_policy !== undefined && selfConfiguration) findings.push(finding('federation.metadata_policy.statement', SEVERITY.ERROR, 'metadata_policy used in an Entity Configuration', 'metadata_policy is defined for Subordinate Statements.'));
  if (claims.constraints !== undefined && selfConfiguration) findings.push(finding('federation.constraints.statement', SEVERITY.ERROR, 'constraints used in an Entity Configuration', 'constraints is defined for Subordinate Statements.'));
  if (claims.source_endpoint !== undefined) {
    if (selfConfiguration) findings.push(finding('federation.source_endpoint.statement', SEVERITY.ERROR, 'source_endpoint used in an Entity Configuration', 'source_endpoint is defined for Subordinate Statements.'));
    try { new URL(claims.source_endpoint); } catch { findings.push(finding('federation.source_endpoint.url', SEVERITY.ERROR, 'Invalid source_endpoint URL', String(claims.source_endpoint))); }
  }

  if (claims.crit !== undefined) {
    if (!Array.isArray(claims.crit) || claims.crit.some((value) => typeof value !== 'string')) findings.push(finding('federation.crit.type', SEVERITY.ERROR, 'Invalid Entity Statement crit claim', 'crit must be an array of claim names.'));
    else if (claims.crit.length) findings.push(finding('federation.crit.unsupported', SEVERITY.INDETERMINATE, 'Critical Entity Statement extensions require application support', `Identity Toolkit does not implement extension claims declared critical: ${claims.crit.join(', ')}.`));
  }

  if (claims.metadata_policy_crit !== undefined) {
    if (!Array.isArray(claims.metadata_policy_crit) || claims.metadata_policy_crit.some((value) => typeof value !== 'string')) findings.push(finding('federation.metadata_policy_crit.type', SEVERITY.ERROR, 'Invalid metadata_policy_crit', 'metadata_policy_crit must be an array of policy operator names.'));
    else if (claims.metadata_policy_crit.length) findings.push(finding('federation.metadata_policy_crit.unsupported', SEVERITY.INDETERMINATE, 'Critical metadata policy operators require support', `Critical operators: ${claims.metadata_policy_crit.join(', ')}.`));
  }

  if (claims.trust_marks !== undefined) {
    if (!Array.isArray(claims.trust_marks)) findings.push(finding('federation.trust_marks.type', SEVERITY.ERROR, 'Invalid trust_marks claim', 'trust_marks must be an array.'));
    else {
      const malformed = claims.trust_marks.filter((item) => !isObject(item) || typeof item.trust_mark_type !== 'string' || typeof item.trust_mark !== 'string');
      findings.push(finding('federation.trust_marks', malformed.length ? SEVERITY.ERROR : SEVERITY.INFO, malformed.length ? 'Malformed Trust Mark entries' : `${claims.trust_marks.length} Trust Mark(s) advertised`, malformed.length ? `${malformed.length} entry/entries are missing trust_mark_type or trust_mark.` : 'Trust Mark JWT signatures and federation accreditation are not trusted merely because the objects are present.'));
    }
  }

  if (header.trust_chain !== undefined || header.peer_trust_chain !== undefined) {
    for (const name of ['trust_chain', 'peer_trust_chain']) {
      if (header[name] === undefined) continue;
      const validShape = Array.isArray(header[name]) && header[name].every((token) => typeof token === 'string' && token.split('.').length === 3);
      findings.push(finding(`federation.${name}.shape`, validShape ? SEVERITY.INFO : SEVERITY.ERROR, validShape ? `${name} header contains ${header[name].length} JWT(s)` : `Invalid ${name} header`, validShape ? 'Trust-chain JWTs are structurally present; this offline analyser does not resolve or establish a trust anchor.' : `${name} must be an array of compact JWT strings.`));
    }
  }

  if (claims.aud !== undefined) findings.push(finding('federation.aud.context', SEVERITY.WARNING, 'aud claim requires explicit-registration/extension context', 'OpenID Federation 1.0 does not use aud as a general Entity Statement claim. Identity Toolkit cannot infer an explicit-registration context from a standalone JWT.'));

  return {
    kind: 'openid-federation',
    summary: {
      statementType: selfConfiguration ? 'Entity Configuration' : 'Subordinate Statement',
      issuer: claims.iss ?? '',
      subject: claims.sub ?? '',
      keyId: header.kid ?? '',
      algorithm: header.alg ?? '',
      issuedAt: claims.iat ?? '',
      expires: claims.exp ?? '',
      authorityHints: claims.authority_hints ?? [],
      trustAnchorHints: claims.trust_anchor_hints ?? [],
      metadataTypes: isObject(claims.metadata) ? Object.keys(claims.metadata) : [],
      federationKeyCount: Array.isArray(claims.jwks?.keys) ? claims.jwks.keys.length : 0,
      trustMarkCount: Array.isArray(claims.trust_marks) ? claims.trust_marks.length : 0,
      hasMetadataPolicy: Boolean(claims.metadata_policy),
      hasConstraints: Boolean(claims.constraints),
    },
    findings,
    raw: claims,
  };
}
