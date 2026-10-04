import { finding, SEVERITY } from '../validation/findings.js';

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function urlFinding(id, label, value, required = false) {
  if (!value) {
    return finding(`${id}.missing`, required ? SEVERITY.ERROR : SEVERITY.INFO, `${label} ${required ? 'missing' : 'not advertised'}`, `${label} is not present in the metadata document.`);
  }
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    return finding(`${id}.invalid`, SEVERITY.ERROR, `${label} is not a valid URL`, String(value));
  }
  if (parsed.protocol === 'https:') return finding(`${id}.https`, SEVERITY.PASS, `${label} uses HTTPS`, value);
  return finding(`${id}.scheme`, SEVERITY.WARNING, `${label} does not use HTTPS`, value);
}

function requiredArrayFinding(document, name, label) {
  const value = document[name];
  if (!Array.isArray(value) || !value.length) {
    return finding(`oidc.discovery.${name}.missing`, SEVERITY.ERROR, `${label} missing`, `${name} must be a non-empty JSON array in OpenID Provider metadata.`);
  }
  return finding(`oidc.discovery.${name}.present`, SEVERITY.PASS, `${label} advertised`, value.join(', '));
}

export function analyseOidcDiscovery(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('OIDC metadata must be a JSON object.');
  const findings = [];

  if (!document.issuer) {
    findings.push(finding('oidc.discovery.issuer.missing', SEVERITY.ERROR, 'Issuer missing', 'The provider metadata document does not contain issuer.'));
  } else {
    let issuerUrl = null;
    try { issuerUrl = new URL(document.issuer); } catch { /* handled below */ }
    if (!issuerUrl) findings.push(finding('oidc.discovery.issuer.invalid', SEVERITY.ERROR, 'Issuer is not a valid URL', String(document.issuer)));
    else if (issuerUrl.protocol !== 'https:' || issuerUrl.search || issuerUrl.hash) {
      findings.push(finding('oidc.discovery.issuer.format', SEVERITY.ERROR, 'Issuer URL does not meet OIDC discovery requirements', 'The issuer should use HTTPS and contain no query or fragment component.', { issuer: document.issuer }));
    } else {
      findings.push(finding('oidc.discovery.issuer', SEVERITY.PASS, 'Issuer identifier is structurally valid', document.issuer));
    }
  }

  const responseTypes = asArray(document.response_types_supported).map(String);
  const requiresTokenEndpoint = responseTypes.some((responseType) => responseType.split(/\s+/).includes('code'));

  findings.push(urlFinding('oidc.discovery.authorization', 'Authorization endpoint', document.authorization_endpoint, true));
  findings.push(urlFinding('oidc.discovery.token', 'Token endpoint', document.token_endpoint, requiresTokenEndpoint));
  findings.push(urlFinding('oidc.discovery.jwks', 'JWKS URI', document.jwks_uri, true));
  findings.push(urlFinding('oidc.discovery.userinfo', 'UserInfo endpoint', document.userinfo_endpoint, false));
  findings.push(urlFinding('oidc.discovery.registration', 'Registration endpoint', document.registration_endpoint, false));
  findings.push(urlFinding('oidc.discovery.end_session', 'End-session endpoint', document.end_session_endpoint, false));

  findings.push(requiredArrayFinding(document, 'response_types_supported', 'Response types'));
  findings.push(requiredArrayFinding(document, 'subject_types_supported', 'Subject identifier types'));
  findings.push(requiredArrayFinding(document, 'id_token_signing_alg_values_supported', 'ID Token signing algorithms'));

  const signingAlgorithms = asArray(document.id_token_signing_alg_values_supported).map(String);
  if (signingAlgorithms.length && !signingAlgorithms.includes('RS256')) {
    findings.push(finding('oidc.discovery.rs256.missing', SEVERITY.WARNING, 'RS256 not advertised', 'OpenID Connect Discovery requires RS256 to be included in id_token_signing_alg_values_supported.'));
  }
  if (signingAlgorithms.includes('none')) {
    findings.push(finding('oidc.discovery.none', SEVERITY.INFO, 'Unsecured ID Token algorithm advertised', 'OIDC permits advertising none in constrained cases; clients must not accept it outside the permitted response-flow conditions.'));
  }

  const scopes = asArray(document.scopes_supported).map(String);
  if (scopes.length && !scopes.includes('openid')) {
    findings.push(finding('oidc.discovery.openid.scope', SEVERITY.ERROR, 'openid scope not advertised', 'When scopes_supported is present, an OpenID Provider must include the openid scope.'));
  } else if (scopes.includes('openid')) {
    findings.push(finding('oidc.discovery.openid.scope', SEVERITY.PASS, 'openid scope advertised', 'The provider explicitly advertises the OpenID Connect openid scope.'));
  }

  const codeChallengeMethods = asArray(document.code_challenge_methods_supported).map(String);
  if (codeChallengeMethods.includes('S256')) findings.push(finding('oidc.discovery.pkce.s256', SEVERITY.PASS, 'PKCE S256 advertised', 'The provider advertises the S256 code challenge method.'));
  else if (codeChallengeMethods.length) findings.push(finding('oidc.discovery.pkce.s256', SEVERITY.WARNING, 'PKCE S256 not advertised', `Advertised methods: ${codeChallengeMethods.join(', ')}`));
  else findings.push(finding('oidc.discovery.pkce.unknown', SEVERITY.INFO, 'PKCE capability not advertised', 'code_challenge_methods_supported is absent; absence does not prove PKCE is unsupported.'));

  const grants = asArray(document.grant_types_supported).map(String);
  const frontChannelTokenResponses = responseTypes.filter((responseType) => responseType.split(/\s+/).includes('token'));
  if (grants.includes('implicit') || frontChannelTokenResponses.length) {
    findings.push(finding(
      'oidc.discovery.implicit',
      SEVERITY.WARNING,
      'Front-channel access-token / implicit capability advertised',
      frontChannelTokenResponses.length
        ? `response_types_supported includes ${frontChannelTokenResponses.join(', ')}. Modern OAuth deployments should prefer authorization code with PKCE rather than returning access tokens from the authorization endpoint.`
        : 'grant_types_supported includes implicit. Modern OAuth deployments should prefer authorization code with PKCE.',
    ));
  }

  const tokenAuth = asArray(document.token_endpoint_auth_methods_supported).map(String);
  if (tokenAuth.includes('none')) findings.push(finding('oidc.discovery.public-clients', SEVERITY.INFO, 'Public-client token endpoint authentication advertised', 'token_endpoint_auth_methods_supported includes none; this can be appropriate for public clients when used with current flow protections such as PKCE.'));

  return {
    kind: 'oidc-discovery',
    summary: {
      issuer: document.issuer ?? '',
      authorizationEndpoint: document.authorization_endpoint ?? '',
      tokenEndpoint: document.token_endpoint ?? '',
      jwksUri: document.jwks_uri ?? '',
      userinfoEndpoint: document.userinfo_endpoint ?? '',
      registrationEndpoint: document.registration_endpoint ?? '',
      endSessionEndpoint: document.end_session_endpoint ?? '',
      responseTypes,
      grantTypes: asArray(document.grant_types_supported),
      scopes: asArray(document.scopes_supported),
      subjectTypes: asArray(document.subject_types_supported),
      idTokenAlgorithms: asArray(document.id_token_signing_alg_values_supported),
      codeChallengeMethods,
    },
    capabilities: {
      scopes,
      claims: asArray(document.claims_supported),
      responseTypes,
      responseModes: asArray(document.response_modes_supported),
      grantTypes: grants,
      subjectTypes: asArray(document.subject_types_supported),
      idTokenAlgorithms: signingAlgorithms,
      codeChallengeMethods,
      acrValues: asArray(document.acr_values_supported),
      tokenEndpointAuthMethods: tokenAuth,
      claimsParameterSupported: document.claims_parameter_supported ?? false,
      requestParameterSupported: document.request_parameter_supported ?? false,
      requestUriParameterSupported: document.request_uri_parameter_supported ?? true,
      requireRequestUriRegistration: document.require_request_uri_registration ?? false,
    },
    findings,
    raw: document,
  };
}
