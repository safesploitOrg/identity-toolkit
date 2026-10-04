function tryJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

function rootElementName(text) {
  const match = text.match(/^\s*(?:<\?xml[^>]*>\s*)?<([A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)\b/);
  return match ? match[2] : '';
}

export function detectInput(input) {
  const text = String(input ?? '').trim();
  if (!text) return { type: 'empty', confidence: 1, label: 'Empty input' };

  const segments = text.split('.');
  if (segments.length === 3 && segments.every((part) => /^[A-Za-z0-9_-]*$/.test(part))) {
    return { type: 'jwt', confidence: 0.98, label: 'JWT / compact JWS' };
  }

  if (text.startsWith('{') || text.startsWith('[')) {
    const parsed = tryJson(text);
    if (parsed && Array.isArray(parsed.keys)) return { type: 'jwks', confidence: 0.99, label: 'JSON Web Key Set' };
    if (parsed && typeof parsed === 'object' && parsed.kty) return { type: 'jwk', confidence: 0.99, label: 'JSON Web Key' };
    if (parsed && typeof parsed === 'object' && parsed.issuer && (parsed.authorization_endpoint || parsed.token_endpoint || parsed.jwks_uri)) {
      return { type: 'oidc-discovery', confidence: 0.99, label: 'OpenID Provider metadata' };
    }
    return { type: 'json', confidence: 0.7, label: 'JSON document' };
  }

  if (text.startsWith('<') || text.startsWith('<?xml')) {
    const root = rootElementName(text);
    if (root === 'Response' || root === 'Assertion') return { type: 'saml', confidence: 0.95, label: `SAML ${root}` };
    if (root === 'RequestSecurityTokenResponse' || root === 'RequestSecurityTokenResponseCollection') return { type: 'wsfed', confidence: 0.96, label: 'WS-Federation / WS-Trust token response' };
    if (root === 'EntityDescriptor' || root === 'EntitiesDescriptor') return { type: 'saml-metadata', confidence: 0.98, label: 'SAML 2.0 metadata' };
    return { type: 'xml', confidence: 0.65, label: `XML document${root ? ` (${root})` : ''}` };
  }

  return { type: 'unknown', confidence: 0.2, label: 'Unknown input' };
}
