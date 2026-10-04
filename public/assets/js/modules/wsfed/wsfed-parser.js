import { analyseXmlWindow } from '../validation/time.js';
import { finding, SEVERITY } from '../validation/findings.js';
import { descendants, firstDescendant, parseXml, serializeXml, textOf } from '../saml/xml-utils.js';
import { parseSaml, SAML_ASSERTION_NS } from '../saml/saml-parser.js';
import { parseSaml11Assertion, SAML11_ASSERTION_NS } from '../saml/saml11-parser.js';

function local(element) {
  return element?.localName || element?.nodeName || '';
}

function findDescendantByLocal(node, name) {
  return descendants(node, name)[0] ?? null;
}

function addressInside(node) {
  if (!node) return '';
  return textOf(findDescendantByLocal(node, 'Address'));
}

function parseLifetime(node) {
  const lifetime = findDescendantByLocal(node, 'Lifetime');
  return {
    created: lifetime ? textOf(findDescendantByLocal(lifetime, 'Created')) : '',
    expires: lifetime ? textOf(findDescendantByLocal(lifetime, 'Expires')) : '',
  };
}

function requestedSecurityToken(node) {
  const container = findDescendantByLocal(node, 'RequestedSecurityToken');
  if (!container) return null;
  return Array.from(container.childNodes ?? []).find((child) => child.nodeType === 1) ?? null;
}

function parseResponse(rstr, options) {
  const findings = [];
  const token = requestedSecurityToken(rstr);
  let saml = null;
  let saml11 = null;

  if (!token) {
    findings.push(finding('wsfed.token.missing', SEVERITY.ERROR, 'Requested security token missing', 'No assertion/token element was found inside RequestedSecurityToken.'));
  } else if (local(token) === 'Assertion' && token.namespaceURI === SAML_ASSERTION_NS) {
    saml = parseSaml(serializeXml(token), options);
    findings.push(...saml.findings.map((item) => ({ ...item, id: `wsfed.${item.id}` })));
  } else if (local(token) === 'Assertion' && token.namespaceURI === SAML11_ASSERTION_NS) {
    saml11 = parseSaml11Assertion(token, options);
    findings.push(...saml11.findings.map((item) => ({ ...item, id: `wsfed.${item.id}` })));
    findings.push(finding('wsfed.saml11', SEVERITY.INFO, 'Embedded SAML 1.x assertion detected', 'WS-Federation deployments commonly carry SAML 1.x assertions. Identity Toolkit applies the WS-Trust envelope checks and a dedicated SAML 1.x assertion parser.'));
  } else {
    findings.push(finding('wsfed.token.unsupported', SEVERITY.INDETERMINATE, 'Requested security token type is not implemented', `${local(token)} (${token.namespaceURI || 'no namespace'})`));
  }

  const appliesTo = findDescendantByLocal(rstr, 'AppliesTo');
  const lifetime = parseLifetime(rstr);
  const summary = {
    tokenType: textOf(findDescendantByLocal(rstr, 'TokenType')),
    requestType: textOf(findDescendantByLocal(rstr, 'RequestType')),
    appliesTo: addressInside(appliesTo),
    created: lifetime.created,
    expires: lifetime.expires,
    keyType: textOf(findDescendantByLocal(rstr, 'KeyType')),
    keySize: textOf(findDescendantByLocal(rstr, 'KeySize')),
    computedKey: textOf(findDescendantByLocal(rstr, 'ComputedKey')),
    assertionVersion: saml ? '2.0' : saml11?.assertion?.version ?? '',
    assertionIssuer: saml?.assertions?.[0]?.issuer ?? saml11?.assertion?.issuer ?? '',
    audience: saml?.assertions?.[0]?.conditions?.audiences ?? saml11?.assertion?.conditions?.audiences ?? [],
  };

  findings.push(...analyseXmlWindow(lifetime.created, lifetime.expires, options.now, options.clockSkewSeconds).map((item) => ({ ...item, id: `wsfed.lifetime.${item.id}` })));

  if (options.expectedAudience && summary.appliesTo) {
    findings.push(finding(
      'wsfed.applies_to.expected',
      summary.appliesTo === options.expectedAudience ? SEVERITY.PASS : SEVERITY.WARNING,
      summary.appliesTo === options.expectedAudience ? 'WS-Trust AppliesTo matches expected resource' : 'WS-Trust AppliesTo differs from expected audience',
      `Expected ${options.expectedAudience}; AppliesTo=${summary.appliesTo}. The embedded assertion audience is validated separately.`,
    ));
  }

  const attachedReference = findDescendantByLocal(rstr, 'RequestedAttachedReference');
  const unattachedReference = findDescendantByLocal(rstr, 'RequestedUnattachedReference');
  return {
    summary,
    saml,
    saml11,
    claims: saml?.assertions?.[0]?.attributes ?? saml11?.assertion?.attributes ?? [],
    attachedReference: attachedReference ? serializeXml(attachedReference) : '',
    unattachedReference: unattachedReference ? serializeXml(unattachedReference) : '',
    findings,
  };
}

export function parseWsFed(text, options = {}) {
  const doc = parseXml(text);
  const rootName = local(doc.documentElement);
  if (!['RequestSecurityTokenResponse', 'RequestSecurityTokenResponseCollection'].includes(rootName)) {
    throw new Error(`Expected WS-Trust RequestSecurityTokenResponse or collection; found ${rootName}.`);
  }

  const rstrs = rootName === 'RequestSecurityTokenResponse'
    ? [doc.documentElement]
    : descendants(doc, 'RequestSecurityTokenResponse').filter((item) => item !== doc.documentElement);
  if (!rstrs.length) throw new Error('WS-Trust response collection does not contain a RequestSecurityTokenResponse.');

  const responses = rstrs.map((rstr) => parseResponse(rstr, options));
  const findings = responses.flatMap((response, index) => response.findings.map((item) => ({ ...item, id: `wsfed.rstr${index}.${item.id}` })));
  if (responses.length > 1) findings.push(finding('wsfed.rstr.multiple', SEVERITY.INFO, 'Multiple token responses present', `The collection contains ${responses.length} RequestSecurityTokenResponse elements.`));
  findings.push(finding('wsfed.parsed', SEVERITY.INFO, 'WS-Federation / WS-Trust response parsed', 'WS-Trust envelope fields, token lifetime, AppliesTo and embedded SAML assertion semantics are analysed as separate dimensions.'));

  const first = responses[0];
  return {
    kind: 'wsfed',
    summary: { ...first.summary, responseCount: responses.length },
    responses,
    saml: first.saml,
    saml11: first.saml11,
    claims: first.claims,
    findings,
    raw: text,
  };
}
