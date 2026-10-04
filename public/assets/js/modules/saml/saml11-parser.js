import { analyseXmlWindow } from '../validation/time.js';
import { finding, SEVERITY } from '../validation/findings.js';
import { attr, childElementsNs, descendantsNs, firstDescendantNs, textOf } from './xml-utils.js';

export const SAML11_ASSERTION_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';
const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

function parseAttributes(assertion) {
  return descendantsNs(assertion, 'Attribute', SAML11_ASSERTION_NS).map((element) => {
    const name = attr(element, 'AttributeName');
    const namespace = attr(element, 'AttributeNamespace');
    return {
      name: namespace && name && !/^https?:|^urn:/.test(name) ? `${namespace.replace(/\/$/, '')}/${name}` : name,
      rawName: name,
      namespace,
      nameFormat: '',
      friendlyName: name,
      values: childElementsNs(element, 'AttributeValue', SAML11_ASSERTION_NS).map(textOf),
    };
  });
}

export function parseSaml11Assertion(assertion, options = {}) {
  if (!assertion || assertion.namespaceURI !== SAML11_ASSERTION_NS || (assertion.localName || assertion.nodeName) !== 'Assertion') {
    throw new Error('Expected a SAML 1.x Assertion element.');
  }
  const conditions = firstDescendantNs(assertion, 'Conditions', SAML11_ASSERTION_NS);
  const authn = firstDescendantNs(assertion, 'AuthenticationStatement', SAML11_ASSERTION_NS);
  const nameIdentifier = firstDescendantNs(assertion, 'NameIdentifier', SAML11_ASSERTION_NS);
  const audiences = descendantsNs(assertion, 'Audience', SAML11_ASSERTION_NS).map(textOf).filter(Boolean);
  const findings = analyseXmlWindow(attr(conditions, 'NotBefore'), attr(conditions, 'NotOnOrAfter'), options.now, options.clockSkewSeconds);

  if (options.expectedAudience) {
    findings.push(finding(
      'saml11.audience.expected',
      audiences.includes(options.expectedAudience) ? SEVERITY.PASS : SEVERITY.ERROR,
      audiences.includes(options.expectedAudience) ? 'SAML 1.x audience matches expectation' : 'SAML 1.x audience mismatch',
      audiences.includes(options.expectedAudience)
        ? options.expectedAudience
        : `Expected ${options.expectedAudience}; assertion contains ${audiences.join(', ') || '(none)'}.`,
    ));
  }

  const parsed = {
    version: `${attr(assertion, 'MajorVersion') || '1'}.${attr(assertion, 'MinorVersion') || '1'}`,
    id: attr(assertion, 'AssertionID') || attr(assertion, 'ID') || attr(assertion, 'Id') || attr(assertion, 'id'),
    issuer: attr(assertion, 'Issuer'),
    issueInstant: attr(assertion, 'IssueInstant'),
    subject: {
      nameId: textOf(nameIdentifier),
      nameIdFormat: attr(nameIdentifier, 'Format'),
      nameQualifier: attr(nameIdentifier, 'NameQualifier'),
    },
    conditions: {
      notBefore: attr(conditions, 'NotBefore'),
      notOnOrAfter: attr(conditions, 'NotOnOrAfter'),
      audiences,
    },
    authn: {
      authnInstant: attr(authn, 'AuthenticationInstant'),
      method: attr(authn, 'AuthenticationMethod'),
    },
    attributes: parseAttributes(assertion),
    signatureCount: descendantsNs(assertion, 'Signature', XMLDSIG_NS).length,
  };

  if (options.expectedIssuer) {
    findings.push(finding(
      'saml11.issuer.expected',
      parsed.issuer === options.expectedIssuer ? SEVERITY.PASS : SEVERITY.ERROR,
      parsed.issuer === options.expectedIssuer ? 'SAML 1.x issuer matches expectation' : 'SAML 1.x issuer mismatch',
      `Expected ${options.expectedIssuer}; assertion contains ${parsed.issuer || '(none)'}.`,
    ));
  }

  return { assertion: parsed, findings };
}
