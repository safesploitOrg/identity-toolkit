import { analyseXmlWindow } from '../validation/time.js';
import { finding, SEVERITY } from '../validation/findings.js';
import {
  attr,
  childElementsNs,
  descendantsNs,
  firstChildNs,
  firstDescendantNs,
  parseXml,
  textOf,
} from './xml-utils.js';

export const SAML_ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
export const SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
export const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const SUCCESS_STATUS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

function elementId(element) {
  return attr(element, 'ID') || attr(element, 'Id') || attr(element, 'id');
}

function parseAttributes(assertion) {
  return descendantsNs(assertion, 'Attribute', SAML_ASSERTION_NS).map((element) => ({
    name: attr(element, 'Name') || attr(element, 'FriendlyName'),
    nameFormat: attr(element, 'NameFormat'),
    friendlyName: attr(element, 'FriendlyName'),
    values: childElementsNs(element, 'AttributeValue', SAML_ASSERTION_NS).map(textOf),
  }));
}

function parseSubject(assertion) {
  const subject = firstDescendantNs(assertion, 'Subject', SAML_ASSERTION_NS);
  const nameId = subject ? firstDescendantNs(subject, 'NameID', SAML_ASSERTION_NS) : null;
  const confirmations = subject ? descendantsNs(subject, 'SubjectConfirmation', SAML_ASSERTION_NS).map((confirmation) => {
    const data = firstDescendantNs(confirmation, 'SubjectConfirmationData', SAML_ASSERTION_NS);
    return {
      method: attr(confirmation, 'Method'),
      recipient: attr(data, 'Recipient'),
      inResponseTo: attr(data, 'InResponseTo'),
      notBefore: attr(data, 'NotBefore'),
      notOnOrAfter: attr(data, 'NotOnOrAfter'),
      address: attr(data, 'Address'),
      hasKeyInfo: descendantsNs(confirmation, 'KeyInfo', XMLDSIG_NS).length > 0,
    };
  }) : [];
  return {
    nameId: textOf(nameId),
    nameIdFormat: attr(nameId, 'Format'),
    nameQualifier: attr(nameId, 'NameQualifier'),
    spNameQualifier: attr(nameId, 'SPNameQualifier'),
    confirmations,
  };
}

function parseConditions(assertion) {
  const conditions = firstDescendantNs(assertion, 'Conditions', SAML_ASSERTION_NS);
  if (!conditions) return { notBefore: '', notOnOrAfter: '', audiences: [], audienceRestrictions: [], oneTimeUse: false, proxyRestriction: null, unknown: [] };
  const restrictionElements = childElementsNs(conditions, 'AudienceRestriction', SAML_ASSERTION_NS);
  const audienceRestrictions = restrictionElements.map((restriction) => childElementsNs(restriction, 'Audience', SAML_ASSERTION_NS).map(textOf).filter(Boolean));
  const oneTimeUse = childElementsNs(conditions, 'OneTimeUse', SAML_ASSERTION_NS).length > 0;
  const proxy = childElementsNs(conditions, 'ProxyRestriction', SAML_ASSERTION_NS)[0] ?? null;
  const known = new Set(['AudienceRestriction', 'OneTimeUse', 'ProxyRestriction']);
  const unknown = Array.from(conditions.childNodes ?? [])
    .filter((node) => node.nodeType === 1 && node.namespaceURI === SAML_ASSERTION_NS && !known.has(node.localName || node.nodeName))
    .map((node) => node.localName || node.nodeName);
  return {
    notBefore: attr(conditions, 'NotBefore'),
    notOnOrAfter: attr(conditions, 'NotOnOrAfter'),
    audiences: audienceRestrictions.flat(),
    audienceRestrictions,
    oneTimeUse,
    proxyRestriction: proxy ? {
      count: attr(proxy, 'Count'),
      audiences: childElementsNs(proxy, 'Audience', SAML_ASSERTION_NS).map(textOf).filter(Boolean),
    } : null,
    unknown,
  };
}

function parseAuthnStatements(assertion) {
  return descendantsNs(assertion, 'AuthnStatement', SAML_ASSERTION_NS).map((statement) => {
    const context = firstDescendantNs(statement, 'AuthnContext', SAML_ASSERTION_NS);
    return {
      authnInstant: attr(statement, 'AuthnInstant'),
      sessionIndex: attr(statement, 'SessionIndex'),
      sessionNotOnOrAfter: attr(statement, 'SessionNotOnOrAfter'),
      contextClass: textOf(firstDescendantNs(context ?? statement, 'AuthnContextClassRef', SAML_ASSERTION_NS)),
      contextDecl: textOf(firstDescendantNs(context ?? statement, 'AuthnContextDeclRef', SAML_ASSERTION_NS)),
      authenticatingAuthorities: descendantsNs(context ?? statement, 'AuthenticatingAuthority', SAML_ASSERTION_NS).map(textOf).filter(Boolean),
    };
  });
}

function parseAssertion(assertion) {
  const authnStatements = parseAuthnStatements(assertion);
  return {
    id: elementId(assertion),
    version: attr(assertion, 'Version'),
    issuer: textOf(firstChildNs(assertion, 'Issuer', SAML_ASSERTION_NS)) || textOf(firstDescendantNs(assertion, 'Issuer', SAML_ASSERTION_NS)),
    issueInstant: attr(assertion, 'IssueInstant'),
    subject: parseSubject(assertion),
    conditions: parseConditions(assertion),
    authnStatements,
    authn: authnStatements[0] ?? { authnInstant: '', sessionIndex: '', sessionNotOnOrAfter: '', contextClass: '', contextDecl: '', authenticatingAuthorities: [] },
    attributes: parseAttributes(assertion),
    signatureCount: descendantsNs(assertion, 'Signature', XMLDSIG_NS).length,
  };
}

function duplicateIds(doc) {
  const seen = new Map();
  const elements = [doc.documentElement, ...Array.from(doc.getElementsByTagName('*'))].filter(Boolean);
  for (const element of elements) {
    const value = elementId(element);
    if (!value) continue;
    const items = seen.get(value) ?? [];
    items.push(element.localName || element.nodeName);
    seen.set(value, items);
  }
  return [...seen.entries()].filter(([, names]) => names.length > 1).map(([id, names]) => ({ id, elements: names }));
}

function signatureReferences(doc) {
  return descendantsNs(doc, 'Signature', XMLDSIG_NS).map((signature, index) => {
    const parent = signature.parentNode;
    return {
      index,
      parent: parent?.localName || parent?.nodeName || '',
      parentNamespace: parent?.namespaceURI || '',
      parentId: elementId(parent),
      references: descendantsNs(signature, 'Reference', XMLDSIG_NS).map((reference) => ({
        uri: attr(reference, 'URI'),
        transforms: descendantsNs(reference, 'Transform', XMLDSIG_NS).map((item) => attr(item, 'Algorithm')).filter(Boolean),
        digestMethod: attr(firstDescendantNs(reference, 'DigestMethod', XMLDSIG_NS), 'Algorithm'),
      })),
      canonicalizationMethod: attr(firstDescendantNs(signature, 'CanonicalizationMethod', XMLDSIG_NS), 'Algorithm'),
      signatureMethod: attr(firstDescendantNs(signature, 'SignatureMethod', XMLDSIG_NS), 'Algorithm'),
      certificates: descendantsNs(signature, 'X509Certificate', XMLDSIG_NS).map(textOf).filter(Boolean),
      keyNames: descendantsNs(signature, 'KeyName', XMLDSIG_NS).map(textOf).filter(Boolean),
    };
  });
}

function rootType(root) {
  const localName = root.localName || root.nodeName;
  if (localName === 'Response' && root.namespaceURI === SAML_PROTOCOL_NS) return 'Response';
  if (localName === 'Assertion' && root.namespaceURI === SAML_ASSERTION_NS) return 'Assertion';
  throw new Error(`Expected a SAML 2.0 Response or Assertion in the SAML namespace; found ${localName} (${root.namespaceURI || 'no namespace'}).`);
}

function addAudienceFindings(findings, conditions, expectedAudience) {
  if (!expectedAudience) return;
  if (!conditions.audienceRestrictions.length) {
    findings.push(finding('saml.audience.missing', SEVERITY.ERROR, 'No AudienceRestriction found', `Expected audience ${expectedAudience} was supplied, but the assertion contains no AudienceRestriction condition.`));
    return;
  }
  const failing = conditions.audienceRestrictions.filter((group) => !group.includes(expectedAudience));
  findings.push(finding(
    'saml.audience.expected',
    failing.length ? SEVERITY.ERROR : SEVERITY.PASS,
    failing.length ? 'SAML audience restriction mismatch' : 'SAML audience restrictions match expectation',
    failing.length
      ? `The expected audience must satisfy every AudienceRestriction. ${failing.length} restriction group(s) do not contain ${expectedAudience}.`
      : `Every AudienceRestriction contains ${expectedAudience}.`,
    { expected: expectedAudience, restrictions: conditions.audienceRestrictions },
  ));
}

function addSubjectConfirmationFindings(findings, assertion, options) {
  const confirmations = assertion.subject.confirmations;
  if (!confirmations.length) {
    findings.push(finding('saml.subject_confirmation.missing', SEVERITY.INFO, 'No SubjectConfirmation element found', 'Whether SubjectConfirmation is required depends on the SAML profile and assertion use.'));
    return;
  }

  const now = options.now ? new Date(options.now) : new Date();
  const skewMs = Math.max(0, Number(options.clockSkewSeconds) || 0) * 1000;
  confirmations.forEach((confirmation, index) => {
    if (confirmation.notOnOrAfter) {
      const end = Date.parse(confirmation.notOnOrAfter);
      if (Number.isNaN(end)) findings.push(finding(`saml.subject_confirmation.${index}.time.invalid`, SEVERITY.WARNING, 'Invalid SubjectConfirmationData NotOnOrAfter', confirmation.notOnOrAfter));
      else if (now.getTime() - skewMs >= end) findings.push(finding(`saml.subject_confirmation.${index}.expired`, SEVERITY.ERROR, 'SubjectConfirmationData has expired', confirmation.notOnOrAfter));
      else findings.push(finding(`saml.subject_confirmation.${index}.time`, SEVERITY.PASS, 'SubjectConfirmationData is current', confirmation.notOnOrAfter));
    }
    if (options.expectedRecipient) {
      findings.push(finding(
        `saml.subject_confirmation.${index}.recipient`,
        confirmation.recipient === options.expectedRecipient ? SEVERITY.PASS : SEVERITY.ERROR,
        confirmation.recipient === options.expectedRecipient ? 'SubjectConfirmation recipient matches' : 'SubjectConfirmation recipient mismatch',
        `Expected ${options.expectedRecipient}; assertion contains ${confirmation.recipient || '(none)'}.`,
      ));
    }
    if (options.expectedInResponseTo) {
      findings.push(finding(
        `saml.subject_confirmation.${index}.inresponseto`,
        confirmation.inResponseTo === options.expectedInResponseTo ? SEVERITY.PASS : SEVERITY.ERROR,
        confirmation.inResponseTo === options.expectedInResponseTo ? 'SubjectConfirmation InResponseTo matches' : 'SubjectConfirmation InResponseTo mismatch',
        `Expected ${options.expectedInResponseTo}; assertion contains ${confirmation.inResponseTo || '(none)'}.`,
      ));
    }
  });
}

function addSignatureCoverageFindings(findings, signatures, root, assertions) {
  for (const signature of signatures) {
    const external = signature.references.filter((reference) => reference.uri && !reference.uri.startsWith('#'));
    if (external.length) findings.push(finding('saml.signature.external-reference', SEVERITY.ERROR, 'External XML signature reference rejected', 'A ds:Reference points outside this XML document. Identity Toolkit will not dereference external resources.', external));
    if (!signature.parentId) {
      findings.push(finding(`saml.signature.${signature.index}.parent-id`, SEVERITY.WARNING, 'Signed parent has no XML ID', `Signature #${signature.index + 1} is directly under ${signature.parent}, which has no ID/Id/id attribute.`));
      continue;
    }
    const expectedUri = `#${signature.parentId}`;
    const coversParent = signature.references.some((reference) => reference.uri === expectedUri);
    findings.push(finding(
      `saml.signature.${signature.index}.coverage`,
      coversParent ? SEVERITY.PASS : SEVERITY.WARNING,
      coversParent ? `Signature references parent ${signature.parent}` : `Signature does not reference its parent ${signature.parent}`,
      coversParent ? `${expectedUri} is present in ds:Reference.` : `Expected a reference to ${expectedUri}; actual references: ${signature.references.map((item) => item.uri || '(empty)').join(', ')}.`,
    ));
  }

  const protectedIds = new Set(signatures.flatMap((signature) => signature.references.map((reference) => reference.uri?.startsWith('#') ? reference.uri.slice(1) : '')).filter(Boolean));
  const rootId = elementId(root);
  const assertionIds = assertions.map(elementId).filter(Boolean);
  if (signatures.length && rootId && protectedIds.has(rootId)) findings.push(finding('saml.signature.response-protected', SEVERITY.PASS, 'SAML Response is referenced by a signature', `Response ID ${rootId} is a ds:Reference target.`));
  if (assertionIds.length) {
    const protectedAssertions = assertionIds.filter((id) => protectedIds.has(id));
    if (protectedAssertions.length) findings.push(finding('saml.signature.assertion-protected', SEVERITY.PASS, `${protectedAssertions.length} assertion(s) are signature reference targets`, protectedAssertions.join(', ')));
    if (signatures.length && !rootId && !protectedAssertions.length) findings.push(finding('saml.signature.coverage.unknown', SEVERITY.WARNING, 'Signature coverage does not clearly bind Response/Assertion IDs', 'Cryptographic verification alone is not enough; the relying party must ensure it consumes the exact signed element.'));
  }
}

export function parseSaml(text, options = {}) {
  const doc = parseXml(text);
  const root = doc.documentElement;
  const rootName = rootType(root);
  const assertions = rootName === 'Assertion' ? [root] : descendantsNs(root, 'Assertion', SAML_ASSERTION_NS);
  const encryptedAssertions = rootName === 'Response' ? descendantsNs(root, 'EncryptedAssertion', SAML_ASSERTION_NS) : [];
  const parsedAssertions = assertions.map(parseAssertion);
  const findings = [];
  const duplicates = duplicateIds(doc);
  const signatures = signatureReferences(doc);

  if (!assertions.length && !encryptedAssertions.length) findings.push(finding('saml.assertion.missing', SEVERITY.ERROR, 'No SAML Assertion found', 'The SAML Response does not contain a SAML 2.0 Assertion or EncryptedAssertion element.'));
  if (encryptedAssertions.length) findings.push(finding('saml.assertion.encrypted', SEVERITY.INDETERMINATE, `${encryptedAssertions.length} EncryptedAssertion element(s) found`, 'Identity Toolkit does not possess decryption keys, so encrypted assertion contents cannot be semantically analysed.'));
  if (assertions.length > 1) findings.push(finding('saml.assertion.multiple', SEVERITY.WARNING, 'Multiple assertions present', `The response contains ${assertions.length} Assertion elements. The relying party must bind validation and claim consumption to the intended signed assertion.`));
  if (duplicates.length) findings.push(finding('saml.id.duplicate', SEVERITY.ERROR, 'Duplicate XML IDs detected', 'Duplicate ID attributes can create signature-wrapping ambiguity and are rejected by this toolkit.', duplicates));
  else findings.push(finding('saml.id.unique', SEVERITY.PASS, 'No duplicate XML IDs detected', 'All discovered ID/Id/id values are unique.'));

  if (!signatures.length) findings.push(finding('saml.signature.missing', SEVERITY.WARNING, 'No XML Signature found', 'The document contains no XMLDSig ds:Signature element. Whether this is acceptable depends on the binding/profile and trust model.'));
  else findings.push(finding('saml.signature.present', SEVERITY.INFO, `${signatures.length} XML Signature element(s) found`, 'Cryptographic verification, certificate trust and signed-element coverage are evaluated as separate dimensions.'));
  addSignatureCoverageFindings(findings, signatures, root, assertions);

  const responseIssuer = rootName === 'Response' ? textOf(firstChildNs(root, 'Issuer', SAML_ASSERTION_NS)) : '';
  const statusCodeElements = rootName === 'Response' ? descendantsNs(root, 'StatusCode', SAML_PROTOCOL_NS) : [];
  const statusCodes = statusCodeElements.map((element) => attr(element, 'Value')).filter(Boolean);
  const statusMessage = rootName === 'Response' ? textOf(firstDescendantNs(root, 'StatusMessage', SAML_PROTOCOL_NS)) : '';
  const summary = {
    type: rootName,
    id: elementId(root),
    version: attr(root, 'Version'),
    issuer: responseIssuer || parsedAssertions[0]?.issuer || '',
    issueInstant: attr(root, 'IssueInstant'),
    destination: attr(root, 'Destination'),
    consent: attr(root, 'Consent'),
    inResponseTo: attr(root, 'InResponseTo'),
    statusCode: statusCodes[0] ?? '',
    statusCodes,
    statusMessage,
    assertionCount: assertions.length,
    encryptedAssertionCount: encryptedAssertions.length,
    signatureCount: signatures.length,
  };

  if (rootName === 'Response') {
    if (summary.version && summary.version !== '2.0') findings.push(finding('saml.version', SEVERITY.ERROR, 'Unexpected SAML Response version', `Version=${summary.version}; expected 2.0.`));
    if (summary.statusCode) findings.push(finding('saml.status', summary.statusCode === SUCCESS_STATUS ? SEVERITY.PASS : SEVERITY.ERROR, summary.statusCode === SUCCESS_STATUS ? 'SAML response status is Success' : 'SAML response status is not Success', `${summary.statusCode}${statusMessage ? ` — ${statusMessage}` : ''}`));
    if (options.expectedRecipient) findings.push(finding('saml.destination.expected', summary.destination === options.expectedRecipient ? SEVERITY.PASS : SEVERITY.ERROR, summary.destination === options.expectedRecipient ? 'Response Destination matches' : 'Response Destination mismatch', `Expected ${options.expectedRecipient}; response contains ${summary.destination || '(none)'}.`));
    if (options.expectedInResponseTo) findings.push(finding('saml.inresponseto.expected', summary.inResponseTo === options.expectedInResponseTo ? SEVERITY.PASS : SEVERITY.ERROR, summary.inResponseTo === options.expectedInResponseTo ? 'Response InResponseTo matches' : 'Response InResponseTo mismatch', `Expected ${options.expectedInResponseTo}; response contains ${summary.inResponseTo || '(none)'}.`));
  }

  for (const assertion of parsedAssertions) {
    if (assertion.version && assertion.version !== '2.0') findings.push(finding('saml.assertion.version', SEVERITY.ERROR, 'Unexpected Assertion version', `Version=${assertion.version}; expected 2.0.`));
    findings.push(...analyseXmlWindow(assertion.conditions.notBefore, assertion.conditions.notOnOrAfter, options.now, options.clockSkewSeconds));
    addAudienceFindings(findings, assertion.conditions, options.expectedAudience);
    addSubjectConfirmationFindings(findings, assertion, options);
    if (assertion.conditions.oneTimeUse) findings.push(finding('saml.condition.one_time_use', SEVERITY.INFO, 'OneTimeUse condition present', 'The assertion declares OneTimeUse. Identity Toolkit cannot inspect a relying party replay cache, so enforcement is not verified.'));
    if (assertion.conditions.proxyRestriction) findings.push(finding('saml.condition.proxy_restriction', SEVERITY.INFO, 'ProxyRestriction condition present', JSON.stringify(assertion.conditions.proxyRestriction)));
    if (assertion.conditions.unknown.length) findings.push(finding('saml.condition.unknown', SEVERITY.INDETERMINATE, 'Unrecognised SAML Conditions present', `Unsupported condition elements: ${assertion.conditions.unknown.join(', ')}. Identity Toolkit will not claim complete semantic validation.`));
    if (options.expectedIssuer) {
      const issuer = assertion.issuer || summary.issuer;
      if (issuer === options.expectedIssuer) findings.push(finding('saml.issuer.expected', SEVERITY.PASS, 'SAML issuer matches expectation', issuer));
      else findings.push(finding('saml.issuer.mismatch', SEVERITY.ERROR, 'SAML issuer mismatch', 'The SAML issuer does not match the expected issuer.', { expected: options.expectedIssuer, actual: issuer }));
    }
  }

  return {
    kind: 'saml',
    document: doc,
    summary,
    assertions: parsedAssertions,
    duplicateIds: duplicates,
    signatures,
    findings,
    raw: text,
  };
}
