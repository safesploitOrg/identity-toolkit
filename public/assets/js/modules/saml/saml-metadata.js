import { finding, SEVERITY } from '../validation/findings.js';
import { attr, childElementsNs, descendantsNs, parseXml, textOf } from './xml-utils.js';

const SAML_METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';
const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const SAML_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

function parseBoolean(value) {
  if (value === '') return null;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  return value;
}

function serviceList(entity, localName) {
  return descendantsNs(entity, localName, SAML_METADATA_NS).map((service) => ({
    binding: attr(service, 'Binding'),
    location: attr(service, 'Location'),
    responseLocation: attr(service, 'ResponseLocation'),
    index: attr(service, 'index'),
    isDefault: parseBoolean(attr(service, 'isDefault')),
  }));
}

function parseKeyDescriptors(entity) {
  return descendantsNs(entity, 'KeyDescriptor', SAML_METADATA_NS).map((descriptor) => ({
    use: attr(descriptor, 'use') || 'unspecified',
    certificates: descendantsNs(descriptor, 'X509Certificate', XMLDSIG_NS).map(textOf).filter(Boolean),
    encryptionMethods: descendantsNs(descriptor, 'EncryptionMethod', XMLDSIG_NS).map((item) => attr(item, 'Algorithm')).filter(Boolean),
  }));
}

function parseRequestedAttributes(spDescriptor) {
  if (!spDescriptor) return [];
  return descendantsNs(spDescriptor, 'RequestedAttribute', SAML_METADATA_NS).map((attribute) => ({
    name: attr(attribute, 'Name'),
    friendlyName: attr(attribute, 'FriendlyName'),
    nameFormat: attr(attribute, 'NameFormat'),
    isRequired: parseBoolean(attr(attribute, 'isRequired')),
    values: childElementsNs(attribute, 'AttributeValue', 'urn:oasis:names:tc:SAML:2.0:assertion').map(textOf),
  }));
}

function roleProtocols(role) {
  return String(attr(role, 'protocolSupportEnumeration') || '').split(/\s+/).filter(Boolean);
}

export function analyseSamlMetadata(text, options = {}) {
  const doc = parseXml(text);
  const root = doc.documentElement;
  const rootName = root.localName || root.nodeName;
  if (!['EntityDescriptor', 'EntitiesDescriptor'].includes(rootName) || root.namespaceURI !== SAML_METADATA_NS) {
    throw new Error(`Expected SAML 2.0 metadata EntityDescriptor/EntitiesDescriptor; found ${rootName} (${root.namespaceURI || 'no namespace'}).`);
  }

  const entities = rootName === 'EntityDescriptor' ? [root] : descendantsNs(doc, 'EntityDescriptor', SAML_METADATA_NS);
  const findings = [];
  if (!entities.length) throw new Error('No EntityDescriptor was found in the SAML metadata.');

  const parsed = entities.map((entity) => {
    const idp = descendantsNs(entity, 'IDPSSODescriptor', SAML_METADATA_NS)[0] ?? null;
    const sp = descendantsNs(entity, 'SPSSODescriptor', SAML_METADATA_NS)[0] ?? null;
    const aa = descendantsNs(entity, 'AttributeAuthorityDescriptor', SAML_METADATA_NS)[0] ?? null;
    const authnAuthority = descendantsNs(entity, 'AuthnAuthorityDescriptor', SAML_METADATA_NS)[0] ?? null;
    const pdp = descendantsNs(entity, 'PDPDescriptor', SAML_METADATA_NS)[0] ?? null;
    const keyDescriptors = parseKeyDescriptors(entity);
    const roles = [idp ? 'IdP' : '', sp ? 'SP' : '', aa ? 'AttributeAuthority' : '', authnAuthority ? 'AuthnAuthority' : '', pdp ? 'PDP' : ''].filter(Boolean);
    return {
      entityId: attr(entity, 'entityID'),
      id: attr(entity, 'ID'),
      validUntil: attr(entity, 'validUntil') || attr(root, 'validUntil'),
      cacheDuration: attr(entity, 'cacheDuration') || attr(root, 'cacheDuration'),
      roles,
      roleProtocols: {
        idp: roleProtocols(idp),
        sp: roleProtocols(sp),
      },
      wantAuthnRequestsSigned: parseBoolean(attr(idp, 'WantAuthnRequestsSigned')),
      authnRequestsSigned: parseBoolean(attr(sp, 'AuthnRequestsSigned')),
      wantAssertionsSigned: parseBoolean(attr(sp, 'WantAssertionsSigned')),
      ssoServices: serviceList(entity, 'SingleSignOnService'),
      sloServices: serviceList(entity, 'SingleLogoutService'),
      acsServices: serviceList(entity, 'AssertionConsumerService'),
      artifactResolutionServices: serviceList(entity, 'ArtifactResolutionService'),
      nameIdFormats: descendantsNs(entity, 'NameIDFormat', SAML_METADATA_NS).map(textOf),
      keys: keyDescriptors,
      requestedAttributes: parseRequestedAttributes(sp),
      signatureCount: descendantsNs(entity, 'Signature', XMLDSIG_NS).length,
    };
  });

  const duplicateEntityIds = parsed.map((item) => item.entityId).filter((id, index, all) => id && all.indexOf(id) !== index);
  if (duplicateEntityIds.length) findings.push(finding('saml.metadata.entity.duplicate', SEVERITY.ERROR, 'Duplicate entityID values', [...new Set(duplicateEntityIds)].join(', ')));
  findings.push(finding('saml.metadata.entities', SEVERITY.INFO, `${parsed.length} SAML metadata entity descriptor(s)`, 'Metadata was parsed locally; embedded signing certificates are displayed but are not assumed trusted.'));

  const now = options.now ? new Date(options.now) : new Date();
  for (const entity of parsed) {
    if (!entity.entityId) findings.push(finding('saml.metadata.entityid.missing', SEVERITY.ERROR, 'EntityDescriptor has no entityID', 'SAML metadata EntityDescriptor requires an entityID.'));
    const validUntil = entity.validUntil ? Date.parse(entity.validUntil) : NaN;
    if (entity.validUntil && Number.isNaN(validUntil)) findings.push(finding('saml.metadata.validuntil.invalid', SEVERITY.WARNING, 'Metadata validUntil is invalid', entity.validUntil));
    else if (Number.isFinite(validUntil) && now.getTime() >= validUntil) findings.push(finding('saml.metadata.expired', SEVERITY.ERROR, 'SAML metadata has expired', `${entity.entityId || '(unknown entity)'} validUntil=${entity.validUntil}`));
    else if (Number.isFinite(validUntil)) findings.push(finding('saml.metadata.validuntil', SEVERITY.PASS, 'SAML metadata is within validUntil', `${entity.entityId || '(unknown entity)'} validUntil=${entity.validUntil}`));

    const protocols = [...new Set([...entity.roleProtocols.idp, ...entity.roleProtocols.sp])];
    if (protocols.length && !protocols.includes(SAML_PROTOCOL)) findings.push(finding('saml.metadata.protocol', SEVERITY.WARNING, 'SAML 2.0 protocol support not advertised', `${entity.entityId}: ${protocols.join(', ')}`));

    const signingCertCount = entity.keys.filter((key) => key.use === 'signing' || key.use === 'unspecified').reduce((count, key) => count + key.certificates.length, 0);
    if ((entity.roles.includes('IdP') || entity.roles.includes('SP')) && !signingCertCount) findings.push(finding('saml.metadata.signing-key.missing', SEVERITY.WARNING, 'No signing certificate advertised', `${entity.entityId || '(unknown entity)'} contains no signing/unspecified X509Certificate in KeyDescriptor.`));

    const invalidUrls = [...entity.ssoServices, ...entity.sloServices, ...entity.acsServices].filter((service) => {
      try { return new URL(service.location).protocol !== 'https:'; } catch { return true; }
    });
    if (invalidUrls.length) findings.push(finding('saml.metadata.endpoint.scheme', SEVERITY.WARNING, 'Non-HTTPS or invalid SAML endpoint found', `${invalidUrls.length} endpoint(s) are not valid HTTPS URLs.`));
  }

  return { kind: 'saml-metadata', entities: parsed, findings, raw: text };
}
