import { finding, SEVERITY } from '../validation/findings.js';
import { descendantsNs, parseXml, textOf } from './xml-utils.js';

const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

function attr(element, name) {
  return element?.getAttribute?.(name) ?? '';
}

function inspectSignature(signature, index) {
  const references = descendantsNs(signature, 'Reference', XMLDSIG_NS).map((reference) => ({
    uri: attr(reference, 'URI'),
    transforms: descendantsNs(reference, 'Transform', XMLDSIG_NS).map((item) => attr(item, 'Algorithm')).filter(Boolean),
    digestMethod: attr(descendantsNs(reference, 'DigestMethod', XMLDSIG_NS)[0], 'Algorithm'),
    digestValuePresent: Boolean(textOf(descendantsNs(reference, 'DigestValue', XMLDSIG_NS)[0])),
  }));
  return {
    index,
    parent: signature.parentNode?.localName || signature.parentNode?.nodeName || '',
    parentId: attr(signature.parentNode, 'ID') || attr(signature.parentNode, 'Id') || attr(signature.parentNode, 'id'),
    signatureMethod: attr(descendantsNs(signature, 'SignatureMethod', XMLDSIG_NS)[0], 'Algorithm'),
    canonicalizationMethod: attr(descendantsNs(signature, 'CanonicalizationMethod', XMLDSIG_NS)[0], 'Algorithm'),
    references,
    certificateCount: descendantsNs(signature, 'X509Certificate', XMLDSIG_NS).length,
    keyValueCount: descendantsNs(signature, 'KeyValue', XMLDSIG_NS).length,
    keyNames: descendantsNs(signature, 'KeyName', XMLDSIG_NS).map(textOf).filter(Boolean),
  };
}

export async function verifySamlXmlSignatures(xmlText) {
  const findings = [];
  const safetyDoc = parseXml(xmlText);
  const safetySignatures = descendantsNs(safetyDoc, 'Signature', XMLDSIG_NS).map(inspectSignature);

  for (const signature of safetySignatures) {
    const external = signature.references.filter((reference) => reference.uri && !reference.uri.startsWith('#'));
    if (external.length) findings.push(finding('saml.xmldsig.external', SEVERITY.ERROR, 'XMLDSig verification blocked', 'External ds:Reference URIs are not permitted by Identity Toolkit.', external));
    if (/sha1/i.test(signature.signatureMethod) || signature.references.some((reference) => /sha1/i.test(reference.digestMethod))) {
      findings.push(finding(`saml.xmldsig.${signature.index}.sha1`, SEVERITY.WARNING, 'SHA-1 XML signature/digest algorithm detected', 'SHA-1 is legacy and should not be used for new federation configurations. Compatibility requirements may still exist in older environments.'));
    }
    if (!signature.certificateCount && !signature.keyValueCount) findings.push(finding(`saml.xmldsig.${signature.index}.key`, SEVERITY.INDETERMINATE, 'No inline verification key material found', 'The signature may rely on out-of-band metadata/trust configuration. Identity Toolkit cannot infer that key locally without supplied federation metadata.'));
  }
  if (findings.some((item) => item.id === 'saml.xmldsig.external')) return { results: safetySignatures.map((item) => ({ ...item, valid: null })), findings };

  const library = globalThis.XmlDsigJs;
  if (!library?.SignedXml || !library?.Parse) {
    findings.push(finding('saml.xmldsig.library', SEVERITY.INDETERMINATE, 'XMLDSig library unavailable', 'The locally vendored xmldsigjs library did not initialise. Run the vendor build before serving/deploying the application.'));
    return { results: safetySignatures.map((item) => ({ ...item, valid: null })), findings };
  }

  try {
    const doc = library.Parse(xmlText);
    const signatures = Array.from(doc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature') ?? []);
    if (!signatures.length) return { results: [], findings };
    const results = [];
    for (let index = 0; index < signatures.length; index += 1) {
      const signature = signatures[index];
      const structural = safetySignatures[index] ?? { index };
      const signedXml = new library.SignedXml(doc);
      signedXml.LoadXml(signature);
      try {
        const valid = await signedXml.Verify();
        results.push({ ...structural, valid });
        findings.push(finding(
          `saml.xmldsig.${index}.result`,
          valid ? SEVERITY.PASS : SEVERITY.ERROR,
          valid ? 'XML Signature cryptographically valid' : 'XML Signature verification failed',
          valid
            ? 'xmldsigjs verified this signature using key material available to XMLDSig. This does not establish trust in the signing certificate, signed-element selection, or complete SAML profile validity.'
            : 'xmldsigjs could not validate this signature using key material available to the signature.',
        ));
      } catch (error) {
        results.push({ ...structural, valid: null, error: error.message });
        findings.push(finding(`saml.xmldsig.${index}.indeterminate`, SEVERITY.INDETERMINATE, 'XML Signature could not be verified', error.message));
      }
    }
    return { results, findings };
  } catch (error) {
    findings.push(finding('saml.xmldsig.parse', SEVERITY.INDETERMINATE, 'XMLDSig processing failed', error.message));
    return { results: safetySignatures.map((item) => ({ ...item, valid: null, error: error.message })), findings };
  }
}
