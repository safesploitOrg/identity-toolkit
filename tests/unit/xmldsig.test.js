import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { DOMImplementation, DOMParser, XMLSerializer } from '@xmldom/xmldom';
import xpath from 'xpath';
import * as xmldsigjs from 'xmldsigjs';
import { verifySamlXmlSignatures } from '../../public/assets/js/modules/saml/xmldsig-verifier.js';

xmldsigjs.setNodeDependencies({ DOMImplementation, DOMParser, XMLSerializer, xpath });
xmldsigjs.Application.setEngine('NodeJS', webcrypto);
globalThis.DOMParser = DOMParser;
globalThis.XMLSerializer = XMLSerializer;
globalThis.XmlDsigJs = xmldsigjs;

test('xmldsigjs 2.8.8 signs and verifies XML locally', async () => {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  const xml = xmldsigjs.Parse('<root ID="r1"><data>identity-toolkit</data></root>');
  const signed = new xmldsigjs.SignedXml();
  await signed.Sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    xml,
    { references: [{ uri: '#r1', hash: 'SHA-256', transforms: ['enveloped', 'c14n'] }] }
  );
  const xmlText = signed.toString();
  const parsed = xmldsigjs.Parse(xmlText);
  const signature = parsed.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
  assert.ok(signature, 'signed XML should contain Signature');
  const verifier = new xmldsigjs.SignedXml(parsed);
  verifier.LoadXml(signature);
  assert.equal(await verifier.Verify(keyPair.publicKey), true);
});


test('Identity Toolkit verifies an enveloped SAML Assertion signature through xmldsigjs', async () => {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  const xml = xmldsigjs.Parse('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="2026-10-02T08:00:00Z"><saml:Issuer>https://idp.example/</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>');
  const signed = new xmldsigjs.SignedXml();
  await signed.Sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    keyPair.privateKey,
    xml,
    {
      keyValue: keyPair.publicKey,
      references: [{ uri: '#_a1', hash: 'SHA-256', transforms: ['enveloped', 'c14n'] }],
    },
  );
  const result = await verifySamlXmlSignatures(signed.toString());
  assert.ok(result.findings.some((item) => item.id === 'saml.xmldsig.0.result' && item.severity === 'pass'));
  assert.equal(result.results[0].valid, true);
});
