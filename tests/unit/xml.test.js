import test from 'node:test';
import assert from 'node:assert/strict';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { parseSaml } from '../../public/assets/js/modules/saml/saml-parser.js';
import { parseWsFed } from '../../public/assets/js/modules/wsfed/wsfed-parser.js';
import { analyseSamlMetadata } from '../../public/assets/js/modules/saml/saml-metadata.js';

globalThis.DOMParser = DOMParser;
globalThis.XMLSerializer = XMLSerializer;

const saml = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="R1" IssueInstant="2026-10-02T00:00:00Z">
  <saml:Issuer>https://idp.example</saml:Issuer>
  <saml:Assertion ID="A1" IssueInstant="2026-10-02T00:00:00Z">
    <saml:Issuer>https://idp.example</saml:Issuer>
    <saml:Subject><saml:NameID Format="urn:test:nameid">alice@example.com</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2026-10-01T23:55:00Z" NotOnOrAfter="2026-10-02T01:00:00Z">
      <saml:AudienceRestriction><saml:Audience>urn:example:app</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-10-02T00:00:00Z" SessionIndex="s1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:test:mfa</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement><saml:Attribute Name="roles"><saml:AttributeValue>Admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

test('parses SAML response fields and attributes', () => {
  const result = parseSaml(saml, { now: new Date('2026-10-02T00:15:00Z'), expectedAudience: 'urn:example:app' });
  assert.equal(result.summary.issuer, 'https://idp.example');
  assert.equal(result.assertions[0].subject.nameId, 'alice@example.com');
  assert.equal(result.assertions[0].attributes[0].values[0], 'Admin');
  assert.ok(result.findings.some((item) => item.id === 'saml.audience.expected'));
});

test('rejects DTD/ENTITY XML', () => {
  assert.throws(() => parseSaml('<!DOCTYPE x [<!ENTITY a "x">]><Assertion/>'), /DOCTYPE\/ENTITY/);
});

test('detects duplicate SAML IDs', () => {
  const bad = saml.replace('ID="A1"', 'ID="R1"');
  const result = parseSaml(bad, { now: new Date('2026-10-02T00:15:00Z') });
  assert.ok(result.findings.some((item) => item.id === 'saml.id.duplicate' && item.severity === 'error'));
});

test('parses WS-Fed envelope and reuses SAML assertion parser', () => {
  const assertion = saml.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)[0];
  const wsfed = `<t:RequestSecurityTokenResponse xmlns:t="urn:test" xmlns:wsp="urn:wsp" xmlns:wsa="urn:wsa" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><t:TokenType>urn:test:saml2</t:TokenType><wsp:AppliesTo><wsa:Address>urn:example:app</wsa:Address></wsp:AppliesTo><t:RequestedSecurityToken>${assertion}</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`;
  const result = parseWsFed(wsfed, { now: new Date('2026-10-02T00:15:00Z') });
  assert.equal(result.summary.appliesTo, 'urn:example:app');
  assert.equal(result.saml.assertions[0].attributes[0].name, 'roles');
});

test('rejects SAML-shaped XML in the wrong namespace', () => {
  assert.throws(() => parseSaml('<Response xmlns="urn:not-saml"><Assertion/></Response>'), /SAML 2\.0 Response or Assertion/);
});


test('validates SAML SubjectConfirmation recipient and InResponseTo', () => {
  const input = saml.replace(
    '<saml:Subject><saml:NameID Format="urn:test:nameid">alice@example.com</saml:NameID></saml:Subject>',
    '<saml:Subject><saml:NameID Format="urn:test:nameid">alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" NotOnOrAfter="2026-10-02T01:00:00Z"/></saml:SubjectConfirmation></saml:Subject>'
  );
  const result = parseSaml(input, { now: new Date('2026-10-02T00:15:00Z'), expectedRecipient: 'https://sp.example/acs', expectedInResponseTo: '_req1' });
  assert.ok(result.findings.some((item) => item.id.includes('.recipient') && item.severity === 'pass'));
  assert.ok(result.findings.some((item) => item.id.includes('.inresponseto') && item.severity === 'pass'));
});

test('requires expected audience to satisfy every AudienceRestriction', () => {
  const input = saml.replace(
    '</saml:Conditions>',
    '<saml:AudienceRestriction><saml:Audience>urn:other:app</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
  );
  const result = parseSaml(input, { now: new Date('2026-10-02T00:15:00Z'), expectedAudience: 'urn:example:app' });
  assert.ok(result.findings.some((item) => item.id === 'saml.audience.expected' && item.severity === 'error'));
});

test('parses WS-Fed with an embedded SAML 1.x assertion', () => {
  const wsfed = `<t:RequestSecurityTokenResponse xmlns:t="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>urn:example:app</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><saml:Assertion MajorVersion="1" MinorVersion="1" AssertionID="_a1" Issuer="https://adfs.example" IssueInstant="2026-10-02T00:00:00Z"><saml:Conditions NotBefore="2026-10-01T23:55:00Z" NotOnOrAfter="2026-10-02T01:00:00Z"><saml:AudienceRestrictionCondition><saml:Audience>urn:example:app</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice@example.com</saml:NameIdentifier></saml:Subject><saml:Attribute AttributeName="role" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims"><saml:AttributeValue>Admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`;
  const result = parseWsFed(wsfed, { now: new Date('2026-10-02T00:15:00Z'), expectedAudience: 'urn:example:app' });
  assert.equal(result.summary.assertionVersion, '1.1');
  assert.equal(result.saml11.assertion.issuer, 'https://adfs.example');
  assert.equal(result.claims[0].values[0], 'Admin');
});

test('analyses SAML metadata signing keys and endpoint policy', () => {
  const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example" validUntil="2027-01-01T00:00:00Z"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
  const result = analyseSamlMetadata(metadata, { now: new Date('2026-10-02T00:00:00Z') });
  assert.equal(result.entities[0].wantAuthnRequestsSigned, true);
  assert.equal(result.entities[0].keys[0].certificates.length, 1);
  assert.ok(result.findings.some((item) => item.id === 'saml.metadata.validuntil' && item.severity === 'pass'));
});
