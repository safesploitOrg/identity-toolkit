import test from 'node:test';
import assert from 'node:assert/strict';
import { childElements } from '../../public/assets/js/modules/saml/xml-utils.js';

test('childElements supports a non-iterable DOM-style NodeList', () => {
  const element = { nodeType: 1, localName: 'Issuer', nodeName: 'saml:Issuer' };
  const text = { nodeType: 3, nodeName: '#text' };
  const childNodes = {
    0: text,
    1: element,
    length: 2,
    item(index) { return this[index] ?? null; },
  };

  assert.equal(childNodes[Symbol.iterator], undefined);
  assert.deepEqual(childElements({ childNodes }), [element]);
  assert.deepEqual(childElements({ childNodes }, 'Issuer'), [element]);
  assert.deepEqual(childElements({ childNodes }, 'Audience'), []);
});

test('childElements handles missing childNodes defensively', () => {
  assert.deepEqual(childElements(null), []);
  assert.deepEqual(childElements({}), []);
});
