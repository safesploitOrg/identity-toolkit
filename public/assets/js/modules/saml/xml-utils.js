export function rejectDangerousXml(text) {
  if (/<!DOCTYPE\b/i.test(text) || /<!ENTITY\b/i.test(text)) {
    throw new Error('DOCTYPE/ENTITY declarations are rejected to avoid XML entity-expansion and external-entity risks.');
  }
}

export function parseXml(text) {
  rejectDangerousXml(text);
  if (typeof DOMParser === 'undefined') throw new Error('DOMParser is unavailable in this environment.');
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  const errors = descendants(doc, 'parsererror');
  if (errors.length) throw new Error(`Malformed XML: ${errors[0].textContent?.trim() || 'parser error'}`);
  return doc;
}

export function descendants(node, localName) {
  const out = [];
  const all = node.getElementsByTagName('*');
  for (let index = 0; index < all.length; index += 1) {
    const element = all[index];
    if (element.localName === localName || element.nodeName === localName) out.push(element);
  }
  if (node.documentElement && (node.documentElement.localName === localName || node.documentElement.nodeName === localName)) {
    out.unshift(node.documentElement);
  }
  return [...new Set(out)];
}

export function firstDescendant(node, localName) {
  return descendants(node, localName)[0] ?? null;
}

export function childElements(node, localName = null) {
  const result = [];
  const children = node?.childNodes;
  if (!children) return result;

  // DOM NodeList implementations are array-like but are not universally iterable.
  // Browsers normally support `for...of`; @xmldom/xmldom intentionally only
  // guarantees indexed/item() access. Use the DOM-compatible common subset.
  for (let index = 0; index < children.length; index += 1) {
    const child = typeof children.item === 'function' ? children.item(index) : children[index];
    if (!child || child.nodeType !== 1) continue;
    if (!localName || child.localName === localName || child.nodeName === localName) result.push(child);
  }
  return result;
}

export function firstChild(node, localName) {
  return childElements(node, localName)[0] ?? null;
}

export function textOf(element) {
  return element?.textContent?.trim() ?? '';
}

export function attr(element, name) {
  return element?.getAttribute?.(name) ?? '';
}

export function serializeXml(node) {
  if (typeof XMLSerializer === 'undefined') throw new Error('XMLSerializer is unavailable in this environment.');
  return new XMLSerializer().serializeToString(node);
}

export function descendantsNs(node, localName, namespaceURI) {
  return descendants(node, localName).filter((element) => element.namespaceURI === namespaceURI);
}

export function firstDescendantNs(node, localName, namespaceURI) {
  return descendantsNs(node, localName, namespaceURI)[0] ?? null;
}

export function childElementsNs(node, localName, namespaceURI) {
  return childElements(node, localName).filter((element) => element.namespaceURI === namespaceURI);
}

export function firstChildNs(node, localName, namespaceURI) {
  return childElementsNs(node, localName, namespaceURI)[0] ?? null;
}
