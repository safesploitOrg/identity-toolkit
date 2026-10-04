# Architecture

## 1. Purpose

Identity Toolkit is a static browser application for inspecting identity tokens, claims and federation configuration without sending artefacts to an application backend.

It is a sibling of PKI Toolkit, not an extension of it.

```text
Identity Toolkit                  PKI Toolkit
----------------                  -----------
JWT / JOSE             <------>   X.509 signing certificates
OIDC / OAuth                       certificate trust paths
SAML 2.0              <------>    XML signing certificates
WS-Federation                     keys / CSR / revocation
OpenID Federation
claims / scopes / roles
federation metadata
```

## 2. Design principles

1. **Local-first and static-hostable** — GitHub Pages is sufficient for the public application.
2. **Decoded ≠ semantically valid ≠ verified ≠ trusted** — each validation dimension remains separate.
3. **Protocol-aware validation** — Generic JWT, OIDC ID Tokens, OAuth access tokens, SAML, WS-Fed and OpenID Federation do not share one generic validity rule set.
4. **No network side effects from untrusted input** — token/metadata URLs are never fetched automatically.
5. **No casual XMLDSig implementation** — XML signature cryptography is delegated to pinned `xmldsigjs` + Web Crypto.
6. **Supply-chain visibility** — third-party runtime code is local, pinned, licensed and SHA-384/SRI checked.
7. **Defensive XML handling** — namespaces, duplicate IDs, entity declarations and signature references are treated as security-relevant input.
8. **No bearer-token persistence** — raw identity artefacts are not stored in browser persistence APIs or copied into reports.
9. **Normalised claims layer** — migrations compare identity semantics rather than protocol/UI implementation details.
10. **Migration output is descriptive** — configuration/claim differences are surfaced without claiming the target application will behave identically.

## 3. High-level flow

```text
JWT / XML / JSON input
          |
          v
    Input detector
          |
  +-------+----------+-----------+----------------+
  |                  |           |                |
  v                  v           v                v
JWT / JOSE          SAML       WS-Fed        Federation config
  |                  |           |          OIDC/JWKS/SAML/OF
  +------------------+-----------+----------------+
                     |
                     v
               Parsed artefact
                     |
       +-------------+--------------+
       |             |              |
       v             v              v
    Claims       Protocol rules    Crypto
 normalisation     / context      verification
       |             |              |
       +-------------+--------------+
                     |
                     v
              Unified result model
                     |
      +--------------+------------------+
      |              |                  |
      v              v                  v
     UI           reports            compare
                              claims / federation
```

## 4. Repository/runtime layout

```text
public/assets/js/
├── app.js                     # DOM/controller only
├── external/                  # generated local third-party runtime
└── modules/
    ├── analyse.js             # protocol dispatcher/unified result
    ├── claims/
    │   ├── claim-dictionary.js
    │   ├── claims.js
    │   └── claim-diff.js
    ├── crypto/signature.js
    ├── federation/
    │   ├── openid-federation.js
    │   └── federation-compare.js
    ├── jwt/
    ├── oauth/
    ├── oidc/
    ├── saml/
    ├── validation/
    └── wsfed/
```

`app.js` owns form state, routing, copy/download actions and rendering calls. Protocol parsing/validation does not live in the controller.

## 5. Runtime security boundary

Only `/public` is deployed.

CSP includes:

```text
connect-src 'none'
```

First-party runtime code intentionally has no fetch/XHR/WebSocket/EventSource path. URLs carried by tokens/metadata are passive diagnostic values.

## 6. Detection and unified result model

`input-detector.js` recognises:

- compact JWT/JWS;
- JWK / JWKS;
- OIDC Provider Metadata;
- SAML Response / Assertion;
- SAML EntityDescriptor / EntitiesDescriptor;
- WS-Trust RequestSecurityTokenResponse / Collection.

Detection is a routing hint, not a trust/validity decision.

Protocol modules return a common high-level shape:

```text
{
  kind,
  detected,
  profile,
  summary,
  claims,
  findings,
  parsed,
  verification?,
  overall
}
```

This lets rendering/reporting stay mostly protocol-neutral.

## 7. JWT / JOSE

### Parsing

`jwt-parser.js`:

- requires three compact JWS segments;
- validates Base64URL input;
- decodes UTF-8 JSON header/payload;
- preserves exact signing-input bytes;
- decodes signature bytes separately.

### Generic validation

`jwt-validator.js` provides common checks:

- `alg` / `typ` observations;
- critical-header handling;
- `b64=false` conservative state;
- `exp`, `nbf`, `iat`;
- explicit expected issuer/audience;
- security observations for embedded/remote key hints.

### Signature verification

`crypto/signature.js` uses Web Crypto with explicitly supplied key material. `jwk.js` filters candidates before import by key purpose/operations/type/algorithm.

A valid signature establishes byte/key consistency only, not issuer trust.

## 8. OIDC / OAuth (`v0.2`)

### OIDC ID Token

`oidc/id-token.js` layers request/application context on top of JWT:

```text
JWT validity
   + expected issuer/audience
   + sub
   + multi-aud / azp
   + expected nonce
   + auth_time / max age
   + acr / amr
   + at_hash / c_hash (when related artefact supplied)
```

Half-hash validation uses Web Crypto and the ID Token JWS algorithm's SHA-2 family.

### OAuth access tokens

`oauth/oauth-token.js` extracts scopes/roles/groups/entitlements/client identity and can apply the RFC 9068 JWT access-token profile when selected/detected.

Provider-specific JWT access tokens remain analyzable without pretending they conform to RFC 9068.

### OIDC Discovery / JWKS

`oidc/discovery.js` validates metadata structure/capabilities without contacting any endpoint.

`jwt/jwk.js` inventories JWKS key IDs, algorithms, types, intended use/operations and flags duplicate IDs or private/symmetric material.

## 9. SAML 2.0 (`v0.3`)

### Parser

`saml/saml-parser.js` models:

- Response status/issuer/destination/InResponseTo;
- one or more Assertions;
- Subject / NameID;
- SubjectConfirmationData;
- Conditions and separate AudienceRestriction groups;
- OneTimeUse / ProxyRestriction;
- multiple AuthnStatements / AuthnContext;
- multi-valued attributes;
- signature structure/reference targets.

Expected recipient, request ID, audience and issuer are explicit user context rather than inferred values.

### Hostile XML boundary

`xml-utils.js` rejects DTD/entity declarations. The SAML parser is namespace-aware and detects duplicate IDs.

External XMLDSig references are rejected before cryptographic verification.

### XMLDSig

`xmldsig-verifier.js` separates:

1. structural signature/reference inspection;
2. reference coverage hints;
3. cryptographic `xmldsigjs` result;
4. signer key/certificate provenance/trust, which is **not** automatically established.

### Metadata

`saml-metadata.js` extracts EntityIDs, role descriptors, SSO/SLO/ACS services, NameID formats, requested attributes, metadata expiry and signing/encryption key descriptors.

The same XMLDSig verifier can inspect/verify signed metadata documents.

## 10. Claims normalisation and migration (`v0.4`)

Protocol claims become:

```text
{
  source,
  name,
  canonical,
  title,
  description,
  value,
  mapped
}
```

The dictionary normalises common cases such as:

```text
scp                                            -> scope
role                                           -> roles
http://schemas.microsoft.com/.../role          -> roles
http://schemas.xmlsoap.org/.../emailaddress    -> email
```

Users can provide additional source-name → canonical-name JSON mappings for one comparison.

`claim-diff.js` performs set-aware comparison for naturally unordered claims and produces same/mapped/changed/added/removed results plus a migration report.

## 11. WS-Federation / WS-Trust (`v0.5`)

`wsfed-parser.js` handles RSTR / RSTR Collection envelopes and extracts WS-Trust context such as AppliesTo, Lifetime, TokenType and key information.

Embedded token flow:

```text
RSTR
 |
 +-- SAML 2.0 Assertion -> main SAML 2.0 parser
 |
 +-- SAML 1.x Assertion -> narrow legacy assertion parser
                              |
                              v
                         normalised claims
                              |
                              v
                         Claims Compare
```

This keeps enterprise migration workflows aligned with the same claims model rather than creating a separate WS-Fed comparison UI.

## 12. Advanced federation analysis (`v0.6`)

### Configuration diff

`federation/federation-compare.js` projects protocol-specific configuration into comparable fields, then reports drift.

It additionally derives:

- issuer / EntityID changes;
- JWKS retained/added/removed key IDs;
- SAML signing-certificate identifiers;
- signing-key transition classification.

The report is descriptive and does not claim a migration is safe without end-to-end relying-party/client validation.

### OpenID Federation

`federation/openid-federation.js` analyzes final OpenID Federation Entity Statement structures:

- `entity-statement+jwt` + signing `kid`;
- Entity Configuration (`iss == sub`) vs Subordinate Statement;
- required claims/times/HTTPS identifiers;
- Federation Entity `jwks`;
- `authority_hints` / `trust_anchor_hints`;
- Entity Type metadata;
- `metadata_policy` / `constraints` placement;
- critical claims/operators;
- Trust Mark structure;
- trust-chain header shape.

For an Entity Configuration, `analyse.js` may verify the JWT against its own `jwks` claim. This is explicitly described as **self-consistency**, not federation trust.

Full policy application and trust-chain resolution from a user-supplied statement bundle remain pre-1.0 hardening work.

## 13. Local `xmldsigjs` and SRI

The browser bundle is generated from exact `xmldsigjs` 2.8.8 plus pinned runtime dependencies:

```text
node_modules/xmldsigjs
        |
      esbuild
        |
        v
public/assets/js/external/xmldsigjs-2.8.8.bundle.js
        |
     SHA-384
        |
   +----+----------------+
   |                     |
   v                     v
vendor-manifest.json   index.html integrity=
```

`verify-vendor.mjs` recalculates the exact deployment-file digest and verifies the manifest + HTML SRI. Pages deployment depends on this passing.

## 14. Testing

Three layers:

1. **Core unit tests** — detector, JWT/JOSE, OIDC/OAuth, claims, JWKS/federation/OpenID Federation.
2. **XML/vendor unit tests** — SAML/WS-Fed and `xmldsigjs`, requiring installed pinned dependencies.
3. **Browser E2E** — Chromium, Firefox and WebKit against the static server, including v0.2–v0.6 workflow smoke tests.

CI also checks CSP/no-network invariants and remote-runtime dependency absence.

## 15. Pre-1.0 hardening

Before stable 1.0:

- duplicate-member and hostile JSON corpus;
- bounded input size/depth policies across all parsers;
- broader XML signature-wrapping corpora;
- SAML schema/profile differential testing;
- OpenID Federation offline trust-chain/policy application;
- accessibility/mobile regression work;
- versioned result/report schema;
- threat-model/security review.
