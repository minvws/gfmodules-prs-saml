# PRS-SAML

The PRS-SAML service is the *SAML-ontvanger* of the
[Pseudoniemendienst (PRS)](https://github.com/minvws/gfmodules-pseudoniemendienst).
It verifies an already resolved TVS SAML ArtifactResponse and decrypts the
encrypted personal ID with a locally configured private key. PRS receives the
personal ID and authentication level and creates the pseudonym separately.

## API

Only PRS should call the internal `POST /saml/decrypt` endpoint. Send a JSON
object with a nonempty, base64-encoded SAML ArtifactResponse:

```json
{
  "samlResponse": "<base64 encoded XML>"
}
```

The XML may be the ArtifactResponse directly or contained in one SOAP 1.1/1.2
Envelope/Body. Extra JSON fields, including `recipientOrganization` and `domain`,
are ignored. They do not control the SAML recipient, audience or trust settings.

Successful verification and decryption return HTTP 200:

```json
{
  "personalId": "NL:bsn:950000012",
  "authnContextClassRef": "http://eidas.europa.eu/LoA/high"
}
```

The receiver validates the signatures on the ArtifactResponse and its direct
summary Assertion, and the direct Response signature when present. It also
checks the trusted issuer, statuses, audience, ACS, registered service, time
validity and configured minimum authentication level. Initially it accepts only
authentication of a person acting for themselves with a legacy BSN. Representation
with legacy BSNs may be enabled explicitly; other identifier types and whole
EncryptedAssertion messages are unsupported. Direct DigiD 3.7 responses are not
supported by this TVS receiver.

When representation is enabled and present, `personalId` identifies the acting
person and `representedPersonalId` identifies the represented person. The latter
field is omitted for self-authentication. Callers must preserve this distinction.

Errors use stable responses: HTTP 400 for invalid SAML, signatures or decryption;
413 for oversized requests; 422 for invalid JSON or request fields; and 503 when SAML is disabled or
unavailable. Decrypt responses carry `Cache-Control: no-store`. Request bodies,
SAML XML, personal IDs, decrypted content and key material must never be logged;
logs contain outcome codes and existing request correlation IDs.

The caller must correlate the signed response with the original AuthnRequest
and ArtifactResolve and enforce replay prevention. This endpoint requires no
expected request IDs and keeps no replay cache: a valid response can be processed
again. It does require the profile's InResponseTo attributes and checks that the
Response and bearer SubjectConfirmationData values agree. This consistency check
does not establish correlation with a caller's original request.

## SAML configuration

The `[saml]` section in [app.conf.example](app.conf.example) is disabled by
default. Health and information endpoints remain available; decrypt returns 503
until SAML is configured and enabled. When enabled, invalid integration settings,
metadata or key material prevent startup.

Provision the following outside version control before setting `enabled = True`:

- A trusted local TVS metadata file whose authenticity the operator has verified
  out of band. Its embedded certificate does not establish trust in the metadata
  itself. It must identify exactly one IdP with current, signing-capable RSA
  certificates; multiple current signing certificates and KeyNames are supported.
- An unencrypted RSA PEM private key of at least 2048 bits and its matching
  X.509 certificate. Restrict private-key access to the service account, for
  example with a dedicated owner and mode `0600`; keep its directory restricted.
  Development keys are provisioned separately as well.
- The expected key recipient (`entity_id`), separate expected SAML `audience`,
  upstream `acs_url` and registered `service_uuid` for the integration.

| Setting | Meaning / default |
| --- | --- |
| `enabled` | Enable the receiver; defaults to `False`. |
| `idp_metadata_file` | Trusted local TVS IdP metadata XML. |
| `entity_id` | Expected EncryptedKey Recipient for the configured local key. |
| `audience` | Expected SAML Audience, independent of `entity_id`. |
| `acs_url` | Actual upstream ACS destination/recipient URL. |
| `service_uuid` | Registered TVS service identifier. |
| `decryption_key_file` | Unencrypted RSA private key in PEM format. |
| `decryption_certificate_file` | Matching X.509 certificate in PEM format. |
| `decryption_key_name` | Optional locally provisioned encryption KeyName as registered in metadata; defaults to the certificate SHA-256 fingerprint. |
| `accepted_identifier_types` | Comma-separated accepted NameQualifier values; currently only `urn:nl-eid-gdi:1.0:id:legacy-BSN` is implemented. |
| `allow_representation` | Enable represented legacy BSNs; defaults to `False`. |
| `minimum_loa` | Recognized minimum LoA URI; defaults to eIDAS `substantial`. |
| `clock_skew_seconds` | Allowed clock skew, 0–120 seconds; defaults to `60`. |
| `max_xml_bytes` | Decoded XML limit, 1024–10485760 bytes; defaults to `2097152`. |

The summary assertion uses the four eID LoA URIs from TVS section 10.3, in
ascending order: `http://eID.logius.nl/LoA/basic`,
`http://eidas.europa.eu/LoA/low`, `http://eidas.europa.eu/LoA/substantial`,
and `http://eidas.europa.eu/LoA/high`. Original IdP class URIs belong to Advice
and are not accepted as the summary's authentication level.

Relative paths resolve against the directory containing the loaded INI file.
The decryption KeyName defaults to the lowercase SHA-256 fingerprint of the
configured certificate. Set it to the trusted registered metadata name when different.
Keys, certificates and metadata load at startup; restart the service
after replacing them. Expiry of metadata and trusted certificates is also checked
for each request. There is no automatic metadata download or online revocation
check.

This receiver performs no artifact resolution, AuthnRequest generation, session
management, pseudonym generation or HSM operations. It does not by itself
establish a complete TVS connection or login service.

## Development

```bash
poetry install
cp app.conf.example app.conf
poetry run python -m app.main
```

The API is then available at http://localhost:8534/docs.
The example configuration keeps SAML disabled; provision the local integration
materials described above to exercise decryption.

Run the checks:

```bash
make lint type-check test
```
