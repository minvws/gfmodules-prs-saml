# SAML API

Only PRS should reach this internal API. The receiver verifies a resolved TVS
ArtifactResponse and returns the decrypted personal ID and authentication level.
PRS creates the pseudonym separately. The receiver does not resolve artifacts,
generate AuthnRequests, manage sessions or perform HSM operations. It is not a
complete TVS connection or login service.

## Request

`POST /saml/decrypt` takes a JSON object with `saml_response` set to the
complete SOAP XML message encoded as a nonempty Base64 string:

```json
{
  "saml_response": "<base64-encoded SOAP XML>"
}
```

The decoded XML must have a SOAP 1.1 or 1.2 `Envelope` with one matching `Body`
whose only element child is the TVS `ArtifactResponse`. The XML declaration is
optional. A bare `ArtifactResponse` without its SOAP envelope returns HTTP 400
(`invalid_saml_response`) when the receiver is enabled.

Extra JSON fields, including `recipientOrganization` and `domain`, are ignored.
They do not control the SAML recipient, audience or trust settings.

## Successful response

Successful verification and decryption return HTTP 200. Synthetic example:

```json
{
  "personalId": "NL:bsn:950000012",
  "authnContextClassRef": "http://eidas.europa.eu/LoA/high"
}
```

By default, the service accepts only self-authentication with a legacy BSN.
When representation is enabled and present, `personalId` identifies the acting
person and `representedPersonalId` identifies the represented person. The latter
field is omitted for self-authentication. Callers must preserve this distinction.

## Validation and supported profiles

The receiver verifies the required ArtifactResponse and direct summary
Assertion signatures, and the direct Response signature when present. It checks
the trusted issuer, statuses, audience, ACS, registered service, time validity
and configured minimum authentication level.

Representation with legacy BSNs can be
[enabled explicitly](saml-configuration.md#enable-the-receiver).
Other identifier types, whole `EncryptedAssertion` messages and direct DigiD 3.7
responses are unsupported.

## Error responses

| Status | Meaning |
| --- | --- |
| `400` | Invalid SAML, failed signature checks or failed decryption (`invalid_saml_response`), or a body-parser failure. |
| `422` | FastAPI's standard request validation error for invalid JSON or fields. |
| `503` | The receiver is disabled or unavailable (`saml_unavailable`). |
| `500` | Unexpected processing or serialization error (`Internal server error`). |

A `400` can also represent a sanitized library error, not necessarily bad
input. Some body-parser failures return `{"detail":"There was an error parsing the body"}`.
FastAPI's `422` response contains `detail`, which may include rejected input.
Do not log these response bodies. Malformed input can receive `400` or `422`
before a disabled service returns `503`.

FastAPI serializes successful results. Serialization failures use the
application's general `500` handler.

## Caller and deployment responsibilities

- **Correlation and replay:** Correlate the signed ArtifactResponse with the
  original ArtifactResolve and the Response and bearer confirmation with the
  original AuthnRequest. Enforce replay prevention upstream. This endpoint
  accepts no expected request IDs and has no replay cache, so it can process a
  valid response again. It requires the profile's `InResponseTo` attributes and
  checks that the Response and bearer SubjectConfirmationData values agree;
  this is not correlation to the original requests.
- **Bearer address:** The receiver does not compare a signed
  `SubjectConfirmationData/@Address` to the attesting user agent or supply a
  validated user-agent address. If the integration relies on this optional
  restriction, enforce it elsewhere using a trustworthy address. Otherwise,
  the receiver can release an identity to a different presenter. The immediate
  PRS or proxy address is not necessarily the user agent's. Actual sender use
  and upstream enforcement are unknown.
- **Cache and resource controls:** The endpoint does not guarantee
  `Cache-Control: no-store` and has no application-defined request-body,
  encoded-field or XML size limits. Apply cache controls at the deployment or
  caller boundary and size, timeout and resource controls at deployment.
- **Sensitive data:** Never log request bodies, SAML XML, personal IDs,
  decrypted content or key material in normal operation. Normal SAML logs
  contain input-free outcomes and existing request correlation IDs.
  [DEBUG logging](saml-configuration.md#local-saml-debugging) can expose
  sensitive values; use it only with synthetic test data.
