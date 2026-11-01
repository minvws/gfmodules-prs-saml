# SAML configuration

## Enable the receiver

The `[saml]` section in [app.conf.example](../app.conf.example) is disabled by
default. Health and information endpoints remain available. A well-formed
decrypt request returns `503` until SAML is configured and enabled; malformed
input can receive `400` or `422` first. When SAML is enabled, invalid integration
settings, metadata or key material prevent startup.

Provision the following outside version control before setting `enabled = True`:

- A trusted local TVS metadata file whose authenticity the operator has verified
  out of band. Its embedded certificate does not establish trust in the metadata
  itself. It must identify exactly one IdP with current, signing-capable RSA
  certificates with nonempty signing `KeyName` values, each bound to its
  certificate in an unambiguous metadata `KeyInfo`. Multiple named signing keys
  are supported; a message-provided certificate alone is not a trust anchor.
- An unencrypted RSA PEM private key of at least 2048 bits and its matching
  X.509 certificate. Restrict private-key access to the service account, for
  example with a dedicated owner and mode `0600`; keep its directory restricted.
  Provision development keys separately as well.
- The expected key recipient (`entity_id`), separate expected SAML `audience`,
  upstream `acs_url` and registered `service_uuid` for the integration.

## Settings

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
| `decryption_key_name` | Optional registered encryption KeyName; defaults to the certificate SHA-256 fingerprint. |
| `allow_representation` | Enable represented legacy BSNs; defaults to `False`. |
| `minimum_loa` | Recognized minimum LoA URI; defaults to eIDAS `substantial`. |
| `clock_skew_seconds` | Allowed clock skew, 0–120 seconds; defaults to `60`. |

Only `urn:nl-eid-gdi:1.0:id:legacy-BSN` identifiers are supported. An old
`accepted_identifier_types` entry is ignored and cannot change this profile.

The summary assertion uses the four eID LoA URIs from TVS section 10.3, in
ascending order: `http://eID.logius.nl/LoA/basic`,
`http://eidas.europa.eu/LoA/low`, `http://eidas.europa.eu/LoA/substantial`,
and `http://eidas.europa.eu/LoA/high`. Original IdP class URIs belong to Advice
and are not accepted as the summary's authentication level.

Relative paths resolve against the directory containing the loaded INI file.
The local decryption `KeyName` defaults to the lowercase SHA-256 fingerprint
of the decryption certificate. Set it to the trusted registered metadata name
when different; this fallback does not create a signing `KeyName` for IdP
metadata.

Keys, certificates and metadata load at startup; restart the service after
replacing them. Expiry of metadata and trusted certificates is also checked for
each request. There is no automatic metadata download or online revocation check.

## Deployment

The `[uvicorn] root_path` INI setting reaches FastAPI only when Swagger is
enabled and is not forwarded to Uvicorn. With Swagger disabled, prefixed URLs
can return `404` unless the proxy strips the prefix or the ASGI server supplies
the appropriate root path. Verify the actual deployment.

For the default entrypoint on a read-only root, mount a pre-existing readable
configuration at `FASTAPI_CONFIG_PATH` (default `app.conf`); `docker/init.sh`
otherwise tries to copy a template. The standalone entrypoint requires
`/src/app.conf` even if `FASTAPI_CONFIG_PATH` points elsewhere. When SAML is
enabled, mount the local metadata, certificate and private key read-only.

Tested verification and decryption paths process SAML in memory, but dropping
references is not secure erasure. Protect or disable swap and core dumps under
the deployment security policy. The in-process xmlsec error callback and debug
setting are process-global. Other code must not replace the callback after
xmlsec loads or reconfigure the debug setting concurrently; otherwise native
diagnostics can escape. The service serializes only its own operations.

## Local SAML debugging

Normal SAML diagnostics log fixed reasons such as `signature_failed`,
`invalid_issuer`, `invalid_conditions_or_audience` or `decryption_failed`,
without received XML or arbitrary library exception messages.

To see original Python exception chains and tracebacks **with synthetic test
data only**, configure the local log level and output:

```ini
[app]
loglevel = debug

[logging]
include_traces = True
syslog_path =
```

Debug traces can contain SAML, personal identifiers, key material and other
secrets. `loglevel = debug` alone enables logging original exceptions, including
outside a local environment. Do not use it in production or when logs are sent
to remote collectors. Restrict access to and remove local diagnostic logs after
use. DEBUG logging does not enable process-global xmlsec native diagnostics or
PySAML2's suppressed library logs; errors swallowed inside those libraries may
still lack details.

## Development checks

After installing dependencies with Poetry, run:

```bash
make POETRY=1 lint type-check test
```
