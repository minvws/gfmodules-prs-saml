# PRS-SAML

PRS-SAML is the internal SAML receiver for the
[Pseudoniemendienst (PRS)](https://github.com/minvws/gfmodules-pseudoniemendienst).
PRS calls `POST /saml/decrypt` to verify an already resolved TVS ArtifactResponse
and retrieve the decrypted personal ID and authentication level.

## Quick start

With Python 3.14 and Poetry:

```bash
poetry install
test -e app.conf || cp app.conf.example app.conf
poetry run python -m app.main
```

With the example configuration, open [Swagger UI](http://localhost:8534/docs).
SAML is disabled by default.

## Documentation

- [SAML API and caller responsibilities](docs/saml-api.md)
- [Configuration, deployment and development checks](docs/saml-configuration.md)
- [Log events](docs/log-events.md)
