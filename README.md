# PRS-SAML

The PRS-SAML service is the *SAML-ontvanger* of the
[Pseudoniemendienst (PRS)](https://github.com/minvws/gfmodules-pseudoniemendienst):

## Development

```bash
poetry install
cp app.conf.example app.conf
poetry run python -m app.main
```

The API is then available at http://localhost:8534/docs.

Run the checks:

```bash
make lint type-check test
```
