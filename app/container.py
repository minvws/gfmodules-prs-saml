from typing import cast

import inject
from fastapi import Request

from app.config import Config
from app.saml.service import SamlService


def build_container(config: Config) -> inject.Injector:
    def configure(binder: inject.Binder) -> None:
        binder.bind(Config, config)
        service = SamlService(config.saml) if config.saml.enabled else None
        binder.bind(SamlService, service)

    return inject.Injector(configure, bind_in_runtime=False)


def get_saml_service(request: Request) -> SamlService | None:
    container: inject.Injector = request.app.state.container
    return cast(SamlService | None, container.get_instance(SamlService))
