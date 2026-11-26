"""Coordinate real application crypto operations across threads."""

import threading
from types import SimpleNamespace
from typing import Any

import pytest
import xmlsec
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from app.saml import decryption, signatures
from tests.saml_helpers import encrypted_identifier
from tests.test_saml_decryption import NS, decrypt
from tests.test_saml_signatures import make_signing_material, signed_element


@pytest.mark.parametrize("holder_kind", ["decrypt", "signature"])
@pytest.mark.parametrize("contender_kind", ["decrypt", "signature"])
@pytest.mark.parametrize("holder_fails", [False, True])
def test_native_trace_writes_do_not_overlap_application_crypto(
    monkeypatch: pytest.MonkeyPatch,
    holder_kind: str,
    contender_kind: str,
    holder_fails: bool,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    identifiers = [encrypted_identifier(private_key), encrypted_identifier(private_key)]
    material = make_signing_material()
    signed = [signed_element(material), signed_element(material)]
    if holder_kind == "signature" and holder_fails:
        signed[0].find("saml:Issuer", NS).text = "changed-issuer"
    active = threading.Event()
    prepared = threading.Event()
    release = threading.Event()
    trace_write_while_active = threading.Event()
    errors: list[Exception] = []
    real_enable = xmlsec.enable_debug_trace
    real_encryption = xmlsec.EncryptionContext
    real_signature = xmlsec.SignatureContext
    real_transport = decryption._validate_transport
    real_select = signatures._select_certificate

    def enable(enabled: bool) -> None:
        if active.is_set():
            trace_write_while_active.set()
        real_enable(enabled)

    def pause_holder() -> None:
        if threading.current_thread().name == "holder":
            active.set()
            if not release.wait(8):
                raise RuntimeError("test coordination timed out")

    def encryption(manager: xmlsec.KeysManager | None = None) -> object:
        inner = real_encryption(manager)

        class Observed:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                inner.key = value

            def decrypt(self, node: etree._Element) -> bytes | etree._Element:
                is_key = node.tag == "{" + NS["xenc"] + "}EncryptedKey"
                if is_key:
                    pause_holder()
                try:
                    return inner.decrypt(node)
                finally:
                    if is_key and threading.current_thread().name == "holder":
                        active.clear()

        return Observed()

    def signature() -> object:
        inner = real_signature()

        class Observed:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                inner.key = value

            def __getattr__(self, name: str) -> Any:
                return getattr(inner, name)

            def verify(self, node: etree._Element) -> None:
                pause_holder()
                try:
                    inner.verify(node)
                finally:
                    if threading.current_thread().name == "holder":
                        active.clear()

        return Observed()

    def transport(method: etree._Element) -> None:
        real_transport(method)
        if threading.current_thread().name == "contender":
            prepared.set()

    def select(key_info: etree._Element, certificates: dict[str, bytes]) -> bytes:
        result = real_select(key_info, certificates)
        if threading.current_thread().name == "contender":
            prepared.set()
        return result

    monkeypatch.setattr(xmlsec, "enable_debug_trace", enable)
    monkeypatch.setattr(
        decryption,
        "xmlsec",
        SimpleNamespace(
            EncryptionContext=encryption,
            Key=xmlsec.Key,
            KeysManager=xmlsec.KeysManager,
            constants=xmlsec.constants,
        ),
    )
    monkeypatch.setattr(
        signatures,
        "xmlsec",
        SimpleNamespace(
            SignatureContext=signature,
            Key=xmlsec.Key,
            constants=xmlsec.constants,
            Error=xmlsec.Error,
        ),
    )
    monkeypatch.setattr(decryption, "_validate_transport", transport)
    monkeypatch.setattr(signatures, "_select_certificate", select)

    def run(kind: str, index: int) -> None:
        try:
            should_fail = index == 0 and holder_fails
            try:
                if kind == "decrypt":
                    key = wrong_key if should_fail else private_key
                    assert decrypt(identifiers[index], key).text == "950000012"
                else:
                    signatures.verify_signature(
                        signed[index], {"idp-signing": material[1]}
                    )
            except ValueError as error:
                expected = (
                    "Invalid encrypted identifier"
                    if kind == "decrypt"
                    else "Invalid SAML signature"
                )
                if not should_fail or str(error) != expected:
                    raise
            else:
                if should_fail:
                    raise AssertionError("Expected native rejection")
        except Exception as error:  # noqa: BLE001 - collect failures from test threads
            errors.append(error)

    holder = threading.Thread(target=run, args=(holder_kind, 0), name="holder")
    contender = threading.Thread(target=run, args=(contender_kind, 1), name="contender")
    holder.start()
    try:
        assert active.wait(5), "holder did not reach its native operation"
        contender.start()
        assert prepared.wait(5), "contender did not reach pre-native validation"
        trace_write_while_active.wait(0.5)
    finally:
        release.set()
        holder.join(8)
        if contender.ident is not None:
            contender.join(8)

    assert not holder.is_alive() and not contender.is_alive()
    if errors:
        pytest.fail(f"Application crypto worker failed ({len(errors)} errors)")
    assert not trace_write_while_active.is_set(), (
        "An application trace-setting write overlapped another native operation"
    )
