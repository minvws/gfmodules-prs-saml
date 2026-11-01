"""Check in-memory SAML processing and native diagnostics in clean interpreters."""

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version


def test_xmlsec_dependency_excludes_versions_without_uri_policy() -> None:
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    requirement = project["tool"]["poetry"]["dependencies"]["xmlsec"]
    if requirement.startswith("^"):
        version = Version(requirement[1:])
        assert version.major > 0
        requirement = f">={version},<{version.major + 1}"
    allowed = SpecifierSet(requirement)
    lock = tomllib.loads((root / "poetry.lock").read_text())
    locked_version = next(
        Version(package["version"])
        for package in lock["package"]
        if package["name"] == "xmlsec"
    )

    assert Version("1.3.17") not in allowed
    assert locked_version >= Version("1.3.18")
    assert locked_version in allowed


def test_in_memory_probe_without_xmlsec_executable() -> None:
    process = subprocess.run(
        [sys.executable, "-m", "tests.saml_in_memory_probe"],
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PATH": ""},
        timeout=60,
    )
    assert process.returncode == 0, f"Probe exited with status {process.returncode}"
    assert process.stdout == b"probe-ok\n"
    assert process.stderr == b""


def test_optimized_in_memory_probe_accepts_real_service() -> None:
    process = subprocess.run(
        [sys.executable, "-O", "-m", "tests.saml_in_memory_probe"],
        check=False,
        capture_output=True,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONOPTIMIZE": "1",
            "PATH": "",
        },
        timeout=60,
    )
    assert process.returncode == 0
    assert process.stdout == b"probe-ok\n"
    assert process.stderr == b""


_NATIVE_OUTPUT_PROBE = r"""
import sys
import xmlsec
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from tests.saml_helpers import encrypted_identifier
from tests.test_saml_decryption import decrypt
from tests.test_saml_signatures import make_signing_material, signed_element, verify


case = sys.argv[1]
if case == "signature":
    material = make_signing_material()
    element = signed_element(material)
    element[0].text = "changed-issuer"
    before = etree.tostring(element)
    xmlsec.enable_debug_trace(True)
    try:
        verify(element, {"idp-signing": material[1]})
    except ValueError as error:
        if str(error) != "Invalid SAML signature":
            raise SystemExit(11)
        if error.__cause__ is not None or error.__context__ is not None:
            raise SystemExit(19)
    else:
        raise SystemExit(12)
    if etree.tostring(element) != before:
        raise SystemExit(13)
else:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if case == "wrong_key":
        identifier = encrypted_identifier(private_key)
        selected_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif case == "invalid_padding":
        identifier = encrypted_identifier(private_key, padding_byte=0)
        selected_key = private_key
    elif case == "malformed_plaintext":
        identifier = encrypted_identifier(private_key, plaintext=b"<NameID>synthetic<")
        selected_key = private_key
    else:
        raise SystemExit(14)
    before = etree.tostring(identifier)
    xmlsec.enable_debug_trace(True)
    try:
        decrypt(identifier, selected_key)
    except ValueError as error:
        if str(error) != "Invalid encrypted identifier":
            raise SystemExit(15)
        if error.__cause__ is not None or error.__context__ is not None:
            raise SystemExit(16)
    else:
        raise SystemExit(17)
    if etree.tostring(identifier) != before:
        raise SystemExit(18)
"""


@pytest.mark.parametrize(
    "case", ["wrong_key", "invalid_padding", "malformed_plaintext", "signature"]
)
def test_native_debug_trace_emits_no_diagnostics_on_failure(case: str) -> None:
    process = subprocess.run(
        [sys.executable, "-c", _NATIVE_OUTPUT_PROBE, case],
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=30,
    )
    if process.returncode:
        pytest.fail(f"Isolated native-output probe failed (exit {process.returncode})")
    if process.stdout or process.stderr:
        pytest.fail(
            "Native-output probe emitted output "
            f"(stdout {len(process.stdout)} bytes, stderr {len(process.stderr)} bytes)",
            pytrace=False,
        )
