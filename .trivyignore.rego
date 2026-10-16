# METADATA
# description: Trivy reports vulnerabilities from pip embedded CycloneDX SBOM instead of installed Python packages
# related_resources:
# - ref: https://github.com/aquasecurity/trivy/discussions/11031
package trivy

default ignore = false

ignore {
    input.VulnerabilityID == "CVE-2025-47273"
    input.PkgIdentifier.BOMRef == "pkg:pypi/setuptools@70.3.0"
}

ignore {
    input.VulnerabilityID == "GHSA-6v7p-g79w-8964"
    input.PkgIdentifier.BOMRef == "pkg:pypi/msgpack@1.1.2"
}

# urllib3 vendored by pip 26.2.1 (python base image and venv); pip is not used at
# runtime and no pip release ships urllib3 >= 2.8.0 yet. The app's own urllib3
# is 2.8.0 (poetry.lock), which Trivy reports separately.
ignore {
    input.VulnerabilityID == "CVE-2026-97687"
    input.PkgIdentifier.BOMRef == "pkg:pypi/urllib3@2.7.0"
}

ignore {
    input.VulnerabilityID == "CVE-2026-97688"
    input.PkgIdentifier.BOMRef == "pkg:pypi/urllib3@2.7.0"
}

ignore {
    input.VulnerabilityID == "CVE-2026-97689"
    input.PkgIdentifier.BOMRef == "pkg:pypi/urllib3@2.7.0"
}
