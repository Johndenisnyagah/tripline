"""Smoke tests for the scaffold: the pinned toolchain is installed and the backends load."""

from importlib.metadata import version

import pytest

PINS = {
    "sigma-cli": "3.1.0",
    "pySigma": "1.5.1",
    "pySigma-backend-kusto": "1.0.1",
    "pySigma-backend-splunk": "2.1.0",
    "pySigma-backend-sqlite": "2.0.0",
    "pySigma-validators-sigmahq": "0.21.0",
    "python-evtx": "0.8.1",
}


@pytest.mark.parametrize(("package", "pinned"), PINS.items())
def test_pinned_version_installed(package: str, pinned: str) -> None:
    assert version(package) == pinned


def test_backends_load() -> None:
    from sigma.plugins import InstalledSigmaPlugins

    plugins = InstalledSigmaPlugins.autodiscover()
    for target in ("kusto", "splunk", "sqlite"):
        assert target in plugins.backends, f"backend {target!r} not installed"
