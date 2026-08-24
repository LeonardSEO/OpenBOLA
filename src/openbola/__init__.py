"""OpenBOLA: authorization-first BOLA/IDOR testing."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("openbola")
except PackageNotFoundError:  # pragma: no cover - source checkout before installation
    __version__ = "0.0.0"

__all__ = ["__version__"]

