"""BOLACheck: authorization-first BOLA/IDOR testing."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bolacheck")
except PackageNotFoundError:  # pragma: no cover - source checkout before installation
    __version__ = "0.0.0"

__all__ = ["__version__"]

