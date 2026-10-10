"""GRC Lake package."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    # Single source of truth: the version declared in pyproject.toml and stamped
    # into the installed distribution metadata. Deriving it here means it can
    # never drift from the wheel the way a hardcoded literal did.
    __version__ = _pkg_version("grc-lake")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
