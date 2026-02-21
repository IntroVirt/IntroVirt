"""pyintrovirt: Python library for IntroVirt VM introspection.

Requires IntroVirt .deb packages to be installed (libintrovirt1, python3-introvirt).
The IntroVirt Python bindings are not on PyPI; install them from the IntroVirt
build or from the generated .deb packages.
"""

import sys

if sys.platform != "linux":
    raise RuntimeError("pyintrovirt only supports Linux")

try:
    import introvirt  # type: ignore[import-not-found]  # noqa: F401
except ImportError as exc:
    raise RuntimeError(
        "IntroVirt Python bindings are not installed. Install the IntroVirt .deb packages (libintrovirt1, python3-introvirt) before using this library."
    ) from exc

__all__: list[str] = []
