# PyIntroVirt

Python wrapper around the python bindings for the IntroVirt user-land library. This wrapper exposes helpers and utilities that make writing IntroVirt tools in Python simple and pythonic.

## System install

Install the `python3-pyintrovirt` deb produced by `ninja package` (with `-DINTROVIRT_PYTHON_BINDINGS=ON`). It installs into the system Python path so `import introvirt` and `import pyintrovirt` work without pip.

Do not copy SWIG artifacts (`introvirt.py`, `introvirt.pyi`, `_introvirt_py*.so`) into this source tree.

## Development

Wheel packaging is CMake-driven. From the IntroVirt repo root, configure with `-DINTROVIRT_PYTHON_BINDINGS=ON`, ensure `uv` and `python3-installer` are available, then run `ninja package`. The wheel is written to `build/python/dist/` for venv installs.

For local development and tests without installing the deb, point `PYTHONPATH` at `build/python/` after building the `introvirt_py` target.

Static type checking with `ty` also needs the generated `introvirt.pyi` from that build:

```bash
uv run --directory pyintrovirt ty check --extra-search-path ../build/python pyintrovirt
```
