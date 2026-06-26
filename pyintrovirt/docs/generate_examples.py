#!/usr/bin/env python3
"""Generate Sphinx example pages from @example tags in pyintrovirt tool docstrings."""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

DOCS_DIR = Path(__file__).resolve().parent
TOOLS_DIR = DOCS_DIR.parent / "pyintrovirt" / "tools"
EXAMPLES_DIR = DOCS_DIR / "examples"

EXAMPLE_TAG = re.compile(r"^@example\s+(\S+)")


def parse_example_docstring(source: str) -> tuple[str, str] | None:
    """Return (example_filename, body) if the module docstring starts with @example."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    docstring = ast.get_docstring(tree, clean=False)
    if not docstring:
        return None
    first_line, _, rest = docstring.partition("\n")
    match = EXAMPLE_TAG.match(first_line.strip())
    if not match:
        return None
    body = rest.strip()
    return match.group(1), body


def rst_title(name: str) -> str:
    underline = "=" * len(name)
    return f"{name}\n{underline}\n\n"


def generate_example_page(stem: str, body: str, rel_source: str) -> str:
    parts = [rst_title(stem)]
    if body:
        parts.append(f"{body}\n\n")
    parts.append(
        "Source\n"
        "------\n\n"
        f".. literalinclude:: {rel_source}\n"
        "   :language: python\n"
    )
    return "".join(parts)


EXAMPLES_INDEX_HEADER = textwrap.dedent(
    """\
    Example tools
    =============

    Python example tools live under ``pyintrovirt/tools/``. Each tool is marked
    with an ``@example`` tag in its module docstring and is listed below with
    full source.

    Requirements
    ------------

    - IntroVirt built with Python bindings (``-DINTROVIRT_PYTHON_BINDINGS=ON``)
    - ``python3-pyintrovirt`` deb installed, or the generated wheel in a venv
    - Root/sudo to access the hypervisor
    - An IntroVirt-patched hypervisor (e.g. KVM) with kvm-introvirt installed

    Running examples
    ----------------

    After installing ``python3-pyintrovirt``, use the console scripts:

    .. code-block:: bash

       sudo ivsyscallmon_py --list
       sudo ivsyscallmon_py -d win10 --syscall NtCreateFile
       sudo ivcallmon_py win10 --procname notepad.exe 'ntdll!Nt*'
       sudo ivfilemon_py -d win10 -f "C:\\\\Windows\\\\System32\\\\config\\\\SAM"

    Or run as modules:

    .. code-block:: bash

       sudo python3 -m pyintrovirt.tools.ivsyscallmon --list
       sudo python3 -m pyintrovirt.tools.ivcallmon win10 --procname notepad.exe
       sudo python3 -m pyintrovirt.tools.ivfilemon -d win10 -f "C:\\\\path\\\\to\\\\file"

    ``ivsyscallmon --list`` replaces the old standalone ``list_domains`` example.

    System call filtering (Windows)
    -------------------------------

    For Windows guests, enable the filter at the domain level
    (``domain.system_call_filter().enabled(True)``) and set which syscalls to trap
    at the guest level via
    ``WindowsGuest.set_system_call_filter(domain.system_call_filter(), SystemCallIndex_XXX, True)``.
    Do not call ``set_64`` or ``set_32`` on the domain filter; the guest converts
    ``SystemCallIndex`` to native indices. This matches **ivfilemon**, **ivcallmon**,
    and **vmcall_interface**.

    Examples
    --------

    .. toctree::
       :maxdepth: 1

    """
)


def main() -> None:
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    examples: list[tuple[str, str, Path]] = []
    for tool_path in sorted(TOOLS_DIR.glob("*.py")):
        source = tool_path.read_text(encoding="utf-8")
        parsed = parse_example_docstring(source)
        if parsed is None:
            continue
        example_name, body = parsed
        stem = tool_path.stem
        rel_source = f"../../pyintrovirt/tools/{tool_path.name}"
        page = generate_example_page(stem, body, rel_source)
        out_path = EXAMPLES_DIR / f"{stem}.rst"
        out_path.write_text(page, encoding="utf-8")
        examples.append((stem, example_name, tool_path))

    if not examples:
        raise SystemExit(f"No @example tools found in {TOOLS_DIR}")

    toctree_lines = "\n".join(f"   {stem}" for stem, _, _ in examples)
    index_content = EXAMPLES_INDEX_HEADER + toctree_lines + "\n"
    (EXAMPLES_DIR / "index.rst").write_text(index_content, encoding="utf-8")

    print(f"Generated {len(examples)} example page(s) in {EXAMPLES_DIR}")


if __name__ == "__main__":
    main()
