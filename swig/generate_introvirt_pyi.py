#!/usr/bin/env python3

"""
Generate a `introvirt.pyi` stub file by introspecting the built `introvirt` module.

This script is intended to be run from CMake after the SWIG-based `introvirt_py`
extension module has been built. It imports `introvirt` from the build tree,
discovers enums, classes, functions, and simple constants, and emits a
deterministic `introvirt.pyi` suitable for static type checkers.
"""

from __future__ import annotations

import argparse
import inspect
import os
import sys
from enum import Enum, EnumMeta
from types import ModuleType
from typing import Any, Dict, Iterable, List, Tuple


def _is_public_name(name: str) -> bool:
    return not name.startswith("_")


def _class_bases_for_stub(cls: type, module_name: str) -> List[str]:
    bases: List[str] = []
    for base in cls.__bases__:
        # Skip `object` and internal SWIG implementation details
        if base is object:
            continue
        mod = getattr(base, "__module__", "")
        if mod in (module_name, "builtins"):
            bases.append(base.__name__)
    return bases


def _format_parameters(sig: inspect.Signature) -> str:
    parts: List[str] = []
    for i, (name, param) in enumerate(sig.parameters.items()):
        annotation = "Any"
        default = ""

        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            parts.append(f"*{name}: {annotation}")
            continue
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            parts.append(f"**{name}: {annotation}")
            continue

        # Keep the first positional parameter name as-is (usually `self` or `cls`)
        if i == 0 and param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            # self / cls are left unannotated; others become Any
            if name not in ("self", "cls"):
                parts.append(f"{name}: {annotation}{default}")
            else:
                parts.append(f"{name}{default}")
            continue

        parts.append(f"{name}: {annotation}{default}")

    return ", ".join(parts)


def _function_stub(name: str, obj: Any) -> str:
    try:
        sig = inspect.signature(obj)
    except (TypeError, ValueError):
        return f"def {name}(*args: Any, **kwargs: Any) -> Any: ..."

    params_src = _format_parameters(sig)
    return f"def {name}({params_src}) -> Any: ..."


def _collect_members(mod: ModuleType) -> Tuple[
    Dict[str, EnumMeta],
    Dict[str, type],
    Dict[str, Any],
    Dict[str, Any],
]:
    enums: Dict[str, EnumMeta] = {}
    classes: Dict[str, type] = {}
    functions: Dict[str, Any] = {}
    constants: Dict[str, Any] = {}

    module_name = mod.__name__
    for name, obj in vars(mod).items():
        if not _is_public_name(name):
            continue

        # Enums
        if isinstance(obj, EnumMeta):
            enums[name] = obj
            continue

        # Classes (but not enums)
        if isinstance(obj, type) and getattr(obj, "__module__", None) == module_name:
            classes[name] = obj
            continue

        # Functions
        if (inspect.isfunction(obj) or inspect.isbuiltin(obj)) and getattr(
            obj, "__module__", None
        ) == module_name:
            functions[name] = obj
            continue

        # Simple constants (ints, strs, bools, floats)
        if isinstance(obj, (int, bool, float, str)):
            constants[name] = obj

    return enums, classes, functions, constants


def _emit_enum(name: str, enum_type: EnumMeta) -> str:
    lines: List[str] = [f"class {name}(Enum):"]
    members = list(enum_type.__members__.keys())
    if not members:
        lines.append("    ...")
    else:
        for member in members:
            lines.append(f'    {member}: "{name}"')
    return "\n".join(lines)


def _emit_class(name: str, cls: type, module_name: str) -> str:
    bases = _class_bases_for_stub(cls, module_name)
    bases_clause = f"({', '.join(bases)})" if bases else ""
    header = f"class {name}{bases_clause}:"

    method_lines: List[str] = []
    for attr_name, attr in inspect.getmembers(cls):
        if not _is_public_name(attr_name):
            continue
        if not (
            inspect.isfunction(attr)
            or inspect.ismethoddescriptor(attr)
            or inspect.isbuiltin(attr)
        ):
            continue
        stub = _function_stub(attr_name, attr)
        method_lines.append(f"    {stub}")

    if not method_lines:
        method_lines.append("    ...")

    return "\n".join([header, *method_lines])


def _emit_constant(name: str, value: Any) -> str:
    if isinstance(value, bool):
        type_name = "bool"
    elif isinstance(value, int):
        type_name = "int"
    elif isinstance(value, float):
        type_name = "float"
    elif isinstance(value, str):
        type_name = "str"
    else:
        type_name = "Any"

    return f"{name}: {type_name}"


def _write_stub(
    output_path: str,
    module: ModuleType,
    enums: Dict[str, EnumMeta],
    classes: Dict[str, type],
    functions: Dict[str, Any],
    constants: Dict[str, Any],
) -> None:
    module_name = module.__name__
    lines: List[str] = []

    # Header and imports
    lines.append(
        '"""Type stubs for the IntroVirt SWIG bindings (auto-generated; do not edit by hand)."""'
    )
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from enum import Enum")
    lines.append("from typing import Any, Iterator, List, Optional, overload")
    lines.append("")

    # Enums
    for name in sorted(enums.keys()):
        lines.append(_emit_enum(name, enums[name]))
        lines.append("")

    # Classes (including exceptions, events, etc.)
    for name in sorted(classes.keys()):
        lines.append(_emit_class(name, classes[name], module_name))
        lines.append("")

    # Functions
    for name in sorted(functions.keys()):
        lines.append(_function_stub(name, functions[name]))

    if functions:
        lines.append("")

    # Constants
    for name in sorted(constants.keys()):
        lines.append(_emit_constant(name, constants[name]))

    contents = "\n".join(lines).rstrip() + "\n"

    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(contents)
    os.replace(tmp_path, output_path)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate introvirt.pyi by introspecting the built introvirt module."
    )
    parser.add_argument(
        "--module-dir",
        required=True,
        help="Directory containing introvirt.py and the compiled _introvirt_py extension.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the generated introvirt.pyi file.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    module_dir = os.path.abspath(args.module_dir)
    sys.path.insert(0, module_dir)

    try:
        import introvirt as introvirt_module  # type: ignore[import]
    except Exception as exc:  # pragma: no cover - failures should abort the build
        raise SystemExit(f"Failed to import introvirt from {module_dir}: {exc}") from exc

    enums, classes, functions, constants = _collect_members(introvirt_module)
    _write_stub(args.output, introvirt_module, enums, classes, functions, constants)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

