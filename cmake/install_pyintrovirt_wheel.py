#!/usr/bin/env python3
"""Install the pyintrovirt wheel into Debian system Python paths."""

from __future__ import annotations

import argparse
import glob
import os
import sys
import sysconfig


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dist-dir",
        required=True,
        help="Directory containing pyintrovirt-*.whl (e.g. build/python/dist)",
    )
    parser.add_argument(
        "--destdir",
        default=os.environ.get("DESTDIR", ""),
        help="Staging root for packaging (DESTDIR); empty for a local install",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    wheels = sorted(glob.glob(os.path.join(args.dist_dir, "pyintrovirt-*.whl")))
    if not wheels:
        print(
            f"error: no pyintrovirt wheel found in {args.dist_dir}",
            file=sys.stderr,
        )
        return 1

    try:
        import installer
        from installer.destinations import SchemeDictionaryDestination
        from installer.sources import WheelFile
        from installer.utils import get_launcher_kind
    except ImportError:
        print(
            "error: python installer module not found; install python3-installer",
            file=sys.stderr,
        )
        return 1

    scheme_dict = dict(sysconfig.get_paths(scheme="deb_system"))
    if "headers" not in scheme_dict:
        scheme_dict["headers"] = os.path.join(
            sysconfig.get_path("include", scheme="deb_system"),
            "pyintrovirt",
        )

    wheel = wheels[-1]
    with WheelFile.open(wheel) as source:
        destination = SchemeDictionaryDestination(
            scheme_dict=scheme_dict,
            interpreter=sys.executable,
            script_kind=get_launcher_kind(),
            bytecode_optimization_levels=[],
            destdir=args.destdir or None,
        )
        installer.install(source, destination, {})

    return 0


if __name__ == "__main__":
    sys.exit(main())
