from __future__ import annotations

import os

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        # Fail fast if required SWIG artifacts were not staged into the project root.
        required = [
            os.path.join(self.root, "introvirt.py"),
            os.path.join(self.root, "introvirt.pyi"),
        ]
        missing = [p for p in required if not os.path.exists(p)]
        so_files = []
        try:
            so_files = [
                os.path.join(self.root, name)
                for name in os.listdir(self.root)
                if name.startswith("_introvirt_py") and name.endswith(".so")
            ]
        except FileNotFoundError:
            missing.append(self.root)

        if not so_files:
            missing.append(os.path.join(self.root, "_introvirt_py*.so"))

        if missing:
            missing_str = "\n".join(f"- {p}" for p in missing)
            raise RuntimeError(
                "Missing required IntroVirt SWIG artifacts in project root.\n"
                "Building the pyintrovirt wheel is handled automatically by the IntroVirt build system.\n"
                "If you are building the wheel manually, these files must be staged before building the wheel/sdist:\n"
                f"{missing_str}\n"
            )

        # Ensure these files are included even though they're top-level (not in the
        # pyintrovirt package) and even when building wheels from an sdist.
        # `force_include` bypasses package-only selection.
        force_include = build_data.setdefault("force_include", {})
        force_include[required[0]] = "introvirt.py"
        force_include[required[1]] = "introvirt.pyi"
        for so_path in so_files:
            force_include[so_path] = os.path.basename(so_path)

        # This wheel is not pure-Python (it bundles a .so). Ensure the wheel tag and
        # metadata reflect that when built by hatchling.
        if self.target_name == "wheel":
            build_data["infer_tag"] = True
            build_data["pure_python"] = False

