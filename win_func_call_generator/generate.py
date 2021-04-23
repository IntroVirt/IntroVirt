#!/usr/bin/env python3
#
# Copyright 2021 Assured Information Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
'''
Generate C++ classes for IntroVirt Windows library functions
'''

import argparse
import hashlib
import json
import os
import logging
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ENV = Environment(
    loader=FileSystemLoader(os.path.join(BASE_PATH, 'templates'))
)
LOGGER = logging.getLogger(__name__)

HEADER_TEMPLATE = ENV.get_template('function.hh.tpl')
SOURCE_TEMPLATE = ENV.get_template('function.cc.tpl')
FWD_TEMPLATE = ENV.get_template('fwd.hh.tpl')
INCLUDES_TEMPLATE = ENV.get_template('includes.hh.tpl')
DEBUG = False


def clang_format(path, data) -> str:
    tmp_path = path.parent / ("." + path.name)
    with open(tmp_path, 'w') as file:
        file.write(data)

    subprocess.run(["clang-format", "-i", "-style=file", tmp_path])
    with open(tmp_path, 'r') as file:
        result = file.read()

    os.unlink(tmp_path)
    return result


def update_file(path, data):
    """
    Update a file with new data.
    This is so that files that haven't changed don't get rebuild.
    """
    if path.exists():
        # Hash the buffer and the file
        new_hash = hashlib.sha1(data.encode())
        with open(path, 'r') as file:
            old_hash = hashlib.sha1(file.read().encode())

        # Don't rewrite if the hashes match
        if new_hash.hexdigest() == old_hash.hexdigest():
            return

    with open(path, 'w') as file:
        # Update the file on disk
        if DEBUG:
            print(f"Updating ${path}")
        file.write(data)


def resolve_typemap_entry(typemap: dict, type_name: str) -> (dict, str):
    """ Recursively resolve a typemap entry """
    if type_name not in typemap:
        print(f"Failed to find {type_name} in typemap")

    remaining = 10
    while True:
        redirect = typemap[type_name].get("redirect")
        if not redirect:
            break
        type_name = redirect
        remaining -= 1
        if remaining == 0:
            raise Exception("Too many nested 'remaining'")

    entry = typemap[type_name]
    if "extends" in entry:
        # We have to merge things together, because "update" will replace them
        base_entry, entry["extends"] = resolve_typemap_entry(
            typemap, entry["extends"])
        base_entry = base_entry.copy()

        # TODO: We shouldn't have to list every single parameter here to override
        if "size_t" in entry:
            base_entry["size_t"] = entry["size_t"]

        if "includes" in base_entry and "includes" in entry:
            base_entry["includes"] = list(set().union(
                base_entry["includes"], entry["includes"]))

        base_entry.update(entry)
        entry = base_entry

    return entry, type_name


def generate_arg_helper_info(arg, typemap):
    """ Add helper information to individual arguments """
    typemap_entry, arg["type"] = resolve_typemap_entry(typemap, arg["type"])
    if not typemap_entry:
        print(f"Failed to find {arg['type']} in typemap")
        return

    # Make sure we're not modifying the original
    typemap_entry = typemap_entry.copy()
    typemap_entry["arg"] = arg
    typemap_entry["index"] = arg.get("index")
    typemap_entry["result_parameter"] = arg.get("result_parameter")

    if (DEBUG):
        print(f"Processing argument {arg['name']} of type {arg['type']}")

    typemap_entry_json = json.dumps(typemap_entry, indent=4)

    # Run template on the helper json
    rtemplate = ENV.from_string(typemap_entry_json)
    arg_config_json = rtemplate.render(typemap_entry)
    arg.update(json.loads(arg_config_json))


def generate_includes(data):
    """ Generate the includes array for a specific function """
    includes = set()
    typemap = data["typemap"]

    if data["result"]["type"] in typemap:
        typemap_entry = typemap[data["result"]["type"]]
        for include in typemap_entry.get("includes", []):
            includes.add(include)

    for arg in data["arguments"]:
        if arg["type"] not in typemap:
            continue
        typemap_entry = typemap[arg["type"]]
        if "includes" not in typemap_entry:
            continue
        for include in typemap_entry["includes"]:
            includes.add(include)

    # Update the final include value
    data["includes"] = includes


def generate_library(library_dir: os.DirEntry, global_typemap: dict, include_dir: Path, src_dir: Path):
    """ Generate the output for a single library """
    if DEBUG:
        print("Loading " + library_dir.path)
    typemap = global_typemap.copy()

    with open(os.path.join(library_dir, "settings.json")) as file:
        if DEBUG:
            print(f"Loading {os.path.join(library_dir, 'settings.json')}")
        settings = json.load(file)
    with open(os.path.join(library_dir, "typemap.json")) as file:
        if DEBUG:
            print(f"Loading {os.path.join(library_dir, 'typemap.json')}")        
        typemap.update(json.load(file))
    with open(os.path.join(library_dir, "functions.json")) as file:
        if DEBUG:
            print(f"Loading {os.path.join(library_dir, 'functions.json')}")        
        functions = json.load(file)

    for function in functions:
        if DEBUG:
            print(f"Parsing {function}")
        data = {"function_name": function, "typemap": typemap}
        data.update(settings)
        data.update(functions[function])
        generate_includes(data)

        index = 0
        for arg in functions[function]["arguments"]:
            arg["json_map"] = "args"
            arg["index"] = index
            # Set defaults for in and out
            if not "in" in arg:
                arg["in"] = True
            if not "out" in arg:
                arg["out"] = False
            generate_arg_helper_info(arg, typemap)
            index += 1

        if not "result" in data:
            data["result"] = {"type": "void"}

        data["result"]["json_map"] = "json"
        data["result"]["result_parameter"] = True
        data["result"]["name"] = "result"
        data["result"]["in"] = False
        data["result"]["out"] = True
        generate_arg_helper_info(data["result"], typemap)

        header_data = clang_format(
            include_dir / "functions" / (function + ".hh"), HEADER_TEMPLATE.render(data))
        update_file(include_dir / "functions" /
                    (function + ".hh"), header_data)

        source_data = clang_format(
            src_dir / "functions" / (function + ".cc"), SOURCE_TEMPLATE.render(data))
        update_file(src_dir / "functions" / (function + ".cc"), source_data)

    data = {"functions": functions}
    data.update(settings)

    includes_file = clang_format(
        include_dir / (library_dir.name + ".hh"), INCLUDES_TEMPLATE.render(data))
    update_file(include_dir / (library_dir.name + ".hh"), includes_file)

    fwd_file = clang_format(include_dir / "fwd.hh", FWD_TEMPLATE.render(data))
    update_file(include_dir / "fwd.hh", fwd_file)


def generate_filelist(library_dir, include_dir, src_dir, headers: bool, sources: bool):
    if headers:
        print(os.path.abspath(include_dir / f"{library_dir.name}.hh"), end=';')
        print(os.path.abspath(include_dir / "fwd.hh"), end=';')

    with open(os.path.join(library_dir, "functions.json")) as file:
        if DEBUG:
            print(f"Loading {os.path.join(library_dir, 'functions.json')}")
        functions = json.load(file)

    for function in functions:
        if headers:
            print(os.path.abspath(include_dir /
                                  "functions" / f"{function}.hh"), end=';')
        if sources:
            print(os.path.abspath(
                src_dir / "functions" / f"{function}.cc"), end=';')


def main():
    """ Main startup routine """
    parser = argparse.ArgumentParser(
        description="Generate Windows function call handlers")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--sources", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("include_dir")
    parser.add_argument("src_dir")

    args = parser.parse_args()

    top_include_dir = Path(args.include_dir).absolute()
    top_src_dir = Path(args.src_dir).absolute()

    global DEBUG
    DEBUG = args.debug

    with open(os.path.join(BASE_PATH, "typemap.json")) as file:
        if DEBUG:
            print(f"Loading {os.path.join(BASE_PATH, 'typemap.json')}")
        global_typemap = json.load(file)

    for library_dir in os.scandir(os.path.join(BASE_PATH, "libraries")):
        include_dir = top_include_dir / library_dir.name
        src_dir = top_src_dir / library_dir.name
        include_functions_dir = include_dir / "functions"
        src_functions_dir = src_dir / "functions"

        if args.headers or args.sources:
            generate_filelist(library_dir, include_dir,
                              src_dir, args.headers, args.sources)
            continue

        if not include_functions_dir.exists():
            include_functions_dir.mkdir(parents=True)
        if not src_functions_dir.exists():
            src_functions_dir.mkdir(parents=True)

        generate_library(library_dir, global_typemap, include_dir, src_dir)


if __name__ == "__main__":
    main()
