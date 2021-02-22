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
Generate C++ syscall classes for IntroVirt
'''

import argparse
import filecmp
import json
import os
import sys
import logging
import subprocess

from collections import defaultdict

from pathlib import Path
from jinja2 import Environment, FileSystemLoader

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ENV = Environment(
    loader=FileSystemLoader(os.path.join(BASE_PATH, 'templates'))
)

LOGGER = logging.getLogger(__name__)


def move_tmp_to_target(source, target):
    '''
    Move temp file to final destination
    '''
    # Check if the file exists
    if Path(target).is_file():
        # Compare the contents
        if not filecmp.cmp(source, target):
            # Replace the file
            LOGGER.debug("Updating %s", target)
            os.replace(source, target)
        else:
            LOGGER.debug("Not updating %s", target)
            os.remove(source)
    else:
        # Target file doesn't even exist
        LOGGER.debug("Creating %s", target)
        os.rename(source, target)


def validate_args(data):
    '''
    Some basic checks on argument sanity
    '''
    indexes = set()

    for arg in data['arguments']:
        # Check for duplicate index settings (likely copy/paste error)
        if 'conditional_indexes' in arg:
            if 'index' in arg:
                print('ERROR: Both index and conditional_indexes specified in ' + data['name'])
                sys.exit(1)
        elif arg['index'] in indexes:
            print('ERROR: Duplicate argument index '
                  + str(arg['index']) + ' in ' + data['name'])
            sys.exit(1)
        else:
            indexes.add(arg['index'])


def parse_helper_arg(arg, helper_arg, arg_map):
    '''
    Parse helper arg type
    '''
    if helper_arg == 'kernel':
        arg['helper']['arguments'].append('this->kernel()')
    elif helper_arg == 'pointer':
        arg['helper']['arguments'].append(arg['functionName'] + '()')
    elif helper_arg == 'value':
        arg['helper']['arguments'].append('*(' + arg['name'] + '_)')
    elif helper_arg == 'size_arg':
        if 'size_arg' in arg:
            if (arg['size_arg']):
                arg['helper']['arguments'].append(arg['size_arg'] + '()')
        elif 'size_args' in arg:
            entry = 'std::min<uint64_t>('
            for size_arg in arg['size_args']:
                if size_arg in arg_map and 'pointer' in arg_map[size_arg] and arg_map[size_arg]['pointer']:

                    entry = entry + '(' + size_arg\
                        + 'Ptr() ? ' + size_arg\
                        + '() : 0xFFFFFFFFFFFFFFFFLL), '
                else:
                    entry = entry + size_arg + '(), '
            arg['helper']['arguments'].append(entry[:-2] + ')')

    elif helper_arg == 'type_arg':
        arg['helper']['arguments'].append(arg['type_arg'] + '()')
    else:
        arg['helper']['arguments'].append(helper_arg)


def load_typemap(arg, typemap):
    '''
    Load typemap settings if they're in the file
    '''
    arg_type = typemap[arg['type']]
    arg['original_type'] = arg['type']

    # Allow typemap to change the return type
    if 'type' in arg_type:
        arg['type'] = arg_type['type']

    if 'use_address_for_injection' in arg_type:
        arg['use_address_for_injection'] = arg_type['use_address_for_injection']

    if 'helper' in arg_type:
        if 'helper' not in arg:
            arg['helper'] = dict(arg_type['helper'])

        arg['helper']['type'] = arg['type']
        if 'rawType' in arg_type:
            arg['helper']['rawType'] = arg_type['rawType']
        else:
            arg['helper']['rawType'] = arg['type']

    if 'includes' in arg_type:
        arg['includes'] = arg_type.get('includes')

    if 'impl_includes' in arg_type:
        arg['impl_includes'] = arg_type.get('impl_includes')

    if 'impl_type' in arg_type:
        arg['impl_type'] = arg_type['impl_type']

    # Allow typemap to set defaults for these
    if 'rawType' in arg_type and 'rawType' not in arg:
        arg['rawType'] = arg_type['rawType']
    if 'writeMethod' in arg_type and 'writeMethod' not in arg:
        arg['writeMethod'] = arg_type['writeMethod']
    if 'writeBase' in arg_type and 'writeBase' not in arg:
        arg['writeBase'] = arg_type['writeBase']


def prepare_arg(arg):
    '''
    Add some variables and set defaults to the argument
    '''
    # Set some extra variables on the argument
    if arg.get('pointer'):
        # Use for get/setFooPtr()
        arg['functionName'] = arg['name'] + 'Ptr'
        # Used for the IMPL variable, pFoo
        arg['variableName'] = 'p' + arg['name']
    else:
        arg['pointer'] = False
        # Use for get/setFoo()
        arg['functionName'] = arg['name']
        # Used for the IMPL variable, Foo
        arg['variableName'] = arg['name']

    # When it's not a pointer, we can just treat it as a uint64_t
    if arg.get('rawType') == 'size_t':
        arg['rawType'] = 'uint64_t'

    # Used in the case where there are conditional indexes
    arg['indexVar'] = arg['variableName'] + 'Idx_'
    # Default the rawType to be the same as the type
    arg.setdefault('rawType', arg['type'])
    # Default to writing in std::dec
    arg.setdefault('writeBase', 'dec')
    # By default with a pointer type, we'll expect a 'write' method
    # By default for a non-pointer, we'll write it directly to the stream
    arg.setdefault('writeMethod', 'write' if arg.get('pointer') else 'direct')

    if 'out' in arg and 'in' not in arg:
        # If only out is specified, assume !in
        arg['in'] = False
    elif 'in' in arg and 'out' not in arg:
        # If only in is specified, assume !out
        arg['out'] = False
    elif 'out' not in arg and 'in' not in arg:
        # If neither is specified, assume in and !out
        arg['in'] = True
        arg['out'] = False

    # By default, don't parse output structures if the result is not NT_SUCCESS
    arg.setdefault('require_success', not arg['in'])

    # By default, don't parse structures if the result is STATUS_BUFFER_OVERFLOW
    arg.setdefault('allow_partial', False)


def process_args(data, typemap):
    '''
    Process the args
    '''
    # Do some simple checks on the arguments for obviously incorrect settings
    validate_args(data)

    data["includes"] = set()
    data["impl_includes"] = set()
    data['has_conditional_indexes'] = False
    conditional_indexes = set()
    data['has_helpers'] = False
    data['has_unique_arguments'] = False

    arg_map = dict()
    for arg in data['arguments']:
        # Put every argument into arg_map by name for easy lookup
        arg_map[arg['name']] = arg

        # Load typemap settings if they're in the file
        if arg['type'] in typemap:
            load_typemap(arg, typemap)
            if 'includes' in arg:
                data["includes"].update(arg['includes'])
            if 'impl_includes' in arg:
                data["impl_includes"].update(arg['impl_includes'])

        # Set some variables in the arg
        prepare_arg(arg)

    # Final processing on the argument
    for arg in data['arguments']:
        data['has_unique_arguments'] = True

        if 'conditional_indexes' in arg:
            # This is a global 'does any argument have conditional_indexes?' flag
            data['has_conditional_indexes'] = True
            arg['indexes'] = dict()
            for cond in arg['conditional_indexes']:
                arg['indexes'][cond['name']] = cond['index']
                conditional_indexes.add(cond['name'])
            data['conditional_indexes'] = sorted(conditional_indexes)

        if arg['pointer'] and 'helper' in arg:
            data['has_helpers'] = True
            arg['helper'].setdefault('mode', 'direct')

            helper_args = arg['helper'].get('arguments', ['kernel', 'pointer'])
            arg['helper']['arguments'] = []
            for helper_arg in helper_args:
                parse_helper_arg(arg, helper_arg, arg_map)


def write_files(data, namespace):
    '''
    Write the generated files
    '''
    # Set some template variables
    data['namespace'] = namespace

    # Load the public header  template
    hdr_override = 'overrides/' + data['name'] + '.hh.tpl'
    if Path('win_syscall_generator/templates/' + hdr_override).is_file():
        template = ENV.get_template(hdr_override)
    else:
        template = ENV.get_template('NtSystemCall.hh.tpl')

    # Write the public header
    path = 'include/introvirt/windows/kernel/' + namespace + '/syscall/' + data['className'] + '.hh'
    tmp_path = path + '.tmp.hh'
    with open(tmp_path, 'w') as output:
        output.write(template.render(data))
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)

    # Load the impl header template
    src_override = 'overrides/' + data['name'] + 'Impl.hh.tpl'
    if Path('win_syscall_generator/templates/' + src_override).is_file():
        template = ENV.get_template(src_override)
    else:
        template = ENV.get_template('NtSystemCallImpl.hh.tpl')

    # Write the impl header
    path = 'src/windows/kernel/' + namespace + '/syscall/' + data['className'] + 'Impl.hh'
    tmp_path = path + '.tmp.hh'
    with open(tmp_path, 'w') as output:
        output.write(template.render(data))
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)


def add_parent_data(ntdata, default_parent_name):
    '''
    Insert a call's parent information if available
    '''
    # Add parent information to each system call
    for name in ntdata:
        syscall = ntdata[name]
        syscall['name'] = name
        syscall['className'] = name

        if 'helper_base' not in syscall:
            syscall['helper_base'] = False

        parent_name = syscall.get('parent')
        if parent_name is None:
            # No parent specified, use the standard base class
            parent_name = default_parent_name
        else:
            syscall['parent'] = ntdata[parent_name]
            ntdata[parent_name]['has_children'] = True

        syscall['parent_name'] = parent_name

        # Validate that if a call has no arguments, it has a parent
        if 'arguments' not in syscall and 'parent' not in syscall:
            print("ERROR: Empty class " + syscall['name'])
            sys.exit(2)


def prepare_args(ntdata):
    '''
    Prepare each calls arguments, parent information and signature
    '''
    # Create full argument lists (for injection constructor)
    for name in ntdata:
        syscall = ntdata[name]
        arguments = []

        parent = syscall.get('parent')
        while parent is not None:
            # Add any parent arguments that aren't virtual
            if 'arguments' in parent:
                parent_args = parent['arguments']
                for parent_arg in parent_args:
                    arguments = [parent_arg] + arguments
            parent = parent.get('parent')

        if 'arguments' in syscall:
            arguments += syscall['arguments']

        # Sort them by index now
        sorted_arguments = {}
        for arg in arguments:
            if 'conditional_indexes' in arg:
                for cond in arg['conditional_indexes']:
                    if cond['name'] == name:
                        index = cond['index']
            else:
                index = arg['index']
            sorted_arguments[index] = arg

        # Save the signature to the syscall (in order)
        syscall['signature'] = []
        for key in sorted(sorted_arguments.keys()):
            syscall['signature'].append(sorted_arguments[key])


def process_calls(ntdata, typemap, categories, default_parent_name):
    '''
    Iterate over each call and prepare it for use
    '''
    # Update syscalls with information about their parents
    add_parent_data(ntdata, default_parent_name)

    # Process all arguments
    for name in ntdata:
        syscall = ntdata[name]
        if 'arguments' in syscall:
            process_args(syscall, typemap)
        
        if not syscall.get('helper_base', False):
            if 'category' in syscall:
                category = categories[syscall['category']]
                category.add(name)
            else:
                print("System call " + name + " missing a category")

        if not 'return_type' in syscall:
            syscall['return_type'] = 'NTSTATUS'

    # Prepare argument information
    prepare_args(ntdata)


def write_templates(ntdata, namespace):
    '''
    Generate all of our support files
    '''
    # Generate nt/syscalls/syscall.hh
    path = 'include/introvirt/windows/kernel/' + namespace + '/syscall/syscall.hh'
    tmp_path = path + '.tmp.hh'
    with open(tmp_path, 'w') as output:
        # Write out the file
        template = ENV.get_template('syscall.hh.tpl')
        output.write(template.render({'namespace': namespace, 'data': ntdata}))
    # Format it
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)

    # Generate nt/syscalls/syscall.hh
    path = 'src/windows/kernel/' + namespace + '/syscall/syscall.hh'
    tmp_path = path + '.tmp.hh'
    with open(tmp_path, 'w') as output:
        # Write out the file
        template = ENV.get_template('syscall_impl.hh.tpl')
        output.write(template.render({'namespace': namespace, 'data': ntdata}))
    # Format it
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)

    # Generate nt/syscalls/fwd.hh
    path = 'include/introvirt/windows/kernel/' + namespace + '/syscall/fwd.hh'
    tmp_path = path + '.tmp.hh'
    with open(tmp_path, 'w') as output:
        # Write out the file
        template = ENV.get_template('fwd.hh.tpl')
        output.write(template.render({'namespace': namespace, 'data': ntdata}))
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)

def write_global(ntdata, user32data, categories):
    # Generate src/windows/supported_syscalls.cc
    path = 'src/windows/supported_syscalls.cc'
    tmp_path = path + '.tmp.cc'
    with open(tmp_path, 'w') as output:
        # Write out the file
        template = ENV.get_template('supported_syscalls.cc.tpl')
        output.write(template.render({'ntdata': ntdata, 'win32kdata': user32data, 'categories': categories}))
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)

    # Generate src/common/SystemCallCreator.cc
    path = 'src/windows/kernel/SystemCallCreator.cc'
    tmp_path = path + '.tmp.cc'
    with open(tmp_path, 'w') as output:
        # Write out the file
        template = ENV.get_template('SystemCallCreator.cc.tpl')
        output.write(template.render({'ntdata': ntdata, 'win32kdata': user32data}))
    subprocess.run(["clang-format", "-i", tmp_path])
    move_tmp_to_target(tmp_path, path)


def main():
    '''
    Entry Point
    '''
    # Parse arguments
    parser = argparse.ArgumentParser(description='Generate system call handler')
    parser.add_argument('--headers', action='store_true')
    parser.add_argument('--sources', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('wintrovirt_dir')

    args = parser.parse_args()
    tld = os.path.abspath(args.wintrovirt_dir)
    os.chdir(tld)

    if args.debug:
        # Enable logging to stdout in debug mode for all the printing.
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        log_to_stdout = logging.StreamHandler(sys.stdout)
        log_to_stdout.setLevel(logging.DEBUG)
        root_logger.addHandler(log_to_stdout)

    # Parse the typemap file
    with open(os.path.join(BASE_PATH, "typemap.json")) as file:
        typemap = json.load(file)

    # Parse the NTDLL json file
    with open(os.path.join(BASE_PATH, "ntdll.json")) as file:
        ntdata = json.load(file)

    # Parse the User32 json file
    with open(os.path.join(BASE_PATH, "user32.json")) as file:
        user32data = json.load(file)

    if args.headers:
        print(os.path.abspath('include/introvirt/windows/kernel/nt/syscall/syscall.hh'), end=';')
        print(os.path.abspath('include/introvirt/windows/kernel/nt/syscall/fwd.hh'), end=';')
        print(os.path.abspath('include/introvirt/windows/kernel/win32k/syscall/syscall.hh'), end=';')
        print(os.path.abspath('include/introvirt/windows/kernel/win32k/syscall/fwd.hh'), end=';')

    if args.sources:
        print(os.path.abspath('src/windows/supported_syscalls.cc'), end=';')
        print(os.path.abspath('src/windows/kernel/SystemCallCreator.cc'), end=';')

    if args.headers or args.sources:
        # Just print out the source files
        for name in ntdata:
            if args.headers:
                print(os.path.abspath('include/introvirt/windows/kernel/nt/syscall/' + name + '.hh'), end=';')
            if args.sources:
                print(os.path.abspath('src/windows/kernel/nt/syscall/' + name + 'Impl.hh'), end=';')
        for name in user32data:
            if args.headers:
                print(os.path.abspath('include/introvirt/windows/kernel/win32k/syscall/' + name + '.hh'), end=';')
            if args.sources:
                print(os.path.abspath('src/windows/kernel/win32k/syscall/' + name + 'Impl.hh'), end=';')
        return

    categories = defaultdict(set)

    # Get the calls ready
    process_calls(ntdata, typemap, categories, "NtSystemCall")
    process_calls(user32data, typemap, categories, "Win32kSystemCall")

    write_templates(ntdata, 'nt')
    write_templates(user32data, 'win32k')

    write_global(ntdata, user32data, categories)

    # Create the actual files
    for name in ntdata:
        write_files(ntdata[name], 'nt')

    # Create the actual files
    for name in user32data:
        write_files(user32data[name], 'win32k')


if __name__ == "__main__":
    main()
