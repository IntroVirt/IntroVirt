/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/linux/profile/LinuxProfile.hh>

#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace introvirt;
using namespace introvirt::linux_guest;

namespace {

int fail(const std::string& message) {
    std::cerr << message << '\n';
    return 1;
}

bool throws_with(const std::string& path, const std::string& needle) {
    try {
        LinuxProfile::load(path);
    } catch (const TraceableException& ex) {
        return std::string(ex.what()).find(needle) != std::string::npos;
    }
    return false;
}

std::string write_temp(const std::string& name, const std::string& body) {
    const std::string path = "/tmp/introvirt-" + name + "-" + std::to_string(::getpid()) + ".json";
    std::ofstream out(path);
    out << body;
    return path;
}

} // namespace

int main() {
    auto profile = LinuxProfile::load(LINUX_PROFILE_FIXTURE);
    if (profile->arch() != "x86_64")
        return fail("arch");
    const auto init_task = profile->symbol("init_task");
    if (!init_task || *init_task != 4096)
        return fail("symbol init_task");
    if (profile->symbol("missing"))
        return fail("missing symbol should be empty");
    const auto pid = profile->member_offset("task_struct", "pid");
    if (!pid || *pid != 16)
        return fail("member_offset task_struct.pid");
    if (profile->member_offset("task_struct", "nope"))
        return fail("missing member should be empty");
    const auto size = profile->type_size("task_struct");
    if (!size || *size != 128)
        return fail("type_size task_struct");
    if (profile->type_size("nope"))
        return fail("missing type size should be empty");

    const std::string bad_format =
        write_temp("bad-format", "{\"format\":\"not-a-profile\",\"symbols\":{\"init_task\":1}}");
    if (!throws_with(bad_format, "unexpected format"))
        return fail("wrong format should throw");

    const std::string no_symbols =
        write_temp("no-symbols", "{\"format\":\"sectepe-linux-isf/1\",\"symbols\":{}}");
    if (!throws_with(no_symbols, "no symbols"))
        return fail("empty symbols should throw");

    return 0;
}
