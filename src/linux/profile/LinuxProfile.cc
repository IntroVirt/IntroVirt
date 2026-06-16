/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "LinuxProfileImpl.hh"

#include <introvirt/linux/profile/LinuxProfile.hh>

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace introvirt {
namespace linux_guest {

std::unique_ptr<LinuxProfile> LinuxProfile::load(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw LinuxProfileException("LinuxProfile: cannot open " + path);
    std::ostringstream buf;
    buf << in.rdbuf();
    return std::make_unique<LinuxProfileImpl>(buf.str());
}

std::unique_ptr<LinuxProfile> LinuxProfile::load_for_release(const std::string& release,
                                                             const std::string& arch) {
    // Resolution order mirrors the Windows NtKernel::profile_path() convention:
    //   1. $INTROVIRT_PROFILE_DIR (explicit override)
    //   2. $HOME/.introvirt/profiles
    std::string dir;
    if (const char* env = std::getenv("INTROVIRT_PROFILE_DIR")) {
        dir = env;
    } else if (const char* home = std::getenv("HOME")) {
        dir = std::string(home) + "/.introvirt/profiles";
    } else {
        return nullptr;
    }

    const std::string path = dir + "/linux-" + release + "-" + arch + ".json";

    // Missing profile is not an error here (the caller decides) — only a
    // present-but-broken profile throws, via load().
    std::ifstream probe(path);
    if (!probe)
        return nullptr;
    return load(path);
}

} // namespace linux_guest
} // namespace introvirt
