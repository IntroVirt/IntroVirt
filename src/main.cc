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

#include <introvirt/VersionInfo.hh>

#include <log4cxx/basicconfigurator.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/xml/domconfigurator.h>

#include <boost/stacktrace.hpp>

#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>

#if __GNUC__ >= 8
#include <filesystem>
namespace filesystem = std::filesystem;
#else
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#endif

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#define IV_LOG4CXX_PROP_FILE SYSCONFDIR "/introvirt/log4cxx.properties"
#define IV_LOG4CXX_XML_FILE SYSCONFDIR "/introvirt/log4cxx.xml"

static constexpr uint32_t DesiredMapMapCount = 1000000;

namespace introvirt {

void crash_handler(int signum) {
    // This should be safe
    boost::stacktrace::safe_dump_to("./introvirt-crash.dmp");

    // This is less safe, but we're crashing anyway
    log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.crash"));
    LOG4CXX_FATAL(logger, "Program crashed with " << strsignal(signum));
    LOG4CXX_FATAL(logger, boost::stacktrace::stacktrace());
    exit(254);
}

static void soMain() __attribute__((constructor));

// Get the mapping limit
uint64_t get_vm_max_map_count() {
    uint64_t result = 0;
    std::ifstream file("/proc/sys/vm/max_map_count");
    if (file.is_open()) {
        std::string line;
        if (getline(file, line)) {
            result = std::atoll(line.c_str());
        }
        file.close();
    }
    return result;
}

// Set the mapping limit
bool set_vm_max_map_count(uint64_t value) {
    std::ofstream file("/proc/sys/vm/max_map_count");
    if (file.is_open()) {
        file << value;
        file.close();
        return true;
    }
    return false;
}

void initialize_log4cxx() {
    // Try to load the XML config file if it exists
    // Otherwise, fall back to the properties file
    if (filesystem::exists(IV_LOG4CXX_XML_FILE)) {
        log4cxx::xml::DOMConfigurator::configure(IV_LOG4CXX_XML_FILE);
    } else if (filesystem::exists(IV_LOG4CXX_PROP_FILE)) {
        log4cxx::PropertyConfigurator::configure(IV_LOG4CXX_PROP_FILE);
    } else {
        std::cerr << "Unable to find a log4cxx configuration file\n";
    }
}

/*
 * Executed when the library is loaded
 */
static void soMain() {
    // Get the logger going.
    initialize_log4cxx();

    const bool is_debug_build = VersionInfo::is_debug_build();
    const bool is_optimized_build = VersionInfo::is_optimized_build();

    // Register some signal handers in case of crash
    ::signal(SIGSEGV, &crash_handler);

    // The logger has to be defined in this function. If declared static it'd execute before the
    // library is initialized.
    log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.config"));

    LOG4CXX_TRACE(logger, "libintrovirt " << VersionInfo::version() << ": DEBUG=" << is_debug_build
                                          << " Optimized=" << is_optimized_build);

    if (!is_optimized_build) {
        LOG4CXX_WARN(logger, "You are running an unoptimized build of libintrovirt!");
    }

    /*
     * Linux has a limit on the number of mmap() calls we can make.
     * At one point this was causing us to fail when we'd attempt to map guest memory.
     * When the library loads, we try to raise it here.
     */
    const uint64_t vm_max_map_count = get_vm_max_map_count();
    if (vm_max_map_count < DesiredMapMapCount) {
        if (set_vm_max_map_count(DesiredMapMapCount)) {
            LOG4CXX_DEBUG(logger, "Raised vm.max_map_count to " << DesiredMapMapCount);
        } else {
            LOG4CXX_WARN(logger, "Failed to raise vm.max_map_count");
        }
    }
}

} // namespace introvirt
