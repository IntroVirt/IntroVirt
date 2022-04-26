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
#include <introvirt/core/domain/Hypervisor.hh>
#include <introvirt/core/exception/UnsupportedHypervisorException.hh>

#include "../../hypervisor/kvm/KvmHypervisor.hh"

#include <boost/algorithm/string/predicate.hpp>

#include <log4cxx/logger.h>

#include <cstdlib>
#include <dlfcn.h>

#if __GNUC__ >= 8
#include <filesystem>
namespace filesystem = std::filesystem;
#else
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#endif

namespace introvirt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.core.Hypervisor"));

// Try the builtin hypervisor support
static std::unique_ptr<Hypervisor> try_builtin_hypervisors() {
    // Try kvm first
    try {
        auto result = std::make_unique<kvm::KvmHypervisor>();
        return result;
    } catch (...) {
    }
    return nullptr;
}

/*
 * Retrieves the path to the plugins folder
 */
static std::string get_plugin_path() {
    // See if the user has specified a custom INTROVIRT_PLUGIN_PATH
    const char* env_plugin_path = getenv("INTROVIRT_PLUGIN_PATH");
    if (env_plugin_path != nullptr) {
        return env_plugin_path;
    }
    return "/var/lib/introvirt/plugins";
}

/*
 * Get the path to the hypervisor plugin folder
 */
static std::string get_hypervisor_plugin_path() { return get_plugin_path() + "/hypervisor"; }

std::unique_ptr<Hypervisor> Hypervisor::instance() {
    std::unique_ptr<Hypervisor> result = try_builtin_hypervisors();
    if (result) {
        return result;
    }

    filesystem::path hypervisor_plugin_path(get_hypervisor_plugin_path());

    if (!filesystem::is_directory(hypervisor_plugin_path)) {
        throw UnsupportedHypervisorException();
    }

    for (auto& entry : filesystem::directory_iterator(hypervisor_plugin_path)) {
        const std::string filename(entry.path().filename().string());
        if (boost::algorithm::ends_with(filename, ".so")) {
            LOG4CXX_DEBUG(logger, "Discovered hypervisor plugin: " << filename);

            const std::string full_path = get_hypervisor_plugin_path() + "/" + filename;

            // Try to open it
            void* plugin_handle = dlopen(full_path.c_str(), RTLD_NOW);
            if (plugin_handle == nullptr) {
                const char* errstr = dlerror();
                LOG4CXX_DEBUG(logger, "Plugin " + filename + ": " + errstr);
                continue;
            }

            // Get the CreateHypervisor function from the library
            void* function = dlsym(plugin_handle, "create_hypervisor_instance");
            if (function != nullptr) {
                // Call the function to create an instance
                using fn_create_hyperisor_instance = std::unique_ptr<Hypervisor> (*)();
                auto create_hyperisor_instance =
                    reinterpret_cast<fn_create_hyperisor_instance>(function);

                try {
                    result = create_hyperisor_instance();
                    if (!result) {
                        LOG4CXX_WARN(logger, "Plugin " + filename +
                                                 ": create_hypervisor_instance() returned nullptr");
                        goto error;
                    }

                    LOG4CXX_DEBUG(logger, "Selected hypervisor plugin " + filename);
                    return result;
                } catch (UnsupportedHypervisorException& ex) {
                    LOG4CXX_DEBUG(logger,
                                  "Plugin " + filename + ": Failed to attach to hypervisor");
                }
            } else {
                LOG4CXX_WARN(logger, "Plugin " + filename +
                                         ": missing symbol 'create_hypervisor_instance'");
                goto error;
            }

        error:
            dlclose(plugin_handle);
        }
    }

    // Didn't find a valid plugin
    throw UnsupportedHypervisorException();
}

Hypervisor::Hypervisor() = default;
Hypervisor::~Hypervisor() = default;

} // namespace introvirt