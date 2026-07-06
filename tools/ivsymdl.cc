/*
 * Copyright 2026 Assured Information Security, Inc.
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

/**
 * @example ivsymdl.cc
 *
 * Downloads Windows PDB symbols for a guest VM using libmspdb. Demonstrates
 * attaching to a domain, guest detection, reading kernel PE debug information,
 * and triggering symbol server downloads.
 */

#include <introvirt/introvirt.hh>
#include <introvirt/windows/PdbStore.hh>

#include <mspdb/file_exception.hh>
#include <mspdb/pdb_exception.hh>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <vector>

#if __GNUC__ >= 8
#include <filesystem>
namespace filesystem = std::filesystem;
#else
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#endif

using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;
using namespace introvirt::windows::pe;

namespace po = boost::program_options;

namespace {

constexpr const char* kDefaultCacheDir = "/var/lib/introvirt/pdb/";
constexpr const char* kSymbolServerUrl = "http://msdl.microsoft.com/download/symbols/";

struct PdbTarget {
    std::string module_name;
    std::string pdb_filename;
    std::string pdb_identifier;
};

std::string pdb_key(const PdbTarget& target) {
    return target.pdb_filename + "/" + target.pdb_identifier;
}

std::string normalize_module_name(std::string name) {
    boost::to_lower(name);
    if (boost::ends_with(name, ".sys") || boost::ends_with(name, ".dll") ||
        boost::ends_with(name, ".exe")) {
        name.resize(name.rfind('.'));
    }
    return name;
}

bool module_matches(const std::string& requested, const std::string& module_name) {
    return normalize_module_name(requested) == normalize_module_name(module_name);
}

std::string pdb_download_url(const PdbTarget& target) {
    return std::string(kSymbolServerUrl) + target.pdb_filename + "/" + target.pdb_identifier +
           "/" + target.pdb_filename;
}

filesystem::path pdb_cache_path(const PdbTarget& target) {
    filesystem::path path{kDefaultCacheDir};
    path /= target.pdb_filename;
    path /= target.pdb_identifier;
    path /= target.pdb_filename;
    return path;
}

filesystem::path pdb_output_path(const std::string& output_dir, const PdbTarget& target) {
    filesystem::path path{output_dir};
    path /= target.pdb_filename;
    path /= target.pdb_identifier;
    path /= target.pdb_filename;
    return path;
}

std::optional<PdbTarget> extract_pdb_target(const guest_ptr<void>& pe_ptr,
                                            const std::string& module_name) {
    try {
        auto pe = pe::PE::make_unique(pe_ptr);
        const auto* debug_dir = pe->optional_header().debug_directory();
        if (!debug_dir)
            return std::nullopt;

        const auto* cv_info = debug_dir->codeview_data();
        if (!cv_info)
            return std::nullopt;

        PdbTarget target;
        target.module_name = module_name;
        target.pdb_filename = cv_info->PdbFileName();
        target.pdb_identifier = cv_info->PdbIdentifier();
        boost::to_upper(target.pdb_identifier);
        return target;
    } catch (TraceableException&) {
        return std::nullopt;
    }
}

std::optional<PdbTarget> extract_kernel_target(const NtKernel& kernel) {
    const auto* debug_dir = kernel.pe().optional_header().debug_directory();
    if (!debug_dir)
        return std::nullopt;

    const auto* cv_info = debug_dir->codeview_data();
    if (!cv_info)
        return std::nullopt;

    PdbTarget target;
    target.module_name = "ntoskrnl";
    target.pdb_filename = cv_info->PdbFileName();
    target.pdb_identifier = cv_info->PdbIdentifier();
    boost::to_upper(target.pdb_identifier);
    return target;
}

std::optional<PdbTarget> extract_win32k_target(const NtKernel& kernel) {
    guest_ptr<void> pWin32k;
    for (const auto& module : kernel.PsLoadedModuleList()) {
        if (module->BaseDllName() == "win32k.sys") {
            pWin32k = kernel.ptr().clone(module->DllBase());
            break;
        }
    }
    if (!pWin32k)
        return std::nullopt;

    auto CidTable = kernel.CidTable();
    for (auto& entry : CidTable->open_handles()) {
        std::unique_ptr<OBJECT_HEADER> header(entry->ObjectHeader());
        if (header->type() != ObjectType::Process)
            continue;

        auto process = kernel.process(header->Body());
        if (!process->Win32Process())
            continue;

        try {
            guest_ptr<void> pe_ptr(pWin32k.domain(), pWin32k.address(),
                                   process->DirectoryTableBase());
            return extract_pdb_target(pe_ptr, "win32k.sys");
        } catch (TraceableException&) {
        }
    }

    return std::nullopt;
}

void add_target(std::vector<PdbTarget>& targets, std::set<std::string>& seen,
                const PdbTarget& target) {
    const std::string key = pdb_key(target);
    if (seen.count(key))
        return;
    seen.insert(key);
    targets.push_back(target);
}

std::vector<PdbTarget> resolve_default_targets(const WindowsGuest& guest) {
    std::vector<PdbTarget> targets;
    std::set<std::string> seen;
    const auto& kernel = guest.kernel();

    if (auto target = extract_kernel_target(kernel))
        add_target(targets, seen, *target);

    if (auto target = extract_win32k_target(kernel))
        add_target(targets, seen, *target);

    return targets;
}

std::vector<PdbTarget> resolve_all_targets(const WindowsGuest& guest) {
    std::vector<PdbTarget> targets;
    std::set<std::string> seen;
    const auto& kernel = guest.kernel();

    if (auto target = extract_kernel_target(kernel))
        add_target(targets, seen, *target);

    for (const auto& module : kernel.PsLoadedModuleList()) {
        const std::string module_name = module->BaseDllName();
        if (module_name == "win32k.sys") {
            if (auto target = extract_win32k_target(kernel))
                add_target(targets, seen, *target);
            continue;
        }

        try {
            auto pe_ptr = kernel.ptr().clone(module->DllBase());
            if (auto target = extract_pdb_target(pe_ptr, module_name))
                add_target(targets, seen, *target);
        } catch (TraceableException&) {
            std::cerr << "Warning: failed to read PE for " << module_name << '\n';
        }
    }

    return targets;
}

std::vector<PdbTarget> resolve_named_targets(const WindowsGuest& guest,
                                             const std::vector<std::string>& names) {
    std::vector<PdbTarget> targets;
    std::set<std::string> seen;
    const auto& kernel = guest.kernel();

    for (const auto& requested : names) {
        bool found = false;

        if (module_matches(requested, "ntoskrnl")) {
            if (auto target = extract_kernel_target(kernel)) {
                add_target(targets, seen, *target);
                found = true;
            }
        }

        if (!found && module_matches(requested, "win32k.sys")) {
            if (auto target = extract_win32k_target(kernel)) {
                add_target(targets, seen, *target);
                found = true;
            }
        }

        if (!found) {
            for (const auto& module : kernel.PsLoadedModuleList()) {
                if (!module_matches(requested, module->BaseDllName()))
                    continue;

                if (module->BaseDllName() == "win32k.sys") {
                    if (auto target = extract_win32k_target(kernel)) {
                        add_target(targets, seen, *target);
                        found = true;
                    }
                } else {
                    try {
                        auto pe_ptr = kernel.ptr().clone(module->DllBase());
                        if (auto target = extract_pdb_target(pe_ptr, module->BaseDllName())) {
                            add_target(targets, seen, *target);
                            found = true;
                        }
                    } catch (TraceableException&) {
                    }
                }
                break;
            }
        }

        if (!found) {
            std::cerr << "ERROR: module not found or has no symbols: " << requested << '\n';
            return {};
        }
    }

    return targets;
}

std::vector<PdbTarget> resolve_targets(const WindowsGuest& guest, const po::variables_map& vm) {
    if (vm.count("symbol"))
        return resolve_named_targets(guest, vm["symbol"].as<std::vector<std::string>>());
    if (vm.count("all"))
        return resolve_all_targets(guest);
    return resolve_default_targets(guest);
}

bool download_pdb(mspdb::PDBStore& store, const PdbTarget& target) {
    const auto cache_path = pdb_cache_path(target);
    const bool cached = filesystem::exists(cache_path);

    std::cout << (cached ? "Cached " : "Downloading ") << target.module_name << ":\n";
    std::cout << "  URL: " << pdb_download_url(target) << '\n';
    std::cout << "  Path: " << cache_path.string() << '\n';

    try {
        auto pdb = store.open_pdb(target.pdb_filename, target.pdb_identifier);
        if (!pdb) {
            std::cerr << "ERROR: failed to download " << target.pdb_filename << " for "
                      << target.module_name << '\n';
            return false;
        }
        return true;
    } catch (const mspdb::pdb_exception& ex) {
        if (filesystem::exists(cache_path)) {
            std::cerr << "Warning: " << target.module_name
                      << " downloaded but PDB parsing failed: " << ex.what() << '\n';
            return true;
        }
        std::cerr << "ERROR: failed to download " << target.pdb_filename << " for "
                  << target.module_name << ": " << ex.what() << '\n';
        return false;
    } catch (const mspdb::file_exception& ex) {
        std::cerr << "ERROR: failed to download " << target.pdb_filename << " for "
                  << target.module_name << ": " << ex.what() << '\n';
        return false;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: failed to download " << target.pdb_filename << " for "
                  << target.module_name << ": " << ex.what() << '\n';
        return false;
    }
}

bool copy_pdb_to_output(const std::string& output_dir, const PdbTarget& target) {
    const auto src = pdb_cache_path(target);
    const auto dst = pdb_output_path(output_dir, target);

    if (!filesystem::exists(src)) {
        std::cerr << "ERROR: cached PDB missing: " << src.string() << '\n';
        return false;
    }

    try {
        filesystem::create_directories(dst.parent_path());
        filesystem::copy_file(src, dst, filesystem::copy_options::overwrite_existing);
        std::cout << "Copied to: " << dst.string() << '\n';
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: failed to copy " << target.module_name << " to " << output_dir << ": "
                  << ex.what() << '\n';
        return false;
    }
}

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {
            std::cout << "ivsymdl - Download Windows PDB symbols for a guest VM\n";
            std::cout << desc << '\n';
            exit(0);
        }

        po::notify(vm);
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        exit(1);
    }
}

} // namespace

int main(int argc, char** argv) {
    po::options_description desc("Options");

    std::string domain_name;
    std::string output_dir;
    std::vector<std::string> symbols;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(),
       "The domain name or ID attach to")
      ("output,o", po::value<std::string>(&output_dir),
       "Copy downloaded symbols to this directory")
      ("all", "Download PDBs for all loaded kernel modules")
      ("symbol,s", po::value<std::vector<std::string>>(&symbols)->composing(),
       "Download PDB for a named module (repeatable)")
      ("help", "Display program help");
    // clang-format on

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    auto hypervisor = Hypervisor::instance();
    auto domain = hypervisor->attach_domain(domain_name);

    std::cout << "Connected to domain: " << domain->name() << " (id: " << domain->id() << ")\n";
    std::cout << "VCPUs: " << domain->vcpu_count() << '\n';

    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest operating system\n";
        return 1;
    }

    domain->pause();

    auto* guest = domain->guest();
    if (guest->os() != OS::Windows) {
        std::cerr << "Unsupported OS: " << guest->os() << '\n';
        domain->resume();
        return 2;
    }

    auto& windows_guest = static_cast<WindowsGuest&>(*guest);
    const auto& kernel = windows_guest.kernel();

    std::cout << "OS version: " << kernel.MajorVersion() << '.' << kernel.MinorVersion()
              << " build " << kernel.NtBuildNumber() << " ("
              << (kernel.x64() ? "x64" : "x86") << ")\n";
    std::cout << "Build lab: " << kernel.NtBuildLab() << '\n';

    const auto* cv_info =
        kernel.pe().optional_header().debug_directory()->codeview_data();
    if (cv_info) {
        std::cout << "Symbol version: " << cv_info->PdbFileName() << " "
                  << cv_info->PdbIdentifier() << '\n';
        std::cout << "  GUID: " << cv_info->PdbGUID() << "  Age: " << cv_info->Age() << '\n';
    }

    std::cout << "Cache directory: " << kDefaultCacheDir << '\n';

    auto targets = resolve_targets(windows_guest, vm);
    if (targets.empty()) {
        domain->resume();
        return 1;
    }

    auto& store = PdbStore::get();
    std::vector<PdbTarget> downloaded;
    size_t failures = 0;

    for (const auto& target : targets) {
        if (download_pdb(store, target)) {
            downloaded.push_back(target);
        } else {
            ++failures;
        }
    }

    if (!output_dir.empty()) {
        for (const auto& target : downloaded) {
            if (!copy_pdb_to_output(output_dir, target)) {
                ++failures;
            }
        }
    }

    if (failures) {
        std::cerr << failures << " symbol(s) failed\n";
    }

    domain->resume();
    return failures ? 1 : 0;
}
