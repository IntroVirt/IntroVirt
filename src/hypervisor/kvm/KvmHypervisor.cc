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
#include "KvmHypervisor.hh"
#include "KvmDomain.hh"
#include "gitversion.h"
#include "kvm_introspection.hh"

#include <introvirt/core/exception/DomainBusyException.hh>
#include <introvirt/core/exception/NoSuchDomainException.hh>
#include <introvirt/core/exception/UnsupportedHypervisorException.hh>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <log4cxx/logger.h>

#include <fcntl.h>
#include <fstream>
#include <memory>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#if __GNUC__ >= 8
#include <filesystem>
namespace filesystem = std::filesystem;
#else
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#endif


namespace introvirt {
namespace kvm {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.kvm.KvmHypervisor"));

static std::string get_domain_name(uint32_t domain_id);
static uint32_t get_domain_id_by_name(const std::string& name);
static int open_kvm_domain(int fd, uint32_t domain_id);

std::unique_ptr<Domain> KvmHypervisor::attach_domain(uint32_t domain_id) {
    const int domain_fd = open_kvm_domain(fd_, domain_id);
    std::string domain_name = get_domain_name(domain_id);

    try {
        return std::make_unique<KvmDomain>(*this, domain_name, domain_id, domain_fd);
    } catch (...) {
        close(domain_fd);
        throw;
    }
}

std::unique_ptr<Domain> KvmHypervisor::attach_domain(const std::string& domain_name) {
    // First we see if we can treat the string as a numeric domain id
    try {
        const uint32_t domain_id = boost::lexical_cast<uint32_t>(domain_name);
        return attach_domain(domain_id);
    } catch (boost::bad_lexical_cast& ex) {
    } catch (NoSuchDomainException& ex) {
    }

    // Then we try to get it by name
    const uint32_t domain_id = get_domain_id_by_name(domain_name);
    if (domain_id == 0xFFFFFFFFL) {
        throw NoSuchDomainException(domain_name);
    }
    const int domain_fd = open_kvm_domain(fd_, domain_id);
    try {
        return std::make_unique<KvmDomain>(*this, domain_name, domain_id, domain_fd);
    } catch (...) {
        close(domain_fd);
        throw;
    }
}

std::vector<DomainInformation> KvmHypervisor::get_running_domains() {
    std::vector<DomainInformation> result;

    filesystem::path proc("/proc");
    for (auto& entry : filesystem::directory_iterator(proc)) {
        try {
            const std::string pidStr = entry.path().filename().string();
            const uint64_t pid = boost::lexical_cast<uint64_t>(pidStr);
            std::string vmname = get_domain_name(pid);
            if (!vmname.empty()) {
                DomainInformation info;
                info.domain_id = pid;
                info.domain_name = vmname;
                result.push_back(std::move(info));
            }
        } catch (boost::bad_lexical_cast& ex) {
        }
    }

    return result;
}

std::string KvmHypervisor::hypervisor_name() const { return "KVM"; }

std::string KvmHypervisor::hypervisor_version() const { return kernel_version_; }

std::string KvmHypervisor::hypervisor_patch_version() const { return hypervisor_patch_version_; }

std::string KvmHypervisor::library_name() const { return "libintrovirt-kvm"; }

std::string KvmHypervisor::library_version() const {
#ifdef GIT_VERSION
    return GIT_VERSION;
#else
    return "Unknown (Compiled without GIT_VERSION)";
#endif
}

KvmHypervisor::KvmHypervisor() : fd_(open("/dev/kvm", O_RDWR)) {
    // Get version Information

    // Try to open the KVM device
    // See if we can even open the kvm device
    if (fd_ < 0) {
        LOG4CXX_DEBUG(logger, "Failed to open /dev/kvm: " << strerror(errno));
        throw UnsupportedHypervisorException();
    }

    struct utsname utsname;
    if (uname(&utsname) < 0) {
        LOG4CXX_DEBUG(logger, "Failed to get kernel version information: " << strerror(errno));
        throw UnsupportedHypervisorException();
    }
    kernel_version_ = utsname.release;

    // Check if the introspection extensions are available
    const int api_version = ioctl(fd_, KVM_CHECK_EXTENSION, KVM_CAP_INTROSPECTION);
    if (!api_version) {
        LOG4CXX_ERROR(logger, "No KVM introspection capability detected");
        close(fd_);
        throw UnsupportedHypervisorException();
    }

    // Make sure we're speaking the same language
    if (api_version != KVM_INTROSPECTION_API_VERSION) {
        LOG4CXX_ERROR(logger, "API version mismatch: Library: " << KVM_INTROSPECTION_API_VERSION
                                                                << " KVM: " << api_version);
        close(fd_);
        throw UnsupportedHypervisorException();
    }

    struct kvm_introspection_patch_ver patch_version;
    if (ioctl(fd_, KVM_GET_INTROSPECTION_PATCH_VERSION, &patch_version) < 0) {
        LOG4CXX_ERROR(logger, "Failed to query introspection patch version: " << strerror(errno));
        close(fd_);
        throw UnsupportedHypervisorException();
    }
    hypervisor_patch_version_ = patch_version.buffer;
}

KvmHypervisor::~KvmHypervisor() { close(fd_); }

static std::string read_file(const filesystem::path& p) {
    std::ifstream in(p);
    std::ostringstream contents;
    contents << in.rdbuf();
    in.close();
    return contents.str();
}

static bool is_domain_id_valid(uint32_t domain_id) {
    filesystem::path proc("/proc");
    filesystem::path commPath = proc / std::to_string(domain_id) / "comm";
    const std::string comm(read_file(commPath));
    return (comm.compare(0, 11, "qemu-system") == 0) || (comm.compare(0, 3, "kvm") == 0);
}

static std::string get_domain_name(uint32_t domain_id) {
    if (!is_domain_id_valid(domain_id))
        return "";

    filesystem::path proc("/proc");
    filesystem::path cmdLinePath = proc / std::to_string(domain_id) / "cmdline";
    const std::string cmdline(read_file(cmdLinePath));

    const size_t idx = cmdline.find("-name");
    if (idx == std::string::npos)
        return "";

    std::string name(cmdline.data() + idx + 6);

    // Ubuntu 18.04 has extra fields in the string we need to strip
    const std::string GuestPrefix("guest=");
    if (boost::algorithm::starts_with(name, GuestPrefix)) {
        name = name.substr(GuestPrefix.length());
    }

    // Ubuntu 16.04 also has an extra trailing parameter, separated by a comma
    const size_t fieldEnd = name.find(',');
    if (fieldEnd != std::string::npos) {
        name = name.substr(0, fieldEnd);
    }

    return name;
}

/**
 * Returns a domain-id given the domain string
 */
static uint32_t get_domain_id_by_name(const std::string& name) {
    if (!name.empty()) {
        filesystem::path proc("/proc");
        for (auto& entry : filesystem::directory_iterator(proc)) {
            try {
                const std::string pidStr = entry.path().filename().string();
                const uint64_t pid = boost::lexical_cast<uint64_t>(pidStr);
                std::string vmname = get_domain_name(pid);
                if (name == vmname)
                    return pid;
            } catch (boost::bad_lexical_cast& ex) {
            }
        }
    }
    return 0xFFFFFFFFL;
}

static int open_kvm_domain(int fd, uint32_t domain_id) {
    const int domain_fd = ioctl(fd, KVM_ATTACH_VM, domain_id);
    if (domain_fd < 0) {
        switch (errno) {
        case ESRCH:
            throw NoSuchDomainException(domain_id);
        case EBUSY:
            throw DomainBusyException(domain_id);
        default:
            LOG4CXX_ERROR(logger, "Received unknown error attempting to attach Domain "
                                      << domain_id << ": " << strerror(errno));

            // TODO(pape): We should probably have a generic exception class for this
            throw NoSuchDomainException(domain_id);
        }
    }
    return domain_fd;
}

extern "C" {
/**
 * @brief Create a hypervisor instance object
 *
 * @return The hypervisor instance
 */
std::unique_ptr<Hypervisor> create_hypervisor_instance() {
    return std::make_unique<KvmHypervisor>();
}
}

} // namespace kvm
} // namespace introvirt