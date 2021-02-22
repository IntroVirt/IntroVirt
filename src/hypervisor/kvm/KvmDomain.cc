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
#include "KvmDomain.hh"
#include "KvmHypervisor.hh"
#include "kvm_introspection.hh"

#include <introvirt/core/exception/BadPhysicalAddressException.hh>
#include <introvirt/core/exception/CommandFailedException.hh>
#include <introvirt/core/exception/InvalidVcpuException.hh>
#include <introvirt/core/exception/NoSuchDomainException.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>

#include <log4cxx/logger.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace introvirt {
namespace kvm {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.kvm.KvmHypervisor"));

std::string KvmDomain::name() const { return name_; }

uint32_t KvmDomain::id() const { return id_; }

KvmVcpu& KvmDomain::vcpu(uint32_t index) {
    // Avoid duplicate code by calling the const version and casting away the const.
    auto const_this = const_cast<const KvmDomain*>(this);
    return const_cast<KvmVcpu&>(const_this->vcpu(index));
}

const KvmVcpu& KvmDomain::vcpu(uint32_t index) const {
    if (unlikely(index >= vcpus_.size())) {
        throw InvalidVcpuException(index);
    }
    return *vcpus_[index];
}

uint32_t KvmDomain::vcpu_count() const { return vcpus_.size(); }

void KvmDomain::intercept_mem_access(uint64_t gfn, bool on_read, bool on_write, bool on_execute) {
    struct kvm_ept_permissions perms = {};
    perms.gfn = gfn;
    perms.perms = PFERR_PRESENT_MASK | PFERR_WRITE_MASK | PFERR_USER_MASK;
    if (on_read)
        perms.perms &= ~PFERR_PRESENT_MASK;
    if (on_write)
        perms.perms &= ~PFERR_WRITE_MASK;
    if (on_execute)
        perms.perms &= ~PFERR_USER_MASK; /* NOTE: This is weird but correct */

    pause();
    LOG4CXX_DEBUG(logger, "intercept_mem_access(0x" << std::hex << gfn << ", " << on_read << ", "
                                                    << on_write << ", " << on_execute << ")");
    if (unlikely(ioctl(fd_, KVM_SET_MEM_ACCESS, &perms))) {
        resume();
        throw CommandFailedException("Failed to set memory access intercept", errno);
    }
    resume();
}
void KvmDomain::clear_mem_access_intercepts() {}

void KvmDomain::intercept_exception(x86::Exception vector, bool enabled) {
    pause();
    try {
        for (auto& vcpu : vcpus_) {
            vcpu->intercept_exception(vector, enabled);
        }
    } catch (...) {
        resume();
        throw;
    }
    resume();
}

bool KvmDomain::intercept_exception(x86::Exception vector) const {
    switch (vector) {
    case x86::Exception::INT3:
        return this->intercept_int3_;
    default:
        return false;
    }
}

const KvmHypervisor& KvmDomain::hypervisor() const { return hypervisor_; }

GuestMemoryMapping KvmDomain::map_pfns(const uint64_t* pfns, size_t count) const {
    const size_t region_size = count * PageDirectory::PAGE_SIZE;

    // Reserve address space for the mapping
    void* result = mmap(nullptr, region_size, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, 0, 0);

    if ((unlikely(result == MAP_FAILED))) {
        LOG4CXX_ERROR(logger, "Failed to reserve " << region_size << " bytes of address space");
        throw CommandFailedException("Failed to reserve address space", errno);
    }

    // Go through each PFN and map it
    char* mapping = reinterpret_cast<char*>(result);
    for (size_t i = 0; i < count; ++i) {
        const uint64_t pfn = pfns[i];
        void* result =
            mmap(mapping, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd_, pfn << 12);

        if ((unlikely(result == MAP_FAILED))) {
            LOG4CXX_WARN(logger,
                         "mmap for pfn 0x" << std::hex << pfn << " failed: " << strerror(errno));
            munmap(mapping, region_size);
            throw BadPhysicalAddressException(pfn << 12, errno);
        }
        mapping += 4096;
    }
    return GuestMemoryMapping(result, region_size);
}

KvmDomain::KvmDomain(const KvmHypervisor& hypervisor, const std::string& name, uint32_t id, int fd)
    : hypervisor_(hypervisor), name_(name), id_(id), fd_(fd) {

    // Attach to the domains VCPUs
    for (unsigned long i = 0;; ++i) {
        const int vcpu_fd = ioctl(fd, KVM_ATTACH_VCPU, i);
        if (vcpu_fd < 0) {
            // We're figuring out how many VCPUs there are in this loop
            // TODO(papes): Is there a way to just query the number?
            if (errno != ESRCH)
                LOG4CXX_DEBUG(logger, "Failed to attach VCPU " << i << ": " << strerror(errno));
            break;
        }
        LOG4CXX_TRACE(logger, "Domain " << name_ << " attached vcpu " << i);
        vcpus_.emplace_back(std::make_unique<KvmVcpu>(*this, i, vcpu_fd));
    }

    if (vcpus_.empty()) {
        LOG4CXX_ERROR(logger, "Domain " << name_ << " failed to attach any vcpus");
        // TODO(papes): We should add another exception class for general domain attach failures
        throw NoSuchDomainException(name_);
    }

    LOG4CXX_DEBUG(logger, "Domain " << name_ << " attached " << vcpus_.size() << " vcpus");

    if (ioctl(fd_, KVM_SET_MEM_ACCESS_ENABLED, 1ul) < 0) {
        LOG4CXX_WARN(logger, "Domain " << name_ << " failed to enable mem_access API");
    }

    // Safe to let the base class initialize now
    initialize();
}

KvmDomain::~KvmDomain() {
    // Release the VCPUs before closing the domain
    vcpus_.clear();

    // Close the handle to the domain
    close(fd_);
}

} // namespace kvm
} // namespace introvirt