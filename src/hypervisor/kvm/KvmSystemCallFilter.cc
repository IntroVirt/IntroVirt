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
#include "KvmSystemCallFilter.hh"
#include "kvm_introspection.hh"

#include <log4cxx/logger.h>

#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>

namespace introvirt {
namespace kvm {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.kvm.KvmSystemCallFilter"));

KvmSystemCallFilter::KvmSystemCallFilter(int fd) : fd_(fd) {
    const unsigned long addr = reinterpret_cast<unsigned long>(page());
    if (ioctl(fd_, KVM_SET_SYSCALL_FILTER, addr) < 0) {
        LOG4CXX_WARN(logger, "KVM_SET_SYSCALL_FILTER failed: "
                                 << strerror(errno)
                                 << " - syscall filtering will be performed in userspace");
        fd_ = -1;
    }
}

KvmSystemCallFilter::~KvmSystemCallFilter() {
    if (fd_ >= 0) {
        if (ioctl(fd_, KVM_SET_SYSCALL_FILTER, 0ul) < 0) {
            LOG4CXX_DEBUG(logger, "KVM_SET_SYSCALL_FILTER(0) failed: " << strerror(errno));
        }
    }
}

} // namespace kvm
} // namespace introvirt
