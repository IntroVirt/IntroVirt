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
#include "DBGKD_GET_VERSION64_IMPL.hh"

#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/windows/exception/SymbolNotFoundException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/types/KDDEBUGGER_DATA64.hh>
#include <introvirt/windows/pe.hh>

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/util/compiler.hh>

#include <log4cxx/logger.h>

#include <memory>

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.DBGKD_GET_VERSION64"));

using namespace std;
using namespace introvirt::windows::pe;

namespace introvirt {
namespace windows {
namespace nt {

MachineType DBGKD_GET_VERSION64_IMPL::MachineType() const { return header_->MachineType; }
uint16_t DBGKD_GET_VERSION64_IMPL::MajorVersion() const { return header_->MajorVersion; }
uint16_t DBGKD_GET_VERSION64_IMPL::MinorVersion() const { return header_->MinorVersion; }
uint16_t DBGKD_GET_VERSION64_IMPL::ProtocolVersion() const { return header_->ProtocolVersion; }
DBGKD_GET_VERSION64::DBGKD_VERS_FLAG DBGKD_GET_VERSION64_IMPL::Flags() const {
    return DBGKD_GET_VERSION64::DBGKD_VERS_FLAG(header_->Flags);
}
uint8_t DBGKD_GET_VERSION64_IMPL::MaxPacketType() const { return header_->MaxPacketType; }
uint8_t DBGKD_GET_VERSION64_IMPL::MaxStateChange() const { return header_->MaxStateChange; }
uint8_t DBGKD_GET_VERSION64_IMPL::MaxManipulate() const { return header_->MaxManipulate; }
uint8_t DBGKD_GET_VERSION64_IMPL::Simulation() const { return header_->Simulation; }
uint64_t DBGKD_GET_VERSION64_IMPL::KernelBase() const {
    if (MachineType() == MachineType::MACHINE_TYPE_X64) {
        return header_->KernBase;
    }
    return header_->KernBase & 0xFFFFFFFF;
}
uint64_t DBGKD_GET_VERSION64_IMPL::PsLoadedModuleList() const {
    if (MachineType() == MachineType::MACHINE_TYPE_X64) {
        return header_->PsLoadedModuleList;
    }
    return header_->PsLoadedModuleList & 0xFFFFFFFF;
}

DBGKD_GET_VERSION64_IMPL::DBGKD_GET_VERSION64_IMPL(const NtKernel& kernel) {
    GuestVirtualAddress kernel_base = kernel.base_address();
    const Domain& domain = kernel_base.domain();

    try {
        // Find the address of KdVersionBlock using the PDB file
        GuestVirtualAddress ptr = kernel.symbol("KdVersionBlock");

        LOG4CXX_DEBUG(logger, "KdVersionBlock: " << ptr);

        // Try to map in the structure
        header_.reset(ptr);
    } catch (SymbolNotFoundException& ex) {
        throw GuestDetectionException(domain, "Failed to find KdVersionBlock in PDB file");
    }

    // Sanity checks
    if (KernelBase() != kernel_base.virtual_address()) {
        throw GuestDetectionException(domain, "KdVersionBlock kernel base mismatch");
    }
}

/*
 * DBGKD_GET_VERSION64::DBGKD_VERS_FLAG
 */

static constexpr uint16_t DBGKD_VERS_FLAG_MP = 0x0001;
static constexpr uint16_t DBGKD_VERS_FLAG_DATA = 0x0002;
static constexpr uint16_t DBGKD_VERS_FLAG_PTR64 = 0x0004;
static constexpr uint16_t DBGKD_VERS_FLAG_NOMM = 0x0008;
static constexpr uint16_t DBGKD_VERS_FLAG_HSS = 0x0010;
static constexpr uint16_t DBGKD_VERS_FLAG_PARTITIONS = 0x0020;

bool DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::MP() const { return value_ & DBGKD_VERS_FLAG_MP; }
bool DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::DATA() const { return value_ & DBGKD_VERS_FLAG_DATA; }
bool DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::PTR64() const { return value_ & DBGKD_VERS_FLAG_PTR64; }
bool DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::NOMM() const { return value_ & DBGKD_VERS_FLAG_NOMM; }
bool DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::HSS() const { return value_ & DBGKD_VERS_FLAG_HSS; }
bool DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::PARTITIONS() const {
    return value_ & DBGKD_VERS_FLAG_PARTITIONS;
}
DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::DBGKD_VERS_FLAG(uint16_t value) : value_(value) {}
DBGKD_GET_VERSION64::DBGKD_VERS_FLAG::operator uint16_t() const { return value_; }

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
