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
#include "KDDEBUGGER_DATA64_IMPL.hh"

#include <introvirt/core/exception/GuestDetectionException.hh>

#include <introvirt/windows/exception/SymbolNotFoundException.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/pe.hh>

#include <log4cxx/logger.h>

#include <cstring>
#include <iomanip>
#include <ios>
#include <memory>

// TODO(papes): Replace these macros with something better

#define BitsCount(val) (sizeof(val) * CHAR_BIT)
#define Shift(val, steps) ((steps) % BitsCount(val))
#define ROL(val, steps)                                                                            \
    (((val) << Shift(val, steps)) | ((val) >> (BitsCount(val) - Shift(val, steps))))
#define BSWAP_64(x)                                                                                \
    (((uint64_t)(x) << 56) | (((uint64_t)(x) << 40) & 0xff000000000000ULL) |                       \
     (((uint64_t)(x) << 24) & 0xff0000000000ULL) | (((uint64_t)(x) << 8) & 0xff00000000ULL) |      \
     (((uint64_t)(x) >> 8) & 0xff000000ULL) | (((uint64_t)(x) >> 24) & 0xff0000ULL) |              \
     (((uint64_t)(x) >> 40) & 0xff00ULL) | ((uint64_t)(x) >> 56))

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.KDDEBUGGER_DATA64"));

static const uint32_t MAGIC_OWNER_TAG = 0x4742444B; //  == "KDBG"

template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::KernelBase() const {
    return debuggerData_.KernBase;
}
template <typename PtrType>
uint32_t KDDEBUGGER_DATA64_IMPL<PtrType>::ServicePackNumber() const {
    return (CmNtCSDVersion_ >> 8) & 0xffffffff;
}
template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::PsLoadedModuleList() const {
    return debuggerData_.PsLoadedModuleList;
}
template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::PsActiveProcessHead() const {
    return debuggerData_.PsActiveProcessHead;
}
template <typename PtrType>
uint16_t KDDEBUGGER_DATA64_IMPL<PtrType>::SizeEThread() const {
    return debuggerData_.SizeEThread;
}
template <typename PtrType>
bool KDDEBUGGER_DATA64_IMPL<PtrType>::PaeEnabled() const {
    return debuggerData_.PaeEnabled != 0u;
}
template <typename PtrType>
const std::string& KDDEBUGGER_DATA64_IMPL<PtrType>::NtBuildLab() const {
    return NtBuildLab_;
}

template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::KiProcessorBlock() const {
    // TODO(papes): Some day maybe we'll return a vector or something
    // TODO(papes): 32-bit detection?
    return debuggerData_.KiProcessorBlock;
}

template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::ObpTypeObjectType() const {
    return *pObpTypeObjectType_;
}

template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::ObpRootDirectoryObject() const {
    return *pObpRootDirectoryObject_;
}

template <typename PtrType>
uint64_t KDDEBUGGER_DATA64_IMPL<PtrType>::PspCidTable() const {
    return *pPspCidTable_;
}

template <typename PtrType>
KDDEBUGGER_DATA64_IMPL<PtrType>::KDDEBUGGER_DATA64_IMPL(const NtKernel& kernel) {
    guest_ptr<structs::_KDDEBUGGER_DATA64> guestptr;
    const GuestVirtualAddress kernel_base = kernel.base_address();
    const Domain& domain = kernel_base.domain();

    GuestVirtualAddress kdDebuggerDataBlock;
    try {
        // Find the address of KdDebuggerDataBlock using the PDB file
        kdDebuggerDataBlock = kernel.symbol("KdDebuggerDataBlock");
        LOG4CXX_DEBUG(logger, "KdDebuggerDataBlock: " << kdDebuggerDataBlock);

        // Try to map in the structure
        guestptr.reset(kdDebuggerDataBlock);
    } catch (SymbolNotFoundException& ex) {
        throw GuestDetectionException(domain, "Failed to find KdVersionBlock in PDB file");
    }

    bool blockEncoded = true;
    if (guestptr->Header.OwnerTag == MAGIC_OWNER_TAG) {
        // tag is cleartext, block is not encoded
        LOG4CXX_DEBUG(logger, "KdDebuggerDataBlock not encoded");
        blockEncoded = false;
        debuggerData_ = *guestptr;
        kiProcessorBlock_ = kernel_base.create(debuggerData_.KiProcessorBlock);
    }

    // if block is encoded, try to decode using PDB file for the kernel
    if (blockEncoded) {
        LOG4CXX_DEBUG(logger, "Attempting decode of KdDebuggerDataBlock");

        GuestVirtualAddress kiWaitNever;
        GuestVirtualAddress kiWaitAlways;
        GuestVirtualAddress kdpDataBlockEncoded;
        try {
            // These symbols are all addresses that we have to then use to get the real data
            kiWaitNever = kernel.symbol("KiWaitNever");
            kiWaitAlways = kernel.symbol("KiWaitAlways");
            kdpDataBlockEncoded = kernel.symbol("KdpDataBlockEncoded");
        } catch (SymbolNotFoundException& ex) {
            throw GuestDetectionException(
                domain, "Failed to find necessary symbols to decode KdDebuggerDataBlock");
        }

        const uint nchunks = sizeof(debuggerData_) / sizeof(uint64_t);
        guest_ptr<uint64_t[]> encodedChunks(kdDebuggerDataBlock, nchunks);

        guest_ptr<uint64_t> kiWaitNeverPtr(kiWaitNever);
        kiWaitNever = kernel_base.create(*kiWaitNeverPtr);

        guest_ptr<uint64_t> kiWaitAlwaysPtr(kiWaitAlways);
        kiWaitAlways = kernel_base.create(*kiWaitAlwaysPtr);

        guest_ptr<uint32_t> tag(kdDebuggerDataBlock + 0x10);
        if (*tag == MAGIC_OWNER_TAG) {
            throw GuestDetectionException(domain, "Failed to decide KdDebuggerDataBlock");
        }

        for (uint64_t i = 0; i < nchunks; i++) {
            uint64_t decodedChunk = encodedChunks[i];
            decodedChunk = ROL((decodedChunk ^ kiWaitNever.virtual_address()),
                               (kiWaitNever.virtual_address() & 0xFF));
            decodedChunk =
                decodedChunk ^ (kdpDataBlockEncoded.virtual_address() | 0xFFFF000000000000ULL);
            decodedChunk = BSWAP_64(decodedChunk);
            decodedChunk = decodedChunk ^ kiWaitAlways.virtual_address();
            (reinterpret_cast<uint64_t*>(&debuggerData_))[i] = decodedChunk;
        }

        if (debuggerData_.Header.OwnerTag != MAGIC_OWNER_TAG) {
            throw GuestDetectionException(domain, "KDBG Decode FAILED");
        }

        LOG4CXX_DEBUG(logger, "KDBG Decoded OK using PDB");

        // if block is encoded, we cannot use KiProcessorBlock within kdbg
        kiProcessorBlock_ = kernel.symbol("KiProcessorBlock");
    }

    const GuestVirtualAddress ppObpTypeObjectType(
        kernel_base.create(debuggerData_.ObpTypeObjectType));
    const GuestVirtualAddress ppObpRootDirectoryObject(
        kernel_base.create(debuggerData_.ObpRootDirectoryObject));
    const GuestVirtualAddress ppPspCidTable(kernel_base.create(debuggerData_.PspCidTable));
    const GuestVirtualAddress pNtBuildLab(kernel_base.create(debuggerData_.NtBuildLab));

    pObpTypeObjectType_ = guest_ptr<PtrType>(ppObpTypeObjectType);
    pObpRootDirectoryObject_ = guest_ptr<PtrType>(ppObpRootDirectoryObject);
    pPspCidTable_ = guest_ptr<PtrType>(ppPspCidTable);
    CmNtCSDVersion_ = *guest_ptr<uint32_t>(kernel_base.create(debuggerData_.CmNtCSDVersion));
    NtBuildLab_ = std::string(map_guest_cstr(pNtBuildLab));

    // Sanity check
    if (KernelBase() != kernel_base.virtual_address()) {
        throw GuestDetectionException(domain, "KdVersionBlock kernel base mismatch");
    }
}

template class KDDEBUGGER_DATA64_IMPL<uint32_t>;
template class KDDEBUGGER_DATA64_IMPL<uint64_t>;

} /* namespace nt */
} // namespace windows
} // namespace introvirt
