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
    guest_ptr<const structs::_KDDEBUGGER_DATA64> kdDebuggerDataBlock;
    const guest_ptr<void>& kernel_base_ptr = kernel.ptr();
    const Domain& domain = kernel_base_ptr.domain();

    try {
        // Find the address of KdDebuggerDataBlock using the PDB file
        kdDebuggerDataBlock = kernel.symbol("KdDebuggerDataBlock");
        LOG4CXX_DEBUG(logger, "KdDebuggerDataBlock: " << kdDebuggerDataBlock);
    } catch (SymbolNotFoundException& ex) {
        throw GuestDetectionException(domain, "Failed to find KdVersionBlock in PDB file");
    }

    if (kdDebuggerDataBlock->Header.OwnerTag == MAGIC_OWNER_TAG) {
        // tag is cleartext, block is not encoded
        LOG4CXX_DEBUG(logger, "KdDebuggerDataBlock not encoded");
        debuggerData_ = *kdDebuggerDataBlock;
    } else {
        // if block is encoded, try to decode using PDB file for the kernel
        LOG4CXX_DEBUG(logger, "Attempting decode of KdDebuggerDataBlock");

        uint64_t kiWaitNever;
        uint64_t kiWaitAlways;
        uint64_t kdpDataBlockEncoded;
        try {
            kiWaitNever = *guest_ptr<uint64_t>(kernel.symbol("KiWaitNever"));
            kiWaitAlways = *guest_ptr<uint64_t>(kernel.symbol("kiWaitAlways"));
            kdpDataBlockEncoded = kernel.symbol("KdpDataBlockEncoded").address();
        } catch (SymbolNotFoundException& ex) {
            throw GuestDetectionException(
                domain, "Failed to find necessary symbols to decode KdDebuggerDataBlock");
        }

        const uint nchunks = sizeof(debuggerData_) / sizeof(uint64_t);
        guest_ptr<const uint64_t[]> encodedChunks(
            reinterpret_ptr_cast<const void>(kdDebuggerDataBlock), nchunks);

        for (uint64_t i = 0; i < nchunks; ++i) {
            uint64_t decodedChunk = encodedChunks[i];
            decodedChunk = ROL((decodedChunk ^ kiWaitNever), (kiWaitNever & 0xFF));
            decodedChunk = decodedChunk ^ (kdpDataBlockEncoded | 0xFFFF000000000000ULL);
            decodedChunk = BSWAP_64(decodedChunk);
            decodedChunk = decodedChunk ^ kiWaitAlways;
            (reinterpret_cast<uint64_t*>(&debuggerData_))[i] = decodedChunk;
        }

        if (debuggerData_.Header.OwnerTag != MAGIC_OWNER_TAG) {
            throw GuestDetectionException(domain, "KDBG Decode FAILED");
        }

        LOG4CXX_DEBUG(logger, "KDBG Decoded OK using PDB");
    }

    guest_ptr<PtrType*, PtrType> ppObpTypeObjectType =
        kernel_base_ptr.clone(debuggerData_.ObpTypeObjectType);
    pObpTypeObjectType_ = ppObpTypeObjectType.get();

    guest_ptr<PtrType*, PtrType> ppObpRootDirectoryObject =
        kernel_base_ptr.clone(debuggerData_.ObpRootDirectoryObject);
    pObpRootDirectoryObject_ = ppObpRootDirectoryObject.get();

    guest_ptr<PtrType*, PtrType> ppPspCidTable = kernel_base_ptr.clone(debuggerData_.PspCidTable);
    pPspCidTable_ = ppPspCidTable.get();

    CmNtCSDVersion_ = *guest_ptr<uint32_t>(kernel_base_ptr.clone(debuggerData_.CmNtCSDVersion));

    NtBuildLab_ = map_guest_cstring(kernel_base_ptr.clone(debuggerData_.NtBuildLab)).str();
    // NtBuildLab_ = std::string(NtBuildLabMapping.get(), NtBuildLabMapping.length());

    // Sanity check
    if (KernelBase() != kernel_base_ptr.address()) {
        throw GuestDetectionException(domain, "KdVersionBlock kernel base mismatch");
    }
}

template class KDDEBUGGER_DATA64_IMPL<uint32_t>;
template class KDDEBUGGER_DATA64_IMPL<uint64_t>;

} /* namespace nt */
} // namespace windows
} // namespace introvirt
