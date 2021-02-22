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
#include "HBASE_BLOCK_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>

#include <log4cxx/logger.h>

#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.registry.HBASE_BLOCK"));

template <typename PtrType>
const int64_t HBASE_BLOCK_IMPL<PtrType>::TimeStamp() const {
    return hbase_block->TimeStamp.get<int64_t>(hbase_block_buffer_);
}

template <typename PtrType>
const std::string& HBASE_BLOCK_IMPL<PtrType>::FileName() const {
    if (!FileName_) {
        const GuestVirtualAddress pFileName = gva_ + hbase_block->FileName.offset();
        LOG4CXX_DEBUG(logger, "HBASE_BLOCK.FileName " << pFileName);
        const auto FileNameBufferSize = hbase_block->FileName.size();
        FileName_.emplace(pFileName, FileNameBufferSize);
    }
    return FileName_->utf8();
}

template <typename PtrType>
uint32_t HBASE_BLOCK_IMPL<PtrType>::RootCell() const {
    return hbase_block->RootCell.get<uint32_t>(hbase_block_buffer_);
}

template <typename PtrType>
uint32_t HBASE_BLOCK_IMPL<PtrType>::Length() const {
    return hbase_block->Length.get<uint32_t>(hbase_block_buffer_);
}

template <typename PtrType>
GuestVirtualAddress HBASE_BLOCK_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
HBASE_BLOCK_IMPL<PtrType>::HBASE_BLOCK_IMPL(const NtKernelImpl<PtrType>& kernel,
                                            const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    hbase_block = LoadOffsets<structs::HBASE_BLOCK>(kernel);
    hbase_block_buffer_.reset(gva_, hbase_block->size());

    const auto Signature = hbase_block->Signature.get<uint32_t>(hbase_block_buffer_);
    if (unlikely(Signature != 0x66676572 /* "regf" */)) {
        throw InvalidStructureException("Invalid signature for HBASE_BLOCK");
    }

    LOG4CXX_DEBUG(logger, "Parsed HBASE_BLOCK " << gva_);
}

template <typename PtrType>
HBASE_BLOCK_IMPL<PtrType>::~HBASE_BLOCK_IMPL() = default;

template class HBASE_BLOCK_IMPL<uint32_t>;
template class HBASE_BLOCK_IMPL<uint64_t>;

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
