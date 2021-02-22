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
#include "NT_TIB_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <log4cxx/logger.h>

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.types.NT_TIB"));

template <typename PtrType>
GuestVirtualAddress NT_TIB_IMPL<PtrType>::StackLimit() const {
    return gva_.create(nt_tib->StackLimit.get<PtrType>(buffer));
}

template <typename PtrType>
GuestVirtualAddress NT_TIB_IMPL<PtrType>::StackBase() const {
    return gva_.create(nt_tib->StackBase.get<PtrType>(buffer));
}

template <typename PtrType>
NT_TIB_IMPL<PtrType>::NT_TIB_IMPL(const NtKernelImpl<PtrType>& kernel,
                                  const GuestVirtualAddress& gva)
    : gva_(gva) {

    nt_tib = LoadOffsets<structs::NT_TIB>(kernel);
    buffer.reset(gva_, nt_tib->size());
}

template class NT_TIB_IMPL<uint32_t>;
template class NT_TIB_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
