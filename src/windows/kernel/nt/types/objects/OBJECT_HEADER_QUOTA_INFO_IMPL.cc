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
#include "OBJECT_HEADER_QUOTA_INFO_IMPL.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
OBJECT_HEADER_QUOTA_INFO_IMPL<PtrType>::OBJECT_HEADER_QUOTA_INFO_IMPL(
    const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva) {}

template class OBJECT_HEADER_QUOTA_INFO_IMPL<uint32_t>;
template class OBJECT_HEADER_QUOTA_INFO_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt