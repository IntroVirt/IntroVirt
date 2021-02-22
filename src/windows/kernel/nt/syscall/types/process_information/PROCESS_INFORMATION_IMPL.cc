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

#include "PROCESS_INFORMATION_IMPL.hh"
#include "PROCESS_BASIC_INFORMATION_IMPL.hh"
#include "PROCESS_COOKIE_INFORMATION_IMPL.hh"
#include "PROCESS_DEFAULT_HARD_ERROR_MODE_INFORMATION_IMPL.hh"
#include "PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL.hh"
#include "PROCESS_IMAGE_FILE_NAME_WIN32_INFORMATION_IMPL.hh"
#include "PROCESS_PRIORITY_CLASS_INFORMATION_IMPL.hh"
#include "PROCESS_WINDOW_INFORMATION_IMPL.hh"
#include "PROCESS_WOW64_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/core/memory/guest_ptr.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
static std::unique_ptr<PROCESS_INFORMATION> make_unique_impl(PROCESS_INFORMATION_CLASS info_class,
                                                             const GuestVirtualAddress& gva,
                                                             uint32_t buffer_size) {

    switch (info_class) {
    case PROCESS_INFORMATION_CLASS::ProcessBasicInformation:
        return std::make_unique<PROCESS_BASIC_INFORMATION_IMPL<PtrType>>(gva, buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessCookie:
        return std::make_unique<PROCESS_COOKIE_INFORMATION_IMPL>(gva, buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessDefaultHardErrorMode:
        return std::make_unique<PROCESS_DEFAULT_HARD_ERROR_MODE_INFORMATION_IMPL>(gva, buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessImageFileName:
        return std::make_unique<PROCESS_IMAGE_FILE_NAME_INFORMATION_IMPL<PtrType>>(gva,
                                                                                   buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessImageFileNameWin32:
        return std::make_unique<PROCESS_IMAGE_FILE_NAME_WIN32_INFORMATION_IMPL<PtrType>>(
            gva, buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessWindowInformation:
        return std::make_unique<PROCESS_WINDOW_INFORMATION_IMPL>(gva, buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessWow64Information:
        return std::make_unique<PROCESS_WOW64_INFORMATION_IMPL>(gva, buffer_size);
    case PROCESS_INFORMATION_CLASS::ProcessPriorityClass:
        return std::make_unique<PROCESS_PRIORITY_CLASS_INFORMATION_IMPL>(gva, buffer_size);
    }

    return std::make_unique<PROCESS_INFORMATION_IMPL<>>(info_class, gva, buffer_size);
}

std::unique_ptr<PROCESS_INFORMATION>
PROCESS_INFORMATION::make_unique(const NtKernel& kernel, PROCESS_INFORMATION_CLASS info_class,
                                 const GuestVirtualAddress& gva, uint32_t buffer_size) {

    if (unlikely(buffer_size == 0))
        return nullptr;

    if (kernel.x64()) {
        return make_unique_impl<uint64_t>(info_class, gva, buffer_size);
    } else {
        return make_unique_impl<uint32_t>(info_class, gva, buffer_size);
    }
}

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
