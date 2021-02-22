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
#pragma once

#include "DISPATCHER_HEADER_IMPL.hh"
#include "OBJECT_IMPL.hh"
#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/kernel/nt/types/objects/DISPATCHER_OBJECT.hh>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType, typename _BaseType>
class DISPATCHER_OBJECT_IMPL : public OBJECT_IMPL<PtrType, _BaseType> {
  public:
    DISPATCHER_HEADER& DispatcherHeader() final { return dispatcher_header_; }
    const DISPATCHER_HEADER& DispatcherHeader() const final { return dispatcher_header_; }

    DISPATCHER_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel, const GuestVirtualAddress& gva,
                           ObjectType expected)
        : OBJECT_IMPL<PtrType, _BaseType>(kernel, gva, expected),
          dispatcher_header_(kernel, OBJECT_IMPL<PtrType, _BaseType>::address()) {}

    DISPATCHER_OBJECT_IMPL(const NtKernelImpl<PtrType>& kernel,
                           std::unique_ptr<OBJECT_HEADER_IMPL<PtrType>>&& object_header,
                           ObjectType expected)
        : OBJECT_IMPL<PtrType, _BaseType>(kernel, std::move(object_header), expected),
          dispatcher_header_(kernel, OBJECT_IMPL<PtrType, _BaseType>::address()) {}

  private:
    DISPATCHER_HEADER_IMPL<PtrType> dispatcher_header_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt