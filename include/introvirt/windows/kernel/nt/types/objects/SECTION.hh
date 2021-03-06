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

#include "OBJECT.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

class SECTION : public OBJECT {
  public:
    virtual uint64_t StartingVpn() const = 0;
    virtual uint64_t EndingVpn() const = 0;

    virtual guest_ptr<void> StartingVa() const = 0;
    virtual guest_ptr<void> EndingVa() const = 0;

    virtual uint64_t SizeOfSection() const = 0;

    virtual const CONTROL_AREA* ControlArea() const = 0;
    virtual const FILE_OBJECT* FileObject() const = 0;

    static std::shared_ptr<SECTION> make_shared(const NtKernel& kernel, const guest_ptr<void>& ptr);

    static std::shared_ptr<SECTION> make_shared(const NtKernel& kernel,
                                                std::unique_ptr<OBJECT_HEADER>&& object_header);

    virtual ~SECTION() = default;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
