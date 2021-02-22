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

#include <introvirt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Base class for all kernel objects
 */
class OBJECT {
  public:
    /**
     * @brief Get the OBJECT_HEADER for this object
     */
    virtual const OBJECT_HEADER& header() const = 0;

    /**
     * @returns The virtual address of this object
     */
    virtual GuestVirtualAddress address() const = 0;

    static std::shared_ptr<OBJECT> make_shared(const NtKernel& kernel,
                                               const GuestVirtualAddress& gva);

    static std::shared_ptr<OBJECT> make_shared(const NtKernel& kernel,
                                               std::unique_ptr<OBJECT_HEADER>&& object_header);

    /**
     * @brief Destroy the instance
     */
    virtual ~OBJECT() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
