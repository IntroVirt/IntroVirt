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

#include <introvirt/windows/kernel/nt/fwd.hh>

#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for the CM_KEY_BODY NT Kernel structure
 *
 * This is a structure used for registry information
 *
 */
class CM_KEY_BODY : public OBJECT {
  public:
    /**
     * @brief Get the KeyControlBlock member of the structure
     *
     * @return The KeyControlBlock
     */
    virtual const CM_KEY_CONTROL_BLOCK& KeyControlBlock() const = 0;

    /**
     * @returns The process ID associated with this CM_KEY_BODY
     */
    virtual uint64_t ProcessID() const = 0;

    /**
     * @brief Helper function for traversing the key back to the root
     *
     * Returns the full path of this key by traversing up the
     * CM_KEY_CONTROL_BLOCK
     *
     * @returns The full path of this key
     */
    virtual const std::string& full_key_path() const = 0;

    static std::shared_ptr<CM_KEY_BODY> make_shared(const NtKernel& kernel,
                                                    const GuestVirtualAddress& gva);

    static std::shared_ptr<CM_KEY_BODY> make_shared(const NtKernel& kernel,
                                                    std::unique_ptr<OBJECT_HEADER>&& object_header);

    virtual ~CM_KEY_BODY() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
