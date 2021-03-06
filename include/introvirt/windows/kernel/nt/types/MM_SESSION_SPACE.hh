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

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>
#include <vector>

namespace introvirt {
namespace windows {
namespace nt {

class MM_SESSION_SPACE {
  public:
    /**
     * @returns The virtual address of this MM_SESSION_SPACE in guest memory
     */
    virtual guest_ptr<void> ptr() const = 0;

    virtual uint32_t SessionID() const = 0;

    /**
     * @returns A list of processes within this session
     */
    virtual std::vector<std::shared_ptr<const PROCESS>> process_list() const = 0;

    virtual ~MM_SESSION_SPACE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
