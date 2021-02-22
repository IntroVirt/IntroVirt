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

#include "../const/ConsoleCallServerGenericRequestCode.hh"

#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/kernel/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace condrv {

class ConsoleCallServerGenericRequest final {
  public:
    ConsoleCallServerGenericRequestCode RequestCode() const;
    uint32_t Data1() const;
    uint32_t Data2() const;
    guest_ptr<uint8_t[]> RequestData();

    GuestVirtualAddress header_address() const;
    GuestVirtualAddress data_address() const;

    ConsoleCallServerGenericRequest(const WindowsGuest& guest,
                                    const GuestVirtualAddress& pRequestHeader,
                                    const GuestVirtualAddress& pRequestData,
                                    uint32_t requestDataLen);
    ~ConsoleCallServerGenericRequest();

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */
