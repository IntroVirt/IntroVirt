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

#include "FLOWSPEC.hh"
#include "WSABUF.hh"

#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/**
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-qos
 */
class QOS {
  public:
    virtual const FLOWSPEC& SendingFlowspec() const = 0;
    virtual FLOWSPEC& SendingFlowspec() = 0;

    virtual const FLOWSPEC& ReceivingFlowspec() const = 0;
    virtual FLOWSPEC& ReceivingFlowspec() = 0;

    virtual const WSABUF& ProviderSpecific() const = 0;
    virtual WSABUF& ProviderSpecific() = 0;

    static std::shared_ptr<QOS> make_shared(const guest_ptr<void>& ptr, bool x64);
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt