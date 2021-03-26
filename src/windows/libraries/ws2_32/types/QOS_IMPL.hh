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

#include "FLOWSPEC_IMPL.hh"
#include "WSABUF_IMPL.hh"

#include <introvirt/windows/libraries/ws2_32/types/QOS.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace ws2_32 {

namespace structs {

template <typename PtrType>
struct _QOS {
    _FLOWSPEC SendingFlowspec;
    _FLOWSPEC ReceivingFlowspec;
    _WSABUF<PtrType> ProviderSpecific;
};

} // namespace structs

template <typename PtrType>
class QOS_IMPL final : public QOS {
  public:
    const FLOWSPEC& SendingFlowspec() const override { return SendingFlowspec_; }
    FLOWSPEC& SendingFlowspec() override { return SendingFlowspec_; }

    const FLOWSPEC& ReceivingFlowspec() const override { return ReceivingFlowspec_; }
    FLOWSPEC& ReceivingFlowspec() override { return ReceivingFlowspec_; }

    const WSABUF& ProviderSpecific() const override { return ProviderSpecific_; }
    WSABUF& ProviderSpecific() override { return ProviderSpecific_; }

    QOS_IMPL(const guest_ptr<void>& ptr)
        : SendingFlowspec_(ptr + offsetof(_QOS, SendingFlowspec)),
          ReceivingFlowspec_(ptr + offsetof(_QOS, ReceivingFlowspec)),
          ProviderSpecific_(ptr + offsetof(_QOS, ProviderSpecific)) {}

  private:
    using _QOS = structs::_QOS<PtrType>;
    FLOWSPEC_IMPL SendingFlowspec_;
    FLOWSPEC_IMPL ReceivingFlowspec_;
    WSABUF_IMPL<PtrType> ProviderSpecific_;
};

} // namespace ws2_32
} // namespace windows
} // namespace introvirt