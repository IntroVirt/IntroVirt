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
#include <introvirt/windows/kernel/nt/types/CLIENT_ID.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

template <typename PtrType>
struct _CLIENT_ID {
    PtrType UniqueProcess; // offset   0x0 size   0x8
    PtrType UniqueThread;  // offset   0x8 size   0x8
};

} // namespace structs

template <typename PtrType>
class CLIENT_ID_IMPL final : public CLIENT_ID {
  public:
    uint64_t UniqueProcess() const override;
    uint64_t UniqueThread() const override;

    void UniqueProcess(uint64_t pid) override;
    void UniqueThread(uint64_t tid) override;

    void write(std::ostream& os, const std::string& linePrefix = "") const override;

    Json::Value json() const override;
    operator Json::Value() const override;

    GuestVirtualAddress address() const override;

    CLIENT_ID_IMPL(const GuestVirtualAddress& gva);

  private:
    const GuestVirtualAddress gva_;
    guest_ptr<structs::_CLIENT_ID<PtrType>> client_id_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt