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

#include <boost/io/ios_state.hpp>

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
    uint64_t UniqueProcess() const override { return ptr_->UniqueProcess; }
    uint64_t UniqueThread() const override { return ptr_->UniqueThread; }

    void UniqueProcess(uint64_t pid) override { ptr_->UniqueProcess = pid; }
    void UniqueThread(uint64_t tid) override { ptr_->UniqueThread = tid; }

    void write(std::ostream& os, const std::string& linePrefix = "") const override {
        boost::io::ios_flags_saver ifs(os);
        os << std::dec;
        os << linePrefix << *this << '\n';
    }

    Json::Value json() const override {
        Json::Value result;
        result["UniqueProcess"] = UniqueProcess();
        result["UniqueThread"] = UniqueThread();
        return result;
    }
    operator Json::Value() const override { return json(); }

    guest_ptr<void> ptr() const override { return ptr_; }

    CLIENT_ID_IMPL(const guest_ptr<void>& ptr) : ptr_(ptr) {}

  private:
    const guest_ptr<structs::_CLIENT_ID<PtrType>> ptr_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt