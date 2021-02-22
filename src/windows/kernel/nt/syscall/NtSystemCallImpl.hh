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

#include "windows/kernel/WindowsSystemCallImpl.hh"

#include <introvirt/util/compiler.hh>
#include <introvirt/windows/kernel/nt/syscall/NtSystemCall.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

#define HANDLE_MASK 0xfffffffffffffffcll

template <typename PtrType>
inline bool IS_SELF_HANDLE(uint64_t handle) {
    if constexpr (std::is_same_v<PtrType, uint64_t>) {
        return (handle & HANDLE_MASK) == 0xfffffffffffffffcll;
    } else {
        return (handle & HANDLE_MASK) == 0xfffffffcl;
    }
}

template <typename PtrType, typename _BaseClass = NtSystemCall>
class NtSystemCallImpl : public WindowsSystemCallImpl<PtrType, _BaseClass> {
  public:
    /**
     * @brief Get the result code
     *
     * NT system calls return an NTSTATUS code on completion
     *
     * @return NTSTATUS
     */
    NTSTATUS result() const final { return result_; }

    /**
     * @brief Set the result code
     *
     * This can be used to maniuplate the value received by the guest userland software.
     *
     * @param code The code to set
     * @throw introvirt::InvalidMethodException if the kernel has not yet returned with a result to
     * overwrite
     */
    void result(NTSTATUS_CODE code) final {
        if (unlikely(!this->has_returned()))
            throw InvalidMethodException();

        this->vcpu().registers().rax(result_);
        result_ = code;
    }

    void handle_return_event(Event& event) override {
        WindowsSystemCallImpl<PtrType, _BaseClass>::handle_return_event(event);

        result_ = NTSTATUS(static_cast<NTSTATUS_CODE>(this->vcpu().registers().rax()));
    }

    void write(std::ostream& os) const override {
        WindowsSystemCallImpl<PtrType, _BaseClass>::write(os);

        boost::io::ios_flags_saver ifs(os);

        os << "\tNTSTATUS: ";
        if (!this->has_returned()) {
            os << "UNAVAILABLE";
        } else if (result_.NT_INFORMATION()) {
            os << "STATUS_INFORMATION";
        } else if (result_.NT_SUCCESS()) {
            os << "STATUS_SUCCESS";
        } else if (result_.NT_ERROR()) {
            os << "STATUS_ERROR";
        } else if (result_.NT_WARNING()) {
            os << "STATUS_WARNING";
        } else {
            os << "STATUS_UNKNOWN";
        }

        if (this->has_returned()) {
            if (result_.code() != STATUS_SUCCESS) {
                os << " (" << result_ << ')';
            }
            os << " (0x" << std::hex << static_cast<uint32_t>(result_.code()) << std::dec << ")";
        }

        os << '\n';
    }

    Json::Value json() const override {
        Json::Value result = WindowsSystemCallImpl<PtrType, _BaseClass>::json();
        if (this->has_returned()) {
            result["result"] = result_.json();
        }
        return result;
    }

    NtSystemCallImpl(WindowsEvent& event, bool supported = true)
        : WindowsSystemCallImpl<PtrType, _BaseClass>(event, supported) {}

  private:
    NTSTATUS result_;
};

} // namespace nt
} // namespace windows
} // namespace introvirt