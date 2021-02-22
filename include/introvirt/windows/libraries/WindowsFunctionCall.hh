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

#include <introvirt/core/function/FunctionCall.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/event/fwd.hh>

#include <functional>
#include <memory>

namespace introvirt {
namespace windows {

enum class WindowsCallType { AUTO, CDECL, STDCALL, FASTCALL, X64 };

class WindowsFunctionCall : public FunctionCall {
  public:
    GuestVirtualAddress return_address() const override;
    void return_address(const GuestVirtualAddress& value) override;

    bool is_return_event(Event& event) const override;
    void handle_return(Event& event) override;
    bool returned() const override;

    /**
     * @brief Check if the call is from x64 mode.hh>
     *
     * This returns false for 32-bit guests or if the processor is in WoW64 mode
     */
    bool x64() const;

    virtual ~WindowsFunctionCall();

  protected:
    uint64_t raw_return_value() const;
    void raw_return_value(uint64_t value);

    uint64_t get_argument(unsigned int index) const;
    void set_argument(unsigned int index, uint64_t value);

    GuestVirtualAddress get_address_argument(unsigned int index) const;
    void set_address_argument(unsigned int index, const GuestVirtualAddress& address);

    Vcpu& vcpu();
    const Vcpu& vcpu() const;

    uint64_t get_ptrsize_value(const GuestVirtualAddress& gva) const;
    void set_ptrsize_value(const GuestVirtualAddress& gva, uint64_t value);

    GuestVirtualAddress get_ptr(const GuestVirtualAddress& gva) const;
    void set_ptr(const GuestVirtualAddress& gva, const GuestVirtualAddress& value);

    WindowsFunctionCall(Event& event, unsigned int argument_count,
                        WindowsCallType type = WindowsCallType::AUTO);

  private:
    uint64_t _get_argument_cdecl(unsigned int index) const;
    void _set_argument_cdecl(unsigned int index, uint64_t value);

    uint64_t _get_argument_fastcall(unsigned int index) const;
    void _set_argument_fastcall(unsigned int index, uint64_t value);

    uint64_t _get_argument_x64(unsigned int index) const;
    void _set_argument_x64(unsigned int index, uint64_t value);

    WindowsEvent* event_;

    GuestVirtualAddress stack_ptr_;
    guest_ptr<uint32_t[]> stack32_;
    guest_ptr<uint64_t[]> stack64_;

    std::function<uint64_t(unsigned int)> get_argument_;
    std::function<void(unsigned int, uint64_t)> set_argument_;

    const uint64_t tid_;
    uint64_t return_rsp_;

    bool returned_ = false;
    uint64_t raw_return_value_ = -1;
};

} // namespace windows
} // namespace introvirt