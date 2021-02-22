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

#include "core/syscall/SystemCallImpl.hh"
#include "windows/kernel/nt/NtKernelImpl.hh"
#include "windows/kernel/nt/types/objects/THREAD_IMPL.hh"

#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/WindowsSystemCall.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>

namespace introvirt {
namespace windows {

template <typename PtrType, typename _BaseClass = WindowsSystemCall>
class WindowsSystemCallImpl : public SystemCallImpl<_BaseClass> {
  public:
    SystemCallIndex index() const final { return call_index_; };

    const std::string& name() const final { return to_string(call_index_); };

    bool supported() const final { return supported_; }

    void handle_return_event(Event& event) override {
        // Update our local pointer
        event_ = static_cast<WindowsEvent*>(&event);
        has_return_event_ = true;
    }

    bool has_returned() const { return has_return_event_; }

    void write(std::ostream& os) const override {}

    Json::Value json() const override {
        Json::Value result;
        result["index"] = to_string(call_index_);
        return result;
    }

    WindowsSystemCallImpl(WindowsEvent& event, bool supported = true)
        : event_(&event),
          call_index_(event.guest().syscalls().normalize(event.vcpu().registers().rax())),
          supported_(supported) {

        // TODO: Would be nice if we knew the number of arguments per-call instead of hardcoding
        static constexpr unsigned int ArgumentCount = 16;

        GuestVirtualAddress sp;
        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            // Stack is held in RSP for 64-bit SYSCALL
            sp = GuestVirtualAddress(event.vcpu().registers().rsp());
        } else {
            // Stack is held in RDX for 32-bit SYSENTER
            sp = GuestVirtualAddress(event.vcpu().registers().rdx());
        }
        stack_.reset(sp, ArgumentCount);
    }

  protected:
    Vcpu& vcpu() { return event_->vcpu(); }
    const Vcpu& vcpu() const { return event_->vcpu(); }

    const nt::NtKernelImpl<PtrType>& kernel() const {
        return static_cast<const nt::NtKernelImpl<PtrType>&>(event_->guest().kernel());
    }
    nt::NtKernelImpl<PtrType>& kernel() {
        return static_cast<nt::NtKernelImpl<PtrType>&>(event_->guest().kernel());
    }

    nt::THREAD_IMPL<PtrType>& CurrentThread() {
        return static_cast<nt::THREAD_IMPL<PtrType>&>(event_->task().pcr().CurrentThread());
    }
    const nt::THREAD_IMPL<PtrType>& CurrentThread() const {
        return static_cast<const nt::THREAD_IMPL<PtrType>&>(event_->task().pcr().CurrentThread());
    }

    WindowsGuest& guest() { return event_->guest(); }
    const WindowsGuest& guest() const { return event_->guest(); }

    void set_argument(unsigned int index, uint64_t value) {
        if (unlikely(has_return_event_))
            throw InvalidMethodException();

        Registers& regs = vcpu().registers();

        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            // 64 bit calling convention passes the first four arguments in registers
            switch (index) {
            case 0:
                regs.r10(value);
                return;
            case 1:
                regs.rdx(value);
                return;
            case 2:
                regs.r8(value);
                return;
            case 3:
                regs.r9(value);
                return;
            default:
                // stack64_[0] is the return address
                stack_[index + 1] = value;
            }
        } else {
            // TODO: Handle EVENT_SW_INT
            // stack32_[0] is the return address
            // stack32_[1] is the return stack
            stack_[index + 2] = (value & 0xFFFFFFFF);
        }
    }

    uint64_t get_argument(unsigned int index) const {
        if (unlikely(has_return_event_))
            throw InvalidMethodException();

        const Registers& regs = vcpu().registers();

        if constexpr (std::is_same_v<PtrType, uint64_t>) {
            // 64 bit calling convention passes the first four arguments in registers
            switch (index) {
            case 0:
                return regs.r10();
            case 1:
                return regs.rdx();
            case 2:
                return regs.r8();
            case 3:
                return regs.r9();
            default:
                // stack64_[0] is the return address
                return stack_[index + 1];
            }
        } else {
            // TODO: Handle EVENT_SW_INT
            // stack32_[0] is the return address
            // stack32_[1] is the return stack
            return stack_[index + 2];
        }
    }

  private:
    WindowsEvent* event_;
    const SystemCallIndex call_index_;
    bool has_return_event_ = false;
    const bool supported_;

    guest_ptr<PtrType[]> stack_;
};

} // namespace windows
} // namespace introvirt