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
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/Event.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/util/introvirt_assert.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/types/KPCR.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
#include <introvirt/windows/libraries/WindowsFunctionCall.hh>

#include <log4cxx/logger.h>

using std::placeholders::_1;
using std::placeholders::_2;

namespace introvirt {
namespace windows {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.function.WindowsFunctionCall"));

guest_ptr<void> WindowsFunctionCall::return_address() const { return stack_.clone(stack_.at(0)); }
void WindowsFunctionCall::return_address(const guest_ptr<void>& value) {
    introvirt_assert(!returned(),
                     "return_address cannot be changed after the return already occurred");
    stack_.set(0, value.address());
}

bool WindowsFunctionCall::returned() const { return returned_; }
bool WindowsFunctionCall::is_return_event(Event& event) const {
    LOG4CXX_DEBUG(logger, "Expecting TID " << tid_ << " RSP 0x" << std::hex << return_rsp_);
    LOG4CXX_DEBUG(logger, "Got TID " << event.task().tid() << " RSP 0x" << std::hex
                                     << event.vcpu().registers().rsp());
    return (event.task().tid() == tid_ && event.vcpu().registers().rsp() == return_rsp_);
}

void WindowsFunctionCall::handle_return(Event& event) {
    if (unlikely(returned_)) {
        LOG4CXX_ERROR(logger, "handle_return() called after return");
        throw InvalidMethodException();
    }

    event_ = static_cast<WindowsEvent*>(&event);
    returned_ = true;

    // As far as I know, values are always returned in rax
    raw_return_value_ = event_->vcpu().registers().rax();

    // Mask off high bits for 32-bit function handlers
    if (!x64())
        raw_return_value_ &= 0xFFFFFFFF;
}

uint64_t WindowsFunctionCall::raw_return_value() const {
    if (unlikely(!returned_)) {
        LOG4CXX_ERROR(logger, "raw_return_value() called before return");
        throw InvalidMethodException();
    }

    return raw_return_value_;
}

void WindowsFunctionCall::raw_return_value(uint64_t value) {
    if (unlikely(!returned_)) {
        LOG4CXX_ERROR(logger, "raw_return_value(uint64_t) called before return");
        throw InvalidMethodException();
    }

    // Mask off high bits for 32-bit function handlers
    if (!x64())
        value &= 0xFFFFFFFF;

    // As far as I know, values are always returned in rax
    event_->vcpu().registers().rax(value);
}

uint64_t WindowsFunctionCall::get_argument(unsigned int index) const {
    if (unlikely(returned_)) {
        LOG4CXX_ERROR(logger, "get_argument(unsigned int) called after return");
        throw InvalidMethodException();
    }

    return get_argument_(index);
}

void WindowsFunctionCall::set_argument(unsigned int index, uint64_t value) {
    if (unlikely(returned_)) {
        LOG4CXX_ERROR(logger, "set_argument(unsigned int, uint64_t) called after return");
        throw InvalidMethodException();
    }

    set_argument_(index, value);
}

guest_ptr<void> WindowsFunctionCall::get_address_argument(unsigned int index) const {
    return guest_ptr<void>(vcpu(), get_argument(index));
}
void WindowsFunctionCall::set_address_argument(unsigned int index, const guest_ptr<void>& address) {
    set_argument(index, address.address());
}

uint64_t WindowsFunctionCall::_get_argument_cdecl(unsigned int index) const {
    return stack_[index + 1];
}

void WindowsFunctionCall::_set_argument_cdecl(unsigned int index, uint64_t value) {
    stack_.set(index + 1, value);
}

uint64_t WindowsFunctionCall::_get_argument_fastcall(unsigned int index) const {
    switch (index) {
    case 0:
        return event_->vcpu().registers().rcx();
    case 1:
        return event_->vcpu().registers().rdx();
    default:
        // Fastcall doesn't leave padding for register spill
        return stack_[index + 1 - 2];
    }
}

void WindowsFunctionCall::_set_argument_fastcall(unsigned int index, uint64_t value) {
    switch (index) {
    case 0:
        event_->vcpu().registers().rcx(value);
        break;
    case 1:
        event_->vcpu().registers().rdx(value);
        break;
    default:
        // Fastcall doesn't leave padding for register spill
        stack_.set(index + 1 - 2, value);
    }
}

uint64_t WindowsFunctionCall::_get_argument_x64(unsigned int index) const {
    switch (index) {
    case 0:
        return event_->vcpu().registers().rcx();
    case 1:
        return event_->vcpu().registers().rdx();
    case 2:
        return event_->vcpu().registers().r8();
    case 3:
        return event_->vcpu().registers().r9();
    default:
        return stack_[index + 1];
    }
}

void WindowsFunctionCall::_set_argument_x64(unsigned int index, uint64_t value) {
    switch (index) {
    case 0:
        event_->vcpu().registers().rcx(value);
        break;
    case 1:
        event_->vcpu().registers().rdx(value);
        break;
    case 2:
        event_->vcpu().registers().r8(value);
        break;
    case 3:
        event_->vcpu().registers().r9(value);
        break;
    default:
        stack_.set(index + 1, value);
    }
}

Vcpu& WindowsFunctionCall::vcpu() { return event_->vcpu(); }
const Vcpu& WindowsFunctionCall::vcpu() const { return event_->vcpu(); }

bool WindowsFunctionCall::x64() const { return x64_; }

WindowsFunctionCall::WindowsFunctionCall(Event& event, unsigned int argument_count,
                                         WindowsCallType type)
    : event_(static_cast<WindowsEvent*>(&event)), tid_(event.task().tid()) {

    auto& vcpu = event.vcpu();
    auto& regs = vcpu.registers();

    x64_ = (vcpu.long_mode() && !vcpu.long_compatibility_mode());

    if (vcpu.long_mode()) {
        // Check for WoW64
        if (vcpu.long_compatibility_mode()) {
            // We're in WoW64 (32-bit) mode, so the calling convention should still be 32-bit
            if (type == WindowsCallType::AUTO)
                type = WindowsCallType::STDCALL;
        } else {
            // Processor is in 64-bit mode, this is the only convention allowed.
            type = WindowsCallType::X64;
        }
    } else if (type == WindowsCallType::AUTO) {
        // Processor is in 32-bit mode
        type = WindowsCallType::STDCALL;
    }

    const unsigned int stack_size = argument_count + 1;
    stack_.reset(x64(), event.vcpu(), regs.rsp(), stack_size);

    switch (type) {
    case WindowsCallType::STDCALL: // These are the same as far as arguments go
    case WindowsCallType::CDECL:
        get_argument_ = std::bind(&WindowsFunctionCall::_get_argument_cdecl, this, _1);
        set_argument_ = std::bind(&WindowsFunctionCall::_set_argument_cdecl, this, _1, _2);
        return_rsp_ = stack_.address() + (sizeof(uint32_t) * argument_count) + sizeof(uint32_t);
        break;
    case WindowsCallType::FASTCALL:
        get_argument_ = std::bind(&WindowsFunctionCall::_get_argument_fastcall, this, _1);
        set_argument_ = std::bind(&WindowsFunctionCall::_set_argument_fastcall, this, _1, _2);
        return_rsp_ = stack_.address() + (sizeof(uint32_t) * argument_count) + sizeof(uint32_t);
        break;
    case WindowsCallType::X64:
        get_argument_ = std::bind(&WindowsFunctionCall::_get_argument_x64, this, _1);
        set_argument_ = std::bind(&WindowsFunctionCall::_set_argument_x64, this, _1, _2);
        // Seems the caller cleans up, the callee only pops off the return address
        return_rsp_ = stack_.address() + sizeof(uint64_t);
        break;
    default:
        // TODO: Throw an exception
        break;
    }
}

WindowsFunctionCall::~WindowsFunctionCall() = default;

} // namespace windows
} // namespace introvirt
