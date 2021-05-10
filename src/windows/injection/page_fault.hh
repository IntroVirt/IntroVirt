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

#include "core/domain/DomainImpl.hh"
#include "core/event/EventImpl.hh"
#include "core/injection/RegisterGuard.hh"
#include "syscall.hh"
#include "windows/WindowsGuestImpl.hh"

#include <introvirt/core/breakpoint/Breakpoint.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/fwd.hh>
#include <introvirt/windows/common/WinError.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/kernel/nt/types/MMVAD.hh>
#include <introvirt/windows/kernel/nt/types/TEB.hh>
#include <introvirt/windows/kernel/nt/types/objects/FILE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>
#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/pe.hh>

#include <boost/algorithm/string.hpp>
#include <log4cxx/logger.h>

#include <cassert>
#include <cstdint>
#include <optional>

namespace introvirt {
namespace windows {
namespace inject {

void dummy_callback(Event& event, std::shared_ptr<Breakpoint>* breakpoint2);

class PageFaultInjector final {
  private:
    static inline log4cxx::LoggerPtr logger =
        log4cxx::Logger::getLogger("introvirt.win.inject.PageFaultInjector");

  public:
    /**
     * @brief Sleep the current thread until the function call returns
     */
    void call(uint64_t address) {
        auto& vcpu = event_.vcpu();

        // Set a breakpoint for our executable page
        std::shared_ptr<Breakpoint> bp;
        bp = guest_->domain().create_breakpoint(
            executable_page_, std::bind(dummy_callback, std::placeholders::_1, &bp));

        // Lock the thread affinity
        auto& thread = static_cast<WindowsEvent&>(event_).task().pcr().CurrentThread();
        const uint64_t desired_affinity = (1u << vcpu.id());
        const auto original_affinity = thread.Affinity();
        const auto original_user_affinity = thread.UserAffinity();
        const auto original_ideal_processor = thread.IdealProcessor();
        const auto original_user_ideal_processor = thread.UserIdealProcessor();

        thread.Affinity(desired_affinity);
        thread.UserAffinity(desired_affinity);
        thread.IdealProcessor(vcpu.id());
        thread.UserIdealProcessor(vcpu.id());

        static_cast<DomainImpl&>(event_.domain()).start_injection(event_);

        LOG4CXX_DEBUG(logger, "Injecting page fault");
        vcpu.registers().rip(executable_page_.address());
        vcpu.inject_exception(x86::Exception::PAGE_FAULT, 6, address);

        // Wait for the return event
        auto new_event = event_.impl().suspend([this](const introvirt::Event& event) {
            if (event.type() == EventType::EVENT_EXCEPTION &&
                event.vcpu().registers().rip() == executable_page_.address()) {
                return WakeAction::ACCEPT;
            }
            return WakeAction::DROP;
        });

        introvirt_assert(vcpu.id() == new_event->vcpu().id(),
                         "VCPU changed during page fault injection");

        // Restore the thread affinity
        thread.Affinity(original_affinity);
        thread.UserAffinity(original_user_affinity);
        thread.IdealProcessor(original_ideal_processor);
        thread.UserIdealProcessor(original_user_ideal_processor);

        static_cast<DomainImpl&>(event_.domain()).end_injection(event_);

        LOG4CXX_DEBUG(logger, "Page fault injection completed");
    }

    PageFaultInjector(Event& event) : guard_(event.vcpu()), event_(event) {
        introvirt_assert(event.os_type() == OS::Windows, "");

        guest_ = &(static_cast<WindowsEvent&>(event).guest());

        switch (event.type()) {
        case EventType::EVENT_MEM_ACCESS:
            LOG4CXX_WARN(logger, "Function injection on nested memory access not supported")
            throw InvalidMethodException();
        default:
            break;
        }

        if (event_.vcpu().long_mode()) {
            allocate_guest_memory<uint64_t>();
        } else {
            allocate_guest_memory<uint32_t>();
        }
    }

    ~PageFaultInjector() {
        // Get us back to the original state
        // We force this early so that our system call injections below succeed.
        guard_.reset();

        try {
            if (event_.vcpu().long_mode())
                free_guest_memory<uint64_t>();
            else
                free_guest_memory<uint32_t>();
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(logger, "FunctionInjector cleanup failed: " << ex.what());
        }
    }

  private:
    template <typename PtrType>
    void allocate_guest_memory() {
        auto* guest = static_cast<WindowsGuestImpl<PtrType>*>(guest_);

        // Allocate executable and data memory
        size_t RegionSize = x86::PageDirectory::PAGE_SIZE;
        executable_page_ = guest->allocate(RegionSize, true);
        LOG4CXX_DEBUG(logger,
                      "Allocated function injection executable page : " << executable_page_);
    }

    template <typename PtrType>
    void free_guest_memory() {
        auto* guest = static_cast<WindowsGuestImpl<PtrType>*>(guest_);
        const size_t RegionSize = x86::PageDirectory::PAGE_SIZE;

        guest->guest_free(executable_page_, RegionSize);
        LOG4CXX_DEBUG(logger, "Freed function injection executable page : " << executable_page_);
    }

  private:
    std::optional<introvirt::inject::RegisterGuard> guard_;
    Event& event_;
    WindowsGuest* guest_;
    guest_ptr<void> executable_page_;
};

} // namespace inject
} // namespace windows
} // namespace introvirt