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
#include <introvirt/core/memory/GuestVirtualAddress.hh>
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

static log4cxx::LoggerPtr
    func_injector_logger(log4cxx::Logger::getLogger("introvirt.win.inject.FunctionInjector"));

void dummy_callback(Event& event, std::shared_ptr<Breakpoint>* breakpoint2);

extern thread_local std::optional<WinError> LastErrorValueInject;

template <typename _WindowsFunctionCall>
class FunctionInjector final {
  public:
    /**
     * @brief Sleep the current thread until the function call returns
     */
    void call(_WindowsFunctionCall& call) {
        auto& vcpu = event_.vcpu();
        auto& regs = vcpu.registers();

        // Set a breakpoint for our executable page
        std::shared_ptr<Breakpoint> bp;
        bp = guest_->domain().create_breakpoint(
            executable_page_, std::bind(dummy_callback, std::placeholders::_1, &bp));

        // Lock the thread affinity
        auto& thread = static_cast<WindowsEvent&>(event_).task().pcr().CurrentThread();
        const uint64_t desired_affinity = (1u << event_.vcpu().id());
        const auto original_affinity = thread.Affinity();
        const auto original_user_affinity = thread.UserAffinity();
        const auto original_ideal_processor = thread.IdealProcessor();
        const auto original_user_ideal_processor = thread.UserIdealProcessor();

        thread.Affinity(desired_affinity);
        thread.UserAffinity(desired_affinity);
        thread.IdealProcessor(event_.vcpu().id());
        thread.UserIdealProcessor(event_.vcpu().id());

        static_cast<DomainImpl&>(event_.domain()).start_injection(event_);

        LOG4CXX_DEBUG(func_injector_logger, "Jumping RIP to " << target_function_);

        // Set RIP to the function address
        regs.rip(target_function_.value());

        // Save the original LastErrorValue and LastStatusValue
        auto* teb = thread.Teb();
        const WinError original_winerror = teb->LastErrorValue();
        const nt::NTSTATUS original_laststatus = teb->LastStatusValue();

        // Wait for the return event
        auto new_event = event_.impl().suspend([this](const introvirt::Event& event) {
            if (event.type() == EventType::EVENT_EXCEPTION &&
                event.vcpu().registers().rip() == executable_page_.value()) {
                return WakeAction::ACCEPT;
            }
            return WakeAction::DROP;
        });

        assert(event_.vcpu().id() == new_event->vcpu().id());

        // Update the injection lasterror/laststatus values
        LastErrorValueInject.emplace(teb->LastErrorValue());
        LastStatusValueInject.emplace(teb->LastStatusValue());

        // Restore the original values
        teb->LastErrorValue(original_winerror);
        teb->LastStatusValue(original_laststatus);

        // Restore the thread affinity
        thread.Affinity(original_affinity);
        thread.UserAffinity(original_user_affinity);
        thread.IdealProcessor(original_ideal_processor);
        thread.UserIdealProcessor(original_user_ideal_processor);

        if (original_cs_) {
            LOG4CXX_DEBUG(func_injector_logger, "Restoring original CS");
            regs.cs(*original_cs_);
        }

        static_cast<DomainImpl&>(event_.domain()).end_injection(event_);

        call.handle_return(*new_event);

        LOG4CXX_DEBUG(func_injector_logger, "Function call completed");
    }

    FunctionInjector(Event& event) : guard_(event.vcpu()), event_(event) {
        assert(event.os_type() == OS::Windows);

        guest_ = &(static_cast<WindowsEvent&>(event).guest());

        switch (event.type()) {
        case EventType::EVENT_MEM_ACCESS:
            LOG4CXX_WARN(func_injector_logger,
                         "Function injection on nested memory access not supported")
            throw InvalidMethodException();
        default:
            break;
        }

        // Look for the target library
        bool target_is_x64;
        if (unlikely(!find_target_function(target_is_x64))) {
            // TODO: Throw a better exception
            throw InvalidMethodException();
        }

        if (event_.vcpu().long_mode()) {
            allocate_guest_memory<uint64_t>();

            // Check if we're in a Wow64 process
            const bool wow64 = static_cast<WindowsEvent&>(event)
                                   .task()
                                   .pcr()
                                   .CurrentThread()
                                   .Process()
                                   .isWow64Process();

            if (wow64) {
                auto& regs = event.vcpu().registers();
                LOG4CXX_DEBUG(func_injector_logger, "Beginning WoW64 function call");

                // auto cs = regs.cs();
                if (target_is_x64) {
                    // We're jumping to a 64-bit function ...
                    if (regs.cs().long_mode() == false) {
                        LOG4CXX_ERROR(func_injector_logger,
                                      "Function transition from 64 to 32 bit mode not implemented");
#if 0
                        // ... but we're in a 32-bit segment. Enter long mode!
                        original_cs_.emplace(cs);
                        LOG4CXX_WARN(func_injector_logger, "Forcing long mode");
                        x86::SegmentSelector sel(0x33);
                        x86::Segment seg(sel, 0x0, 0x0, 0xFB, true, 3, false, true, true, false,
                                         false);
                        regs.cs(seg);
#endif
                    }
                    begin_function_call<uint64_t>();
                } else {
                    // We're jumping to a 32-bit function ...
                    if (regs.cs().long_mode() == true) {
                        LOG4CXX_ERROR(func_injector_logger,
                                      "Function transition from 64 to 32 bit mode not implemented");
#if 0
                        // ... but we're currently in a 64-bit segment. Exit long mode!
                        original_cs_.emplace(cs);
                        LOG4CXX_WARN(func_injector_logger, "Forcing long mode exit");
                        x86::SegmentSelector sel(0x23);
                        x86::Segment seg(sel, 0x0, 0xfffff, 0xFB, true, 3, true, true, false, true,
                                         false);
                        regs.cs(seg);

                        std::optional<pe::Pe> pe;
                        if (!find_pe("wow64cpu", pe)) {
                            LOG4CXX_WARN(func_injector_logger, "Failed to find wow64cpu");
                            throw InvalidMethodException(); // TODO : Proper exception
                        }
                        const auto& pdb = pe->pdb();
                        const auto* symbol = pdb.name_to_symbol("TurboThunkDispatch");
                        if (symbol == nullptr) {
                            LOG4CXX_WARN(func_injector_logger, "Failed to find TurboThunkDispatch");
                            throw InvalidMethodException(); // TODO : Proper exception
                        }

                        auto pTurboThunkDispatch = pe->address() + symbol->image_offset();
                        LOG4CXX_WARN(func_injector_logger,
                                     "Loading r15 with TurboThunkDispatch=" << pTurboThunkDispatch);
                        regs.r15(pTurboThunkDispatch.value());
#endif
                    }
                    begin_function_call<uint32_t>();
                }
            } else {
                LOG4CXX_DEBUG(func_injector_logger, "Beginning 64 bit function call");
                begin_function_call<uint64_t>();
            }
        } else {
            allocate_guest_memory<uint32_t>();
            LOG4CXX_DEBUG(func_injector_logger, "Beginning 32 bit function call");
            begin_function_call<uint32_t>();
        }
    }

    ~FunctionInjector() {
        // Get us back to the original state
        // We force this early so that our system call injections below succeed.
        guard_.reset();

        try {
            if (event_.vcpu().long_mode())
                free_guest_memory<uint64_t>();
            else
                free_guest_memory<uint32_t>();
        } catch (TraceableException& ex) {
            LOG4CXX_WARN(func_injector_logger, "FunctionInjector cleanup failed: " << ex.what());
        }
    }

  private:
    bool find_pe(std::string name, std::unique_ptr<pe::PE>& pe) const {
        std::string library_name;
        library_name += '\\';
        boost::to_lower(name);
        library_name += name;
        library_name += ".dll";

        // Get the current process
        auto& proc = static_cast<WindowsEvent&>(event_).task().pcr().CurrentThread().Process();

        // Find where the library is mapped in by walking the VaD
        GuestVirtualAddress library_address;

        auto mmvad = proc.VadRoot();
        for (const auto& entry : mmvad->VadTreeInOrder()) {
            if (entry->FileObject()) {
                try {
                    std::string file_name(boost::to_lower_copy(entry->FileObject()->FileName()));
                    if (boost::ends_with(file_name, library_name)) {
                        library_address = entry->StartingAddress();
                        break;
                    }
                } catch (VirtualAddressNotPresentException& ex) {
                    LOG4CXX_DEBUG(func_injector_logger,
                                  "Failed to read file object at " << ex.virtual_address());
                }
            }
        }

        if (!library_address) {
            // TODO: Get a better exception here
            LOG4CXX_WARN(func_injector_logger, "Failed to find library named " << library_name);
            return false;
        }

        pe = pe::PE::make_unique(library_address);
        return true;
    }

    bool find_target_function(bool& x64) {
        // Find the address of the function we want to call
        std::unique_ptr<pe::PE> pe;
        if (!find_pe(std::string(_WindowsFunctionCall::LibraryName), pe)) {
            return false;
        }
        const auto& export_map = pe->export_directory()->NameToExportMap();

        // TODO: C++20 should let us pass the string_view directly
        auto iter = export_map.find(std::string(_WindowsFunctionCall::FunctionName));
        if (iter != export_map.end()) {
            target_function_ = iter->second.address;
        } else {
            LOG4CXX_WARN(func_injector_logger, "Failed to find '"
                                                   << _WindowsFunctionCall::FunctionName << "' in "
                                                   << _WindowsFunctionCall::LibraryName);
            return false;
        }

        // Check if the target library is x64
        x64 = (pe->file_header().Machine() == pe::MACHINE_TYPE_X64);

        // We have a result
        return true;
    }

    template <typename PtrType>
    void begin_function_call() {
        // Move the stack pointer down based on the number of arguments we have
        auto& vcpu = event_.vcpu();
        auto& regs = vcpu.registers();

        regs.rsp(regs.rsp() - ((_WindowsFunctionCall::ArgumentCount + 2) * sizeof(PtrType)));

        // Make sure we're aligned
        regs.rsp(regs.rsp() & ~0x7LL);

        // Set the return address
        *guest_ptr<PtrType>(GuestVirtualAddress(regs.rsp())) = executable_page_.value();
    }

    template <typename PtrType>
    void allocate_guest_memory() {
        auto* guest = static_cast<WindowsGuestImpl<PtrType>*>(guest_);

        // Allocate executable and data memory
        size_t RegionSize = x86::PageDirectory::PAGE_SIZE;
        data_page_ = guest->allocate(RegionSize);
        LOG4CXX_DEBUG(func_injector_logger,
                      "Allocated function injection data page : " << data_page_);

        executable_page_ = guest->allocate(RegionSize, true);
        LOG4CXX_DEBUG(func_injector_logger,
                      "Allocated function injection executable page : " << executable_page_);
    }

    template <typename PtrType>
    void free_guest_memory() {
        auto* guest = static_cast<WindowsGuestImpl<PtrType>*>(guest_);
        const size_t RegionSize = x86::PageDirectory::PAGE_SIZE;

        guest->guest_free(executable_page_, RegionSize);
        LOG4CXX_DEBUG(func_injector_logger,
                      "Freed function injection executable page : " << executable_page_);

        guest->guest_free(data_page_, RegionSize);
        LOG4CXX_DEBUG(func_injector_logger, "Freed function injection data page : " << data_page_);
    }

  private:
    std::optional<introvirt::inject::RegisterGuard> guard_;
    Event& event_;
    WindowsGuest* guest_;
    GuestVirtualAddress executable_page_;
    GuestVirtualAddress data_page_;
    GuestVirtualAddress target_function_;
    std::optional<x86::Segment> original_cs_;
};

} // namespace inject
} // namespace windows
} // namespace introvirt