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

#include "WindowsSystemCallEventImpl.hh"
#include "core/event/EventImpl.hh"
#include "windows/kernel/nt/types/KPCR_IMPL.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/event/WindowsEvent.hh>
#include <introvirt/windows/event/WindowsEventTaskInformation.hh>
#include <introvirt/windows/fwd.hh>
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <log4cxx/logger.h>

#include <memory>
#include <optional>

namespace introvirt {
namespace windows {

static log4cxx::LoggerPtr
    win_event_impl_logger(log4cxx::Logger::getLogger("introvirt.win.event.WindowsEventImpl"));

class WindowsEventImpl final : public EventImplTpl<WindowsEvent> {
  public:
    OS os_type() const override { return OS::Windows; }

    WindowsEventTaskInformation& task() override { return proc_info_; }
    const WindowsEventTaskInformation& task() const override { return proc_info_; }

    WindowsGuest& guest() override { return guest_; }
    const WindowsGuest& guest() const override { return guest_; }

    uint64_t page_directory() const override {
        uint64_t KernelDirectoryTableBase = task().pcr().KernelDirectoryTableBase();
        if (KernelDirectoryTableBase) {
            // Page table isolation is enabled
            return KernelDirectoryTableBase;
        }
        return vcpu().registers().cr3();
    }

    WindowsSystemCallEvent& syscall() override {
        if (unlikely(!syscall_))
            throw InvalidMethodException();
        return *syscall_;
    }
    const WindowsSystemCallEvent& syscall() const override {
        if (unlikely(!syscall_))
            throw InvalidMethodException();
        return *syscall_;
    }

    uint64_t thread_id() const override { return task().pcr().CurrentThread().address().value(); }

    WindowsEventImpl(WindowsGuest& guest, std::unique_ptr<HypervisorEvent>&& hypervisor_event)
        : EventImplTpl<WindowsEvent>(std::move(hypervisor_event)), guest_(guest),
          proc_info_(guest.kernel().kpcr(vcpu())) {

        switch (type()) {
        case EventType::EVENT_FAST_SYSCALL:
        case EventType::EVENT_FAST_SYSCALL_RET:
            syscall_.emplace(*this, *hypervisor_event_);
            break;
        default:
            break;
        }

        LOG4CXX_TRACE(win_event_impl_logger, "Created WindowsEvent for VCPU "
                                                 << hypervisor_event_->vcpu().id() << " event "
                                                 << hypervisor_event_->id() << " ["
                                                 << proc_info_.pid() << ':' << proc_info_.tid()
                                                 << "]: " << hypervisor_event_->type() << " "
                                                 << (syscall_ ? (syscall_->name()) : ""));
    }

  protected:
    WindowsGuest& guest_;
    WindowsEventTaskInformation proc_info_;
    std::optional<WindowsSystemCallEventImpl> syscall_;
    uint64_t page_directory_;
};

} // namespace windows
} // namespace introvirt