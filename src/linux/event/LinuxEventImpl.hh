/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include "core/event/EventImpl.hh"
#include "linux/event/LinuxEventTaskInformationImpl.hh"
#include "linux/event/LinuxSystemCallEventImpl.hh"

#include <introvirt/core/syscall/SystemCall.hh> // complete type for EventImplTpl::json()
#include <introvirt/linux/LinuxGuest.hh>
#include <introvirt/linux/event/LinuxEvent.hh>

#include <memory>
#include <optional>

namespace introvirt {

class HypervisorEvent;

namespace linux_guest {

/**
 * @brief Concrete Linux event (mirrors windows::WindowsEventImpl).
 *
 * EventImplTpl<LinuxEvent> provides everything generic (vcpu/domain/type,
 * cr/msr/exception/mem_access, json, the suspend/step machinery). This class
 * adds the Linux-specific pieces: os_type, task(), guest(), thread_id(), and
 * syscall() (a LinuxSystemCallEventImpl for fast-syscall events — name +
 * number; argument decoding is later Phase 3 work).
 */
class LinuxEventImpl final : public EventImplTpl<LinuxEvent> {
  public:
    OS os_type() const override { return OS::Linux; }

    LinuxEventTaskInformation& task() override { return task_info_; }
    const LinuxEventTaskInformation& task() const override { return task_info_; }

    LinuxGuest& guest() override { return guest_; }
    const LinuxGuest& guest() const override { return guest_; }

    SystemCallEvent& syscall() override;
    const SystemCallEvent& syscall() const override;

    uint64_t thread_id() const override { return task_info_.task_struct_address(); }

    LinuxEventImpl(LinuxGuest& guest, std::unique_ptr<HypervisorEvent>&& hypervisor_event);

  private:
    LinuxGuest& guest_;
    LinuxEventTaskInformationImpl task_info_;
    std::optional<LinuxSystemCallEventImpl> syscall_;
};

} // namespace linux_guest
} // namespace introvirt
