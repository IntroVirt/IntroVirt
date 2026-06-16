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

#include "core/syscall/SystemCallImpl.hh"

#include <introvirt/core/syscall/SystemCall.hh>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace introvirt {

class Event;
class HypervisorEvent;

namespace linux_guest {

/**
 * @brief A generic Linux syscall handler (the Linux analogue of the generated
 * WindowsSystemCall classes).
 *
 * Captures the x86_64 syscall ABI at entry — number in RAX, args in
 * RDI/RSI/RDX/R10/R8/R9 — decodes pathname strings + common flag/enum
 * arguments (open flags, mmap/mprotect prot, socket domain/type), and
 * correlates the return value via ``handle_return_event`` (the framework
 * carries this handler from the entry event to the return event; see
 * DomainImpl::process). ``will_return()`` is therefore true.
 */
class LinuxSystemCall final : public SystemCallImpl<SystemCall> {
  public:
    const std::string& name() const override { return name_; }
    bool supported() const override { return true; }
    bool will_return() const override { return true; }
    void handle_return_event(Event& event) override;

    void write(std::ostream& os) const override;
    Json::Value json() const override;

    explicit LinuxSystemCall(HypervisorEvent& event);

  private:
    uint32_t number_ = 0;
    std::string name_;
    uint64_t args_[6] = {0, 0, 0, 0, 0, 0};
    std::string path_;     // decoded pathname argument, if any
    bool has_path_ = false;
    // Decoded flag/enum arguments, in order (label -> human string).
    std::vector<std::pair<std::string, std::string>> decoded_;
    bool has_return_ = false;
    int64_t return_value_ = 0;
};

} // namespace linux_guest
} // namespace introvirt
