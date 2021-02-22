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

#include "PROCESS_INFORMATION_IMPL.hh"

#include <introvirt/windows/exception/InvalidStructureException.hh>
#include <introvirt/windows/kernel/nt/syscall/types/process_information/PROCESS_PRIORITY_CLASS_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _PROCESS_PRIORITY_CLASS_INFORMATION {
    uint8_t Foreground;
    uint8_t PriorityClass;
};

static_assert(sizeof(_PROCESS_PRIORITY_CLASS_INFORMATION) == 0x2);

} // namespace structs

using PROCESS_PRIORITY_CLASS_INFORMATION_IMPL_BASE =
    PROCESS_INFORMATION_IMPL<PROCESS_PRIORITY_CLASS_INFORMATION,
                             structs::_PROCESS_PRIORITY_CLASS_INFORMATION>;

class PROCESS_PRIORITY_CLASS_INFORMATION_IMPL final
    : public PROCESS_PRIORITY_CLASS_INFORMATION_IMPL_BASE {
  public:
    bool Foreground() const override { return this->data_->Foreground; }
    void Foreground(bool Foreground) override { this->data_->Foreground = Foreground; }

    // Windows uses this weird maping rather than just using the default values
    static constexpr int PROCESS_PRIORITY_CLASS_UNKNOWN = 0;
    static constexpr int PROCESS_PRIORITY_CLASS_IDLE = 1;
    static constexpr int PROCESS_PRIORITY_CLASS_NORMAL = 2;
    static constexpr int PROCESS_PRIORITY_CLASS_HIGH = 3;
    static constexpr int PROCESS_PRIORITY_CLASS_REALTIME = 4;
    static constexpr int PROCESS_PRIORITY_CLASS_BELOW_NORMAL = 5;
    static constexpr int PROCESS_PRIORITY_CLASS_ABOVE_NORMAL = 6;

    PRIORITY_CLASS PriorityClass() const override {

        switch (this->data_->PriorityClass) {
        case PROCESS_PRIORITY_CLASS_IDLE:
            return PRIORITY_CLASS::IDLE_PRIORITY_CLASS;
        case PROCESS_PRIORITY_CLASS_NORMAL:
            return PRIORITY_CLASS::NORMAL_PRIORITY_CLASS;
        case PROCESS_PRIORITY_CLASS_HIGH:
            return PRIORITY_CLASS::HIGH_PRIORITY_CLASS;
        case PROCESS_PRIORITY_CLASS_REALTIME:
            return PRIORITY_CLASS::REALTIME_PRIORITY_CLASS;
        case PROCESS_PRIORITY_CLASS_BELOW_NORMAL:
            return PRIORITY_CLASS::BELOW_NORMAL_PRIORITY_CLASS;
        case PROCESS_PRIORITY_CLASS_ABOVE_NORMAL:
            return PRIORITY_CLASS::ABOVE_NORMAL_PRIORITY_CLASS;
        }

        return PRIORITY_CLASS::UNKNOWN_PRIORITY_CLASS;
    }

    void PriorityClass(PRIORITY_CLASS PriorityClass) override {
        switch (PriorityClass) {
        case PRIORITY_CLASS::IDLE_PRIORITY_CLASS:
            this->data_->PriorityClass = PROCESS_PRIORITY_CLASS_IDLE;
            break;
        case PRIORITY_CLASS::NORMAL_PRIORITY_CLASS:
            this->data_->PriorityClass = PROCESS_PRIORITY_CLASS_NORMAL;
            break;
        case PRIORITY_CLASS::HIGH_PRIORITY_CLASS:
            this->data_->PriorityClass = PROCESS_PRIORITY_CLASS_HIGH;
            break;
        case PRIORITY_CLASS::REALTIME_PRIORITY_CLASS:
            this->data_->PriorityClass = PROCESS_PRIORITY_CLASS_REALTIME;
            break;
        case PRIORITY_CLASS::BELOW_NORMAL_PRIORITY_CLASS:
            this->data_->PriorityClass = PROCESS_PRIORITY_CLASS_BELOW_NORMAL;
            break;
        case PRIORITY_CLASS::ABOVE_NORMAL_PRIORITY_CLASS:
            this->data_->PriorityClass = PROCESS_PRIORITY_CLASS_ABOVE_NORMAL;
            break;
        case PRIORITY_CLASS::UNKNOWN_PRIORITY_CLASS:
        default:
            throw InvalidStructureException("Invalid priority class value");
            break;
        }
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    PROCESS_PRIORITY_CLASS_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : PROCESS_PRIORITY_CLASS_INFORMATION_IMPL_BASE(
              PROCESS_INFORMATION_CLASS::ProcessPriorityClass, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt