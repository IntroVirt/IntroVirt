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

#include "SYSTEM_INFORMATION_IMPL.hh"

#include <introvirt/windows/kernel/nt/syscall/types/system_information/SYSTEM_TIMEOFDAY_INFORMATION.hh>

namespace introvirt {
namespace windows {
namespace nt {

namespace structs {

struct _SYSTEM_TIMEOFDAY_INFORMATION {
    int64_t BootTime;       // Size=8 Offset=0
    int64_t CurrentTime;    // Size=8 Offset=8
    int64_t TimeZoneBias;   // Size=8 Offset=16
    uint32_t TimeZoneId;    // Size=4 Offset=24
    uint32_t Reserved;      // Size=4 Offset=28
    uint64_t BootTimeBias;  // Size=8 Offset=32
    uint64_t SleepTimeBias; // Size=8 Offset=40
};

static_assert(sizeof(_SYSTEM_TIMEOFDAY_INFORMATION) == 48);

} // namespace structs

using SYSTEM_TIMEOFDAY_INFORMATION_IMPL_BASE =
    SYSTEM_INFORMATION_IMPL<SYSTEM_TIMEOFDAY_INFORMATION, structs::_SYSTEM_TIMEOFDAY_INFORMATION>;

class SYSTEM_TIMEOFDAY_INFORMATION_IMPL final : public SYSTEM_TIMEOFDAY_INFORMATION_IMPL_BASE {
  public:
    WindowsTime BootTime() const override {
        return WindowsTime::from_windows_time(this->data_->BootTime);
    }
    void BootTime(WindowsTime BootTime) override {
        this->data_->BootTime = BootTime.windows_time();
    }

    WindowsTime CurrentTime() const override {
        return WindowsTime::from_windows_time(this->data_->CurrentTime);
    }
    void CurrentTime(WindowsTime CurrentTime) override {
        this->data_->CurrentTime = CurrentTime.windows_time();
    }

    int64_t TimeZoneBias() const override { return this->data_->TimeZoneBias; }
    void TimeZoneBias(int64_t TimeZoneBias) override { this->data_->TimeZoneBias = TimeZoneBias; }

    uint32_t TimeZoneId() const override { return this->data_->TimeZoneId; }
    void TimeZoneId(uint32_t TimeZoneId) override { this->data_->TimeZoneId = TimeZoneId; }

    uint32_t Reserved() const override { return this->data_->Reserved; }
    void Reserved(uint32_t Reserved) override { this->data_->Reserved = Reserved; }

    uint64_t BootTimeBias() const override { return this->data_->BootTimeBias; }
    void BootTimeBias(uint64_t BootTimeBias) override { this->data_->BootTimeBias = BootTimeBias; }

    uint64_t SleepTimeBias() const override { return this->data_->SleepTimeBias; }
    void SleepTimeBias(uint64_t SleepTimeBias) override {
        this->data_->SleepTimeBias = SleepTimeBias;
    }

    void write(std::ostream& os, const std::string& linePrefix = "") const override;
    Json::Value json() const override;

    SYSTEM_TIMEOFDAY_INFORMATION_IMPL(const GuestVirtualAddress& gva, uint32_t buffer_size)
        : SYSTEM_TIMEOFDAY_INFORMATION_IMPL_BASE(
              SYSTEM_INFORMATION_CLASS::SystemTimeOfDayInformation, gva, buffer_size) {}
};

} // namespace nt
} // namespace windows
} // namespace introvirt