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

#include "SYSTEM_INFORMATION.hh"

#include <introvirt/windows/util/WindowsTime.hh>

namespace introvirt {
namespace windows {
namespace nt {

class SYSTEM_TIMEOFDAY_INFORMATION : public SYSTEM_INFORMATION {
  public:
    virtual WindowsTime BootTime() const = 0;
    virtual void BootTime(WindowsTime BootTime) = 0;

    virtual WindowsTime CurrentTime() const = 0;
    virtual void CurrentTime(WindowsTime CurrentTime) = 0;

    virtual int64_t TimeZoneBias() const = 0;
    virtual void TimeZoneBias(int64_t TimeZoneBias) = 0;

    virtual uint32_t TimeZoneId() const = 0;
    virtual void TimeZoneId(uint32_t TimeZoneId) = 0;

    virtual uint32_t Reserved() const = 0;
    virtual void Reserved(uint32_t Reserved) = 0;

    virtual uint64_t BootTimeBias() const = 0;
    virtual void BootTimeBias(uint64_t BootTimeBias) = 0;

    virtual uint64_t SleepTimeBias() const = 0;
    virtual void SleepTimeBias(uint64_t SleepTimeBias) = 0;
};

} // namespace nt
} // namespace windows
} // namespace introvirt
