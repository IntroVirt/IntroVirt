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

#include <introvirt/core/fwd.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace nt {

class DISPATCHER_HEADER {
  public:
    enum class ObjectType {
        EventNotificationObject = 0,
        EventSynchronizationObject = 1,
        MutantObject = 2,
        ProcessObject = 3,
        QueueObject = 4,
        SemaphoreObject = 5,
        ThreadObject = 6,
        GateObject = 7,
        TimerNotificationObject = 8,
        TimerSynchronizationObject = 9,
        Spare2Object = 10,
        Spare3Object = 11,
        Spare4Object = 12,
        Spare5Object = 13,
        Spare6Object = 14,
        Spare7Object = 15,
        Spare8Object = 16,
        Spare9Object = 17,
        ApcObject = 18,
        DpcObject = 19,
        DeviceQueueObject = 20,
        EventPairObject = 21,
        InterruptObject = 22,
        ProfileObject = 23,
        ThreadedDpcObject = 24,
    };

    /**
     * @returns One of the DISPATCHER_HEADER::Type values indicating which dispatcher object this is
     */
    virtual DISPATCHER_HEADER::ObjectType Type() const = 0;

    /**
     * For a Timer, indicates if it is Absolute (that is to say, it expires at a given date and
     * time) or Relative (it expires in a relative amount of time).
     *
     * @returns True if the timer is absolute
     */
    virtual bool Absolute() const = 0;

    /**
     * @brief Get the size of the dispatcher object
     *
     * This returns the size of the object in bytes.
     * The raw field contains the size in DWORDs, but this call converts for you.
     */
    virtual uint32_t Size() const = 0;

    /**
     * For a Timer, indicates if it has been inserted
     *
     * @returns If this object is a timer, true if it has been inserted
     */
    virtual bool Inserted() const = 0;

    /**
     *  Usually 1 for Signaled and 0 for Not Signaled, but can be negative for Recursive Mutex and
     * above 1 for Semaphores.
     *
     *  @returns The signal state
     */
    virtual int32_t SignalState() const = 0;

    virtual ~DISPATCHER_HEADER() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
