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

#include "THREAD_INFORMATION.hh"

namespace introvirt {
namespace windows {
namespace nt {

class THREAD_TIMES_INFORMATION : public THREAD_INFORMATION {
  public:
    virtual uint64_t CreationTime() const = 0;
    virtual void CreationTime(uint64_t CreationTime) = 0;

    virtual uint64_t ExitTime() const = 0;
    virtual void ExitTime(uint64_t ExitTime) = 0;

    virtual uint64_t KernelTime() const = 0;
    virtual void KernelTime(uint64_t KernelTime) = 0;

    virtual uint64_t UserTime() const = 0;
    virtual void UserTime(uint64_t UserTime) = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
