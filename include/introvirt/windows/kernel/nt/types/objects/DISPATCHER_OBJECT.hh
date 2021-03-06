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

#include "OBJECT.hh"

#include <introvirt/windows/kernel/nt/fwd.hh>

namespace introvirt {
namespace windows {
namespace nt {

class DISPATCHER_OBJECT : public OBJECT {
  public:
    virtual DISPATCHER_HEADER& DispatcherHeader() = 0;
    virtual const DISPATCHER_HEADER& DispatcherHeader() const = 0;

    virtual ~DISPATCHER_OBJECT() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
