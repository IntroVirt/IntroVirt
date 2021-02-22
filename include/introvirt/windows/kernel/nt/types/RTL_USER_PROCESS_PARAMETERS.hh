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

#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/kernel/nt/fwd.hh>

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

class RTL_USER_PROCESS_PARAMETERS {
  public:
    virtual const std::string& CommandLine() const = 0;
    virtual const std::string& ImagePathName() const = 0;
    virtual const std::string& WindowTitle() const = 0;
    virtual const std::map<std::string, std::string>& Environment() const = 0;

    virtual GuestVirtualAddress address() const = 0;
    virtual void write(std::ostream& os, const std::string& linePrefix = "") const = 0;
    virtual Json::Value json() const = 0;

    static std::unique_ptr<RTL_USER_PROCESS_PARAMETERS> make_unique(const NtKernel& kernel,
                                                                    const GuestVirtualAddress& gva);

    virtual ~RTL_USER_PROCESS_PARAMETERS() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
