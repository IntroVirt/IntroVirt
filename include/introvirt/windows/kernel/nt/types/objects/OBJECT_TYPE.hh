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
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Class for the Windows NT OBJECT_TYPE structure
 */
class OBJECT_TYPE : public OBJECT {
  public:
    virtual const std::string& Name() const = 0;
    virtual uint32_t TotalNumberOfObjects() const = 0;
    virtual uint32_t TotalNumberOfHandles() const = 0;
    virtual uint32_t HighWaterNumberOfObjects() const = 0;
    virtual uint32_t HighWaterNumberOfHandles() const = 0;
    virtual uint32_t Key() const = 0;
    virtual uint8_t Index() const = 0;

    static std::shared_ptr<OBJECT_TYPE> make_shared(const NtKernel& kernel,
                                                    const GuestVirtualAddress& gva);

    static std::shared_ptr<OBJECT_TYPE> make_shared(const NtKernel& kernel,
                                                    std::unique_ptr<OBJECT_HEADER>&& object_header);

    virtual ~OBJECT_TYPE() = default;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
