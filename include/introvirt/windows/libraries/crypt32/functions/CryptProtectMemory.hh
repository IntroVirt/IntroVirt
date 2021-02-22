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

#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/libraries/crypt32/types/types.hh>

#include <memory>
#include <string>

namespace introvirt {
namespace windows {
namespace crypt32 {

/**
 * @brief Handler for crypt32!CryptProtectMemory
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory
 */
class CryptProtectMemory : public WindowsFunctionCall {
  public:
    /* Input arguments */
    GuestVirtualAddress pDataIn() const;
    void pDataIn(const GuestVirtualAddress& value);

    uint32_t cbDataIn() const;
    void cbDataIn(uint32_t value);

    uint32_t dwFlags() const;
    void dwFlags(uint32_t value);

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptProtectMemory(Event& event);
    ~CryptProtectMemory() override;

    static constexpr int ArgumentCount = 3;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptProtectMemory";

  private:
    GuestVirtualAddress pDataIn_;
    uint32_t cbDataIn_;
    uint32_t dwFlags_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt
