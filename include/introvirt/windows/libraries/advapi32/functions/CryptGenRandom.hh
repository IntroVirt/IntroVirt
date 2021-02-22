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
#include <introvirt/core/memory/GuestVirtualAddress.hh>
#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/libraries/advapi32/types/types.hh>

#include <cstdint>
#include <memory>

namespace introvirt {

namespace windows {
namespace advapi32 {

/**
 * @brief Handler for advapi32!CryptGenRandom
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenrandom
 */
class CryptGenRandom final : public WindowsFunctionCall {
  public:
    /* Input Arguments */
    HCRYPTPROV hProv() const;
    void hProv(HCRYPTPROV value);

    uint32_t dwLen() const;
    void dwLen(uint32_t value);

    GuestVirtualAddress pbBuffer() const;
    void pbBuffer(const GuestVirtualAddress& value);

    /* Return value */

    bool result() const;
    void result(bool value);

    /* Overrides */
    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptGenRandom(Event& event);
    ~CryptGenRandom() override;

    static constexpr int ArgumentCount = 3;
    inline static const std::string LibraryName = "advapi32";
    inline static const std::string FunctionName = "CryptGenRandom";

  private:
    HCRYPTPROV hProv_;
    uint32_t dwLen_;
    GuestVirtualAddress pbBuffer_;
};

} // namespace advapi32
} // namespace windows
} // namespace introvirt
