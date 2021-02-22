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
#include <introvirt/windows/libraries/advapi32/types/types.hh>

namespace introvirt {
namespace windows {
namespace advapi32 {

/**
 * @brief Handler for advapi32!CryptAcquireContextW
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
 */
class CryptAcquireContextW final : public WindowsFunctionCall {
  public:
    /* Input arguments */
    GuestVirtualAddress phProv() const;
    void phProv(const GuestVirtualAddress& value);

    GuestVirtualAddress pszContainer() const;
    void pszContainer(const GuestVirtualAddress& value);

    GuestVirtualAddress pszProvider() const;
    void pszProvider(const GuestVirtualAddress& value);

    uint32_t dwProvType() const;
    void dwProvType(uint32_t value);

    uint32_t dwFlags() const;
    void dwFlags(uint32_t value);

    /* Helpers */

    /**
     * @brief Get the handle pointed at by phProv
     */
    HCRYPTPROV hProv() const;

    /**
     * @brief Set the handle pointed at by phProv
     */
    void hProv(HCRYPTPROV value);

    /**
     * @brief Get the string held by pszContainer
     */
    std::string szContainer() const;

    /**
     * @brief Get the string held by pszProvider
     */
    std::string szProvider() const;

    /* Return value */
    bool result() const;
    void result(bool value);

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptAcquireContextW(Event& event);
    ~CryptAcquireContextW() override;

    static constexpr int ArgumentCount = 5;
    inline static const std::string LibraryName = "advapi32";
    inline static const std::string FunctionName = "CryptAcquireContextW";

  private:
    GuestVirtualAddress phProv_;
    GuestVirtualAddress pszContainer_;
    GuestVirtualAddress pszProvider_;
    uint32_t dwProvType_;
    uint32_t dwFlags_;
};

} // namespace advapi32
} // namespace windows
} // namespace introvirt
