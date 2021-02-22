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

#include <string_view>

namespace introvirt {
namespace windows {
namespace advapi32 {

/**
 * @brief Handler for advapi32!CryptExportKey
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey
 */
class CryptExportKey final : public WindowsFunctionCall {
  public:
    /* Input arguments */
    HCRYPTKEY hKey() const;
    void hKey(HCRYPTKEY value);

    HCRYPTKEY hExpKey() const;
    void hExpKey(HCRYPTKEY value);

    BLOB_TYPE dwBlobType() const;
    void dwBlobType(BLOB_TYPE value);

    uint32_t dwFlags() const;
    void dwFlags(uint32_t value);

    GuestVirtualAddress pbData() const;
    void pbData(const GuestVirtualAddress& value);

    GuestVirtualAddress pdwDataLen() const;
    void pdwDataLen(const GuestVirtualAddress& value);

    /* Return value */
    bool result() const;
    void result(bool value);

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    static bool inject(HCRYPTKEY hKey, HCRYPTKEY hExpKey, BLOB_TYPE dwBlobType, uint32_t dwFlags,
                       const GuestVirtualAddress& pbData, const GuestVirtualAddress& pdwDataLen);

    CryptExportKey(Event& event);
    ~CryptExportKey() override;

    static constexpr int ArgumentCount = 6;
    inline static const std::string LibraryName = "advapi32";
    inline static const std::string FunctionName = "CryptExportKey";

  private:
    CryptExportKey(Event& event, HCRYPTKEY hKey, HCRYPTKEY hExpKey, BLOB_TYPE dwBlobType,
                   uint32_t dwFlags, const GuestVirtualAddress& pbData,
                   const GuestVirtualAddress& pdwDataLen);

    HCRYPTKEY hKey_;
    HCRYPTKEY hExpKey_;
    BLOB_TYPE dwBlobType_;
    uint32_t dwFlags_;
    GuestVirtualAddress pbData_;
    GuestVirtualAddress pdwDataLen_;
};

} // namespace advapi32
} // namespace windows

} // namespace introvirt