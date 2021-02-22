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
#include <introvirt/windows/libraries/crypt32/const/CryptStructType.hh>
#include <introvirt/windows/libraries/crypt32/types/types.hh>

namespace introvirt {
namespace windows {
namespace crypt32 {

/**
 * @brief Handler for crypt32!CryptDecodeObjectEx
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecodeobjectex
 */
class CryptDecodeObjectEx : public WindowsFunctionCall {
  public:
    /* Input arguments */
    uint32_t dwCertEncodingType() const;
    void dwCertEncodingType(uint32_t dwCertEncodingType);

    /**
     * lpszStructType is dual purposed, see the docs.
     *
     * This getter only returns a value if the high-order word is zero.
     * Otherwise check lpszStructType().
     */
    CryptStructType StructType() const;
    void StructType(CryptStructType type);

    /**
     * This getter only returns a value if the high-order word is non-zero.
     * Otherwise check StructType().
     */
    GuestVirtualAddress lpszStructType() const;
    void lpszStructType(const GuestVirtualAddress& gva);

    GuestVirtualAddress pbEncoded() const;
    void pbEncoded(const GuestVirtualAddress& gva);

    uint32_t cbEncoded() const;
    void cbEncoded(uint32_t cbEncoded);

    uint32_t dwFlags() const;
    void dwFlags(uint32_t dwFlags);

    GuestVirtualAddress pDecodePara() const;
    void pDecodePara(const GuestVirtualAddress& gva);

    GuestVirtualAddress pvStructInfo() const;
    void pvStructInfo(const GuestVirtualAddress& gva);

    GuestVirtualAddress pcbStructInfo() const;
    void pcbStructInfo(const GuestVirtualAddress& gva);

    /* Helpers */
    std::string szStructType() const;

    const CRYPT_DECODE_PARA* DecodePara() const;
    CRYPT_DECODE_PARA* DecodePara();

    uint32_t cbStructInfo() const;
    void cbStructInfo(uint32_t cbStructInfo);

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptDecodeObjectEx(Event& event);
    ~CryptDecodeObjectEx() override;

    static constexpr int ArgumentCount = 8;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptDecodeObjectEx";

  private:
    uint32_t dwCertEncodingType_;
    GuestVirtualAddress lpszStructType_;
    GuestVirtualAddress pbEncoded_;
    uint32_t cbEncoded_;
    uint32_t dwFlags_;
    GuestVirtualAddress pDecodePara_;
    GuestVirtualAddress pvStructInfo_;
    GuestVirtualAddress pcbStructInfo_;

    mutable std::unique_ptr<CRYPT_DECODE_PARA> DecodePara_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt