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
 * @brief Handler for crypt32!CryptProtectData
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
 */
class CryptProtectData final : public WindowsFunctionCall {
  public:
    /* Input arguments */
    GuestVirtualAddress pDataIn() const;
    void pDataIn(const GuestVirtualAddress& value);

    GuestVirtualAddress pszDataDescr() const;
    void pszDataDescr(const GuestVirtualAddress& value);

    GuestVirtualAddress pOptionalEntropy() const;
    void pOptionalEntropy(const GuestVirtualAddress& value);

    GuestVirtualAddress pvReserved() const;
    void pvReserved(const GuestVirtualAddress& value);

    GuestVirtualAddress pPromptStruct() const;
    void pPromptStruct(const GuestVirtualAddress& value);

    /*
     * See CRYPTPROTECT_FLAG for valid flags
     */
    uint32_t dwFlags() const;
    void dwFlags(uint32_t value);

    GuestVirtualAddress pDataOut() const;
    void pDataOut(const GuestVirtualAddress& value);

    /* Helpers */
    const CRYPTOAPI_BLOB* DataIn() const;
    CRYPTOAPI_BLOB* DataIn();

    std::string DataDescr() const;

    const CRYPTOAPI_BLOB* OptionalEntropy() const;
    CRYPTOAPI_BLOB* OptionalEntropy();

    const CRYPTPROTECT_PROMPTSTRUCT* PromptStruct() const;
    CRYPTPROTECT_PROMPTSTRUCT* PromptStruct();

    const CRYPTOAPI_BLOB* DataOut() const;
    CRYPTOAPI_BLOB* DataOut();

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptProtectData(Event& event);
    ~CryptProtectData() override;

    static constexpr int ArgumentCount = 7;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptProtectData";

  private:
    GuestVirtualAddress pDataIn_;
    GuestVirtualAddress pszDataDescr_;
    GuestVirtualAddress pOptionalEntropy_;
    GuestVirtualAddress pvReserved_;
    GuestVirtualAddress pPromptStruct_;
    uint32_t dwFlags_;
    GuestVirtualAddress pDataOut_;

    mutable std::unique_ptr<CRYPTOAPI_BLOB> DataIn_;
    mutable std::unique_ptr<CRYPTOAPI_BLOB> OptionalEntropy_;
    mutable std::unique_ptr<CRYPTPROTECT_PROMPTSTRUCT> PromptStruct_;
    mutable std::unique_ptr<CRYPTOAPI_BLOB> DataOut_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt
