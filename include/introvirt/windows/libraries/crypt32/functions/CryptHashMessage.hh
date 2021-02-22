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

#include <introvirt/windows/libraries/crypt32/types/CRYPT_HASH_MESSAGE_PARA.hh>

#include <introvirt/windows/libraries/WindowsFunctionCall.hh>
#include <introvirt/windows/libraries/crypt32/types/types.hh>

namespace introvirt {
namespace windows {
namespace crypt32 {

/**
 * @brief Handler for crypt32!CryptHashMessage
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashmessage
 */
class CryptHashMessage : public WindowsFunctionCall {
  public:
    /* Input arguments */
    GuestVirtualAddress pHashPara() const;
    void pHashPara(const GuestVirtualAddress& gva);

    bool fDetachedHash() const;
    void fDetachedHash(bool fDetachedHash);

    uint32_t cToBeHashed() const;
    void cToBeHashed(uint32_t cToBeHashed);

    GuestVirtualAddress prgpbToBeHashed() const;
    void prgpbToBeHashed(const GuestVirtualAddress& gva);

    GuestVirtualAddress prgcbToBeHashed() const;
    void prgcbToBeHashed(const GuestVirtualAddress& gva);

    GuestVirtualAddress pbHashedBlob() const;
    void pbHashedBlob(const GuestVirtualAddress& gva);

    GuestVirtualAddress pcbHashedBlob() const;
    void pcbHashedBlob(const GuestVirtualAddress& gva);

    GuestVirtualAddress pbComputedHash() const;
    void pbComputedHash(const GuestVirtualAddress& gva);

    GuestVirtualAddress pcbComputedHash() const;
    void pcbComputedHash(const GuestVirtualAddress& gva);

    /* Helpers */
    const CRYPT_HASH_MESSAGE_PARA* HashPara() const;
    CRYPT_HASH_MESSAGE_PARA* HashPara();

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptHashMessage(Event& event);
    ~CryptHashMessage() override;

    static constexpr int ArgumentCount = 9;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptHashMessage";

  private:
    GuestVirtualAddress pHashPara_;
    bool fDetachedHash_;
    uint32_t cToBeHashed_;
    GuestVirtualAddress prgpbToBeHashed_;
    GuestVirtualAddress prgcbToBeHashed_;
    GuestVirtualAddress pbHashedBlob_;
    GuestVirtualAddress pcbHashedBlob_;
    GuestVirtualAddress pbComputedHash_;
    GuestVirtualAddress pcbComputedHash_;

    mutable std::unique_ptr<CRYPT_HASH_MESSAGE_PARA> HashPara_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt