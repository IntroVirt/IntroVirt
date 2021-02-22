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

namespace introvirt {
namespace windows {
namespace crypt32 {

/**
 * @brief Handler for crypt32!CryptDecryptMessage
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecryptmessage
 */
class CryptDecryptMessage : public WindowsFunctionCall {
  public:
    /* Input arguments */

    GuestVirtualAddress pDecryptPara() const;
    void pDecryptPara(const GuestVirtualAddress& gva);

    GuestVirtualAddress pbEncryptedBlob() const;
    void pbEncryptedBlob(const GuestVirtualAddress& gva);

    uint32_t cbEncryptedBlob() const;
    void cbEncryptedBlob(uint32_t cbEncryptedBlob);

    GuestVirtualAddress pbDecrypted() const;
    void pbDecrypted(const GuestVirtualAddress& gva);

    GuestVirtualAddress ppXchgCert() const;
    void ppXchgCert(const GuestVirtualAddress& gva);

    GuestVirtualAddress pcbDecrypted() const;
    void pcbDecrypted(const GuestVirtualAddress& gva);

    /* Helpers */
    const CRYPT_DECRYPT_MESSAGE_PARA* DecryptPara() const;
    CRYPT_DECRYPT_MESSAGE_PARA* DecryptPara();

    uint32_t cbDecrypted() const;
    void cbDecrypted(uint32_t cbDecrypted);

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptDecryptMessage(Event& event);
    ~CryptDecryptMessage() override;

    static constexpr int ArgumentCount = 6;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptDecryptMessage";

  private:
    GuestVirtualAddress pDecryptPara_;
    GuestVirtualAddress pbEncryptedBlob_;
    uint32_t cbEncryptedBlob_;
    GuestVirtualAddress pbDecrypted_;
    GuestVirtualAddress pcbDecrypted_;
    GuestVirtualAddress ppXchgCert_;

    mutable std::unique_ptr<CRYPT_DECRYPT_MESSAGE_PARA> DecryptPara_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt