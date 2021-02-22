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
 * @brief Handler for crypt32!CryptEncryptMessage
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencryptmessage
 */
class CryptEncryptMessage : public WindowsFunctionCall {
  public:
    /* Input arguments */

    GuestVirtualAddress pEncryptPara() const;
    void pEncryptPara(const GuestVirtualAddress& gva);

    uint32_t cRecipientCert() const;
    void cRecipientCert(uint32_t cRecipientCert);

    GuestVirtualAddress prgpRecipientCert() const;
    void prgpRecipientCert(const GuestVirtualAddress& gva);

    GuestVirtualAddress pbToBeEncrypted() const;
    void pbToBeEncrypted(const GuestVirtualAddress& gva);

    uint32_t cbToBeEncrypted() const;
    void cbToBeEncrypted(uint32_t cbToBeEncrypted);

    GuestVirtualAddress pbEncryptedBlob() const;
    void pbEncryptedBlob(const GuestVirtualAddress& gva);

    GuestVirtualAddress pcbEncryptedBlob() const;
    void pcbEncryptedBlob(const GuestVirtualAddress& gva);

    /* Helpers */
    const CRYPT_DECRYPT_MESSAGE_PARA* EncryptPara() const;
    CRYPT_DECRYPT_MESSAGE_PARA* EncryptPara();

    uint32_t cbEncryptedBlob() const;
    void cbEncryptedBlob(uint32_t cbEncryptedBlob);

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptEncryptMessage(Event& event);
    ~CryptEncryptMessage() override;

    static constexpr int ArgumentCount = 7;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptEncryptMessage";

  private:
    GuestVirtualAddress pEncryptPara_;
    uint32_t cRecipientCert_;
    GuestVirtualAddress prgpRecipientCert_;
    GuestVirtualAddress pbToBeEncrypted_;
    uint32_t cbToBeEncrypted_;
    GuestVirtualAddress pbEncryptedBlob_;
    GuestVirtualAddress pcbEncryptedBlob_;

    mutable std::unique_ptr<CRYPT_DECRYPT_MESSAGE_PARA> EncryptPara_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt