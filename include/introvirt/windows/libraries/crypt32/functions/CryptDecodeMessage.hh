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
 * @brief Handler for crypt32!CryptDecodeMessage
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecodemessage
 */
class CryptDecodeMessage : public WindowsFunctionCall {
  public:
    /* Input arguments */
    uint32_t dwMsgTypeFlags() const;
    void dwMsgTypeFlags(uint32_t dwMsgTypeFlags);

    GuestVirtualAddress pDecryptPara() const;
    void pDecryptPara(const GuestVirtualAddress& gva);

    GuestVirtualAddress pVerifyPara() const;
    void pVerifyPara(const GuestVirtualAddress& gva);

    uint32_t dwSignerIndex() const;
    void dwSignerIndex(uint32_t dwSignerIndex);

    GuestVirtualAddress pbEncodedBlob() const;
    void pbEncodedBlob(const GuestVirtualAddress& gva);

    uint32_t cbEncodedBlob() const;
    void cbEncodedBlob(uint32_t cbEncodedBlob);

    uint32_t dwPrevInnerContentType() const;
    void dwPrevInnerContentType(uint32_t dwPrevInnerContentType);

    GuestVirtualAddress pdwMsgType() const;
    void pdwMsgType(const GuestVirtualAddress& gva);

    GuestVirtualAddress pdwInnerContentType() const;
    void pdwInnerContentType(const GuestVirtualAddress& gva);

    GuestVirtualAddress pbDecoded() const;
    void pbDecoded(const GuestVirtualAddress& gva);

    GuestVirtualAddress pcbDecoded() const;
    void pcbDecoded(const GuestVirtualAddress& gva);

    GuestVirtualAddress ppXchgCert() const;
    void ppXchgCert(const GuestVirtualAddress& gva);

    GuestVirtualAddress ppSignerCert() const;
    void ppSignerCert(const GuestVirtualAddress& gva);

    /* Helpers */
    const CRYPT_DECRYPT_MESSAGE_PARA* DecryptPara() const;
    CRYPT_DECRYPT_MESSAGE_PARA* DecryptPara();

    const CRYPT_VERIFY_MESSAGE_PARA* VerifyPara() const;
    CRYPT_VERIFY_MESSAGE_PARA* VerifyPara();

    uint32_t dwMsgType() const;
    void dwMsgType(uint32_t dwMsgType);

    uint32_t dwInnerContentType() const;
    void dwInnerContentType(uint32_t dwInnerContentType);

    uint32_t cbDecoded() const;
    void cbDecoded(uint32_t cbDecoded);

    bool result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    CryptDecodeMessage(Event& event);
    ~CryptDecodeMessage() override;

    static constexpr int ArgumentCount = 13;
    inline static const std::string LibraryName = "crypt32";
    inline static const std::string FunctionName = "CryptDecodeMessage";

  private:
    uint32_t dwMsgTypeFlags_;
    GuestVirtualAddress pDecryptPara_;
    GuestVirtualAddress pVerifyPara_;
    uint32_t dwSignerIndex_;
    GuestVirtualAddress pbEncodedBlob_;
    uint32_t cbEncodedBlob_;
    uint32_t dwPrevInnerContentType_;
    GuestVirtualAddress pdwMsgType_;
    GuestVirtualAddress pdwInnerContentType_;
    GuestVirtualAddress pbDecoded_;
    GuestVirtualAddress pcbDecoded_;
    GuestVirtualAddress ppXchgCert_;
    GuestVirtualAddress ppSignerCert_;

    mutable std::unique_ptr<CRYPT_DECRYPT_MESSAGE_PARA> DecryptPara_;
    mutable std::unique_ptr<CRYPT_VERIFY_MESSAGE_PARA> VerifyPara_;
};

} // namespace crypt32
} // namespace windows
} // namespace introvirt