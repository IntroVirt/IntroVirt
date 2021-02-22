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
#include <introvirt/windows/libraries/secur32/const/SECURITY_STATUS.hh>
#include <introvirt/windows/libraries/secur32/types/SecBufferDesc.hh>

namespace introvirt {
namespace windows {
namespace secur32 {

/**
 * @brief Handler for crypt32!EncryptMessage
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel
 */
class EncryptMessage : public WindowsFunctionCall {
  public:
    /* Input arguments */
    GuestVirtualAddress phContext() const;
    void phContext(const GuestVirtualAddress& value);

    uint32_t fQOP() const;
    void fQOP(uint32_t fQOP);

    GuestVirtualAddress pMessage() const;
    void pMessage(const GuestVirtualAddress& gva);

    uint32_t MessageSeqNo() const;
    void MessageSeqNo(uint32_t MessageSeqNo);

    /* Helpers */
    const SecBufferDesc* Message() const;
    SecBufferDesc* Message();

    SECURITY_STATUS result() const;

    const std::string& function_name() const override;
    const std::string& library_name() const override;
    void write(std::ostream& os = std::cout) const override;

    EncryptMessage(Event& event);
    ~EncryptMessage() override;

    static constexpr int ArgumentCount = 4;
    inline static const std::string LibraryName = "secur32";
    inline static const std::string FunctionName = "EncryptMessage";

  private:
    GuestVirtualAddress phContext_;
    uint32_t fQOP_;
    GuestVirtualAddress pMessage_;
    uint32_t MessageSeqNo_;

    mutable std::unique_ptr<SecBufferDesc> Message_;
};

} // namespace secur32
} // namespace windows
} // namespace introvirt