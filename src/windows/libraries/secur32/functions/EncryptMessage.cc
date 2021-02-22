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
#include <introvirt/windows/libraries/secur32/functions/EncryptMessage.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace secur32 {

/* Input arguments */
GuestVirtualAddress EncryptMessage::phContext() const { return phContext_; }
void EncryptMessage::phContext(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    phContext_ = gva;
}

uint32_t EncryptMessage::fQOP() const { return fQOP_; }
void EncryptMessage::fQOP(uint32_t fQOP) {
    set_argument(1, fQOP);
    fQOP_ = fQOP;
}

GuestVirtualAddress EncryptMessage::pMessage() const { return pMessage_; }
void EncryptMessage::pMessage(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pMessage_ = gva;
}

uint32_t EncryptMessage::MessageSeqNo() const { return MessageSeqNo_; }
void EncryptMessage::MessageSeqNo(uint32_t MessageSeqNo) {
    set_argument(3, MessageSeqNo);
    MessageSeqNo_ = MessageSeqNo;
}

// Helpers

const SecBufferDesc* EncryptMessage::Message() const {
    if (!Message_ && pMessage_) {
        Message_ = SecBufferDesc::make_unique(pMessage_, x64());
    }
    return Message_.get();
}
SecBufferDesc* EncryptMessage::Message() {
    const auto* const_this = this;
    return const_cast<SecBufferDesc*>(const_this->Message());
}

SECURITY_STATUS EncryptMessage::result() const {
    return static_cast<SECURITY_STATUS>(raw_return_value());
}

const std::string& EncryptMessage::function_name() const { return FunctionName; }
const std::string& EncryptMessage::library_name() const { return LibraryName; }
void EncryptMessage::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

EncryptMessage::EncryptMessage(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    phContext_ = get_address_argument(0);
    fQOP_ = get_argument(1);
    pMessage_ = get_address_argument(2);
    MessageSeqNo_ = get_argument(3);
}

EncryptMessage::~EncryptMessage() = default;

} // namespace secur32
} // namespace windows
} // namespace introvirt