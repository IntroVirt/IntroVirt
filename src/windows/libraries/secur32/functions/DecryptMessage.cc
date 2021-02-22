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
#include <introvirt/windows/libraries/secur32/functions/DecryptMessage.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace secur32 {

/* Input arguments */
GuestVirtualAddress DecryptMessage::phContext() const { return phContext_; }
void DecryptMessage::phContext(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    phContext_ = gva;
}

GuestVirtualAddress DecryptMessage::pMessage() const { return pMessage_; }
void DecryptMessage::pMessage(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pMessage_ = gva;
}

uint32_t DecryptMessage::MessageSeqNo() const { return MessageSeqNo_; }
void DecryptMessage::MessageSeqNo(uint32_t MessageSeqNo) {
    set_argument(2, MessageSeqNo);
    MessageSeqNo_ = MessageSeqNo;
}

GuestVirtualAddress DecryptMessage::pfQOP() const { return pfQOP_; }
void DecryptMessage::pfQOP(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    pfQOP_ = gva;
}

// Helpers

const SecBufferDesc* DecryptMessage::Message() const {
    if (!Message_ && pMessage_) {
        Message_ = SecBufferDesc::make_unique(pMessage_, x64());
    }
    return Message_.get();
}

SecBufferDesc* DecryptMessage::Message() {
    const auto* const_this = this;
    return const_cast<SecBufferDesc*>(const_this->Message());
}

SECURITY_STATUS DecryptMessage::result() const {
    return static_cast<SECURITY_STATUS>(raw_return_value());
}

const std::string& DecryptMessage::function_name() const { return FunctionName; }
const std::string& DecryptMessage::library_name() const { return LibraryName; }
void DecryptMessage::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

DecryptMessage::DecryptMessage(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    phContext_ = get_address_argument(0);
    pMessage_ = get_address_argument(1);
    MessageSeqNo_ = get_argument(2);
    pfQOP_ = get_address_argument(3);
}

DecryptMessage::~DecryptMessage() = default;

} // namespace secur32
} // namespace windows
} // namespace introvirt