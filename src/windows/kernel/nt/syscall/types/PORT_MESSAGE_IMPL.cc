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
#include "PORT_MESSAGE_IMPL.hh"

#include "windows/kernel/nt/structs/structs.hh"

#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/LPC_TYPE.hh>
#include <introvirt/windows/kernel/nt/syscall/types/PORT_MESSAGE.hh>
#include <introvirt/windows/kernel/nt/types/CLIENT_ID.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace nt {

template <typename PtrType>
int16_t PORT_MESSAGE_IMPL<PtrType>::DataLength() const {
    return port_message_->DataLength.get<int16_t>(buffer);
}

template <typename PtrType>
int16_t PORT_MESSAGE_IMPL<PtrType>::TotalLength() const {
    return port_message_->TotalLength.get<int16_t>(buffer);
}

template <typename PtrType>
LPC_TYPE PORT_MESSAGE_IMPL<PtrType>::MessageType() const {
    const LPC_TYPE type = static_cast<LPC_TYPE>(port_message_->Type.get<int16_t>(buffer));

    // Check the type and convert to unknown if we don't know what it is
    switch (type) {
    case LPC_TYPE::LPC_REQUEST:
    case LPC_TYPE::LPC_REPLY:
    case LPC_TYPE::LPC_DATAGRAM:
    case LPC_TYPE::LPC_LOST_REPLY:
    case LPC_TYPE::LPC_PORT_CLOSED:
    case LPC_TYPE::LPC_CLIENT_DIED:
    case LPC_TYPE::LPC_EXCEPTION:
    case LPC_TYPE::LPC_DEBUG_EVENT:
    case LPC_TYPE::LPC_ERROR_EVENT:
    case LPC_TYPE::LPC_CONNECTION_REQUEST:
    case LPC_TYPE::LPC_UNKNOWN_MESSAGE_TYPE:
        return type;
    }

    return LPC_TYPE::LPC_UNKNOWN_MESSAGE_TYPE;
}

template <typename PtrType>
int16_t PORT_MESSAGE_IMPL<PtrType>::DataInfoOffset() const {
    return port_message_->DataInfoOffset.get<int16_t>(buffer);
}

template <typename PtrType>
const CLIENT_ID& PORT_MESSAGE_IMPL<PtrType>::ClientId() const {
    return *client_id_;
}

template <typename PtrType>
uint32_t PORT_MESSAGE_IMPL<PtrType>::MessageId() const {
    return port_message_->MessageId.get<uint32_t>(buffer);
}

template <typename PtrType>
uint32_t PORT_MESSAGE_IMPL<PtrType>::CallbackId() const {
    return port_message_->CallbackId.get<uint32_t>(buffer);
}

template <typename PtrType>
GuestVirtualAddress PORT_MESSAGE_IMPL<PtrType>::address() const {
    return gva_;
}

template <typename PtrType>
uint64_t PORT_MESSAGE_IMPL<PtrType>::HeaderSize() const {
    return port_message_->size();
}

template <typename PtrType>
void PORT_MESSAGE_IMPL<PtrType>::write(std::ostream& os, const std::string& linePrefix) const {
    boost::io::ios_flags_saver ifs(os);

    os << std::dec;
    os << linePrefix << "DataLength:     " << DataLength() << '\n';
    os << linePrefix << "TotalLength:    " << TotalLength() << '\n';
    os << linePrefix << "MessageType:    " << MessageType() << '\n';
    os << linePrefix << "DataInfoOffset: " << DataInfoOffset() << '\n';
    os << linePrefix << "ClientId:       " << ClientId() << '\n';
    os << linePrefix << "MessageID:      " << MessageId() << '\n';
    os << linePrefix << "CallbackId:     " << CallbackId() << '\n';
}

template <typename PtrType>
Json::Value PORT_MESSAGE_IMPL<PtrType>::json() const {
    Json::Value result;
    result["DataLength"] = DataLength();
    result["TotalLength"] = TotalLength();
    result["MessageType"] = to_string(MessageType());
    result["DataInfoOffset"] = DataInfoOffset();
    result["ClientId"] = ClientId();
    result["MessageID"] = MessageId();
    result["CallbackId"] = CallbackId();
    return result;
}

template <typename PtrType>
PORT_MESSAGE_IMPL<PtrType>::PORT_MESSAGE_IMPL(const NtKernelImpl<PtrType>& kernel,
                                              const GuestVirtualAddress& gva)
    : kernel_(kernel), gva_(gva) {

    // Load our structure offsets
    port_message_ = LoadOffsets<structs::PORT_MESSAGE>(kernel);

    // Map in the structure. Doing one mapping is a lot cheaper than mapping every field.
    buffer.reset(gva_, port_message_->size());

    // Create the CLIENT_ID entry
    const auto pClientId = gva_ + port_message_->ClientId.offset();
    client_id_.emplace(pClientId);
}

std::unique_ptr<PORT_MESSAGE> PORT_MESSAGE::make_unique(const NtKernel& kernel,
                                                        const GuestVirtualAddress& gva) {

    if (kernel.x64()) {
        return std::make_unique<PORT_MESSAGE_IMPL<uint64_t>>(
            static_cast<const NtKernelImpl<uint64_t>&>(kernel), gva);
    } else {
        return std::make_unique<PORT_MESSAGE_IMPL<uint32_t>>(
            static_cast<const NtKernelImpl<uint32_t>&>(kernel), gva);
    }
}

template class PORT_MESSAGE_IMPL<uint32_t>;
template class PORT_MESSAGE_IMPL<uint64_t>;

} // namespace nt
} // namespace windows
} /* namespace introvirt */
