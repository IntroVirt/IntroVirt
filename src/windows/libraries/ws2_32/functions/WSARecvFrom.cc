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
#include <introvirt/core/exception/InvalidMethodException.hh>
#include <introvirt/windows/libraries/ws2_32/functions/WSARecvFrom.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(WSARecvFrom, s, 0, SOCKET);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpBuffers, 1);
DEFINE_VALUE_GETTER_SETTER(WSARecvFrom, dwBufferCount, 2, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpNumberOfBytesRecvd, 3);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpFlags, 4);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpFrom, 6);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpFromLen, 5);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpOverlapped, 7);
DEFINE_ADDRESS_GETTER_SETTER(WSARecvFrom, lpCompletionRoutine, 8);

/* Helpers */
uint32_t WSARecvFrom::NumberOfBytesRecvd() const {
    if (lpNumberOfBytesRecvd_) {
        return *guest_ptr<uint32_t>(lpNumberOfBytesRecvd_);
    }
    // TODO: Throw an exception
    return 0;
}
void WSARecvFrom::NumberOfBytesRecvd(uint32_t NumberOfBytesRecvd) {
    if (lpNumberOfBytesRecvd_) {
        *guest_ptr<uint32_t>(lpNumberOfBytesRecvd_) = NumberOfBytesRecvd;
        return;
    }
    // TODO: Throw an exception
}

uint32_t WSARecvFrom::Flags() const {
    if (lpFlags_) {
        return *guest_ptr<uint32_t>(lpFlags_);
    }
    // TODO: Throw an exception
    return 0;
}
void WSARecvFrom::Flags(uint32_t Flags) {
    if (lpFlags_) {
        *guest_ptr<uint32_t>(lpFlags_) = Flags;
        return;
    }
    // TODO: Throw an exception
}

const SOCKADDR* WSARecvFrom::From() const {
    if (!from_ && lpFrom_) {
        from_ = SOCKADDR::make_unique(lpFrom(), x64());
    }
    return from_.get();
}
SOCKADDR* WSARecvFrom::From() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->From());
}

int32_t WSARecvFrom::FromLen() const {
    if (lpFromLen_) {
        return *guest_ptr<int32_t>(lpFromLen_);
    }
    // TODO: Throw an exception
    return 0;
}
void WSARecvFrom::FromLen(int32_t FromLen) {
    if (lpFromLen_) {
        *guest_ptr<int32_t>(lpFromLen_) = FromLen;
        return;
    }
    // TODO: Throw an exception
}

int32_t WSARecvFrom::result() const { return raw_return_value(); }

const std::string& WSARecvFrom::function_name() const { return FunctionName; }
const std::string& WSARecvFrom::library_name() const { return LibraryName; }
void WSARecvFrom::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

WSARecvFrom::WSARecvFrom(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    lpBuffers_ = get_address_argument(1);
    dwBufferCount_ = get_argument(2);
    lpNumberOfBytesRecvd_ = get_address_argument(3);
    lpFlags_ = get_address_argument(4);
    lpFrom_ = get_address_argument(5);
    lpFromLen_ = get_address_argument(6);
    lpOverlapped_ = get_address_argument(7);
    lpCompletionRoutine_ = get_address_argument(8);
}

WSARecvFrom::~WSARecvFrom() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt