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
#include <introvirt/windows/libraries/ws2_32/functions/getsockname.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET getsockname::s() const { return s_; }
void getsockname::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

GuestVirtualAddress getsockname::pName() const { return pName_; }
void getsockname::pName(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pName_ = gva;
}

GuestVirtualAddress getsockname::pNameLen() const { return pNameLen_; }
void getsockname::pNameLen(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pNameLen_ = gva;
}

/* Helpers */
const SOCKADDR* getsockname::name() const {
    if (!name_ && pName_) {
        if (unlikely(!returned())) {
            throw InvalidMethodException();
        }
        if (result() == 0) {
            name_ = SOCKADDR::make_unique(pName(), x64());
        }
    }
    return name_.get();
}
SOCKADDR* getsockname::name() {
    const auto* const_this = this;
    return const_cast<SOCKADDR*>(const_this->name());
}

int64_t getsockname::result() const { return raw_return_value(); }

const std::string& getsockname::function_name() const { return FunctionName; }
const std::string& getsockname::library_name() const { return LibraryName; }
void getsockname::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

getsockname::getsockname(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    pName_ = get_address_argument(1);
    pNameLen_ = get_address_argument(2);
}

getsockname::~getsockname() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt