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
#include <introvirt/windows/libraries/ws2_32/functions/setsockopt.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET setsockopt::s() const { return s_; }
void setsockopt::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

int32_t setsockopt::level() const { return s_; }
void setsockopt::level(int32_t level) {
    set_argument(1, level);
    level_ = level;
}

int32_t setsockopt::optname() const { return optname_; }
void setsockopt::optname(int32_t optname) {
    set_argument(2, optname);
    optname_ = optname;
}

GuestVirtualAddress setsockopt::pOptVal() const { return pOptVal_; }
void setsockopt::pOptVal(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    pOptVal_ = gva;
}

int32_t setsockopt::optlen() const { return optlen_; }
void setsockopt::optlen(int32_t optlen) {
    set_argument(4, optlen);
    optlen_ = optlen;
}

/* Helpers */

int32_t setsockopt::result() const { return raw_return_value(); }

const std::string& setsockopt::function_name() const { return FunctionName; }
const std::string& setsockopt::library_name() const { return LibraryName; }
void setsockopt::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

setsockopt::setsockopt(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    level_ = get_argument(1);
    optname_ = get_argument(2);
    pOptVal_ = get_address_argument(3);
    optlen_ = get_argument(4);
}

setsockopt::~setsockopt() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt