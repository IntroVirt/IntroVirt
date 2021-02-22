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
#include <introvirt/windows/libraries/ws2_32/functions/select.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
int32_t select::nfds() const { return nfds_; }
void select::nfds(int32_t nfds) {
    set_argument(0, nfds);
    nfds_ = nfds;
}

GuestVirtualAddress select::pReadFds() const { return pReadFds_; }
void select::pReadFds(const GuestVirtualAddress& gva) {
    set_address_argument(1, gva);
    pReadFds_ = gva;
}

GuestVirtualAddress select::pWriteFds() const { return pWriteFds_; }
void select::pWriteFds(const GuestVirtualAddress& gva) {
    set_address_argument(2, gva);
    pWriteFds_ = gva;
}

GuestVirtualAddress select::pExceptFds() const { return pExceptFds_; }
void select::pExceptFds(const GuestVirtualAddress& gva) {
    set_address_argument(3, gva);
    pExceptFds_ = gva;
}

GuestVirtualAddress select::pTimeout() const { return pTimeout_; }
void select::pTimeout(const GuestVirtualAddress& gva) {
    set_address_argument(4, gva);
    pTimeout_ = gva;
}

/* Helpers */
int32_t select::result() const { return raw_return_value(); }

const std::string& select::function_name() const { return FunctionName; }
const std::string& select::library_name() const { return LibraryName; }
void select::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

select::select(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    nfds_ = get_argument(0);
    pReadFds_ = get_address_argument(1);
    pWriteFds_ = get_address_argument(2);
    pExceptFds_ = get_address_argument(3);
    pTimeout_ = get_address_argument(4);
}

select::~select() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt