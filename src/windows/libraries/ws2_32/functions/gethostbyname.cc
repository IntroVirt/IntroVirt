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
#include <introvirt/windows/libraries/ws2_32/functions/gethostbyname.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
GuestVirtualAddress gethostbyname::pName() const { return pName_; }
void gethostbyname::pName(const GuestVirtualAddress& gva) {
    set_address_argument(0, gva);
    pName_ = gva;
}

/* Helpers */
std::string gethostbyname::name() const {
    if (!pName_)
        return std::string();

    auto mapping = map_guest_cstr(pName_);
    return std::string(mapping.get(), mapping.length());
}

GuestVirtualAddress gethostbyname::result_address() const {
    return GuestVirtualAddress(raw_return_value());
}

std::unique_ptr<HOSTENT> gethostbyname::result() const {
    GuestVirtualAddress pResult(result_address());
    std::unique_ptr<HOSTENT> result;
    if (pResult) {
        result = HOSTENT::make_unique(pResult, x64());
    }
    return result;
}

const std::string& gethostbyname::function_name() const { return FunctionName; }
const std::string& gethostbyname::library_name() const { return LibraryName; }
void gethostbyname::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

gethostbyname::gethostbyname(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    pName_ = get_address_argument(0);
}

gethostbyname::~gethostbyname() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt