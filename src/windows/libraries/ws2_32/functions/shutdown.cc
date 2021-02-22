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
#include <introvirt/windows/libraries/ws2_32/functions/shutdown.hh>

#include <boost/io/ios_state.hpp>

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
SOCKET shutdown::s() const { return s_; }
void shutdown::s(SOCKET s) {
    set_argument(0, s);
    s_ = s;
}

int32_t shutdown::how() const { return how_; }
void shutdown::how(int32_t how) {
    set_argument(1, how);
    how_ = how;
}

/* Helpers */
int32_t shutdown::result() const { return raw_return_value(); }

const std::string& shutdown::function_name() const { return FunctionName; }
const std::string& shutdown::library_name() const { return LibraryName; }
void shutdown::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

shutdown::shutdown(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    s_ = get_argument(0);
    how_ = get_argument(1);
}

shutdown::~shutdown() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt