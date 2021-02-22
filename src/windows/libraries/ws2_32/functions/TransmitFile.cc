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
#include <introvirt/windows/libraries/ws2_32/functions/TransmitFile.hh>

#include <boost/io/ios_state.hpp>

#include "../../helpers.hh"

namespace introvirt {
namespace windows {
namespace ws2_32 {

/* Input arguments */
DEFINE_VALUE_GETTER_SETTER(TransmitFile, hSocket, 0, SOCKET);
DEFINE_VALUE_GETTER_SETTER(TransmitFile, hFile, 1, uint64_t);
DEFINE_VALUE_GETTER_SETTER(TransmitFile, nNumberOfBytesToWrite, 2, uint32_t);
DEFINE_VALUE_GETTER_SETTER(TransmitFile, nNumberOfBytesPerSend, 3, uint32_t);
DEFINE_ADDRESS_GETTER_SETTER(TransmitFile, lpOverlapped, 4);
DEFINE_ADDRESS_GETTER_SETTER(TransmitFile, lpTransmitBuffers, 5);
DEFINE_VALUE_GETTER_SETTER(TransmitFile, dwReserved, 6, uint32_t);

/* Helpers */
bool TransmitFile::result() const { return raw_return_value(); }

const std::string& TransmitFile::function_name() const { return FunctionName; }
const std::string& TransmitFile::library_name() const { return LibraryName; }
void TransmitFile::write(std::ostream& os) const {
    boost::io::ios_flags_saver ifs(os);
    // TODO
}

TransmitFile::TransmitFile(Event& event) : WindowsFunctionCall(event, ArgumentCount) {
    hSocket_ = get_argument(0);
    hFile_ = get_argument(1);
    nNumberOfBytesToWrite_ = get_argument(2);
    nNumberOfBytesPerSend_ = get_argument(3);
    lpOverlapped_ = get_address_argument(4);
    lpTransmitBuffers_ = get_address_argument(5);
    dwReserved_ = get_argument(6);
}

TransmitFile::~TransmitFile() = default;

} // namespace ws2_32
} // namespace windows
} // namespace introvirt