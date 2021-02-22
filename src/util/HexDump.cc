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

#include <introvirt/util/HexDump.hh>

#include <introvirt/core/memory/GuestPhysicalAddress.hh>
#include <introvirt/core/memory/GuestVirtualAddress.hh>

#include <iomanip>
#include <utility>

using namespace std;

namespace introvirt {

HexDump::HexDump(const void* buf, size_t len, size_t start_address, std::string prepend)
    : buf_(static_cast<const uint8_t*>(buf)), len_(len), start_address_(start_address),
      prepend_(prepend) {}

HexDump::HexDump(const GuestAddress& ga, size_t len, std::string prepend)
    : len_(len), start_address_(ga.value()), prepend_(prepend) {

    guest_data_ = guest_ptr<uint8_t[]>(ga, len);
    buf_ = guest_data_.get();
}

void HexDump::write(ostream& os) const {
    os << hex << setfill('0');

    for (unsigned int i = 0; i < len_; i += 16) {
        os << prepend_;
        os << setw(16);
        os << (start_address_ + i) << "  ";

        for (unsigned int j = i; j < (i + 16); ++j) {
            if (j < len_) {
                os << setw(2) << static_cast<unsigned int>(buf_[j] & 0xFF) << " ";
            } else {
                os << "   "; // Padding to reach the end
            }
            if (j == (i + 7)) {
                os << " "; // Spacing between groups on the hex side
            }
        }
        os << " |";
        for (unsigned int j = i; j < (i + 16); ++j) {
            if (j < len_) {
                if (isprint(buf_[j]) != 0) {
                    os << char(buf_[j]);
                } else {
                    os << '.';
                }
            }
        }
        os << "|\n";
    }

    os << dec;
}

} // namespace introvirt
