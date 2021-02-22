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
#pragma once

#include <introvirt/core/memory/GuestAddress.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <cstdint>
#include <iostream>
#include <ostream>
#include <string>

namespace introvirt {

/**
 * @brief A class for outputting formatted hex dumps
 */
class HexDump {
  public:
    /**
     * @brief Write the formatted hex output
     *
     * @param os The output stream to write to
     */
    void write(std::ostream& os = std::cout) const;

    /**
     * @brief Construct a new HexDump object using the given buffer
     *
     * @param buf The buffer to read from
     * @param len The number of bytes to read
     * @param start_address The address to label the output data as
     * @param prepend A prefix to add before each line
     */
    HexDump(const void* buf, std::size_t len, std::size_t start_address = 0,
            std::string prepend = "");

    /**
     * @brief Construct a HexDump object using guest memory at the specified address
     *
     * @param ga The address to read
     * @param len The number of bytes to read
     * @param prepend A prefix to add before each line
     */
    HexDump(const GuestAddress& ga, size_t len, std::string prepend = "");

  private:
    guest_ptr<uint8_t[]> guest_data_;
    const uint8_t* buf_;
    std::size_t len_;
    std::size_t start_address_;
    const std::string prepend_;
};

} // namespace introvirt
