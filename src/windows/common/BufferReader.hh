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

#include <cstddef>
#include <stdexcept>

namespace introvirt {
namespace windows {

class BufferReader {
  public:
    BufferReader(const void* buffer, size_t len)
        : buffer(reinterpret_cast<const uint8_t*>(buffer)), len(len) {

        mark();
    }

    template <typename T>
    const T* get() {
        if (len < sizeof(T))
            throw std::out_of_range("Buffer underrun");

        const T* result = reinterpret_cast<const T*>(buffer);

        buffer += sizeof(T);
        len -= sizeof(T);

        return result;
    }

    template <typename T>
    const T& read() {
        if (len < sizeof(T))
            throw std::out_of_range("Buffer underrun");

        const T* result = reinterpret_cast<const T*>(buffer);

        buffer += sizeof(T);
        len -= sizeof(T);

        return *result;
    }

    void mark() {
        buffer_mark = buffer;
        len_mark = len;
    }

    // Reset to the last mark
    void reset() {
        buffer = buffer_mark;
        len = len_mark;
    }

    void skip(size_t bytes) {
        if (len < bytes)
            throw std::out_of_range("Buffer underrun");

        buffer += bytes;
        len -= bytes;
    }

    size_t remaining() const { return len; }

  private:
    const uint8_t* buffer;
    size_t len;

    const uint8_t* buffer_mark;
    size_t len_mark;
};

} /* namespace windows */
} /* namespace introvirt */
