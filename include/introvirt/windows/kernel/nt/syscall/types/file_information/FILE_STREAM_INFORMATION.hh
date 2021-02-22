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
#include "FILE_INFORMATION.hh"

#include <introvirt/windows/kernel/nt/syscall/types/offset_iterator.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief A single entry from a FILE_STREAM_INFORMATION buffer
 *
 */
class FILE_STREAM_INFORMATION_ENTRY {
  public:
    virtual uint32_t NextEntryOffset() const = 0;
    virtual void NextEntryOffset(uint32_t value) = 0;

    virtual const std::string& StreamName() const = 0;
    virtual void StreamName(const std::string& StreamName) = 0;

    virtual int64_t StreamSize() const = 0;
    virtual void StreamSize(int64_t StreamSize) = 0;

    virtual int64_t StreamAllocationSize() const = 0;
    virtual void StreamAllocationSize(int64_t StreamAllocationSize) = 0;

    virtual GuestVirtualAddress address() const = 0;
    virtual uint32_t buffer_size() const = 0;

    // Assign this entry the value of another one
    virtual FILE_STREAM_INFORMATION_ENTRY& operator=(const FILE_STREAM_INFORMATION_ENTRY&) = 0;

    static std::shared_ptr<FILE_STREAM_INFORMATION_ENTRY>
    make_shared(const GuestVirtualAddress& gva);

    virtual ~FILE_STREAM_INFORMATION_ENTRY() = default;
};

/**
 * @brief A buffer that holds a list of FILE_STREAM_INFORMATION elements
 */
class FILE_STREAM_INFORMATION : public FILE_INFORMATION {
  public:
    using iterator = offset_iterator<FILE_STREAM_INFORMATION_ENTRY, false>;
    using const_iterator = offset_iterator<FILE_STREAM_INFORMATION_ENTRY, true>;

    virtual iterator begin() = 0;
    virtual iterator end() = 0;
    virtual iterator erase(const const_iterator& position) = 0;

    virtual const_iterator begin() const = 0;
    virtual const_iterator end() const = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */