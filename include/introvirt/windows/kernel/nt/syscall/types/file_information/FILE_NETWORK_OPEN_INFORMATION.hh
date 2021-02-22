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

#include "FILE_INFORMATION.hh"

#include <introvirt/windows/util/WindowsTime.hh>

namespace introvirt {
namespace windows {
namespace nt {

class FILE_NETWORK_OPEN_INFORMATION : public FILE_INFORMATION {
  public:
    /* Getters */
    virtual WindowsTime CreationTime() const = 0;
    virtual WindowsTime LastAccessTime() const = 0;
    virtual WindowsTime LastWriteTime() const = 0;
    virtual WindowsTime ChangeTime() const = 0;
    virtual uint64_t EndOfFile() const = 0;
    virtual FILE_ATTRIBUTES FileAttributes() const = 0;

    /* Setters - These change the values in the guest! */
    virtual void CreationTime(WindowsTime time) = 0;
    virtual void LastAccessTime(WindowsTime time) = 0;
    virtual void LastWriteTime(WindowsTime time) = 0;
    virtual void ChangeTime(WindowsTime time) = 0;
    virtual void EndOfFile(uint64_t eof) = 0;
    virtual void FileAttributes(FILE_ATTRIBUTES atts) = 0;

    static std::unique_ptr<FILE_NETWORK_OPEN_INFORMATION>
    make_unique(const GuestVirtualAddress& gva);
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */
