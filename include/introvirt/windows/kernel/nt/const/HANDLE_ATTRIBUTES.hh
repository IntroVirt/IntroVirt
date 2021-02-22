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

#include <introvirt/util/json/json.hh>

#include <cstdint>
#include <string>

namespace introvirt {
namespace windows {
namespace nt {

enum class HANDLE_ATTRIBUTES_FLAG {
    OBJ_INHERIT = 0x00000002,
    OBJ_PERMANENT = 0x00000010,
    OBJ_EXCLUSIVE = 0x00000020,
    OBJ_CASE_INSENSITIVE = 0x00000040,
    OBJ_OPENIF = 0x00000080,
    OBJ_OPENLINK = 0x00000100,
    OBJ_KERNEL_HANDLE = 0x00000200,
    OBJ_FORCE_ACCESS_CHECK = 0x00000400,
    OBJ_VALID_ATTRIBUTES = 0x000007f2
};

class HANDLE_ATTRIBUTES {
  public:
    HANDLE_ATTRIBUTES(uint32_t flags = 0);
    HANDLE_ATTRIBUTES(const HANDLE_ATTRIBUTES&);
    HANDLE_ATTRIBUTES& operator=(const HANDLE_ATTRIBUTES&);

  public:
    uint32_t get() const;
    Json::Value json() const;

    operator uint32_t() const;
    operator Json::Value() const;

    bool isSet(HANDLE_ATTRIBUTES_FLAG flag) const;
    void set(HANDLE_ATTRIBUTES_FLAG flag);
    void clear(HANDLE_ATTRIBUTES_FLAG flag);

    uint32_t flags;
};

const std::string& to_string(HANDLE_ATTRIBUTES_FLAG atts);

std::string to_string(HANDLE_ATTRIBUTES type);

} // namespace nt
} // namespace windows
} // namespace introvirt
