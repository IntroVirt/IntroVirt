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

#include <cstdint>
#include <introvirt/core/fwd.hh>

namespace introvirt {
namespace windows {
namespace advapi32 {

enum ALG_ID : uint32_t;
enum BLOB_TYPE : uint8_t;
class BLOB;
enum KP_VALUE : uint32_t;
class PLAINTEXTKEYBLOB;

typedef guest_size_t HCRYPTKEY;
typedef guest_size_t HCRYPTPROV;
typedef guest_size_t HCRYPTHASH;

} // namespace advapi32
} // namespace windows
} // namespace introvirt