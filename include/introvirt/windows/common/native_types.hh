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

// Common libwintrovirt guest struct information

namespace introvirt {
namespace windows {

/*
 * Basic Types
 */
using CHAR = int8_t;
using UCHAR = uint8_t;
using WCHAR = int16_t;

using INT8 = int8_t;
using UINT8 = uint8_t;
using BYTE = uint8_t;

using SHORT = int16_t;
using USHORT = uint16_t;

using INT16 = int16_t;
using UINT16 = uint16_t;
using WORD = uint16_t;
using ATOM = WORD;

using INT = int32_t;
using UINT = uint32_t;
using DWORD = uint32_t;

using LONG = int32_t;
using ULONG = uint32_t;

using LONGLONG = int64_t;
using ULONGLONG = uint64_t;
using ULONG64 = uint64_t;

using QUAD = int64_t;
using UQUAD = uint64_t;

using FLOAT = float;
using DOUBLE = double;

using BOOL = INT;
using BOOLEAN = UCHAR;

using Ptr32 = uint32_t;
using Ptr64 = uint64_t;

using PVOID32 = Ptr32;
using PVOID64 = Ptr64;

using FUNC32 = PVOID32;
using FUNC64 = PVOID64;

} // namespace windows
} // namespace introvirt
