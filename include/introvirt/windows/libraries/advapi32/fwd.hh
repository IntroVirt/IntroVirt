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

namespace introvirt {
namespace windows {

/**
 * @brief Function and type handlers for advapi32.dll
 */
namespace advapi32 {

typedef uint64_t HCRYPTKEY;
typedef uint64_t HCRYPTHASH;
typedef uint64_t HCRYPTPROV;

class CryptAcquireContextA;
class CryptEncrypt;
class CryptExportKey;
class CryptGenRandom;
class CryptSetKeyParam;
class CryptGetKeyParam;

enum ALG_ID : uint32_t;
enum BLOB_TYPE : uint8_t;
class BLOB;
enum KP_VALUE : uint32_t;
class PLAINTEXTKEYBLOB;

} // namespace advapi32
} // namespace windows
} // namespace introvirt
