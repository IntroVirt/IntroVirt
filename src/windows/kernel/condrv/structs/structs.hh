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

#include <cstdint>

#define ALIGNED __attribute__((aligned(sizeof(PtrType))))

namespace introvirt {
namespace windows {
namespace condrv {
namespace structs {

/*
 * This is the first part of the IOCTL's input buffer
 */
template <typename PtrType>
struct ConsoleCallServerGenericHeader {
    PtrType requestHandle;
    uint32_t data1;
    uint32_t data2;
    PtrType data3; // Don't know if data1, 2, or 3 is PtrType, but one of them seems to be.
    PtrType requestHeaderPtr;
};

/*
 * This is pointed at by ConsoleCallGenericHeader::requestHeaderPtr
 */
struct ConsoleCallServerGenericRequestHeader {
    uint32_t requestCode;
    uint32_t unknown_1;
    uint32_t data1;
    uint32_t data2;
};

/*
 * This is the generic version of the second part of the IOCTL's input buffer
 */
template <typename PtrType>
struct ConsoleCallServerGenericData {
    uint32_t unknown_1;
    uint32_t unknown_2;
    PtrType responsePtr;
};

/*
 * This is a specialized version of ConsoleCallServerGenericData
 */
template <typename PtrType>
struct ConsoleCallServerGenericWriteConsoleData {
    uint32_t dataSize;
    PtrType dataPtr;
    PtrType unknown1;
    PtrType responsePtr;
} ALIGNED;

} /* namespace structs */
} /* namespace condrv */
} /* namespace windows */
} /* namespace introvirt */

#undef ALIGNED
