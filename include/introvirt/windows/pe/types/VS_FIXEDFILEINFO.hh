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

#include <introvirt/core/fwd.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace windows {
namespace pe {

/**
 * @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms646997%28v=vs.85%29.aspx
 */
class VS_FIXEDFILEINFO {
  public:
    virtual uint32_t dwSignature() const = 0;

    /**
     * @returns The major binary version number of this structure.
     */
    virtual uint32_t dwStrucVersion() const = 0;

    /**
     * @returns The file's binary version number
     */
    virtual uint64_t dwFileVersion() const = 0;

    /**
     * @returns The binary version number of the product with which this file was distributed.
     */
    virtual uint64_t dwProductVersion() const = 0;

    /**
     * @returns A bitmask that specifies the valid bits in FileFlags.
     */
    virtual uint32_t dwFileFlagsMask() const = 0;

    /**
     * @returns a bitmask of VS_FF_* types
     */
    virtual uint32_t dwFileFlags() const = 0;

    /**
     * @returns a VOS_* type indicating the operating system for which this file was designed.
     * Multiple bits can be set (ex. 16-bit Windows running on MS-DOS).
     */
    virtual uint32_t dwFileOS() const = 0;

    /**
     * @returns a VFT_* type indicating the general type of file.
     */
    virtual uint32_t dwFileType() const = 0;

    /**
     * @returns a VFT_DRV_* or VFT_FONT_* (depending on the file type)
     */
    virtual uint32_t dwFileSubtype() const = 0;

    /**
     * @returns The file's binary creation date and time stamp
     */
    virtual uint64_t dwFileDate() const = 0;

    virtual ~VS_FIXEDFILEINFO() = default;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
