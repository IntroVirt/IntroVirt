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

namespace introvirt {
namespace windows {
namespace pe {

enum FileType {
    /**
     * The file contains an application.
     */
    VFT_APP = 0x00000001L,
    /**
     * The file contains a DLL.
     */
    VFT_DLL = 0x00000002L,
    /**
     * The file contains a device driver. If dwFileType is VFT_DRV, dwFileSubtype contains a more
     * specific description of the driver.
     */
    VFT_DRV = 0x00000003L,
    /**
     * The file contains a font. If dwFileType is VFT_FONT, dwFileSubtype contains a more specific
     * description of the font file.
     */
    VFT_FONT = 0x00000004L,
    /**
     * The file contains a static-link library.
     */
    VFT_STATIC_LIB = 0x00000007L,
    /**
     * The file type is unknown to the system.
     */
    VFT_UNKNOWN = 0x00000000L,
    /**
     * The file contains a virtual device.
     */
    VFT_VXD = 0x00000005L,
};

} // namespace pe
} // namespace windows
} // namespace introvirt
