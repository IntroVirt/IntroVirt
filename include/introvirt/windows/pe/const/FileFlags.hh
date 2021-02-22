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
namespace pe {

/**
 * The file contains debugging information or is compiled with debugging features enabled.
 */
static const uint32_t VS_FF_DEBUG = 0x00000001L;
/**
 * The file's version structure was created dynamically; therefore, some of the members in this
 * structure may be empty or incorrect. This flag should never be set in a file's VS_VERSIONINFO
 * data.
 */
static const uint32_t VS_FF_INFOINFERRED = 0x00000010L;
/**
 * The file has been modified and is not identical to the original shipping file of the same version
 * number.
 */
static const uint32_t VS_FF_PATCHED = 0x00000004L;
/**
 * The file is a development version, not a commercially released product.
 */
static const uint32_t VS_FF_PRERELEASE = 0x00000002L;
/**
 * The file was not built using standard release procedures. If this flag is set, the StringFileInfo
 * structure should contain a PrivateBuild entry.
 */
static const uint32_t VS_FF_PRIVATEBUILD = 0x00000008L;
/**
 * The file was built by the original company using standard release procedures but is a variation
 * of the normal file of the same version number. If this flag is set, the StringFileInfo structure
 * should contain a SpecialBuild entry.
 */
static const uint32_t VS_FF_SPECIALBUILD = 0x00000020L;

} // namespace pe
} // namespace windows
} // namespace introvirt
