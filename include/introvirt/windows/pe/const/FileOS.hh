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

/**
 * The file was designed for MS-DOS.
 */
static const uint32_t VOS_DOS = 0x00010000L;
/**
 * The file was designed for Windows NT.
 */
static const uint32_t VOS_NT = 0x00040000L;
/**
 * The file was designed for 16-bit Windows.
 */
static const uint32_t VOS__WINDOWS16 = 0x00000001L;
/**
 * The file was designed for 32-bit Windows.
 */
static const uint32_t VOS__WINDOWS32 = 0x00000004L;
/**
 * The file was designed for 16-bit OS/2.
 */
static const uint32_t VOS_OS216 = 0x00020000L;
/**
 * The file was designed for 32-bit OS/2.
 */
static const uint32_t VOS_OS232 = 0x00030000L;
/**
 * The file was designed for 16-bit Presentation Manager.
 */
static const uint32_t VOS__PM16 = 0x00000002L;
/**
 * The file was designed for 32-bit Presentation Manager.
 */
static const uint32_t VOS__PM32 = 0x00000003L;
/**
 * The operating system for which the file was designed is unknown to the system.
 */
static const uint32_t VOS_UNKNOWN = 0x00000000L;

} // namespace pe
} // namespace windows
} // namespace introvirt
