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
/* -----------------------------------------------------------------------------*/
/* If dwFileType is VFT_DRV, dwFileSubtype can be one of the following values. */
/* -----------------------------------------------------------------------------*/
/**
 * The file contains a communications driver.
 */
static const uint32_t VFT2_DRV_COMM = 0x0000000AL;
/**
 * The file contains a display driver.
 */
static const uint32_t VFT2_DRV_DISPLAY = 0x00000004L;
/**
 * The file contains an installable driver.
 */
static const uint32_t VFT2_DRV_INSTALLABLE = 0x00000008L;
/**
 * The file contains a keyboard driver.
 */
static const uint32_t VFT2_DRV_KEYBOARD = 0x00000002L;
/**
 * The file contains a language driver.
 */
static const uint32_t VFT2_DRV_LANGUAGE = 0x00000003L;
/**
 * The file contains a mouse driver.
 */
static const uint32_t VFT2_DRV_MOUSE = 0x00000005L;
/**
 * The file contains a network driver.
 */
static const uint32_t VFT2_DRV_NETWORK = 0x00000006L;
/**
 * The file contains a printer driver.
 */
static const uint32_t VFT2_DRV_PRINTER = 0x00000001L;
/**
 * The file contains a sound driver.
 */
static const uint32_t VFT2_DRV_SOUND = 0x00000009L;
/**
 * The file contains a system driver.
 */
static const uint32_t VFT2_DRV_SYSTEM = 0x00000007L;
/**
 * The file contains a versioned printer driver.
 */
static const uint32_t VFT2_DRV_VERSIONED_PRINTER = 0x0000000CL;

/**
 * The driver type is unknown by the system.
 */
static const uint32_t VFT2_DRIVER_UNKNOWN = 0x00000000L;

/* -----------------------------------------------------------------------------*/
/* If dwFileType is VFT_FONT, dwFileSubtype can be one of the following values. */
/* -----------------------------------------------------------------------------*/
/**
 * The file contains a raster font.
 */
static const uint32_t VFT2_FONT_RASTER = 0x00000001L;
/**
 * The file contains a TrueType font.
 */
static const uint32_t VFT2_FONT_TRUETYPE = 0x00000003L;
/**
 * The file contains a vector font.
 */
static const uint32_t VFT2_FONT_VECTOR = 0x00000002L;

/**
 * The font type is unknown by the system.
 */
static const uint32_t VFT2_FONT_UNKNOWN = 0x00000000L;

/* If dwFileType is VFT_VXD, dwFileSubtype contains the virtual device identifier included in the
 * virtual device control block. */

} // namespace pe
} // namespace windows
} // namespace introvirt
