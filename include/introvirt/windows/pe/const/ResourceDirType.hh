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

class ResourceDirType {
  public:
    static const uint16_t CURSOR = 1;
    static const uint16_t BITMAP = 2;
    static const uint16_t ICON = 3;
    static const uint16_t MENU = 4;
    static const uint16_t DIALOG = 5;
    static const uint16_t STRING = 6;
    static const uint16_t FONT_DIRECTORY = 7;
    static const uint16_t FONT = 8;
    static const uint16_t ACCELERATOR = 9;
    static const uint16_t RCDATA = 10;
    static const uint16_t MESSAGE_TABLE = 11;
    static const uint16_t VERSION = 16;
    static const uint16_t DLGINCLUDE = 17;
    static const uint16_t PLUG_AND_PLAY = 19;
    static const uint16_t VXD = 20;
    static const uint16_t ANIMATED_CURSOR = 21;
    static const uint16_t ANIMATED_ICON = 22;
    static const uint16_t HTML = 23;
    static const uint16_t MANIFEST = 24;
};
