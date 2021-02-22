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

#include <ostream>
#include <string>

namespace introvirt {
namespace windows {
namespace pe {

enum RelocationType {
    IMAGE_REL_BASED_ABSOLUTE = 0,
    IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_LOW,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_HIGHADJ,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_5,
    IMAGE_REL_BASED_RESERVED,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_7,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_8,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_9,
    IMAGE_REL_BASED_DIR64,
};

const std::string& to_string(RelocationType type);
std::ostream& operator<<(std::ostream&, RelocationType type);

} // namespace pe
} // namespace windows
} // namespace introvirt