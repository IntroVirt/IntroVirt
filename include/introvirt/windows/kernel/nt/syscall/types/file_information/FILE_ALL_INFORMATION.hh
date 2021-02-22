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

#include "FILE_INFORMATION.hh"

#include "FILE_ACCESS_INFORMATION.hh"
#include "FILE_ALIGNMENT_INFORMATION.hh"
#include "FILE_BASIC_INFORMATION.hh"
#include "FILE_EA_INFORMATION.hh"
#include "FILE_INTERNAL_INFORMATION.hh"
#include "FILE_MODE_INFORMATION.hh"
#include "FILE_NAME_INFORMATION.hh"
#include "FILE_POSITION_INFORMATION.hh"
#include "FILE_STANDARD_INFORMATION.hh"

#include <cstdint>

namespace introvirt {
namespace windows {
namespace nt {

/**
 * @brief Handler for the FileAllInformation type
 *
 * Some applications will only request a partial size of this buffer, so not all fields will always
 * be available. Check for nullptr when accessing.
 *
 */
class FILE_ALL_INFORMATION : public FILE_INFORMATION {
  public:
    virtual FILE_BASIC_INFORMATION* BasicInformation() = 0;
    virtual const FILE_BASIC_INFORMATION* BasicInformation() const = 0;

    virtual FILE_STANDARD_INFORMATION* StandardInformation() = 0;
    virtual const FILE_STANDARD_INFORMATION* StandardInformation() const = 0;

    virtual FILE_INTERNAL_INFORMATION* InternalInformation() = 0;
    virtual const FILE_INTERNAL_INFORMATION* InternalInformation() const = 0;

    virtual FILE_EA_INFORMATION* EaInformation() = 0;
    virtual const FILE_EA_INFORMATION* EaInformation() const = 0;

    virtual FILE_ACCESS_INFORMATION* AccessInformation() = 0;
    virtual const FILE_ACCESS_INFORMATION* AccessInformation() const = 0;

    virtual FILE_POSITION_INFORMATION* PositionInformation() = 0;
    virtual const FILE_POSITION_INFORMATION* PositionInformation() const = 0;

    virtual FILE_MODE_INFORMATION* ModeInformation() = 0;
    virtual const FILE_MODE_INFORMATION* ModeInformation() const = 0;

    virtual FILE_ALIGNMENT_INFORMATION* AlignmentInformation() = 0;
    virtual const FILE_ALIGNMENT_INFORMATION* AlignmentInformation() const = 0;

    virtual FILE_NAME_INFORMATION* NameInformation() = 0;
    virtual const FILE_NAME_INFORMATION* NameInformation() const = 0;
};

} /* namespace nt */
} /* namespace windows */
} /* namespace introvirt */