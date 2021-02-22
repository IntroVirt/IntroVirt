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
#include "FILE_ALL_INFORMATION_IMPL.hh"

#include <introvirt/core/exception/BufferTooSmallException.hh>
#include <introvirt/util/compiler.hh>

namespace introvirt {
namespace windows {
namespace nt {

FILE_BASIC_INFORMATION* FILE_ALL_INFORMATION_IMPL::BasicInformation() {
    if (BasicInformation_)
        return &(*BasicInformation_);
    return nullptr;
}
const FILE_BASIC_INFORMATION* FILE_ALL_INFORMATION_IMPL::BasicInformation() const {
    if (BasicInformation_)
        return &(*BasicInformation_);
    return nullptr;
}

FILE_STANDARD_INFORMATION* FILE_ALL_INFORMATION_IMPL::StandardInformation() {
    if (StandardInformation_)
        return &(*StandardInformation_);
    return nullptr;
}
const FILE_STANDARD_INFORMATION* FILE_ALL_INFORMATION_IMPL::StandardInformation() const {
    if (StandardInformation_)
        return &(*StandardInformation_);
    return nullptr;
}

FILE_INTERNAL_INFORMATION* FILE_ALL_INFORMATION_IMPL::InternalInformation() {
    if (InternalInformation_)
        return &(*InternalInformation_);
    return nullptr;
}
const FILE_INTERNAL_INFORMATION* FILE_ALL_INFORMATION_IMPL::InternalInformation() const {
    if (InternalInformation_)
        return &(*InternalInformation_);
    return nullptr;
}

FILE_EA_INFORMATION* FILE_ALL_INFORMATION_IMPL::EaInformation() {
    if (EaInformation_)
        return &(*EaInformation_);
    return nullptr;
}
const FILE_EA_INFORMATION* FILE_ALL_INFORMATION_IMPL::EaInformation() const {
    if (EaInformation_)
        return &(*EaInformation_);
    return nullptr;
}

FILE_ACCESS_INFORMATION* FILE_ALL_INFORMATION_IMPL::AccessInformation() {
    if (AccessInformation_)
        return &(*AccessInformation_);
    return nullptr;
}
const FILE_ACCESS_INFORMATION* FILE_ALL_INFORMATION_IMPL::AccessInformation() const {
    if (AccessInformation_)
        return &(*AccessInformation_);
    return nullptr;
}

FILE_POSITION_INFORMATION* FILE_ALL_INFORMATION_IMPL::PositionInformation() {
    if (PositionInformation_)
        return &(*PositionInformation_);
    return nullptr;
}
const FILE_POSITION_INFORMATION* FILE_ALL_INFORMATION_IMPL::PositionInformation() const {
    if (PositionInformation_)
        return &(*PositionInformation_);
    return nullptr;
}

FILE_MODE_INFORMATION* FILE_ALL_INFORMATION_IMPL::ModeInformation() {
    if (ModeInformation_)
        return &(*ModeInformation_);
    return nullptr;
}
const FILE_MODE_INFORMATION* FILE_ALL_INFORMATION_IMPL::ModeInformation() const {
    if (ModeInformation_)
        return &(*ModeInformation_);
    return nullptr;
}

FILE_ALIGNMENT_INFORMATION* FILE_ALL_INFORMATION_IMPL::AlignmentInformation() {
    if (AlignmentInformation_)
        return &(*AlignmentInformation_);
    return nullptr;
}
const FILE_ALIGNMENT_INFORMATION* FILE_ALL_INFORMATION_IMPL::AlignmentInformation() const {
    if (AlignmentInformation_)
        return &(*AlignmentInformation_);
    return nullptr;
}

FILE_NAME_INFORMATION* FILE_ALL_INFORMATION_IMPL::NameInformation() {
    if (NameInformation_)
        return &(*NameInformation_);
    return nullptr;
}
const FILE_NAME_INFORMATION* FILE_ALL_INFORMATION_IMPL::NameInformation() const {
    if (NameInformation_)
        return &(*NameInformation_);
    return nullptr;
}

void FILE_ALL_INFORMATION_IMPL::write(std::ostream& os, const std::string& linePrefix) const {
    os << linePrefix << "FileInformationClass: " << to_string(FileInformationClass()) << '\n';

    const std::string new_prefix(linePrefix + "    ");

    if (BasicInformation()) {
        BasicInformation()->write(os, new_prefix);
    }
    if (StandardInformation()) {
        StandardInformation()->write(os, new_prefix);
    }
    if (InternalInformation()) {
        InternalInformation()->write(os, new_prefix);
    }
    if (EaInformation()) {
        EaInformation()->write(os, new_prefix);
    }
    if (AccessInformation()) {
        AccessInformation()->write(os, new_prefix);
    }
    if (PositionInformation()) {
        PositionInformation()->write(os, new_prefix);
    }
    if (ModeInformation()) {
        ModeInformation()->write(os, new_prefix);
    }
    if (AlignmentInformation()) {
        AlignmentInformation()->write(os, new_prefix);
    }
    if (NameInformation()) {
        NameInformation()->write(os, new_prefix);
    }
}

Json::Value FILE_ALL_INFORMATION_IMPL::json() const {
    Json::Value result;
    result["FileInformationClass"] = to_string(FileInformationClass());
    if (BasicInformation()) {
        result["BasicInformation"] = BasicInformation()->json();
    }
    if (StandardInformation()) {
        result["StandardInformation"] = StandardInformation()->json();
    }
    if (InternalInformation()) {
        result["InternalInformation"] = InternalInformation()->json();
    }
    if (EaInformation()) {
        result["EaInformation"] = EaInformation()->json();
    }
    if (AccessInformation()) {
        result["AccessInformation"] = AccessInformation()->json();
    }
    if (PositionInformation()) {
        result["PositionInformation"] = PositionInformation()->json();
    }
    if (ModeInformation()) {
        result["ModeInformation"] = ModeInformation()->json();
    }
    if (AlignmentInformation()) {
        result["AlignmentInformation"] = AlignmentInformation()->json();
    }
    if (NameInformation()) {
        result["NameInformation"] = NameInformation()->json();
    }
    return result;
}

FILE_ALL_INFORMATION_IMPL::FILE_ALL_INFORMATION_IMPL(const GuestVirtualAddress& base_address,
                                                     uint32_t buffer_size)
    : gva_(base_address), buffer_size_(buffer_size) {

    // Read each possible field and parse it, as long as data is remaining
    auto gva = base_address;

    // _FILE_BASIC_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_BASIC_INFORMATION))
        return;
    BasicInformation_.emplace(gva, sizeof(structs::_FILE_BASIC_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_BASIC_INFORMATION);
    gva += sizeof(structs::_FILE_BASIC_INFORMATION);

    // _FILE_STANDARD_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_STANDARD_INFORMATION))
        return;
    StandardInformation_.emplace(gva, sizeof(structs::_FILE_STANDARD_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_STANDARD_INFORMATION);
    gva += sizeof(structs::_FILE_STANDARD_INFORMATION);

    // _FILE_INTERNAL_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_INTERNAL_INFORMATION))
        return;
    InternalInformation_.emplace(gva, sizeof(structs::_FILE_INTERNAL_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_INTERNAL_INFORMATION);
    gva += sizeof(structs::_FILE_INTERNAL_INFORMATION);

    // _FILE_EA_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_EA_INFORMATION))
        return;
    EaInformation_.emplace(gva, sizeof(structs::_FILE_EA_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_EA_INFORMATION);
    gva += sizeof(structs::_FILE_EA_INFORMATION);

    // _FILE_ACCESS_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_ACCESS_INFORMATION))
        return;
    AccessInformation_.emplace(gva, sizeof(structs::_FILE_ACCESS_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_ACCESS_INFORMATION);
    gva += sizeof(structs::_FILE_ACCESS_INFORMATION);

    // _FILE_POSITION_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_POSITION_INFORMATION))
        return;
    PositionInformation_.emplace(gva, sizeof(structs::_FILE_POSITION_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_POSITION_INFORMATION);
    gva += sizeof(structs::_FILE_POSITION_INFORMATION);

    // _FILE_MODE_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_MODE_INFORMATION))
        return;
    ModeInformation_.emplace(gva, sizeof(structs::_FILE_MODE_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_MODE_INFORMATION);
    gva += sizeof(structs::_FILE_MODE_INFORMATION);

    // _FILE_ALIGNMENT_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_ALIGNMENT_INFORMATION))
        return;
    AlignmentInformation_.emplace(gva, sizeof(structs::_FILE_ALIGNMENT_INFORMATION));
    buffer_size -= sizeof(structs::_FILE_ALIGNMENT_INFORMATION);
    gva += sizeof(structs::_FILE_ALIGNMENT_INFORMATION);

    // _FILE_NAME_INFORMATION
    if (buffer_size < sizeof(structs::_FILE_NAME_INFORMATION))
        return;
    NameInformation_.emplace(gva, buffer_size);
}

} // namespace nt
} // namespace windows
} // namespace introvirt