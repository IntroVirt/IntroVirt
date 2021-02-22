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

#include "FILE_INFO_IMPL.hh"
#include "StringTableImpl.hh"
#include <introvirt/windows/pe/types/StringFileInfo.hh>

#include <cassert>
#include <optional>

namespace introvirt {
namespace windows {
namespace pe {

class StringFileInfoImpl final : public FILE_INFO_IMPL<StringFileInfo> {
  public:
    const pe::StringTable* StringTable() const override {
        if (StringTable_)
            return &(*StringTable_);
        return nullptr;
    };

    StringFileInfoImpl(const GuestVirtualAddress& pStringFileInfo)
        : FILE_INFO_IMPL<StringFileInfo>(pStringFileInfo) {

        assert(this->szKey() == "StringFileInfo");
        StringTable_.emplace(this->pChildren());
    }

  public:
    std::optional<StringTableImpl> StringTable_;
};

} /* namespace pe */
} /* namespace windows */
} /* namespace introvirt */
